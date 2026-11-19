"""One-time copy of the old SQLite database into PostgreSQL (DD-06):
`python -m sec450.migrate_sqlite /path/to/sec450.db`.

Every table is copied as it is: same ids, same text, so the batch and audit hash
chains (DD-07, DD-08) verify unchanged and existing API keys keep working. The copy
runs in one transaction; afterwards every row is compared with the source and both
chains are verified. Prints a JSON summary; exits 0 only if everything matches.

Stop the collector and api first, so nothing is written to either database meanwhile
(README.md, "Moving from SQLite"). In Docker:

    docker compose run --rm -v sec450_db:/data collector \\
        python -m sec450.migrate_sqlite /data/sec450.db
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import time
from collections.abc import Generator, Iterator
from contextlib import closing
from itertools import zip_longest
from typing import Any, cast

from .config import load_config
from .db import AUDIT_LOCK, SCHEMA, Connection, Row, connect, copy_rows, init_db, one, transaction
from .hashchain import verify_audit, verify_batches

# In dependency order, as the schema creates them.
TABLES = re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA)


def _source_columns(src: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in src.execute(f'PRAGMA table_info("{table}")')]


def _target_columns(dst: Connection, table: str) -> list[str]:
    return [r[0] for r in dst.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() "
        "AND table_name = %s ORDER BY ordinal_position", (table,))]


def _primary_key(dst: Connection, table: str) -> list[str]:
    return [r[0] for r in dst.execute(
        "SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid "
        "AND a.attnum = ANY(i.indkey) WHERE i.indrelid = %s::regclass AND i.indisprimary "
        "ORDER BY array_position(i.indkey, a.attnum)", (table,))]


def _quoted(columns: list[str]) -> list[str]:
    return [f'"{c}"' for c in columns]


def _source_rows(src: sqlite3.Connection, table: str, columns: list[str], order: list[str]) -> Iterator[tuple]:
    return src.execute(f"SELECT {', '.join(_quoted(columns))} FROM {table} ORDER BY {', '.join(_quoted(order))}")


def _target_rows(dst: Connection, table: str, columns: list[str], order: list[str]) -> Generator[Row, None, None]:
    return cast(Generator[Row, None, None], dst.cursor().stream(
        f"SELECT {', '.join(_quoted(columns))} FROM {table} ORDER BY {', '.join(_quoted(order))}"))


def copy_database(src: sqlite3.Connection, dst: Connection, replace: bool = False) -> dict[str, int]:
    """Copy every table; returns the row count per table."""
    init_db(dst)
    counts: dict[str, int] = {}
    with transaction(dst):
        dst.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_LOCK,))   # the audit chain too
        existing = {t: one(dst.execute(f"SELECT COUNT(*) FROM {t}"))[0] for t in TABLES}
        if any(existing.values()):
            if not replace:
                raise SystemExit(f"target database is not empty ({ {t: n for t, n in existing.items() if n} }); "
                                 "pass --replace to overwrite it")
            dst.execute(f"TRUNCATE {', '.join(TABLES)} RESTART IDENTITY CASCADE")
        for table in TABLES:
            columns = _target_columns(dst, table)
            if sorted(_source_columns(src, table)) != sorted(columns):
                raise SystemExit(f"{table}: columns differ between SQLite and PostgreSQL")
            order = _primary_key(dst, table)
            copy_rows(dst, table, _quoted(columns), _source_rows(src, table, columns, order))
            counts[table] = one(dst.execute(f"SELECT COUNT(*) FROM {table}"))[0]
            # Identity columns continue after the copied ids.
            for (col,) in dst.execute(
                    "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() "
                    "AND table_name = %s AND is_identity = 'YES'", (table,)).fetchall():
                dst.execute(f"SELECT setval(pg_get_serial_sequence(%s, %s), COALESCE(MAX(\"{col}\"), 0) + 1, false) "
                            f"FROM {table}", (table, col))
    dst.execute("ANALYZE")
    return counts


def compare(src: sqlite3.Connection, dst: Connection) -> dict[str, Any]:
    """Row-by-row comparison in primary-key order; returns the first difference per table."""
    differences: dict[str, Any] = {}
    for table in TABLES:
        columns = _target_columns(dst, table)
        order = _primary_key(dst, table)
        with closing(_target_rows(dst, table, columns, order)) as target:
            for i, (a, b) in enumerate(zip_longest(_source_rows(src, table, columns, order), target)):
                if a is None or b is None or tuple(a) != tuple(b):
                    differences[table] = {"row": i, "sqlite": a and list(a), "postgres": b and list(b)}
                    break
    return differences


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sec450.migrate_sqlite")
    parser.add_argument("sqlite_path", help="the old database file (e.g. /data/sec450.db)")
    parser.add_argument("--config", help="path to config.yaml (default: $SEC450_CONFIG or ./config.yaml)")
    parser.add_argument("--replace", action="store_true", help="empty a non-empty target first")
    args = parser.parse_args(argv)

    src = sqlite3.connect(f"file:{args.sqlite_path}?mode=ro", uri=True)
    dst = connect(load_config(args.config).database)
    started = time.monotonic()
    counts = copy_database(src, dst, replace=args.replace)
    copied = time.monotonic()
    differences = compare(src, dst)
    chains = {"batches": verify_batches(dst), "audit": verify_audit(dst)}
    ok = not differences and all(c["status"] == "intact" for c in chains.values())
    print(json.dumps({"ok": ok, "rows": counts, "differences": differences, "chains": chains,
                      "copy_seconds": round(copied - started, 1),
                      "verify_seconds": round(time.monotonic() - copied, 1)}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
