"""SHA-256 hash chains over log batches and audit entries (REQ-08, REQ-09, DD-07, DD-08)."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Generator
from contextlib import closing
from typing import Any, cast

from .db import Connection, Row

GENESIS = "0" * 64


def _digest(payload: Any) -> str:
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def batch_hash(prev_hash: str, source: str, collected_at: str, lines: list[str]) -> str:
    """hash = SHA-256(prev_hash | source | collected_at | SHA-256(lines))   (DD-07)

    "|" is the field separator (the "‖" in the design doc). It cannot be
    ambiguous: hashes are hex, collected_at is ISO 8601, and source names are
    validated in config.py to contain no "|". Lines are joined with "\n"; a
    stored line never contains a newline because the collector splits on it.
    """
    return _batch_hash_joined(prev_hash, source, collected_at, "\n".join(lines))


def _batch_hash_joined(prev_hash: str, source: str, collected_at: str, joined_lines: str) -> str:
    return _sha256("|".join((prev_hash, source, collected_at, _sha256(joined_lines))))


def audit_hash(prev_hash: str, fields: dict[str, Any]) -> str:
    return _digest([prev_hash, fields])


def anchor(conn: Connection, chain: str) -> tuple[int | None, str]:
    row = conn.execute(
        "SELECT first_retained_id, anchor_hash FROM chain_anchor WHERE chain = %s", (chain,)
    ).fetchone()
    return (row["first_retained_id"], row["anchor_hash"]) if row else (None, GENESIS)


def last_hash(conn: Connection, table: str) -> str:
    """Hash of the newest row in the chain, or the anchor if the chain is empty."""
    id_col = "batch_id" if table == "batch" else "entry_id"
    row = conn.execute(f"SELECT hash FROM {table} ORDER BY {id_col} DESC LIMIT 1").fetchone()
    if row:
        return row["hash"]
    return anchor(conn, "batch" if table == "batch" else "audit")[1]


def verify_batches(conn: Connection) -> dict[str, Any]:
    """Walk the batch chain from its anchor.

    Returns {"status": "intact", "batches": n} or
    {"status": "broken", "batch_id": id, "reason": ...} for the first mismatch.
    """
    first_id, expected_prev = anchor(conn, "batch")
    # One streamed query, lines joined in the database exactly as batch_hash() joins them,
    # instead of a round trip per batch.
    stream = cast(Generator[Row, None, None], conn.cursor().stream(
        "SELECT b.batch_id, b.source, b.collected_at, b.line_count, b.prev_hash, b.hash, "
        "COUNT(r.raw_id) AS n_lines, COALESCE(string_agg(r.text, E'\\n' ORDER BY r.seq), '') AS joined "
        "FROM batch b LEFT JOIN raw_line r USING (batch_id) GROUP BY b.batch_id ORDER BY b.batch_id"))
    n = 0
    with closing(stream) as batches:   # closing stops the stream, so the connection is free again
        for b in batches:
            n += 1
            if n == 1 and first_id is not None and b["batch_id"] != first_id:
                reason = "first retained batch missing"
            elif b["prev_hash"] != expected_prev:
                reason = "prev_hash does not match preceding batch"
            elif b["n_lines"] != b["line_count"]:
                reason = "line count mismatch"
            elif _batch_hash_joined(b["prev_hash"], b["source"], b["collected_at"], b["joined"]) != b["hash"]:
                reason = "content hash mismatch"
            else:
                expected_prev = b["hash"]
                continue
            return {"status": "broken", "batch_id": b["batch_id"], "reason": reason}
    return {"status": "intact", "batches": n}


AUDIT_FIELDS = ("ts", "key_id", "method", "path", "params_json", "status_code", "result_count")


def verify_audit(conn: Connection) -> dict[str, Any]:
    first_id, expected_prev = anchor(conn, "audit")
    rows = conn.execute("SELECT * FROM audit_entry ORDER BY entry_id").fetchall()
    if rows and first_id is not None and rows[0]["entry_id"] != first_id:
        return {"status": "broken", "entry_id": rows[0]["entry_id"], "reason": "first retained entry missing"}
    for r in rows:
        fields = {k: r[k] for k in AUDIT_FIELDS}
        if r["prev_hash"] != expected_prev or audit_hash(r["prev_hash"], fields) != r["hash"]:
            return {"status": "broken", "entry_id": r["entry_id"]}
        expected_prev = r["hash"]
    return {"status": "intact", "entries": len(rows)}
