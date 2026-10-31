"""API request counts from the audit log: `python -m sec450.usage` (REQ-09).

Every /v1 request, including rejected ones (401, 429), has an audit entry, and
retention never deletes them, so these counts cover the API's whole life.
Requests to /health and /test, and requests refused before reaching the app
(TLS or Cloudflare), are not counted. In Docker:

    docker compose exec api python -m sec450.usage            # last 30 days
    docker compose exec api python -m sec450.usage --days 0   # everything
    docker compose exec api python -m sec450.usage --json
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import timedelta

from .config import load_config
from .db import connect
from .timeutil import Clock, iso

GROUPS = {
    "day": "substr(ts, 1, 10)",
    "key": "COALESCE(key_id, '(no valid key)')",
    "path": "path",
    "status": "CAST(status_code AS TEXT)",
}


def usage(conn: sqlite3.Connection, since: str | None = None) -> dict:
    where, args = ("WHERE ts >= ?", [since]) if since else ("", [])
    total, first, last = conn.execute(f"SELECT COUNT(*), MIN(ts), MAX(ts) FROM audit_entry {where}", args).fetchone()
    result: dict = {"since": since, "total": total, "first": first, "last": last}
    for name, expr in GROUPS.items():
        order = "1 DESC" if name == "day" else "2 DESC, 1"
        result[f"by_{name}"] = {r[0]: r[1] for r in conn.execute(
            f"SELECT {expr}, COUNT(*) FROM audit_entry {where} GROUP BY 1 ORDER BY {order}", args)}
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sec450.usage")
    parser.add_argument("--days", type=int, default=30, help="look back this many days (0 = all time)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of tables")
    parser.add_argument("--config", help="path to config.yaml (default: $SEC450_CONFIG or ./config.yaml)")
    args = parser.parse_args(argv)

    conn = connect(load_config(args.config).database_path)
    since = iso(Clock().now() - timedelta(days=args.days)) if args.days > 0 else None
    result = usage(conn, since)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    print(f"{result['total']} API requests"
          + (f" since {since[:10]}" if since else "")
          + (f" ({result['first'][:19]}Z to {result['last'][:19]}Z)" if result["total"] else ""))
    for name in GROUPS:
        print(f"\nby {name}:")
        for value, count in result[f"by_{name}"].items():
            print(f"  {count:>8}  {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
