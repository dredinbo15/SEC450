"""Read-only API key management (REQ-09, DD-11).

    python -m sec450.keys create      # prints the key once; only its hash is stored
    python -m sec450.keys revoke KEY_ID
    python -m sec450.keys list
"""
from __future__ import annotations

import argparse
import hashlib
import secrets
import sqlite3

from .config import load_config
from .db import connect, init_db, transaction
from .timeutil import Clock, iso


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def create_key(conn: sqlite3.Connection, clock: Clock | None = None) -> tuple[str, str]:
    key_id = "k_" + secrets.token_hex(6)
    key = "sec450_" + secrets.token_urlsafe(32)
    with transaction(conn) as c:
        c.execute("INSERT INTO api_key (key_id, key_hash, created_at) VALUES (?, ?, ?)",
                  (key_id, hash_key(key), iso((clock or Clock()).now())))
    return key_id, key


def revoke_key(conn: sqlite3.Connection, key_id: str) -> bool:
    with transaction(conn) as c:
        return c.execute("UPDATE api_key SET revoked = 1 WHERE key_id = ?", (key_id,)).rowcount == 1


def lookup_key(conn: sqlite3.Connection, key: str) -> str | None:
    """Return the key id for a valid, unrevoked key."""
    row = conn.execute("SELECT key_id FROM api_key WHERE key_hash = ? AND revoked = 0",
                       (hash_key(key),)).fetchone()
    return row["key_id"] if row else None


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m sec450.keys")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("create")
    sub.add_parser("list")
    revoke = sub.add_parser("revoke")
    revoke.add_argument("key_id")
    args = parser.parse_args()

    conn = connect(load_config().database_path)
    init_db(conn)
    if args.cmd == "create":
        key_id, key = create_key(conn)
        print(f"key_id: {key_id}\nkey:    {key}\nStore the key now; it cannot be shown again.")
    elif args.cmd == "revoke":
        print("revoked" if revoke_key(conn, args.key_id) else "no such key")
    else:
        for r in conn.execute("SELECT key_id, revoked, created_at FROM api_key ORDER BY created_at"):
            print(f"{r['key_id']}  {'revoked' if r['revoked'] else 'active '}  {r['created_at']}")


if __name__ == "__main__":
    main()
