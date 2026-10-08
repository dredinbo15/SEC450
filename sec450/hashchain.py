"""SHA-256 hash chains over log batches and audit entries (REQ-08, REQ-09, DD-07, DD-08)."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

GENESIS = "0" * 64


def _digest(payload: Any) -> str:
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def batch_hash(prev_hash: str, batch_id: int, source: str, collected_at: str, lines: list[str]) -> str:
    return _digest([prev_hash, batch_id, source, collected_at, lines])


def audit_hash(prev_hash: str, fields: dict[str, Any]) -> str:
    return _digest([prev_hash, fields])


def anchor(conn: sqlite3.Connection, chain: str) -> tuple[int | None, str]:
    row = conn.execute(
        "SELECT first_retained_id, anchor_hash FROM chain_anchor WHERE chain = ?", (chain,)
    ).fetchone()
    return (row["first_retained_id"], row["anchor_hash"]) if row else (None, GENESIS)


def last_hash(conn: sqlite3.Connection, table: str) -> str:
    """Hash of the newest row in the chain, or the anchor if the chain is empty."""
    id_col = "batch_id" if table == "batch" else "entry_id"
    row = conn.execute(f"SELECT hash FROM {table} ORDER BY {id_col} DESC LIMIT 1").fetchone()
    if row:
        return row["hash"]
    return anchor(conn, "batch" if table == "batch" else "audit")[1]


def verify_batches(conn: sqlite3.Connection) -> dict[str, Any]:
    """Walk the batch chain from its anchor.

    Returns {"status": "intact", "batches": n} or
    {"status": "broken", "batch_id": id, "reason": ...} for the first mismatch.
    """
    first_id, expected_prev = anchor(conn, "batch")
    batches = conn.execute(
        "SELECT batch_id, source, collected_at, line_count, prev_hash, hash FROM batch ORDER BY batch_id"
    ).fetchall()
    if batches and first_id is not None and batches[0]["batch_id"] != first_id:
        return {"status": "broken", "batch_id": batches[0]["batch_id"], "reason": "first retained batch missing"}
    for b in batches:
        lines = [r["text"] for r in conn.execute(
            "SELECT text FROM raw_line WHERE batch_id = ? ORDER BY seq", (b["batch_id"],))]
        if b["prev_hash"] != expected_prev:
            reason = "prev_hash does not match preceding batch"
        elif len(lines) != b["line_count"]:
            reason = "line count mismatch"
        elif batch_hash(b["prev_hash"], b["batch_id"], b["source"], b["collected_at"], lines) != b["hash"]:
            reason = "content hash mismatch"
        else:
            expected_prev = b["hash"]
            continue
        return {"status": "broken", "batch_id": b["batch_id"], "reason": reason}
    return {"status": "intact", "batches": len(batches)}


AUDIT_FIELDS = ("ts", "key_id", "method", "path", "params_json", "status_code", "result_count")


def verify_audit(conn: sqlite3.Connection) -> dict[str, Any]:
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
