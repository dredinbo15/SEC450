"""SHA-256 hash chains over log batches and audit entries (REQ-08, REQ-09, DD-07, DD-08)."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Collection, Sequence
from typing import Any

GENESIS = "0" * 64


def _digest(payload: Any) -> str:
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def lines_digest(lines: Sequence[str | bytes]) -> str:
    """SHA-256 of the lines joined by "\n". A str is hashed as its UTF-8 bytes, so a batch of
    valid UTF-8 lines hashes the same whether it is given as text or as the bytes read."""
    return hashlib.sha256(b"\n".join(ln.encode("utf-8") if isinstance(ln, str) else ln
                                     for ln in lines)).hexdigest()


def chain_hash(prev_hash: str, source: str, collected_at: str, lines_hash: str) -> str:
    return _sha256("|".join((prev_hash, source, collected_at, lines_hash)))


def batch_hash(prev_hash: str, source: str, collected_at: str, lines: Sequence[str | bytes]) -> str:
    """hash = SHA-256(prev_hash | source | collected_at | SHA-256(lines))   (DD-07)

    "|" is the field separator (the "‖" in the design doc). It cannot be
    ambiguous: hashes are hex, collected_at is ISO 8601, and source names are
    validated in config.py to contain no "|". Lines are joined with "\n"; a
    stored line never contains a newline because the collector splits on it.
    """
    return chain_hash(prev_hash, source, collected_at, lines_digest(lines))


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


def stored_lines(conn: sqlite3.Connection, batch_id: int) -> list[str | bytes]:
    """A batch's lines as they were hashed: the original bytes where text is a lossy decode."""
    return [r["raw_bytes"] if r["raw_bytes"] is not None else r["text"] for r in conn.execute(
        "SELECT text, raw_bytes FROM raw_line WHERE batch_id = ? ORDER BY seq", (batch_id,))]


def verify_batches(conn: sqlite3.Connection, content_ids: Collection[int] | None = None) -> dict[str, Any]:
    """Walk the batch chain from its anchor.

    With content_ids, the lines are re-hashed only for those batches (and for old batches
    with no stored lines_hash); every other batch is checked through its stored lines_hash,
    which still proves the chain's links and order. Without it, every line is re-hashed.

    Returns {"status": "intact", "batches": n} or
    {"status": "broken", "batch_id": id, "reason": ...} for the first mismatch.
    """
    first_id, expected_prev = anchor(conn, "batch")
    batches = conn.execute(
        "SELECT batch_id, source, collected_at, line_count, prev_hash, hash, lines_hash FROM batch ORDER BY batch_id"
    ).fetchall()
    if batches and first_id is not None and batches[0]["batch_id"] != first_id:
        return {"status": "broken", "batch_id": batches[0]["batch_id"], "reason": "first retained batch missing"}
    for b in batches:
        reason = None
        lines_hash = b["lines_hash"]
        if b["prev_hash"] != expected_prev:
            reason = "prev_hash does not match preceding batch"
        elif content_ids is None or b["batch_id"] in content_ids or lines_hash is None:
            lines = stored_lines(conn, b["batch_id"])
            if len(lines) != b["line_count"]:
                reason = "line count mismatch"
            elif lines_hash is not None and lines_digest(lines) != lines_hash:
                reason = "content hash mismatch"
            lines_hash = lines_digest(lines)
        if reason is None and chain_hash(b["prev_hash"], b["source"], b["collected_at"], lines_hash) != b["hash"]:
            reason = "content hash mismatch"
        if reason is None:
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
