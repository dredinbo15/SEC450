"""Hash-chained audit log of every API request (REQ-09, DD-12)."""
from __future__ import annotations

import json

from .. import hashchain
from ..db import AUDIT_LOCK, Connection, transaction


def write_audit(conn: Connection, ts: str, key_id: str | None, method: str, path: str,
                params: dict, status_code: int, result_count: int) -> None:
    """Append one entry. Raises on any failure; callers must fail closed."""
    fields = {
        "ts": ts, "key_id": key_id, "method": method, "path": path,
        "params_json": json.dumps(params, sort_keys=True, ensure_ascii=False),
        "status_code": status_code, "result_count": result_count,
    }
    with transaction(conn, lock=AUDIT_LOCK) as c:
        prev = hashchain.last_hash(c, "audit_entry")
        c.execute(
            "INSERT INTO audit_entry (ts, key_id, method, path, params_json, status_code, result_count, "
            "prev_hash, hash) VALUES (%(ts)s, %(key_id)s, %(method)s, %(path)s, %(params_json)s, %(status_code)s, "
            "%(result_count)s, %(prev_hash)s, %(hash)s)",
            {**fields, "prev_hash": prev, "hash": hashchain.audit_hash(prev, fields)},
        )
