"""Lab application log parser: one JSON object per line.

Required keys: ts, event, outcome. Optional: peer_ip, x_forwarded_for, user,
api_key_id, path, status, bytes.
"""
from __future__ import annotations

import json
from datetime import datetime

from ..models import ParsedEvent, ParseError
from ..timeutil import to_utc
from .common import ParseContext, resolve_client_ip

OUTCOMES = {"success", "failure", "unknown"}


def parse_app(line: str, ctx: ParseContext) -> ParsedEvent:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(obj, dict):
        raise ParseError("JSON line is not an object")
    missing = [k for k in ("ts", "event", "outcome") if k not in obj]
    if missing:
        raise ParseError(f"missing field(s): {', '.join(missing)}")
    if obj["outcome"] not in OUTCOMES:
        raise ParseError(f"bad outcome {obj['outcome']!r}")
    try:
        ts = to_utc(datetime.fromisoformat(str(obj["ts"]).replace("Z", "+00:00")), ctx.tz)
        status = int(obj["status"]) if obj.get("status") is not None else None
        bytes_sent = int(obj.get("bytes") or 0)
    except (TypeError, ValueError) as exc:
        raise ParseError(f"bad field value: {exc}") from exc
    return ParsedEvent(
        ts=ts,
        action=str(obj["event"]),
        target=str(obj.get("path") or ""),
        outcome=obj["outcome"],
        client_ip=resolve_client_ip(obj.get("peer_ip"), obj.get("x_forwarded_for"), ctx.trusted_proxies),
        username=obj.get("user") or None,
        api_key_id=obj.get("api_key_id") or None,
        status_code=status,
        bytes_sent=bytes_sent,
    )
