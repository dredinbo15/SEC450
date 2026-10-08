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
MAX_INT = 2**63 - 1  # SQLite INTEGER


def _opt_str(obj: dict, key: str) -> str | None:
    value = obj.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ParseError(f"field {key!r} must be a string")
    return value


def _opt_int(obj: dict, key: str, high: int) -> int | None:
    value = obj.get(key)
    if value is None or value == "":
        return None
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ParseError(f"field {key!r} is not an integer") from exc
    if not 0 <= number <= high:
        raise ParseError(f"field {key!r} out of range: {number}")
    return number


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
    except (TypeError, ValueError) as exc:
        raise ParseError(f"bad field value: {exc}") from exc
    return ParsedEvent(
        ts=ts,
        action=str(obj["event"]),
        target=str(obj.get("path") or ""),
        outcome=obj["outcome"],
        client_ip=resolve_client_ip(_opt_str(obj, "peer_ip"), _opt_str(obj, "x_forwarded_for"),
                                    ctx.trusted_proxies),
        username=_opt_str(obj, "user"),
        api_key_id=_opt_str(obj, "api_key_id"),
        status_code=_opt_int(obj, "status", 999),
        bytes_sent=_opt_int(obj, "bytes", MAX_INT) or 0,
    )
