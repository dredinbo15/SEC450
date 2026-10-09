"""OpenSSH auth log parser (classic syslog or RFC 3339 timestamps)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from ..models import Outcome, ParsedEvent, ParseError
from ..timeutil import to_utc
from .common import ParseContext, normalize_ip

SYSLOG_RE = re.compile(
    r"^(?P<time>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+) "
    r"(?P<host>\S+) (?P<prog>[\w\-.]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)

MESSAGES: list[tuple[re.Pattern[str], str, Outcome]] = [
    (re.compile(r"^Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
                r"(?P<user>\S+) from (?P<ip>\S+) port \d+"), "ssh_login", "failure"),
    (re.compile(r"^Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
                r"from (?P<ip>\S+) port \d+"), "ssh_login", "success"),
    (re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)"), "ssh_invalid_user", "failure"),
]
FROM_IP_RE = re.compile(r"from (?P<ip>[0-9a-fA-F:.]+)")


def _parse_time(text: str, ctx: ParseContext) -> datetime:
    if text[0].isdigit():
        return to_utc(datetime.fromisoformat(text.replace("Z", "+00:00")), ctx.tz)
    # Classic syslog has no year: assume the current one, rolling back at New Year.
    local_now = ctx.now.astimezone(ZoneInfo(ctx.tz))
    ts = to_utc(datetime.strptime(f"{local_now.year} {text}", "%Y %b %d %H:%M:%S"), ctx.tz)
    if ts > ctx.now + timedelta(days=7):
        ts = to_utc(datetime.strptime(f"{local_now.year - 1} {text}", "%Y %b %d %H:%M:%S"), ctx.tz)
    return ts


def parse_auth(line: str, ctx: ParseContext) -> ParsedEvent:
    m = SYSLOG_RE.match(line)
    if not m:
        raise ParseError("does not match syslog format")
    try:
        ts = _parse_time(m["time"], ctx)
    except ValueError as exc:
        raise ParseError(f"bad syslog time {m['time']!r}") from exc
    msg = m["msg"]
    for pattern, action, outcome in MESSAGES:
        hit = pattern.match(msg)
        if hit:
            return ParsedEvent(
                ts=ts, action=action, target=f"{m['prog']}@{m['host']}", outcome=outcome,
                client_ip=normalize_ip(hit["ip"]), username=hit["user"] or None,
            )
    ip = FROM_IP_RE.search(msg)
    return ParsedEvent(
        ts=ts, action=f"{m['prog']}_other", target=msg[:200], outcome="unknown",
        client_ip=normalize_ip(ip["ip"]) if ip else None,
    )
