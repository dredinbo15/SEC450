"""Nginx access and error log parsers.

Access lines use the lab's log_format (combined plus X-Forwarded-For):
  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
  "$http_referer" "$http_user_agent" "$http_x_forwarded_for"
"""
from __future__ import annotations

import re
from datetime import datetime

from ..models import ParsedEvent, ParseError
from ..timeutil import to_utc
from .common import ParseContext, normalize_ip, resolve_client_ip, split_request

ACCESS_RE = re.compile(
    r'^(?P<peer>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)"'
    r'(?: "(?P<xff>[^"]*)")?\s*$'
)

ERROR_RE = re.compile(
    r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] \d+#\d+: (?:\*\d+ )?(?P<msg>.*)$"
)
ERROR_CLIENT_RE = re.compile(r", client: (?P<client>[^,\s]+)")
ERROR_REQUEST_RE = re.compile(r', request: "(?P<request>[^"]*)"')


def parse_access(line: str, ctx: ParseContext) -> ParsedEvent:
    m = ACCESS_RE.match(line)
    if not m:
        raise ParseError("does not match nginx access format")
    try:
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError as exc:
        raise ParseError(f"bad nginx time {m['time']!r}") from exc
    status = int(m["status"])
    method, target = split_request(m["request"])
    user = m["user"]
    return ParsedEvent(
        ts=to_utc(ts, ctx.tz),
        action=method,
        target=target,
        outcome="success" if status < 400 else "failure",
        client_ip=resolve_client_ip(m["peer"], m["xff"], ctx.trusted_proxies),
        username=None if user == "-" else user,
        status_code=status,
        bytes_sent=0 if m["bytes"] == "-" else int(m["bytes"]),
        extra={"peer_ip": normalize_ip(m["peer"]), "user_agent": m["ua"]},
    )


def parse_error(line: str, ctx: ParseContext) -> ParsedEvent:
    m = ERROR_RE.match(line)
    if not m:
        raise ParseError("does not match nginx error format")
    try:
        ts = datetime.strptime(m["time"], "%Y/%m/%d %H:%M:%S")
    except ValueError as exc:
        raise ParseError(f"bad nginx error time {m['time']!r}") from exc
    msg = m["msg"]
    client = ERROR_CLIENT_RE.search(msg)
    request = ERROR_REQUEST_RE.search(msg)
    target = split_request(request["request"])[1] if request else msg.split(",", 1)[0][:200]
    return ParsedEvent(
        ts=to_utc(ts, ctx.tz),
        action="nginx_error",
        target=target,
        outcome="failure",
        client_ip=normalize_ip(client["client"]) if client else None,
        extra={"level": m["level"]},
    )
