import ipaddress
from datetime import UTC, datetime

import pytest

from sec450.models import ParseError
from sec450.parsers import PARSERS, ParseContext

NOW = datetime(2026, 10, 8, 15, 0, tzinfo=UTC)
TZ = "America/Indiana/Indianapolis"
PROXY = [ipaddress.ip_network("172.20.0.10/32")]


def ctx(tz=TZ):
    return ParseContext(tz=tz, now=NOW, trusted_proxies=PROXY)


def test_local_time_converts_to_utc():  # AC-02
    ev = PARSERS["app"]('{"ts": "2026-10-08T10:00:00", "event": "login", "outcome": "failure"}', ctx())
    assert ev.ts == datetime(2026, 10, 8, 14, 0, tzinfo=UTC)


def test_fall_back_hour_converts_without_error():  # AC-02
    ev = PARSERS["nginx_error"]("2026/11/01 01:30:00 [error] 1#1: *2 open() failed, client: 10.0.0.1", ctx())
    assert ev.ts.tzinfo is not None


def test_nginx_access_fields():
    line = ('198.51.100.7 - alice [08/Oct/2026:10:00:00 -0400] "GET /admin?id=1 HTTP/1.1" 404 512 '
            '"-" "curl/8" "-"')
    ev = PARSERS["nginx_access"](line, ctx())
    assert (ev.client_ip, ev.username, ev.target, ev.status_code, ev.bytes_sent, ev.outcome) == \
        ("198.51.100.7", "alice", "/admin?id=1", 404, 512, "failure")
    assert ev.ts == datetime(2026, 10, 8, 14, 0, tzinfo=UTC)


@pytest.mark.parametrize("peer,expected", [("172.20.0.10", "203.0.113.9"), ("198.51.100.1", "198.51.100.1")])
def test_forwarded_ip_trusted_only_from_proxy(peer, expected):  # AC-05
    line = (f'{peer} - - [08/Oct/2026:10:00:00 -0400] "GET / HTTP/1.1" 200 10 "-" "ua" '
            f'"203.0.113.9"')
    assert PARSERS["nginx_access"](line, ctx()).client_ip == expected


def test_ssh_failed_login():
    ev = PARSERS["ssh_auth"]("Oct  8 10:00:00 ssh01 sshd[42]: Failed password for invalid user bob "
                             "from 2001:db8::1 port 5555 ssh2", ctx())
    assert (ev.action, ev.outcome, ev.username, ev.client_ip) == ("ssh_login", "failure", "bob", "2001:db8::1")


@pytest.mark.parametrize("kind,line", [
    ("app", "not json"),
    ("app", '{"ts": "2026-10-08T10:00:00Z", "event": "x"}'),
    ("nginx_access", "garbage"),
    ("ssh_auth", "no timestamp here"),
])
def test_malformed_lines_raise(kind, line):  # AC-17
    with pytest.raises(ParseError):
        PARSERS[kind](line, ctx())
