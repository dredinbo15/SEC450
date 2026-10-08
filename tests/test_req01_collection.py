"""REQ-01: collect every source on an interval and parse into the event schema in UTC."""
import ipaddress
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from sec450.collector import Collector
from sec450.config import Config
from sec450.geoip import GeoIP
from sec450.hashchain import verify_batches
from sec450.models import ParsedEvent
from sec450.parsers import PARSERS, ParseContext

from .conftest import ROOT

NOW = datetime(2026, 10, 8, 15, 0, tzinfo=timezone.utc)
TZ = "America/Indiana/Indianapolis"  # EDT (UTC-4) in October, EST (UTC-5) after 1 Nov 2026 02:00
PROXY = [ipaddress.ip_network("172.20.0.10/32")]


def U(*args) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


def E(ts, action, target, outcome, client_ip=None, username=None, api_key_id=None,
      status_code=None, bytes_sent=0, **extra) -> ParsedEvent:
    return ParsedEvent(ts, action, target, outcome, client_ip, username, api_key_id,
                       status_code, bytes_sent, extra)


# --- AC-02: 40 fixture lines, 10 per format, with hand-written expected events -------------

NGINX_ACCESS = [
    ('198.51.100.7 - - [08/Oct/2026:10:00:00 -0400] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0" "-"',
     E(U(2026, 10, 8, 14, 0), "GET", "/", "success", "198.51.100.7", status_code=200, bytes_sent=612,
       peer_ip="198.51.100.7", user_agent="Mozilla/5.0")),
    ('198.51.100.7 - alice [08/Oct/2026:10:00:01 -0400] "POST /login HTTP/1.1" 401 0 "-" "curl/8.5.0" "-"',
     E(U(2026, 10, 8, 14, 0, 1), "POST", "/login", "failure", "198.51.100.7", "alice", status_code=401,
       peer_ip="198.51.100.7", user_agent="curl/8.5.0")),
    ('198.51.100.7 - - [08/Oct/2026:10:00:02 -0400] "GET /style.css HTTP/1.1" 304 - "-" "ua" "-"',
     E(U(2026, 10, 8, 14, 0, 2), "GET", "/style.css", "success", "198.51.100.7", status_code=304,
       peer_ip="198.51.100.7", user_agent="ua")),
    ('172.20.0.10 - - [08/Oct/2026:10:00:03 -0400] "GET /a HTTP/1.1" 200 10 "-" "ua" "203.0.113.9"',
     E(U(2026, 10, 8, 14, 0, 3), "GET", "/a", "success", "203.0.113.9", status_code=200, bytes_sent=10,
       peer_ip="172.20.0.10", user_agent="ua")),
    ('198.51.100.1 - - [08/Oct/2026:10:00:04 -0400] "GET /a HTTP/1.1" 200 10 "-" "ua" "203.0.113.9"',
     E(U(2026, 10, 8, 14, 0, 4), "GET", "/a", "success", "198.51.100.1", status_code=200, bytes_sent=10,
       peer_ip="198.51.100.1", user_agent="ua")),
    ('172.20.0.10 - - [08/Oct/2026:10:00:05 -0400] "GET /b HTTP/1.1" 200 10 "-" "ua" "203.0.113.9, 172.20.0.10"',
     E(U(2026, 10, 8, 14, 0, 5), "GET", "/b", "success", "203.0.113.9", status_code=200, bytes_sent=10,
       peer_ip="172.20.0.10", user_agent="ua")),
    ('2001:db8::5 - - [08/Oct/2026:10:00:06 -0400] "GET /search?q=%27 HTTP/1.1" 404 153 "-" "ua" "-"',
     E(U(2026, 10, 8, 14, 0, 6), "GET", "/search?q=%27", "failure", "2001:db8::5", status_code=404,
       bytes_sent=153, peer_ip="2001:db8::5", user_agent="ua")),
    (r'198.51.100.3 - - [08/Oct/2026:10:00:07 -0400] "\x16\x03\x01" 400 157 "-" "-" "-"',
     E(U(2026, 10, 8, 14, 0, 7), "INVALID", r"\x16\x03\x01", "failure", "198.51.100.3", status_code=400,
       bytes_sent=157, peer_ip="198.51.100.3", user_agent="-")),
    ('198.51.100.4 - - [08/Oct/2026:14:05:00 +0000] "GET /utc HTTP/1.1" 200 1 "-" "ua" "-"',
     E(U(2026, 10, 8, 14, 5), "GET", "/utc", "success", "198.51.100.4", status_code=200, bytes_sent=1,
       peer_ip="198.51.100.4", user_agent="ua")),
    ('198.51.100.5 - - [08/Oct/2026:10:00:09 -0400] "GET /download/big.iso HTTP/1.1" 200 10485761 "-" "wget"',
     E(U(2026, 10, 8, 14, 0, 9), "GET", "/download/big.iso", "success", "198.51.100.5", status_code=200,
       bytes_sent=10485761, peer_ip="198.51.100.5", user_agent="wget")),
]

NGINX_ERROR = [
    ('2026/10/08 10:00:00 [error] 12#12: *5 open() "/usr/share/nginx/html/x" failed (2: No such file or '
     'directory), client: 198.51.100.7, server: web01, request: "GET /x HTTP/1.1", host: "web01"',
     E(U(2026, 10, 8, 14, 0), "nginx_error", "/x", "failure", "198.51.100.7", level="error")),
    ('2026/10/08 10:01:00 [warn] 1#1: conflicting server name "web01" on 0.0.0.0:80, ignored',
     E(U(2026, 10, 8, 14, 1), "nginx_error", 'conflicting server name "web01" on 0.0.0.0:80', "failure",
       level="warn")),
    ('2026/10/08 10:02:00 [crit] 12#12: *7 SSL_do_handshake() failed (SSL: error) while SSL handshaking, '
     'client: 2001:db8::9, server: 0.0.0.0:443',
     E(U(2026, 10, 8, 14, 2), "nginx_error", "SSL_do_handshake() failed (SSL: error) while SSL handshaking",
       "failure", "2001:db8::9", level="crit")),
    ('2026/11/01 01:30:00 [error] 12#12: *8 open() "/y" failed (2: No such file or directory), '
     'client: 198.51.100.7, server: web01, request: "GET /y HTTP/1.1", host: "web01"',
     E(U(2026, 11, 1, 5, 30), "nginx_error", "/y", "failure", "198.51.100.7", level="error")),
    ('2026/10/08 10:04:00 [error] 12#12: *9 "/usr/share/nginx/html/../../etc/passwd" is not found '
     '(2: No such file or directory), client: 203.0.113.50, server: web01, '
     'request: "GET /../../etc/passwd HTTP/1.1", host: "web01"',
     E(U(2026, 10, 8, 14, 4), "nginx_error", "/../../etc/passwd", "failure", "203.0.113.50", level="error")),
    ('2026/10/08 10:05:00 [alert] 12#12: *10 limiting requests, excess: 10.500 by zone "one", '
     'client: 198.51.100.8, server: web01, request: "POST /api/login HTTP/1.1", host: "web01"',
     E(U(2026, 10, 8, 14, 5), "nginx_error", "/api/login", "failure", "198.51.100.8", level="alert")),
    ('2026/10/08 10:06:00 [notice] 1#1: signal process started',
     E(U(2026, 10, 8, 14, 6), "nginx_error", "signal process started", "failure", level="notice")),
    ('2026/10/08 10:07:00 [error] 12#12: *11 upstream timed out (110: Connection timed out) while reading '
     'response header from upstream, client: 198.51.100.9, server: web01, request: "GET /api/slow HTTP/1.1", '
     'upstream: "http://172.20.0.30:8000/api/slow", host: "web01"',
     E(U(2026, 10, 8, 14, 7), "nginx_error", "/api/slow", "failure", "198.51.100.9", level="error")),
    ('2026/10/08 10:08:00 [info] 12#12: *12 client sent invalid request while reading client request line, '
     'client: 198.51.100.10, server: web01, request: "BADREQ"',
     E(U(2026, 10, 8, 14, 8), "nginx_error", "BADREQ", "failure", "198.51.100.10", level="info")),
    ('2026/10/08 23:59:59 [error] 12#12: *13 access forbidden by rule, client: 198.51.100.11, '
     'server: web01, request: "GET /.git/config HTTP/1.1", host: "web01"',
     E(U(2026, 10, 9, 3, 59, 59), "nginx_error", "/.git/config", "failure", "198.51.100.11", level="error")),
]

SSH_AUTH = [
    ("Oct  8 10:00:00 ssh01 sshd[42]: Failed password for root from 203.0.113.20 port 51234 ssh2",
     E(U(2026, 10, 8, 14, 0), "ssh_login", "sshd@ssh01", "failure", "203.0.113.20", "root")),
    ("Oct  8 10:00:01 ssh01 sshd[42]: Failed password for invalid user admin from 203.0.113.20 port 51235 ssh2",
     E(U(2026, 10, 8, 14, 0, 1), "ssh_login", "sshd@ssh01", "failure", "203.0.113.20", "admin")),
    ("Oct  8 10:00:02 ssh01 sshd[43]: Accepted publickey for alice from 198.51.100.7 port 50000 ssh2: RSA SHA256:abc",
     E(U(2026, 10, 8, 14, 0, 2), "ssh_login", "sshd@ssh01", "success", "198.51.100.7", "alice")),
    ("Oct  8 10:00:03 ssh01 sshd[44]: Invalid user oracle from 203.0.113.21 port 40000",
     E(U(2026, 10, 8, 14, 0, 3), "ssh_invalid_user", "sshd@ssh01", "failure", "203.0.113.21", "oracle")),
    ("Oct  8 10:00:04 ssh01 sshd[44]: Invalid user  from 203.0.113.22 port 40001",
     E(U(2026, 10, 8, 14, 0, 4), "ssh_invalid_user", "sshd@ssh01", "failure", "203.0.113.22")),
    ("2026-10-08T10:05:00.123456-04:00 ssh01 sshd[45]: Failed keyboard-interactive/pam for bob "
     "from 2001:db8::1 port 5555 ssh2",
     E(U(2026, 10, 8, 14, 5, 0, 123456), "ssh_login", "sshd@ssh01", "failure", "2001:db8::1", "bob")),
    ("Oct  8 10:06:00 ssh01 sshd[46]: Connection closed by authenticating user root 203.0.113.20 port 51234 [preauth]",
     E(U(2026, 10, 8, 14, 6), "sshd_other",
       "Connection closed by authenticating user root 203.0.113.20 port 51234 [preauth]", "unknown")),
    ("Oct  8 10:07:00 ssh01 sshd[47]: Received disconnect from 203.0.113.20 port 51234:11: Bye Bye [preauth]",
     E(U(2026, 10, 8, 14, 7), "sshd_other", "Received disconnect from 203.0.113.20 port 51234:11: Bye Bye [preauth]",
       "unknown", "203.0.113.20")),
    ("Oct  8 10:08:00 ssh01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
     E(U(2026, 10, 8, 14, 8), "sudo_other", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
       "unknown")),
    # No year in classic syslog: a date >7 days ahead of the collector belongs to last year (EST, UTC-5).
    ("Dec 31 23:59:00 ssh01 sshd[48]: Failed password for root from 203.0.113.23 port 1 ssh2",
     E(U(2026, 1, 1, 4, 59), "ssh_login", "sshd@ssh01", "failure", "203.0.113.23", "root")),
]

APP = [
    ({"ts": "2026-10-08T10:00:00", "event": "login", "outcome": "failure", "peer_ip": "198.51.100.7",
      "user": "alice", "path": "/login", "status": 401},
     E(U(2026, 10, 8, 14, 0), "login", "/login", "failure", "198.51.100.7", "alice", status_code=401)),
    ({"ts": "2026-10-08T14:00:01Z", "event": "view", "outcome": "success", "peer_ip": "198.51.100.7"},
     E(U(2026, 10, 8, 14, 0, 1), "view", "", "success", "198.51.100.7")),
    ({"ts": "2026-10-08T16:00:02+02:00", "event": "view", "outcome": "success", "path": "/home"},
     E(U(2026, 10, 8, 14, 0, 2), "view", "/home", "success")),
    ({"ts": "2026-10-08T10:00:03", "event": "api_call", "outcome": "success", "peer_ip": "203.0.113.30",
      "api_key_id": "key-7", "path": "/api/v1/export", "status": 200, "bytes": 2048},
     E(U(2026, 10, 8, 14, 0, 3), "api_call", "/api/v1/export", "success", "203.0.113.30", api_key_id="key-7",
       status_code=200, bytes_sent=2048)),
    ({"ts": "2026-10-08T10:00:04", "event": "view", "outcome": "success", "peer_ip": "172.20.0.10",
      "x_forwarded_for": "203.0.113.31"},
     E(U(2026, 10, 8, 14, 0, 4), "view", "", "success", "203.0.113.31")),
    ({"ts": "2026-10-08T10:00:05", "event": "view", "outcome": "success", "peer_ip": "198.51.100.2",
      "x_forwarded_for": "203.0.113.31"},
     E(U(2026, 10, 8, 14, 0, 5), "view", "", "success", "198.51.100.2")),
    ({"ts": "2026-10-08T10:00:06", "event": "heartbeat", "outcome": "success"},
     E(U(2026, 10, 8, 14, 0, 6), "heartbeat", "", "success")),
    ({"ts": "2026-10-08T10:00:07", "event": "logout", "outcome": "unknown", "peer_ip": "2001:db8::abcd", "user": ""},
     E(U(2026, 10, 8, 14, 0, 7), "logout", "", "unknown", "2001:db8::abcd")),
    ({"ts": "2026-10-08T10:00:08", "event": "download", "outcome": "failure", "peer_ip": "198.51.100.12",
      "path": "/files/1", "status": "500", "bytes": "4096"},
     E(U(2026, 10, 8, 14, 0, 8), "download", "/files/1", "failure", "198.51.100.12", status_code=500,
       bytes_sent=4096)),
    ({"ts": "2026-11-01T01:30:00", "event": "login", "outcome": "success", "user": "bob"},
     E(U(2026, 11, 1, 5, 30), "login", "", "success", username="bob")),
]

FIXTURES = (
    [("nginx_access", line, ev) for line, ev in NGINX_ACCESS]
    + [("nginx_error", line, ev) for line, ev in NGINX_ERROR]
    + [("ssh_auth", line, ev) for line, ev in SSH_AUTH]
    + [("app", json.dumps(obj), ev) for obj, ev in APP]
)


def test_fixture_set_is_ten_per_format():  # AC-02 setup
    assert len(FIXTURES) == 40
    assert {k: sum(1 for f in FIXTURES if f[0] == k) for k in PARSERS} == dict.fromkeys(PARSERS, 10)


@pytest.mark.parametrize("kind,line,expected", FIXTURES)
def test_every_field_matches(kind, line, expected):  # AC-02
    assert PARSERS[kind](line, ParseContext(tz=TZ, now=NOW, trusted_proxies=PROXY)) == expected


def test_fall_back_hour_is_first_occurrence():  # AC-02 boundary
    ctx = ParseContext(tz=TZ, now=NOW)
    # 01:30 happens twice on 1 Nov 2026; fold=0 takes the EDT one (05:30Z), 01:30 EST would be 06:30Z.
    ev = PARSERS["app"]('{"ts": "2026-11-01T01:30:00", "event": "x", "outcome": "unknown"}', ctx)
    assert ev.ts == U(2026, 11, 1, 5, 30)


# --- AC-01: collection timeliness and interval bounds --------------------------------------

def _cfg_data(tmp_path: Path) -> dict:
    data = yaml.safe_load((ROOT / "config.example.yaml").read_text(encoding="utf-8"))
    data["database_path"] = str(tmp_path / "test.db")
    for src in data["sources"]:
        src["path"] = str(tmp_path / f"{src['name']}.log")
    return data


@pytest.mark.parametrize("interval,ok", [(1, True), (60, True), (300, True), (301, False), (0, False)])
def test_interval_bounds(tmp_path, interval, ok):  # AC-01 boundary
    data = _cfg_data(tmp_path)
    data["collector"]["interval_seconds"] = interval
    if ok:
        assert Config.model_validate(data).collector.interval_seconds == interval
    else:
        with pytest.raises(ValidationError):
            Config.model_validate(data)


def test_interval_defaults_to_60(tmp_path):  # REQ-01 default
    data = _cfg_data(tmp_path)
    del data["collector"]["interval_seconds"]
    assert Config.model_validate(data).collector.interval_seconds == 60


TAGGED = {
    "nginx_access": lambda i: f'198.51.100.7 - - [08/Oct/2026:10:00:00 -0400] "GET /tag/{i} HTTP/1.1" 200 1 "-" "ua" "-"',
    "nginx_error": lambda i: f'2026/10/08 10:00:00 [error] 1#1: *1 x, client: 198.51.100.7, request: "GET /tag/{i} HTTP/1.1"',
    "ssh_auth": lambda i: f"Oct  8 10:00:00 ssh01 sshd[1]: Failed password for u{i} from 198.51.100.7 port 1 ssh2",
    "app": lambda i: json.dumps({"ts": "2026-10-08T14:00:00Z", "event": "view", "outcome": "success",
                                 "path": f"/tag/{i}"}),
}


def test_one_cycle_collects_every_source(cfg, conn, clock):  # AC-01
    for src in cfg.sources:
        Path(src.path).write_text("".join(TAGGED[src.kind](i) + "\n" for i in range(100)), encoding="utf-8")
    started = time.monotonic()
    Collector(cfg, conn, clock, GeoIP()).run_cycle()
    elapsed = time.monotonic() - started

    counts = dict(conn.execute("SELECT source, COUNT(*) FROM event GROUP BY source").fetchall())
    assert counts == {src.name: 100 for src in cfg.sources}
    assert conn.execute("SELECT COUNT(*) FROM raw_line WHERE status = 'quarantined'").fetchone()[0] == 0
    # Lines appended at T0 are read at the next cycle start (<= 60 s); the cycle itself must fit in
    # the remaining 10 s of the 70 s budget.
    assert elapsed < 10


# --- AC-03: a failed commit loses and duplicates nothing ------------------------------------

class FailingBatchCommit:
    """Connection proxy whose first COMMIT after a batch insert fails, like SQLITE_BUSY on commit."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self._armed = False
        self.failed = False

    def execute(self, sql, *args):
        if sql.startswith("INSERT INTO batch"):
            self._armed = True
        if sql == "COMMIT" and self._armed and not self.failed:
            self.failed = True
            raise sqlite3.OperationalError("database is locked")
        return self._conn.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def test_commit_failure_then_retry_stores_each_line_once(cfg, conn, clock):  # AC-03
    src = next(s for s in cfg.sources if s.name == "app")
    Path(src.path).write_text("".join(TAGGED["app"](i) + "\n" for i in range(100)), encoding="utf-8")

    proxy = FailingBatchCommit(conn)
    with pytest.raises(sqlite3.OperationalError):
        Collector(cfg, proxy, clock, GeoIP()).collect_source(src)
    assert proxy.failed and not conn.in_transaction
    assert conn.execute("SELECT COUNT(*) FROM event").fetchone()[0] == 0

    clock.advance(60)
    Collector(cfg, conn, clock, GeoIP()).collect_source(src)
    targets = sorted(r[0] for r in conn.execute("SELECT target FROM event"))
    assert targets == sorted(f"/tag/{i}" for i in range(100))
    assert verify_batches(conn)["status"] == "intact"
