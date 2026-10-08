"""REQ-02: record the requester (IP, user/API key, ASN, country) and data destination (IP, bytes)."""
import json
import logging
from pathlib import Path

import pytest

from sec450.collector import Collector
from sec450.geoip import GeoIP
from sec450.parsers.common import normalize_ip

from .mmdb_writer import Uint32, write_mmdb

ASN = {"8.8.8.0/24": 15169, "81.2.69.0/24": 20712, "2001:4860::/32": 15169, "9.9.9.0/24": 19281}
COUNTRY = {"8.8.8.0/24": "US", "81.2.69.0/24": "GB", "2001:4860::/32": "US", "5.5.5.0/24": "DE"}


@pytest.fixture
def geoip(tmp_path):
    """Test GeoIP databases (AC-04 setup). 9.9.9.0/24 has only an ASN, 5.5.5.0/24 only a country."""
    asn = write_mmdb(tmp_path / "asn.mmdb", "GeoLite2-ASN", {
        net: {"autonomous_system_number": Uint32(n), "autonomous_system_organization": f"AS{n}"}
        for net, n in ASN.items()})
    country = write_mmdb(tmp_path / "country.mmdb", "GeoLite2-Country", {
        net: {"country": {"iso_code": cc}} for net, cc in COUNTRY.items()})
    g = GeoIP(asn, country)
    yield g
    g.close()


def access(peer, user="-", path="/", status=200, size=0, xff="-"):
    return (f'{peer} - {user} [08/Oct/2026:10:00:00 -0400] "GET {path} HTTP/1.1" {status} {size} '
            f'"-" "ua" "{xff}"')


def app(**fields):
    return json.dumps({"ts": "2026-10-08T14:00:00Z", "event": "api_call", "outcome": "success", **fields})


def collect(cfg, conn, clock, geoip, lines: dict[str, list[str]]) -> list[tuple]:
    for src in cfg.sources:
        Path(src.path).write_text("".join(f"{ln}\n" for ln in lines.get(src.kind, [])), encoding="utf-8")
    Collector(cfg, conn, clock, geoip).run_cycle()
    assert conn.execute("SELECT COUNT(*) FROM raw_line WHERE status = 'quarantined'").fetchone()[0] == 0
    return [tuple(r) for r in conn.execute(
        "SELECT client_ip, username, api_key_id, asn, country, bytes_sent FROM event ORDER BY event_id")]


# --- GeoIP unit behavior ------------------------------------------------------------------

@pytest.mark.parametrize("ip,expected", [
    ("8.8.8.8", (15169, "US")),                # known public test IP (AC-04)
    ("81.2.69.142", (20712, "GB")),
    ("2001:4860::8888", (15169, "US")),        # IPv6
    ("9.9.9.9", (19281, None)),                # ASN database only
    ("5.5.5.5", (None, "DE")),                 # country database only
    ("1.1.1.1", (None, None)),                 # public but not in either database
    ("172.20.0.5", (None, None)),              # private lab IP (AC-04 boundary)
    ("10.0.0.1", (None, None)),
    ("127.0.0.1", (None, None)),
    ("203.0.113.9", (None, None)),             # documentation range, not global
    ("fd00::1", (None, None)),                 # IPv6 unique-local
    (None, (None, None)),
])
def test_lookup(geoip, ip, expected):  # AC-04
    assert geoip.lookup(ip) == expected


def test_missing_database_files_give_nulls(tmp_path, caplog):  # DD-13: enrichment never blocks collection
    with caplog.at_level(logging.WARNING):
        g = GeoIP(tmp_path / "nope-asn.mmdb", tmp_path / "nope-country.mmdb")
    assert g.lookup("8.8.8.8") == (None, None)
    assert "not found" in caplog.text


@pytest.mark.parametrize("raw,expected", [
    ("::ffff:8.8.8.8", "8.8.8.8"),             # dual-stack listener form
    ("::FFFF:172.20.0.10", "172.20.0.10"),
    ("2001:DB8::0001", "2001:db8::1"),
    (" 8.8.8.8 ", "8.8.8.8"),
    ("-", None),
])
def test_normalize_ip(raw, expected):
    assert normalize_ip(raw) == expected


# --- AC-04: 20 fixture requests, requester and destination stored on each event -------------

AC04_LINES = {
    "nginx_access": [
        access("8.8.8.8", size=512),
        access("81.2.69.142", user="alice", path="/login", status=302),
        access("172.20.0.10", size=1000, xff="8.8.8.9"),            # geo follows the real client
        access("2001:4860::8888", size=2048),
        access("::ffff:81.2.69.10", size=300),
        access("172.20.0.5", size=100),
        access("1.1.1.1", size=50),
        access("9.9.9.9", path="/big.iso", size=10485761),
    ],
    "nginx_error": [
        '2026/10/08 10:00:00 [error] 1#1: *1 open() "/x" failed, client: 81.2.69.200, server: web01, '
        'request: "GET /x HTTP/1.1"',
        "2026/10/08 10:00:00 [notice] 1#1: signal process started",
    ],
    "ssh_auth": [
        "Oct  8 10:00:00 ssh01 sshd[1]: Failed password for root from 8.8.8.7 port 1 ssh2",
        "Oct  8 10:00:00 ssh01 sshd[1]: Accepted publickey for alice from 81.2.69.5 port 1 ssh2",
        "Oct  8 10:00:00 ssh01 sshd[1]: Invalid user oracle from 5.5.5.5 port 1",
        "Oct  8 10:00:00 ssh01 sshd[1]: Failed password for bob from 172.20.0.6 port 1 ssh2",
    ],
    "app": [
        app(event="login", user="carol", peer_ip="8.8.8.1"),
        app(api_key_id="key-7", peer_ip="81.2.69.7", bytes=4096),
        app(api_key_id="key-8", peer_ip="172.20.0.10", x_forwarded_for="2001:4860::1", bytes=123),
        app(peer_ip="5.5.5.6", x_forwarded_for="8.8.8.8"),
        app(user="dave", api_key_id="key-9", peer_ip="9.9.9.10", bytes=10),
        app(event="heartbeat"),
    ],
}

#             client_ip          username  api_key_id  asn    country  bytes_sent
AC04_EXPECTED = [
    ("8.8.8.8",          None,    None,    15169, "US", 512),
    ("81.2.69.142",      "alice", None,    20712, "GB", 0),
    ("8.8.8.9",          None,    None,    15169, "US", 1000),
    ("2001:4860::8888",  None,    None,    15169, "US", 2048),
    ("81.2.69.10",       None,    None,    20712, "GB", 300),
    ("172.20.0.5",       None,    None,    None,  None, 100),
    ("1.1.1.1",          None,    None,    None,  None, 50),
    ("9.9.9.9",          None,    None,    19281, None, 10485761),
    ("81.2.69.200",      None,    None,    20712, "GB", 0),
    (None,               None,    None,    None,  None, 0),
    ("8.8.8.7",          "root",  None,    15169, "US", 0),
    ("81.2.69.5",        "alice", None,    20712, "GB", 0),
    ("5.5.5.5",          "oracle", None,   None,  "DE", 0),
    ("172.20.0.6",       "bob",   None,    None,  None, 0),
    ("8.8.8.1",          "carol", None,    15169, "US", 0),
    ("81.2.69.7",        None,    "key-7", 20712, "GB", 4096),
    ("2001:4860::1",     None,    "key-8", 15169, "US", 123),
    ("5.5.5.6",          None,    None,    None,  "DE", 0),
    ("9.9.9.10",         "dave",  "key-9", 19281, None, 10),
    (None,               None,    None,    None,  None, 0),
]


def test_requester_and_destination_fields(cfg, conn, clock, geoip):  # AC-04
    assert sum(map(len, AC04_LINES.values())) == len(AC04_EXPECTED) == 20
    assert collect(cfg, conn, clock, geoip, AC04_LINES) == AC04_EXPECTED


# --- AC-05: forwarded-IP header honored only from the trusted proxy -------------------------

TRUSTED = [  # (kind, peer, X-Forwarded-For, expected client_ip)
    ("nginx_access", "172.20.0.10", "8.8.8.1", "8.8.8.1"),
    ("nginx_access", "172.20.0.10", "81.2.69.1", "81.2.69.1"),
    ("nginx_access", "172.20.0.10", "6.6.6.6, 8.8.8.3", "8.8.8.3"),        # spoofed leftmost hop ignored
    ("nginx_access", "::ffff:172.20.0.10", "8.8.8.4", "8.8.8.4"),          # proxy seen via dual-stack
    ("nginx_access", "172.20.0.10", "2001:4860::5", "2001:4860::5"),
    ("app", "172.20.0.10", "8.8.8.6", "8.8.8.6"),
    ("app", "172.20.0.10", "8.8.8.7, 172.20.0.10", "8.8.8.7"),             # proxy's own hop skipped
    ("app", "172.20.0.10", "81.2.69.8", "81.2.69.8"),
    ("app", "172.20.0.10", "not-an-ip", "172.20.0.10"),                    # garbage header -> peer
    ("app", "172.20.0.10", " 8.8.8.10 ", "8.8.8.10"),
]
UNTRUSTED = [
    ("nginx_access", "198.51.100.1", "8.8.8.99", "198.51.100.1"),
    ("nginx_access", "172.20.0.11", "8.8.8.99", "172.20.0.11"),            # neighbor of the proxy
    ("nginx_access", "8.8.8.20", "8.8.8.99", "8.8.8.20"),
    ("nginx_access", "2001:4860::20", "8.8.8.99", "2001:4860::20"),
    ("nginx_access", "::ffff:172.20.0.11", "8.8.8.99", "172.20.0.11"),
    ("app", "198.51.100.6", "8.8.8.99", "198.51.100.6"),
    ("app", "172.20.0.9", "8.8.8.99", "172.20.0.9"),
    ("app", "81.2.69.20", "8.8.8.99", "81.2.69.20"),
    ("app", "5.5.5.20", "8.8.8.99", "5.5.5.20"),
    ("app", "9.9.9.20", "8.8.8.99", "9.9.9.20"),
]


def test_forwarded_ip_trust(cfg, conn, clock, geoip):  # AC-05
    cases = TRUSTED + UNTRUSTED
    lines: dict[str, list[str]] = {}
    for kind, peer, xff, _ in cases:
        lines.setdefault(kind, []).append(access(peer, xff=xff) if kind == "nginx_access"
                                          else app(peer_ip=peer, x_forwarded_for=xff))
    rows = collect(cfg, conn, clock, geoip, lines)
    # Rows come back in source order (nginx_access, then app); match the cases the same way.
    ordered = [c for c in cases if c[0] == "nginx_access"] + [c for c in cases if c[0] == "app"]
    assert len(rows) == 20
    for (_, peer, xff, expected), (client_ip, _, _, asn, country, _) in zip(ordered, rows):
        assert client_ip == expected, (peer, xff)
        assert (asn, country) == geoip.lookup(expected)   # enrichment is for the resolved requester
