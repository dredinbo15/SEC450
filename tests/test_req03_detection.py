"""REQ-03: evaluate stored events against configurable rules and flag matches within 5 minutes."""
from datetime import timedelta

import pytest
from pydantic import ValidationError

from sec450.collector import Collector
from sec450.config import Config
from sec450.detection import run_detection
from sec450.geoip import GeoIP
from sec450.timeutil import iso, parse_iso

from .conftest import T0, insert_events


def at(seconds: float) -> str:
    return iso(T0 + timedelta(seconds=seconds))


def clusters(conn) -> list[tuple]:
    return [tuple(r) for r in conn.execute("SELECT rule_id, severity FROM cluster ORDER BY cluster_id")]


def spread(n: int, span: float) -> list[float]:
    """n timestamps evenly covering `span` seconds, first at 0 and last at `span`."""
    return [i * span / (n - 1) for i in range(n)]


def failed_logins(times):
    return [{"ts": at(t), "action": "ssh_login", "outcome": "failure"} for t in times]


def distinct_404s(times):
    return [{"ts": at(t), "status_code": 404, "target": f"/missing{i}"} for i, t in enumerate(times)]


def transfer(total: int, span: float):
    return [{"ts": at(0), "bytes_sent": total - 1}, {"ts": at(span), "bytes_sent": 1}]


# AC-06: for each rule, below threshold / at threshold / threshold spread over window + 1 s.
AC06_CASES = {
    "R1 below": (failed_logins(spread(4, 10)), []),
    "R1 at": (failed_logins(spread(5, 300)), [("R1", "high")]),
    "R1 window+1": (failed_logins(spread(5, 301)), []),
    "R2 below": (distinct_404s(spread(19, 10)), []),
    "R2 at": (distinct_404s(spread(20, 60)), [("R2", "medium")]),
    "R2 window+1": (distinct_404s(spread(20, 61)), []),
    "R3 benign": ([{"ts": at(0), "target": "/products?id=42&sort=price"}], []),
    "R3 traversal": ([{"ts": at(0), "target": "/download?file=..%2f..%2fetc%2fpasswd"}], [("R3", "high")]),
    "R3 sql injection": ([{"ts": at(0), "target": "/item?id=1%27%20OR%201=1"}], [("R3", "high")]),
    "R4 at 10 MB": (transfer(10_485_760, 10), []),
    "R4 over 10 MB": (transfer(10_485_761, 600), [("R4", "critical")]),
    "R4 window+1": (transfer(10_485_761, 601), []),
}


@pytest.mark.parametrize("events,expected", AC06_CASES.values(), ids=AC06_CASES.keys())
def test_rule_thresholds_and_windows(cfg, conn, clock, events, expected):  # AC-06
    insert_events(conn, events)
    clock.advance(700)
    run_detection(conn, cfg, clock)
    assert clusters(conn) == expected


def test_r2_counts_distinct_paths_only(cfg, conn, clock):
    insert_events(conn, [{"ts": at(i), "status_code": 404, "target": "/same"} for i in range(30)])
    run_detection(conn, cfg, clock)
    assert clusters(conn) == []


def test_r1_counts_per_source_ip(cfg, conn, clock):
    insert_events(conn, [{"ts": at(i), "action": "login", "outcome": "failure", "client_ip": f"203.0.113.{i}"}
                         for i in range(10)])
    run_detection(conn, cfg, clock)
    assert clusters(conn) == []


def test_rerun_does_not_duplicate_clusters(cfg, conn, clock):
    insert_events(conn, failed_logins(range(5)))
    run_detection(conn, cfg, clock)
    run_detection(conn, cfg, clock)
    assert clusters(conn) == [("R1", "high")]
    assert conn.execute("SELECT COUNT(*) FROM cluster_event").fetchone()[0] == 5


def test_disabled_rule_is_skipped(cfg, conn, clock):
    next(r for r in cfg.detection.rules if r.id == "R3").enabled = False
    insert_events(conn, [{"ts": at(0), "target": "/a/../../etc/passwd"}])
    run_detection(conn, cfg, clock)
    assert clusters(conn) == []


def test_threshold_change_needs_only_config(cfg, conn, clock):  # AC-08 (automated part)
    data = cfg.model_dump(mode="json")
    next(r for r in data["detection"]["rules"] if r["id"] == "R1")["threshold"] = 3
    insert_events(conn, failed_logins(range(3)))
    run_detection(conn, cfg, clock)
    assert clusters(conn) == []
    run_detection(conn, Config.model_validate(data), clock)
    assert clusters(conn) == [("R1", "high")]


def test_flagged_in_same_cycle_as_collection(cfg, conn, clock):  # REQ-03 5-minute limit
    ssh = next(s for s in cfg.sources if s.name == "ssh_auth")
    ssh.path.write_text("".join(
        f"Oct  8 10:00:0{i} ssh01 sshd[1]: Failed password for root from 203.0.113.9 port {i} ssh2\n"
        for i in range(5)), encoding="utf-8")
    Collector(cfg, conn, clock, GeoIP()).run_cycle()
    run_detection(conn, cfg, clock)
    row = conn.execute("SELECT cl.created_at, b.collected_at FROM cluster cl "
                       "JOIN cluster_event ce USING (cluster_id) JOIN event e USING (event_id) "
                       "JOIN raw_line r USING (raw_id) JOIN batch b USING (batch_id) "
                       "WHERE cl.rule_id = 'R1' LIMIT 1").fetchone()
    assert row is not None
    assert parse_iso(row["created_at"]) - parse_iso(row["collected_at"]) <= timedelta(seconds=300)


def _rules_with(cfg, **r3_changes) -> dict:
    data = cfg.model_dump(mode="json")
    next(r for r in data["detection"]["rules"] if r["id"] == "R3").update(r3_changes)
    return data


def test_invalid_pattern_rejected_at_startup(cfg):
    with pytest.raises(ValidationError, match="invalid pattern"):
        Config.model_validate(_rules_with(cfg, patterns=["(unclosed"]))


def test_pattern_rule_without_patterns_rejected(cfg):
    with pytest.raises(ValidationError, match="at least one pattern"):
        Config.model_validate(_rules_with(cfg, patterns=[]))
