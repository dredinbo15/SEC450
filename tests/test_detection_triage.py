from datetime import timedelta

import pytest

from sec450.detection import run_detection
from sec450.redact import redact_text
from sec450.reports import generate_pending_reports
from sec450.timeutil import iso
from sec450.triage import TriageError, TriageResult, run_triage

from .conftest import T0, insert_events


def at(seconds: float) -> str:
    return iso(T0 + timedelta(seconds=seconds))


def clusters(conn):
    return conn.execute("SELECT rule_id, severity FROM cluster ORDER BY cluster_id").fetchall()


@pytest.mark.parametrize("spacing,expected", [(75, 1), (75.25, 0)])  # 4 gaps: 300 s vs 301 s
def test_r1_window_boundary(cfg, conn, clock, spacing, expected):  # AC-06
    insert_events(conn, [{"ts": at(i * spacing), "action": "ssh_login", "outcome": "failure"} for i in range(5)])
    clock.advance(400)
    run_detection(conn, cfg, clock)
    assert len(clusters(conn)) == expected


def test_r1_below_threshold(cfg, conn, clock):
    insert_events(conn, [{"ts": at(i), "action": "ssh_login", "outcome": "failure"} for i in range(4)])
    run_detection(conn, cfg, clock)
    assert clusters(conn) == []


@pytest.mark.parametrize("total,expected", [(10_485_760, 0), (10_485_761, 1)])
def test_r4_byte_boundary(cfg, conn, clock, total, expected):  # AC-06
    insert_events(conn, [{"ts": at(0), "bytes_sent": total - 1}, {"ts": at(10), "bytes_sent": 1}])
    run_detection(conn, cfg, clock)
    assert len(clusters(conn)) == expected


def test_r2_distinct_404s(cfg, conn, clock):
    insert_events(conn, [{"ts": at(i), "status_code": 404, "target": f"/x{i}"} for i in range(20)])
    run_detection(conn, cfg, clock)
    assert [tuple(r) for r in clusters(conn)] == [("R2", "medium")]


def test_r3_pattern(cfg, conn, clock):
    insert_events(conn, [{"ts": at(0), "target": "/download?file=..%2f..%2fetc%2fpasswd"}])
    run_detection(conn, cfg, clock)
    assert [tuple(r) for r in clusters(conn)] == [("R3", "high")]


@pytest.mark.parametrize("n,redacted", [(31, False), (32, True)])
def test_token_length_boundary(n, redacted):  # AC-09
    token = "a" * n
    assert ("[REDACTED]" in redact_text(f"/x/{token}")) is redacted


def test_named_secrets_redacted():
    text = "/login?user=bob&password=hunter2&api_key=abc Authorization: Bearer xyz Cookie: s=1"
    out = redact_text(text)
    for secret in ("hunter2", "abc", "xyz", "s=1"):
        assert secret not in out


class MockLLM:
    model = "mock"

    def __init__(self, fail: bool):
        self.fail = fail
        self.calls = 0
        self.payloads = []

    def assess(self, payload):
        self.calls += 1
        self.payloads.append(payload)
        if self.fail:
            raise TriageError("HTTP 500")
        return TriageResult(classification="test", recommended_severity="critical", explanation="x")


def _make_cluster(conn, severity):
    conn.execute("INSERT INTO cluster (rule_id, severity, group_key, window_start, window_end, state, created_at) "
                 "VALUES ('R1', ?, '203.0.113.5', ?, ?, 'open', ?)", (severity, at(0), at(0), at(0)))


def test_triage_gating_and_advisory(cfg, conn, clock):  # AC-10
    for sev in ("low", "medium", "high"):
        _make_cluster(conn, sev)
    clock.advance(600)
    llm = MockLLM(fail=False)
    run_triage(conn, cfg, clock, llm)
    assert llm.calls == 2
    rows = conn.execute("SELECT severity, state, ai_recommended_severity FROM cluster ORDER BY cluster_id").fetchall()
    assert [tuple(r) for r in rows] == [("low", "closed", None), ("medium", "triaged", "critical"),
                                        ("high", "triaged", "critical")]


def test_triage_failure_path_still_reports(cfg, conn, clock):  # AC-11
    _make_cluster(conn, "high")
    clock.advance(600)
    llm = MockLLM(fail=True)
    run_triage(conn, cfg, clock, llm)
    assert llm.calls == 3
    assert conn.execute("SELECT state FROM cluster").fetchone()[0] == "triage_unavailable"
    generate_pending_reports(conn, cfg, clock)
    body = conn.execute("SELECT body_json FROM report").fetchone()[0]
    assert '"status": "unavailable"' in body
