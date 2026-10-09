from datetime import timedelta

import pytest

from sec450.mock_llm import MockLLMClient
from sec450.redact import redact_text
from sec450.reports import generate_pending_reports
from sec450.timeutil import iso
from sec450.triage import run_triage

from .conftest import T0


def at(seconds: float) -> str:
    return iso(T0 + timedelta(seconds=seconds))


@pytest.mark.parametrize("n,redacted", [(31, False), (32, True)])
def test_token_length_boundary(n, redacted):  # AC-09
    token = "a" * n
    assert ("[REDACTED]" in redact_text(f"/x/{token}")) is redacted


def test_named_secrets_redacted():
    text = "/login?user=bob&password=hunter2&api_key=abc Authorization: Bearer xyz Cookie: s=1"
    out = redact_text(text)
    for secret in ("hunter2", "abc", "xyz", "s=1"):
        assert secret not in out


def _make_cluster(conn, severity):
    conn.execute("INSERT INTO cluster (rule_id, severity, group_key, window_start, window_end, state, created_at) "
                 "VALUES ('R1', ?, '203.0.113.5', ?, ?, 'FLAGGED', ?)", (severity, at(0), at(0), at(0)))


def _states(conn) -> list[tuple]:
    return [tuple(r) for r in conn.execute(
        "SELECT severity, state, ai_recommended_severity FROM cluster ORDER BY cluster_id")]


def test_triage_gating_and_advisory(cfg, conn, clock):  # AC-10
    for sev in ("low", "medium", "high"):
        _make_cluster(conn, sev)
    clock.advance(600)
    llm = MockLLMClient("ok")
    run_triage(conn, cfg, clock, llm)
    assert llm.calls == 2
    assert _states(conn) == [("low", "DONE", None), ("medium", "TRIAGED", "critical"),
                             ("high", "TRIAGED", "critical")]


def test_ac15_medium_done_without_report_high_reported(cfg, conn, clock):
    """Cluster lifecycle end states: medium -> DONE with no report, high -> REPORTED with one."""
    for sev in ("medium", "high"):
        _make_cluster(conn, sev)
    clock.advance(600)
    run_triage(conn, cfg, clock, MockLLMClient("ok"))
    generate_pending_reports(conn, cfg, clock)
    assert _states(conn) == [("medium", "DONE", "critical"), ("high", "REPORTED", "critical")]
    assert [r[0] for r in conn.execute("SELECT cluster_id FROM report")] == [2]
    generate_pending_reports(conn, cfg, clock)  # a second pass must not report twice
    assert conn.execute("SELECT COUNT(*) FROM report").fetchone()[0] == 1


@pytest.mark.parametrize("mode", ["timeout", "http_error", "bad_json", "missing_field"])
def test_ac11_llm_failure_path_still_reports(cfg, conn, clock, mode):
    """Each failure type: exactly 3 attempts, TRIAGE_UNAVAILABLE, report says "unavailable"."""
    _make_cluster(conn, "high")
    clock.advance(600)
    llm = MockLLMClient(mode)
    run_triage(conn, cfg, clock, llm)
    assert llm.calls == 3
    assert conn.execute("SELECT state FROM cluster").fetchone()[0] == "TRIAGE_UNAVAILABLE"
    generate_pending_reports(conn, cfg, clock)
    assert conn.execute("SELECT state FROM cluster").fetchone()[0] == "REPORTED"
    body = conn.execute("SELECT body_json FROM report").fetchone()[0]
    assert '"status": "unavailable"' in body
