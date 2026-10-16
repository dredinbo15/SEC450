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


def _budget(conn) -> list[tuple]:
    return [tuple(r) for r in conn.execute("SELECT cluster_id, day, outcome FROM triage_budget ORDER BY cluster_id")]


def test_daily_ai_limit_skips_later_clusters_until_next_utc_day(cfg, conn, clock):
    """triage.max_calls_per_day: once spent, clusters are still reported, marked "daily AI limit reached"."""
    cfg.triage.max_calls_per_day = 1
    llm = MockLLMClient("ok")
    for sev in ("medium", "high"):
        _make_cluster(conn, sev)
    clock.advance(600)
    run_triage(conn, cfg, clock, llm)
    assert llm.calls == 1
    assert _states(conn) == [("medium", "TRIAGED", "critical"), ("high", "TRIAGE_UNAVAILABLE", None)]
    day = clock.now().date().isoformat()
    assert _budget(conn) == [(1, day, "called"), (2, day, "skipped")]

    generate_pending_reports(conn, cfg, clock)       # the skipped high cluster is still reported
    body = conn.execute("SELECT body_json FROM report").fetchone()[0]
    assert '"status": "unavailable"' in body and '"reason": "daily AI limit reached"' in body

    clock.advance(24 * 3600)                         # next UTC day: the budget is fresh
    _make_cluster(conn, "high")
    clock.advance(600)
    run_triage(conn, cfg, clock, llm)
    assert llm.calls == 2 and _states(conn)[-1] == ("high", "TRIAGED", "critical")


def test_daily_ai_limit_counts_a_cluster_once(cfg, conn, clock):
    """Retries do not use extra budget, and a cluster resumed after a crash is not blocked by itself."""
    cfg.triage.max_calls_per_day = 1
    _make_cluster(conn, "high")
    clock.advance(600)
    llm = MockLLMClient("http_error")
    run_triage(conn, cfg, clock, llm)
    assert llm.calls == 3                            # 3 attempts, 1 unit of budget
    assert [r[2] for r in _budget(conn)] == ["called"]

    conn.execute("UPDATE cluster SET state = 'TRIAGE_PENDING'")   # as if the worker crashed mid-triage
    run_triage(conn, cfg, clock, MockLLMClient("ok"))
    assert _states(conn) == [("high", "TRIAGED", "critical")]


def test_daily_ai_limit_zero_and_unlimited(cfg, conn, clock):
    for sev in ("medium", "high"):
        _make_cluster(conn, sev)
    clock.advance(600)
    cfg.triage.max_calls_per_day = 0
    llm = MockLLMClient("ok")
    run_triage(conn, cfg, clock, llm)
    assert llm.calls == 0 and {s for _, s, _ in _states(conn)} == {"TRIAGE_UNAVAILABLE"}

    cfg.triage.max_calls_per_day = None              # the default: no limit
    _make_cluster(conn, "high")
    _make_cluster(conn, "high")
    clock.advance(600)
    run_triage(conn, cfg, clock, llm)
    assert llm.calls == 2
