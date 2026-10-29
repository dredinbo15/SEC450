"""DD-18: high/critical reports are posted to the incident API once each, in its exact request shape."""
import httpx
import pytest

from sec450.incidents import build_incident, forward_pending_cluster_incidents, forward_pending_incidents
from sec450.mock_llm import MockLLMClient

from .conftest import insert_events
from .test_thin_slice import ATTACKER, _run_pipeline

ALLOWED = {"title", "log", "occurredAt", "source"}   # CreateIncident has additionalProperties: false


class FakeApi:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.posted: list[dict] = []

    def __call__(self, cfg, incident):
        self.posted.append(incident)
        r = self.responses.pop(0) if self.responses else 201
        if isinstance(r, Exception):
            raise r
        return httpx.Response(r, json={"incidentId": f"inc-{len(self.posted)}"} if r < 300 else {"detail": "bad"})


@pytest.fixture
def inc_cfg(slice_cfg, conn, clock):
    """One brute-force report, made with forwarding off so the pipeline never does real HTTP."""
    _run_pipeline(slice_cfg, conn, clock, MockLLMClient("ok"))
    slice_cfg.incidents.enabled = True
    slice_cfg.incidents.backfill = True
    conn.execute("INSERT INTO incident_forwarding (id, enabled_at) VALUES (1, '2026-10-08T13:00:00Z')")
    return slice_cfg


def _deliveries(conn):
    return [tuple(r) for r in conn.execute("SELECT report_id, status, incident_id FROM incident_delivery")]


def test_report_posted_once_in_the_api_shape(inc_cfg, conn, clock):
    api = FakeApi()
    rid = conn.execute("SELECT report_id FROM report").fetchone()[0]
    assert forward_pending_incidents(conn, inc_cfg, clock, post=api) == [rid]
    assert forward_pending_incidents(conn, inc_cfg, clock, post=api) == []          # not sent twice

    (incident,) = api.posted
    assert set(incident) == ALLOWED
    assert 1 <= len(incident["title"]) <= 200 and ATTACKER in incident["title"]
    assert incident["log"].count("\n") == 5 and "Failed password" in incident["log"]   # 6 raw lines
    assert incident["occurredAt"].startswith("2026-10-08T14:00") and incident["occurredAt"].endswith("Z")
    assert incident["source"] == f"sec450 R1 report {rid}"
    assert _deliveries(conn) == [(rid, "sent", "inc-1")]


def test_outage_retries_and_rejection_does_not(inc_cfg, conn, clock):
    rid = conn.execute("SELECT report_id FROM report").fetchone()[0]
    assert forward_pending_incidents(conn, inc_cfg, clock, post=FakeApi(httpx.ConnectTimeout("asleep"))) == []
    assert forward_pending_incidents(conn, inc_cfg, clock, post=FakeApi(503)) == []
    assert _deliveries(conn) == []                                              # still pending
    assert forward_pending_incidents(conn, inc_cfg, clock, post=FakeApi(422)) == []
    assert _deliveries(conn) == [(rid, "rejected", None)]                       # refused once, not retried
    assert forward_pending_incidents(conn, inc_cfg, clock, post=FakeApi()) == []


def test_without_backfill_existing_reports_are_not_sent(slice_cfg, conn, clock):
    _run_pipeline(slice_cfg, conn, clock, MockLLMClient("ok"))   # forwarding still off: report already exists
    slice_cfg.incidents.enabled = True
    api = FakeApi()
    assert forward_pending_incidents(conn, slice_cfg, clock, post=api) == []
    assert api.posted == [] and [s for _, s, _ in _deliveries(conn)] == ["skipped"]


def test_severity_filter_and_title_limit():
    body = {"summary": "x" * 300, "matched_rule": {"id": "R4", "severity": "critical"},
            "timeline": [{"ts": "2026-10-17T18:03:13.000000Z"}], "raw_lines": [{"text": "a"}, {"text": "b"}]}
    inc = build_incident(9, body)
    assert len(inc["title"]) == 200 and inc["log"] == "a\nb" and inc["source"] == "sec450 R4 report 9"


def test_without_backfill_a_fresh_install_still_sends_its_first_report(slice_cfg, conn, clock):
    """Enabled before any report exists: the first real report must go out, not be skipped as 'existing'."""
    slice_cfg.incidents.enabled = True
    api = FakeApi()
    assert forward_pending_incidents(conn, slice_cfg, clock, post=api) == []   # no reports yet
    slice_cfg.incidents.enabled = False                                      # keep the pipeline offline
    _run_pipeline(slice_cfg, conn, clock, MockLLMClient("ok"))
    slice_cfg.incidents.enabled = True
    assert len(forward_pending_incidents(conn, slice_cfg, clock, post=api)) == 1


def _medium_cluster(conn, created_at="2026-10-08T14:05:00.000000Z"):
    insert_events(conn, [{"ts": f"2026-10-08T14:00:0{i}.000000Z", "target": f"/missing-{i}", "status_code": 404,
                          "outcome": "failure"} for i in range(3)])
    cid = conn.execute("INSERT INTO cluster (rule_id, severity, group_key, window_start, window_end, state, "
                       "created_at) VALUES ('R2', 'medium', '203.0.113.5', '2026-10-08T14:00:00.000000Z', "
                       "'2026-10-08T14:00:02.000000Z', 'DONE', ?)", (created_at,)).lastrowid
    conn.execute("INSERT INTO cluster_event (cluster_id, event_id) SELECT ?, event_id FROM event", (cid,))
    return cid


def test_medium_cluster_sent_once_from_the_cluster(cfg, conn, clock):
    """Mediums have no report (REQ-06), so the incident is built from the finished cluster."""
    cfg.incidents.enabled = True
    cfg.incidents.severities = ["medium", "high", "critical"]
    conn.execute("INSERT INTO incident_forwarding (id, enabled_at) VALUES (1, '2026-10-08T14:00:00Z')")
    old = _medium_cluster(conn, created_at="2026-10-08T13:00:00.000000Z")   # before forwarding was enabled
    cid = _medium_cluster(conn)
    api = FakeApi()
    assert forward_pending_cluster_incidents(conn, cfg, clock, post=api) == [cid]
    assert forward_pending_cluster_incidents(conn, cfg, clock, post=api) == []      # once only
    (incident,) = api.posted
    assert set(incident) == ALLOWED
    assert incident["title"].startswith("404 scan (medium): ") and "203.0.113.5" in incident["title"]
    assert incident["source"] == f"sec450 R2 cluster {cid}" and incident["log"].count("\n") >= 2
    assert old not in [r[0] for r in conn.execute("SELECT cluster_id FROM incident_cluster_delivery")]

    cfg.incidents.severities = ["high", "critical"]                         # mediums off: nothing more is sent
    _medium_cluster(conn)
    assert forward_pending_cluster_incidents(conn, cfg, clock, post=api) == []


def test_incident_log_lines_are_redacted():
    """The incident API is outside the system: credentials are removed as for the LLM (REQ-04)."""
    body = {"summary": "s", "matched_rule": {"id": "R3", "severity": "high"}, "timeline": [],
            "raw_lines": [{"text": "GET /login?user=bob&password=hunter2 Authorization: Bearer abc.def"}]}
    log = build_incident(1, body)["log"]
    assert "hunter2" not in log and "abc.def" not in log and "[REDACTED]" in log and "user=bob" in log


@pytest.mark.parametrize("status", [408, 429])
def test_timeouts_and_rate_limits_are_retried(inc_cfg, conn, clock, status):
    """408 and 429 mean "not now": the report stays pending instead of being recorded as rejected."""
    assert forward_pending_incidents(conn, inc_cfg, clock, post=FakeApi(status)) == []
    assert _deliveries(conn) == []
    assert len(forward_pending_incidents(conn, inc_cfg, clock, post=FakeApi())) == 1
