import httpx
import pytest
from fastapi.testclient import TestClient

from sec450.dashboard.client import ApiClient, ApiError
from sec450.dashboard.review import cluster_review_reasons, system_alerts
from sec450.keys import create_key

from .conftest import insert_events


def cluster(severity="medium", state="triaged", recommended=None):
    ai = None if recommended is None else {"classification": "x", "recommended_severity": recommended}
    return {"severity": severity, "state": state, "ai_assessment": ai}


@pytest.mark.parametrize("c,expected", [
    (cluster("low", "open"), 0),
    (cluster("medium", recommended="medium"), 0),
    (cluster("high", recommended="high"), 1),
    (cluster("critical", recommended="critical"), 1),
    (cluster("medium", "triage_unavailable"), 1),
    (cluster("high", "triage_unavailable"), 2),
    (cluster("medium", recommended="critical"), 1),   # AI rates higher
    (cluster("high", recommended="low"), 2),          # AI rates lower: possible false alarm
])
def test_cluster_review_reasons(c, expected):
    assert len(cluster_review_reasons(c)) == expected


def test_system_alerts():
    intact = {"batches": {"status": "intact"}, "audit": {"status": "intact"}}
    assert system_alerts(intact, [], [{"clock_anomaly": False}]) == []
    broken = {"batches": {"status": "broken", "batch_id": 23, "reason": "content hash mismatch"},
              "audit": {"status": "broken", "entry_id": 4}}
    gap = {"source": "ssh_auth", "start": "2026-10-08T13:00:00Z", "end": None, "reason": "unreadable"}
    alerts = system_alerts(broken, [gap], [{"clock_anomaly": True}])
    assert len(alerts) == 4 and "batch 23" in alerts[0] and "since" in alerts[2]


def test_client_goes_through_audited_api(cfg, conn, clock):
    from sec450.api.app import create_app
    _, key = create_key(conn, clock)
    insert_events(conn, [{"ts": "2026-10-08T13:00:00.000000Z"}])
    api = TestClient(create_app(cfg, clock))

    def forward(req: httpx.Request) -> httpx.Response:
        r = api.request(req.method, str(req.url), headers=dict(req.headers))
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)

    transport = httpx.MockTransport(forward)
    client = ApiClient(cfg.dashboard.model_copy(update={"api_key": key, "api_url": "http://testserver"}),
                       transport=transport)
    assert client.get("/v1/events", source_ip=None)["count"] == 1
    assert conn.execute("SELECT COUNT(*) FROM audit_entry").fetchone()[0] == 1
    with pytest.raises(ApiError, match="400"):
        client.get("/v1/events", severity="urgent")

    bad = ApiClient(cfg.dashboard.model_copy(update={"api_key": "nope", "api_url": "http://testserver"}),
                    transport=transport)
    with pytest.raises(ApiError, match="401"):
        bad.get("/v1/events")


def test_client_requires_key(cfg, monkeypatch):
    monkeypatch.delenv("SEC450_API_KEY", raising=False)
    with pytest.raises(ApiError, match="no API key"):
        ApiClient(cfg.dashboard)
