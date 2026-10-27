"""Course testing interface (sec450/api/testing.py, docs/testing-interface.md).

test_grader_flow_against_own_system replays the course's grading sequence (tester setup with the
target, run, stored report, system report) and applies the same format rules as the staff checker.
"""
import pytest
from fastapi.testclient import TestClient

from sec450.api.app import create_app
from sec450.mock_llm import MockLLMClient

from .test_thin_slice import _run_pipeline

OUTCOMES = {"pass", "fail", "error", "skip"}
SOURCES = {"tester", "system", "communication", "unknown"}
TARGET = "http://testserver"     # TestClient's own host, so the tester treats it as this deployment


def report_problems(report, session_id, target):
    """The staff checker's format rules for a tester report."""
    found = []
    if report.get("session_id") != session_id:
        found.append("session_id")
    if report.get("target_url") not in (target, target.rstrip("/")):
        found.append("target_url")
    results = report.get("results")
    if not isinstance(results, list) or not results:
        return [*found, "no results"]
    ids = [row.get("test_id") for row in results]
    if len(ids) != len(set(ids)) or not all(isinstance(i, str) and i for i in ids):
        found.append("test_id values")
    for row in results:
        if row.get("outcome") not in OUTCOMES or not row.get("message"):
            found.append(f"{row.get('test_id')} outcome/message")
        if row.get("outcome") == "error" and row.get("source") not in SOURCES:
            found.append(f"{row.get('test_id')} error source")
    for name in ("code", "component", "system"):
        m = (report.get("coverage") or {}).get(name)
        if not isinstance(m, dict) or not isinstance(m.get("basis"), str) or not m["basis"]:
            found.append(f"coverage.{name} basis")
            continue
        covered, total = m.get("covered"), m.get("total")
        if covered is None and total is None:
            continue
        if not all(isinstance(v, int) and v >= 0 for v in (covered, total)) or covered > total:
            found.append(f"coverage.{name} counts")
    return found


@pytest.fixture
def app(slice_cfg, conn, clock):
    _run_pipeline(slice_cfg, conn, clock, MockLLMClient("ok"))     # one R1 cluster and its report
    app = create_app(slice_cfg, clock)
    app.state.tester_client_factory = lambda target, is_self: TestClient(app, base_url=TARGET)
    app.state.tester_now = clock.now
    app.state.tester_tls_probe = lambda: [("tls-plain-http-refused", "pass", "stub"),
                                          ("tls-1.2-accepted", "pass", "stub")]
    return app


@pytest.fixture
def client(app):
    return TestClient(app, base_url=TARGET)


def test_grader_flow_against_own_system(client, conn):
    setup = client.post("/tester/test/setup", json={"target_url": TARGET})
    assert setup.status_code == 201, setup.text
    sid = setup.json()["session_id"]
    run = client.post("/tester/test/run", json={"session_id": sid})
    assert run.status_code == 200, run.text
    stored = client.get("/tester/test/report", params={"session_id": sid})
    assert stored.status_code == 200
    system = client.get("/test/report", params={"session_id": sid})
    assert system.status_code == 200 and "code" in system.json()["coverage"]

    report = stored.json()
    assert run.json() == report
    assert report_problems(report, sid, TARGET) == []
    not_passing = [r for r in report["results"] if r["outcome"] != "pass"]
    assert not_passing == [], not_passing
    assert report["coverage"]["component"]["covered"] == report["coverage"]["component"]["total"] == 8
    assert report["coverage"]["system"]["covered"] >= 6

    # The run's key was revoked afterwards, and its requests were audited with the chain intact.
    assert conn.execute("SELECT COUNT(*) FROM api_key WHERE revoked = 0").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM audit_entry").fetchone()[0] > 20


def test_each_session_runs_once_and_reports_need_a_finished_run(client):
    sid = client.post("/tester/test/setup", json={"target_url": TARGET}).json()["session_id"]
    assert client.get("/tester/test/report", params={"session_id": sid}).status_code == 409
    assert client.post("/tester/test/run", json={"session_id": sid}).status_code == 200
    again = client.post("/tester/test/run", json={"session_id": sid})
    assert again.status_code == 409 and again.json()["source"] == "tester"


def test_two_runs_in_a_row_are_not_rate_limited(client):
    for _ in range(3):
        sid = client.post("/tester/test/setup", json={"target_url": TARGET}).json()["session_id"]
        results = client.post("/tester/test/run", json={"session_id": sid}).json()["results"]
        assert all(r["outcome"] == "pass" for r in results), results


@pytest.mark.parametrize("path,body,status", [
    ("/tester/test/setup", {}, 400),
    ("/tester/test/setup", {"target_url": ""}, 400),
    ("/tester/test/setup", {"target_url": "http://example.com"}, 400),     # not https
    ("/tester/test/run", {}, 400),
    ("/tester/test/run", {"session_id": "nope"}, 404),
    ("/test/setup", {}, 400),
    ("/test/setup", {"session_id": "s1", "setup": "x"}, 400),
])
def test_bad_requests_get_problem_bodies(client, path, body, status):
    r = client.post(path, json=body)
    assert r.status_code == status
    assert r.json()["message"] and r.json()["source"] in SOURCES


def test_system_setup_and_report(client):
    assert client.post("/test/setup", json={"session_id": "s1", "setup": {}}).status_code == 201
    assert client.post("/test/setup", json={"session_id": "s1"}).status_code == 409
    r = client.get("/test/report", params={"session_id": "s1"})
    assert r.status_code == 200 and r.json()["coverage"]["code"]["basis"]
    assert client.get("/test/report").status_code == 400
    assert client.get("/test/report", params={"session_id": "other"}).status_code == 404
    assert client.get("/tester/test/report", params={"session_id": "other"}).status_code == 404


def test_tester_refuses_internal_targets(app, client):
    from sec450.api.testing import public_target_guard
    app.state.tester_target_guard = public_target_guard
    for target in ("https://127.0.0.1", "https://localhost:8443", "https://10.0.0.5", "https://user:pw@example.com"):
        r = client.post("/tester/test/setup", json={"target_url": target})
        assert r.status_code == 400, target


def test_external_target_without_key_skips_key_checks(app, client):
    """Another team's system: setup is forwarded to it, and checks needing our key are skipped."""
    app.state.tester_target_guard = lambda target: None
    target = "https://pod-mate.example"
    sid = client.post("/tester/test/setup", json={"target_url": target}).json()["session_id"]
    report = client.post("/tester/test/run", json={"session_id": sid}).json()
    assert report_problems(report, sid, target) == []
    outcomes = {r["test_id"]: r["outcome"] for r in report["results"]}
    assert outcomes["auth-missing-key"] == "pass"
    assert outcomes["auth-valid-key"] == "skip"
    assert outcomes["tls-versions"] == "skip"


def test_target_setup_failure_is_forwarded(app, client):
    app.state.tester_target_guard = lambda target: None

    class Refusing:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, *a, **kw):
            import httpx
            return httpx.Response(401, json={"message": "reset token required", "source": "system"})

    app.state.tester_client_factory = lambda target, is_self: Refusing()
    r = client.post("/tester/test/setup", json={"target_url": "https://pod-mate.example"})
    assert r.status_code == 401 and r.json()["source"] == "system"
    assert "reset token required" in r.json()["message"]


def test_server_errors_are_reported_as_system_errors(app, client):
    """A 5xx from the target becomes outcome=error, source=system, not an aborted run."""
    real = app.state.tester_client_factory

    def factory(target, is_self):
        c = real(target, is_self)
        get = c.get

        def flaky(path, *a, **kw):
            if path == "/v1/integrity":
                import httpx
                return httpx.Response(500, text="boom")
            return get(path, *a, **kw)
        c.get = flaky
        return c

    app.state.tester_client_factory = factory
    sid = client.post("/tester/test/setup", json={"target_url": TARGET}).json()["session_id"]
    report = client.post("/tester/test/run", json={"session_id": sid}).json()
    row = next(r for r in report["results"] if r["test_id"] == "integrity-chains")
    assert (row["outcome"], row["source"]) == ("error", "system")
