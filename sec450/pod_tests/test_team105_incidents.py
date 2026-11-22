"""Team 102 -> Team 105: checks of their incident-management API against their own OpenAPI contract.

Contract: {BASE}/openapi.json (incidents) and {BASE}/test/openapi.json (course interface), base /system.
All tests share one session store (conftest.store) and the isolation test opens a second: their host
keeps every session and has a capacity limit. Nothing is written to their production store.
Where their behaviour differs from their spec the test fails with the difference spelled out; we don't
bend the expectation to fit. Tests marked `finding` record security weaknesses and fail while they exist.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx
import pytest

from .conftest import PodSession, new_session_id

STATES = ["RECEIVED", "UNDER_REVIEW", "POTENTIALLY_MATERIAL", "NOT_MATERIAL", "MATERIAL_CONFIRMED", "CLOSED"]
SEED_SOURCE = "team105-candidate-fixtures"   # every new session store starts with two of these
INCIDENT_KEYS = {"id", "title", "log", "occurredAt", "createdAt", "state", "relatedIncidentIds"}   # required
PROTOCOL_SOURCES = {"tester", "system", "communication", "unknown"}

# A log with none of their materiality indicators, and one with "ransomware" (an indicator, as their seed shows).
QUIET_LOG = "Nov 20 10:00:00 sshd[1]: Failed password for root from 203.0.113.5 port 52114 ssh2"
RANSOM_LOG = "Ransomware note found on file server; shares encrypted"

_OMIT = object()   # payload(field=_OMIT) leaves the field out


def payload(**overrides: Any) -> dict[str, Any]:
    body = {"title": "Team 102 pod test", "log": QUIET_LOG, "occurredAt": "2026-11-20T10:00:00Z",
            "source": "team102-pod-tests"}
    body.update(overrides)
    return {k: v for k, v in body.items() if v is not _OMIT}



def body(r: httpx.Response) -> Any:
    """The JSON body, or a failure that shows what came back instead (their host firewall answers in HTML)."""
    try:
        return r.json()
    except ValueError:
        pytest.fail(f"{r.request.method} {r.request.url.path} -> {r.status_code} "
                    f"{r.headers.get('content-type')}, not JSON: {r.text[:300]!r}")


def expect(r: httpx.Response, status: int) -> Any:
    assert r.status_code == status, (f"{r.request.method} {r.request.url.path}: expected {status}, "
                                     f"got {r.status_code}: {r.text[:400]}")
    return body(r)


def is_datetime(value: Any) -> bool:
    try:
        return isinstance(value, str) and datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def check_incident(inc: Any) -> dict[str, Any]:
    """IncidentResponse: required keys present and typed as the spec says."""
    assert isinstance(inc, dict), f"IncidentResponse should be an object, got {inc!r}"
    assert INCIDENT_KEYS <= inc.keys(), f"IncidentResponse missing {sorted(INCIDENT_KEYS - inc.keys())}"
    assert inc["state"] in STATES, f"unknown state {inc['state']!r}"
    assert is_datetime(inc["occurredAt"]) and is_datetime(inc["createdAt"]), "timestamps must be date-time"
    assert isinstance(inc["relatedIncidentIds"], list)
    assert inc.get("source") is None or isinstance(inc["source"], str)
    return inc


def check_error(r: httpx.Response, status: int, error: str | None = None, field: str | None = None) -> dict:
    """ErrorResponse {error, message, field?} with the expected status, code and field."""
    err = expect(r, status)
    assert isinstance(err, dict) and isinstance(err.get("error"), str) and isinstance(err.get("message"), str), \
        f"not an ErrorResponse: {err!r}"
    if error is not None:
        assert err["error"] == error, f"expected error {error!r}, got {err!r}"
    if field is not None:
        assert err.get("field") == field, f"expected field {field!r}, got {err!r}"
    return err


def check_protocol_error(r: httpx.Response, status: int) -> None:
    """ProtocolErrorBody {message, source}, additionalProperties false."""
    err = expect(r, status)
    assert set(err) == {"message", "source"} and err["message"], f"not a ProtocolErrorBody: {err!r}"
    assert err["source"] in PROTOCOL_SOURCES, f"source {err['source']!r} not in {sorted(PROTOCOL_SOURCES)}"


def create(api: httpx.Client, **overrides: Any) -> dict[str, Any]:
    return check_incident(expect(api.post("/incidents", json=payload(**overrides)), 201))


# --- Course interface (/system/test) -------------------------------------------------------------------------

def test_index_lists_course_endpoints(system: httpx.Client) -> None:
    """GET /test describes the course interface; graders start here."""
    index = expect(system.get("/test"), 200)
    assert {"POST /test/setup", "GET /test/report"} <= set(index.get("system", [])), index


def test_setup_creates_session(store: PodSession) -> None:
    """POST /test/setup with a new id -> 201 SessionResponse echoing the id (the run's shared store)."""
    if store.setup_response is None:
        pytest.skip("POD105_SESSION_ID reuses a store; no session was prepared in this run")
    assert expect(store.setup_response, 201) == {"session_id": store.id}


def test_setup_reused_id_conflicts(system: httpx.Client, store: PodSession) -> None:
    """Preparing the same session id twice -> 409, so one run can't silently take over another's store."""
    check_protocol_error(system.post("/test/setup", json={"session_id": store.id, "setup": {}}), 409)


@pytest.mark.parametrize("bad", [
    {"setup": {}},                                           # session_id required
    {"session_id": "", "setup": {}},                         # minLength 1
    {"session_id": "team102-pytest-no-setup"},               # setup required
    {"session_id": "team102-pytest-extra", "setup": {}, "x": 1},   # additionalProperties false
], ids=["no-session-id", "empty-session-id", "no-setup", "extra-key"])
def test_setup_rejects_bad_body(system: httpx.Client, bad: dict) -> None:
    """SystemSetupRequest violations -> 400 ProtocolErrorBody."""
    check_protocol_error(system.post("/test/setup", json=bad), 400)


def test_report_for_known_session(system: httpx.Client, store: PodSession) -> None:
    """GET /test/report?session_id= -> 200 SystemReport for a prepared session."""
    sid = store.id
    report = expect(system.get("/test/report", params={"session_id": sid}), 200)
    assert set(report) == {"session_id", "coverage"} and report["session_id"] == sid, report
    code = report["coverage"]["code"]
    assert {"covered", "total", "basis"} == set(code) and code["basis"], code


def test_report_unknown_session_404(system: httpx.Client) -> None:
    check_protocol_error(system.get("/test/report", params={"session_id": new_session_id()}), 404)


def test_report_without_session_id_400(system: httpx.Client) -> None:
    check_protocol_error(system.get("/test/report"), 400)


def test_unknown_session_header_404(system: httpx.Client) -> None:
    """An API request naming a session that was never prepared is refused, not served from another store."""
    r = system.get("/api/v1/incidents", headers={"X-Test-Session-Id": new_session_id()})
    assert r.status_code == 404, f"expected 404 for an unknown session, got {r.status_code}: {r.text[:300]}"


def test_health(system: httpx.Client, api: httpx.Client) -> None:
    """GET /health and GET /api/v1/health -> 200."""
    expect(system.get("/health"), 200)
    expect(api.get("/health"), 200)


# --- Session isolation: the Team 102 -> Team 105 integration test ------------------------------------------

def test_team102_integration_incident_is_isolated(
    api: httpx.Client, open_session: Callable[[], PodSession], production: httpx.Client
) -> None:
    """Create our integration incident, read it back, and confirm it exists only in this session's store.

    The second session must start with just their two seed incidents: nothing from ours or from production.
    """
    sent = payload(title="Team 102 Integration Test", log="Team 102 -> Team 105 integration check",
                   source="Team 102")
    created = check_incident(expect(api.post("/incidents", json=sent), 201))
    got = check_incident(expect(api.get(f"/incidents/{created['id']}"), 200))
    assert got["id"] == created["id"]
    assert (got["title"], got["log"], got["source"]) == (sent["title"], sent["log"], sent["source"])
    assert got["state"] == "RECEIVED"

    r = production.get(f"/api/v1/incidents/{created['id']}")   # read-only
    assert r.status_code == 404, f"session incident visible in production: {r.status_code} {r.text[:300]}"

    other = open_session().client
    check_error(other.get(f"/incidents/{created['id']}"), 404, "INCIDENT_NOT_FOUND")
    fresh = [check_incident(i) for i in expect(other.get("/incidents"), 200)]
    assert len(fresh) == 2 and {i["source"] for i in fresh} == {SEED_SOURCE}, f"fresh store holds {fresh}"


# --- Create validation ------------------------------------------------------------------------------------

def test_create_returns_incident(api: httpx.Client) -> None:
    """POST /incidents -> 201 IncidentResponse: input echoed, state RECEIVED, nothing assessed or linked."""
    sent = payload()
    inc = create(api)
    assert (inc["title"], inc["log"], inc["source"]) == (sent["title"], sent["log"], sent["source"])
    assert datetime.fromisoformat(inc["occurredAt"]) == datetime.fromisoformat(sent["occurredAt"])
    assert inc["state"] == "RECEIVED"
    assert inc.get("assessment") is None and inc.get("review") is None and inc["relatedIncidentIds"] == []


def test_create_without_source(api: httpx.Client) -> None:
    """source is optional; the response then carries source null."""
    assert create(api, source=_OMIT).get("source") is None


def test_create_title_at_limit(api: httpx.Client) -> None:
    """A 200-character title is the maximum and is accepted."""
    assert create(api, title="t" * 200)["title"] == "t" * 200


@pytest.mark.parametrize("overrides, field", [
    ({"title": _OMIT}, "title"),
    ({"log": _OMIT}, "log"),
    ({"occurredAt": _OMIT}, "occurredAt"),
    ({"severity": "high"}, "severity"),           # additionalProperties false
    ({"title": "t" * 201}, "title"),              # maxLength 200
    ({"title": ""}, "title"),                     # minLength 1
    ({"log": ""}, "log"),                         # minLength 1
    ({"occurredAt": "yesterday"}, "occurredAt"),  # format date-time
    ({"source": "s" * 101}, "source"),            # maxLength 100
], ids=["missing-title", "missing-log", "missing-occurredAt", "extra-field", "title-201", "empty-title",
        "empty-log", "bad-occurredAt", "source-101"])
def test_create_rejects_invalid(api: httpx.Client, overrides: dict, field: str) -> None:
    """CreateIncident violations -> 400 ErrorResponse naming the offending field; nothing is stored."""
    before = len(expect(api.get("/incidents"), 200))
    check_error(api.post("/incidents", json=payload(**overrides)), 400, "INVALID_REQUEST", field)
    assert len(expect(api.get("/incidents"), 200)) == before, "a rejected incident was stored"


@pytest.mark.parametrize("headers, content", [
    ({"Content-Type": "text/plain"}, b'{"title": "x"}'),
    ({"Content-Type": "application/x-www-form-urlencoded"}, b"title=x"),
], ids=["text-plain", "form"])
def test_create_non_json_415(api: httpx.Client, headers: dict, content: bytes) -> None:
    """A body that isn't application/json -> 415 ErrorResponse."""
    check_error(api.post("/incidents", headers=headers, content=content), 415)


def test_create_malformed_json_400(api: httpx.Client) -> None:
    """Broken JSON -> 400 ErrorResponse. `field` is optional, but when set it should name a request field."""
    err = check_error(api.post("/incidents", headers={"Content-Type": "application/json"}, content=b'{"title":'),
                      400, "INVALID_REQUEST")
    assert err.get("field") in (None, "body"), \
        f"ErrorResponse.field should be a field name or null, got {err.get('field')!r} (a parser offset?)"


# --- Read, list and filter --------------------------------------------------------------------------------

def test_get_unknown_id_404(api: httpx.Client) -> None:
    check_error(api.get("/incidents/00000000-0000-4000-8000-000000000000"), 404, "INCIDENT_NOT_FOUND")


def test_list_includes_created(api: httpx.Client) -> None:
    """GET /incidents returns every incident in the store, the new one included."""
    inc = create(api)
    listed = {i["id"]: check_incident(i) for i in expect(api.get("/incidents"), 200)}
    assert inc["id"] in listed and listed[inc["id"]] == inc


@pytest.mark.parametrize("state", STATES)
def test_filter_by_state(api: httpx.Client, state: str) -> None:
    """?state= returns only incidents in that state; a new incident shows up under RECEIVED only."""
    inc = create(api)
    listed = expect(api.get("/incidents", params={"state": state}), 200)
    assert all(i["state"] == state for i in listed), f"?state={state} returned {[i['state'] for i in listed]}"
    assert (inc["id"] in {i["id"] for i in listed}) == (state == "RECEIVED")


@pytest.mark.parametrize("state", ["BOGUS", "received"])
def test_filter_unknown_state_400(api: httpx.Client, state: str) -> None:
    check_error(api.get("/incidents", params={"state": state}), 400, "INVALID_REQUEST", "state")


# --- Assessment -> review -> related -> disclosure workflow ---------------------------------------------

def assess(api: httpx.Client, incident_id: str) -> dict[str, Any]:
    a = expect(api.post(f"/incidents/{incident_id}/assessment"), 200)
    assert isinstance(a.get("potentiallyMaterial"), bool) and a.get("explanation"), f"not an AssessmentResponse: {a}"
    assert isinstance(a.get("indicators", []), list)
    return a


def review(api: httpx.Client, incident_id: str, decision: str, **extra: Any) -> httpx.Response:
    return api.post(f"/incidents/{incident_id}/review", json={"decision": decision, "reviewer": "Team 102", **extra})


def test_assessment_without_indicators_goes_under_review(api: httpx.Client) -> None:
    """RECEIVED --assessment--> UNDER_REVIEW when nothing looks material; the assessment is stored on the incident."""
    inc = create(api)
    a = assess(api, inc["id"])
    assert a["potentiallyMaterial"] is False
    got = check_incident(expect(api.get(f"/incidents/{inc['id']}"), 200))
    assert got["state"] == "UNDER_REVIEW" and got["assessment"] == a


def test_assessment_with_indicator_is_potentially_material(api: httpx.Client) -> None:
    """RECEIVED --assessment--> POTENTIALLY_MATERIAL when the log holds an indicator (ransomware)."""
    inc = create(api, title="Ransomware on file server", log=RANSOM_LOG)
    a = assess(api, inc["id"])
    assert a["potentiallyMaterial"] is True and a.get("indicators"), a
    assert expect(api.get(f"/incidents/{inc['id']}"), 200)["state"] == "POTENTIALLY_MATERIAL"


def test_second_assessment_409(api: httpx.Client) -> None:
    inc = create(api)
    assess(api, inc["id"])
    check_error(api.post(f"/incidents/{inc['id']}/assessment"), 409, "INVALID_STATE")


def test_review_before_assessment_409(api: httpx.Client) -> None:
    """A human review needs an assessment first."""
    inc = create(api)
    check_error(review(api, inc["id"], "MATERIAL"), 409, "INVALID_STATE")


def test_not_material_review(api: httpx.Client) -> None:
    """UNDER_REVIEW --review NOT_MATERIAL--> NOT_MATERIAL; no disclosure can be drafted from there."""
    inc = create(api)
    assess(api, inc["id"])
    got = check_incident(expect(review(api, inc["id"], "NOT_MATERIAL"), 200))
    assert got["state"] == "NOT_MATERIAL" and got["review"]["decision"] == "NOT_MATERIAL"
    assert got["review"].get("rationale") is None and is_datetime(got["review"]["reviewedAt"])
    check_error(api.post(f"/incidents/{inc['id']}/disclosure"), 409, "INVALID_STATE")


def test_disclosure_needs_material_review(api: httpx.Client) -> None:
    """An assessed but unreviewed incident can't get a disclosure draft."""
    inc = create(api)
    assess(api, inc["id"])
    check_error(api.post(f"/incidents/{inc['id']}/disclosure"), 409, "INVALID_STATE")


def test_full_workflow(api: httpx.Client) -> None:
    """assessment -> MATERIAL review -> link related -> disclosure, with the history endpoints.

    RECEIVED -> POTENTIALLY_MATERIAL -> MATERIAL_CONFIRMED; linking and drafting don't change the state.
    """
    a = create(api, title="Ransomware on file server", log=RANSOM_LOG)
    b = create(api, title="Related outbound transfer")
    assess(api, a["id"])

    reviewed = check_incident(expect(review(api, a["id"], "MATERIAL", rationale="Encrypted shares"), 200))
    assert reviewed["state"] == "MATERIAL_CONFIRMED"
    assert reviewed["review"]["decision"] == "MATERIAL" and reviewed["review"]["reviewer"] == "Team 102"
    assert reviewed["review"]["rationale"] == "Encrypted shares" and is_datetime(reviewed["review"]["reviewedAt"])
    check_error(review(api, a["id"], "NOT_MATERIAL"), 409, "INVALID_STATE")   # one review per incident

    linked = check_incident(expect(api.post(f"/incidents/{a['id']}/related", json={"relatedIncidentId": b["id"]}),
                                   200))
    assert linked["relatedIncidentIds"] == [b["id"]] and linked["state"] == "MATERIAL_CONFIRMED"
    assert a["id"] in expect(api.get(f"/incidents/{b['id']}"), 200)["relatedIncidentIds"], "link is one-sided"
    check_error(api.post(f"/incidents/{a['id']}/related", json={"relatedIncidentId": b["id"]}), 409,
                "DUPLICATE_RELATION")
    check_error(api.post(f"/incidents/{a['id']}/related", json={"relatedIncidentId": a["id"]}), 409,
                "DUPLICATE_RELATION")

    d = expect(api.post(f"/incidents/{a['id']}/disclosure"), 200)
    assert d["incidentId"] == a["id"] and d["final"] is False and d["draft"] and is_datetime(d["generatedAt"])
    assert expect(api.get(f"/incidents/{a['id']}"), 200)["state"] == "MATERIAL_CONFIRMED"

    reviews = expect(api.get(f"/incidents/{a['id']}/reviews"), 200)
    assert len(reviews) == 1 and reviews[0]["id"]
    assert {k: reviews[0][k] for k in reviewed["review"]} == reviewed["review"]
    disclosures = expect(api.get(f"/incidents/{a['id']}/disclosures"), 200)
    assert len(disclosures) == 1 and disclosures[0]["id"]
    assert {k: disclosures[0][k] for k in d} == d


@pytest.mark.parametrize("bad, field", [
    ({"decision": "MAYBE", "reviewer": "Team 102"}, "decision"),
    ({"decision": "MATERIAL", "reviewer": ""}, "reviewer"),
    ({"decision": "MATERIAL"}, "reviewer"),
    ({"decision": "MATERIAL", "reviewer": "Team 102", "x": 1}, "x"),
], ids=["bad-decision", "empty-reviewer", "no-reviewer", "extra-field"])
def test_review_rejects_invalid(api: httpx.Client, bad: dict, field: str) -> None:
    """ReviewRequest violations -> 400 ErrorResponse naming the field."""
    inc = create(api)
    assess(api, inc["id"])
    check_error(api.post(f"/incidents/{inc['id']}/review", json=bad), 400, "INVALID_REQUEST", field)


def test_review_non_json_415(api: httpx.Client) -> None:
    inc = create(api)
    assess(api, inc["id"])
    check_error(api.post(f"/incidents/{inc['id']}/review", headers={"Content-Type": "text/plain"}, content=b"x"), 415)


def test_related_validation(api: httpx.Client) -> None:
    """LinkRequest: empty id -> 400; an id that doesn't exist -> 404."""
    inc = create(api)
    check_error(api.post(f"/incidents/{inc['id']}/related", json={"relatedIncidentId": ""}), 400,
                "INVALID_REQUEST", "relatedIncidentId")
    check_error(api.post(f"/incidents/{inc['id']}/related",
                         json={"relatedIncidentId": "00000000-0000-4000-8000-000000000000"}), 404,
                "INCIDENT_NOT_FOUND")


@pytest.mark.parametrize("method, path, json", [
    ("POST", "assessment", None),
    ("POST", "review", {"decision": "MATERIAL", "reviewer": "Team 102"}),
    ("POST", "related", {"relatedIncidentId": "10500000-0000-4000-8000-000000000001"}),
    ("POST", "disclosure", None),
    ("GET", "reviews", None),
    ("GET", "disclosures", None),
])
def test_workflow_unknown_incident_404(api: httpx.Client, method: str, path: str, json: dict | None) -> None:
    r = api.request(method, f"/incidents/00000000-0000-4000-8000-000000000000/{path}", json=json)
    check_error(r, 404, "INCIDENT_NOT_FOUND")


# --- Security findings -------------------------------------------------------------------------------------

@pytest.mark.finding
def test_finding_incidents_readable_without_authentication(api: httpx.Client) -> None:
    """Incident logs (attacker IPs, affected systems) should need credentials to read; their API has none."""
    r = api.get("/incidents")   # no Authorization header; only the course session id
    assert r.status_code in (401, 403), (
        f"SECURITY FINDING: GET /api/v1/incidents without credentials returned {r.status_code} with "
        f"{len(body(r))} incidents. The spec declares no security scheme, so anyone can read, file and review "
        "incidents.")


@pytest.mark.finding
def test_finding_duplicate_submissions_accepted(api: httpx.Client) -> None:
    """Resending the same report should return the existing incident (their spec documents a 200 'Existing Team 102
    report incident' response on POST /incidents), not create a second one."""
    sent = payload(title="Team 102 Integration Test", source="Team 102")
    first = check_incident(expect(api.post("/incidents", json=sent), 201))
    r = api.post("/incidents", json=sent)
    second = check_incident(body(r))
    assert r.status_code == 200 and second["id"] == first["id"], (
        f"SECURITY FINDING / SPEC MISMATCH: an identical second submission returned {r.status_code} with a new id "
        f"({second['id']} vs {first['id']}); the spec's 200 'Existing Team 102 report incident' did not happen. "
        "Retries and replays duplicate incidents (production already holds duplicates).")
