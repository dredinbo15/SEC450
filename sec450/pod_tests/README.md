# Team 105 incident API tests

These tests check the other pod's (Team 105) incident-management API at `https://sec450-incident-api.onrender.com/system` against their own OpenAPI contract (`/system/openapi.json` and `/system/test/openapi.json`). They don't touch our system. There is no database, they import nothing from `sec450` or `tests/`, and neither a plain `pytest` nor CI runs them, because `testpaths` is `["tests"]`. Ruff and mypy check it; bandit skips it, as it skips `tests/`. `.dockerignore` keeps it out of the image.

## Running

```sh
pytest sec450/pod_tests -rA          # -rA lists every test with its result
pytest sec450/pod_tests -m "not finding"   # contract checks only, without the security findings
```

The first request wakes their free-tier host, which can take about a minute. The suite waits up to `POD105_WAKE_SECONDS` (180) for `/system/health`, and each request has a `POD105_TIMEOUT` of 90 s. `POD105_BASE_URL` points it at another deployment.

## Where the requests go

- Every incident request goes to an isolated course session store: `POST /system/test/setup {"session_id": ..., "setup": {}}`, then `X-Test-Session-Id` on every `/system/api/v1/...` call. Session ids start with `team102-pytest-`.
- A request hook in `conftest.py` refuses three kinds of request before they're sent: anything other than GET outside `/system` (their production store), any `.../test/reset`, and any `/system/api/...` request without the session header. A headerless request would land in whichever session was created most recently, possibly someone else's.
- Production gets exactly one request, a read-only GET, to confirm that an incident created in our session isn't there.

### Session capacity

Their host keeps every session, has no way to delete one, and once its capacity is used up answers setup with **503 "Course session capacity reached"**. That blocks everyone, Team 105 and the graders included. So a run opens at most two sessions: one store all tests share, and a second fresh one for the isolation test (`MAX_SESSIONS` in `conftest.py`). Tests create their own incidents and don't depend on how many the shared store holds.

When setup returns 503, you can still run the suite against a store prepared earlier:

```sh
POD105_SESSION_ID=<a session id you created before> pytest sec450/pod_tests -rA
```

`test_setup_creates_session` is skipped then, and the isolation test fails at its second session until capacity frees up.

## What it checks

| Area | Tests | Why |
|---|---|---|
| Course interface | `GET /test` index; setup 201, reused id 409, four bad bodies 400; report 200 for a known session, 404 unknown, 400 without `session_id`; unknown session header 404; both health endpoints | Graders drive the pod through this interface |
| Isolation (the Team 102 → Team 105 integration test) | Create "Team 102 Integration Test", read it back (id, title, log, source, state RECEIVED); it's 404 in production; a second fresh session holds only the two seed incidents and doesn't see it | Our forwarded incidents must never mix with their production data or another session's |
| Create validation | missing title/log/occurredAt, extra field, 201-character title, empty title or log, bad `occurredAt`, 101-character source → 400 `ErrorResponse` naming the field, nothing stored; text/plain and form bodies → 415; malformed JSON → 400; 200-character title and no source accepted | The `CreateIncident` schema our forwarder relies on |
| Read | unknown id 404 `INCIDENT_NOT_FOUND`; list holds the new incident; `?state=` for every state returns only that state; unknown or lowercase state 400 | |
| Workflow | assessment → UNDER_REVIEW (no indicators) or POTENTIALLY_MATERIAL (ransomware); a second assessment 409; review before assessment 409; NOT_MATERIAL review; disclosure needs a MATERIAL review (409); full run: MATERIAL review → MATERIAL_CONFIRMED, one review only, two-way related link, duplicate or self link 409, disclosure draft (`final: false`), `/reviews` and `/disclosures` history; review validation 400/415; related validation 400/404; every workflow endpoint 404 for an unknown incident | The states and transitions their API produces. CLOSED exists in the enum, but no endpoint leads to it |
| Security findings (`-m finding`) | Incidents readable without credentials; an identical resubmission creates a second incident | Recorded as tests that fail while the weakness is there |

Where their behaviour differs from their own spec, the test fails with the difference in the message; it doesn't adjust the expectation to fit.
