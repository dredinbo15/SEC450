# SEC450 testing interface (Team 102, Pod C)

This is the spec for the course's cross-team testing. Both services run in the `api` container (`sec450/api/testing.py`) and are reached through the Cloudflare tunnel:

| Service | Base URL | Endpoints |
|---|---|---|
| System | `https://seclog.redinbo.win` | `POST /test/setup`, `GET /test/report`, plus the SEC450 query API (`/health`, `/v1/...`) |
| Tester | `https://seclog.redinbo.win/tester` | `POST /test/setup`, `POST /test/run`, `GET /test/report` |

`GET /test` on either base URL lists the endpoints. Errors on every `/test` endpoint are JSON `{"message": "...", "source": "tester" | "system" | "communication" | "unknown"}`.

## Access

**No credentials are needed for any `/test` endpoint.**
- System setup only registers the session. It never deletes collected logs, because raw lines are immutable and hash-chained (REQ-08).
- When the tester targets this system, it creates a read-only API key for that run and revokes it when the run ends. Its `/v1` calls are therefore authenticated, rate limited and audited like any client's (REQ-09).
- The SEC450 query API itself (`/v1/...`) needs `Authorization: Bearer <key>`. Keys are issued by Team 102 on request.

Run one session at a time. Expected times: tester setup under 30 s, tester run under 120 s (typically a few seconds).

## System

- **`POST /test/setup`** with `{"session_id": "<1-128 chars>", "setup": {}}`
  - Returns `201 {"session_id": ...}`.
  - A reused ID gets `409`. A missing or invalid body gets `400`.
  - Data is not reset: the lab's traffic generator keeps producing logs and attacks continuously, and the checks read the live data.
- **`GET /test/report?session_id=...`**
  - Returns `200 {"session_id", "coverage": {"code": {"covered": null, "total": null, "basis": "..."}}}`. Line coverage is not instrumented in the deployed service; CI runs the pytest suite on every push.
  - A missing ID gets `400`; an unknown ID gets `404`.
  - Sessions are held in memory and are lost if the container restarts.

## Tester

- **`POST /test/setup`** with `{"target_url": "<system base URL>"}`
  - Creates a UUID session and calls the target's `/test/setup` with `{"session_id", "setup": {}}`.
  - Returns `201 {"session_id"}` only after the target confirms the same ID. Otherwise it returns the target's status, message and source.
  - Targets must be public `https://` hosts; internal and private addresses are refused with `400`. The address is checked again on every connection, so a hostname that later resolves inward fails as a `communication` error.
  - At most 10 sessions are set up per minute (`429` with `Retry-After` after that).
- **`POST /test/run`** with `{"session_id": ...}`
  - Runs the suite once and returns the report. A second run gets `409`; an unknown ID gets `404`.
  - At most 2 setups or runs proceed at once; others get `503` with `Retry-After`, and the session stays ready to run.
  - A run has a 120 s time budget. Checks still pending when it is used up are reported as `skip`.
- **`GET /test/report?session_id=...`**
  - Returns the stored report (identical to the run response), or `409` before the run has finished.

### The suite

| Test IDs | Checks | Criteria |
|---|---|---|
| `health` | `GET /health` returns `{"status": "ok"}` | |
| `system-test-report` | the target's `/test/report` returns `coverage.code` | |
| `auth-missing-key`, `auth-wrong-key` | `401` with `WWW-Authenticate: Bearer` and no data | AC-24 |
| `auth-valid-key` | `200` with an events list and count | AC-24 |
| `param-*` (8 invalid) | start after end, 31 days + 1 s, malformed timestamp, invalid IP, bad severity, limit 0 and 1001, unknown parameter → `400` with an error body and no data | AC-14 |
| `param-*` (4 valid) | exactly 31 days, IPv6, limit 1 and 1000 → `200` | AC-14 |
| `events-collected` | at least one event in the last 24 h (the pipeline is running) | REQ-01 |
| `filter-source-ip`, `filter-severity`, `clusters-list`, `reports-list` | filters return only matching rows | AC-13 |
| `report-bad-id` | ids `abc` and `0` → `400`; unknown id → `404` | AC-14 |
| `report-content` | the latest report has every REQ-06 field and its raw log lines | AC-15 |
| `tls-plain-http-refused`, `tls-1.2-accepted`, `tls-1.3-accepted` | probed on the API port when the tester runs beside the target | AC-23 |
| `integrity-chains` | batch and audit hash chains both verify `intact`, including this run's audited requests | AC-21, AC-26 |

**Outcomes**
- `pass` or `fail` when the response matches the contract or doesn't.
- `error` with `source: system` for a 5xx from the target, `source: communication` for a timeout or connection failure, `source: tester` for a tester bug.
- `skip` when a check can't apply. For another team's system, the tester holds no API key there, so the `/v1` checks that need one are skipped and the rest still run.

**Coverage**
- `component`: the 8 operations of this interface (`/health`, the five `/v1` reads, system setup and system report) exercised in the session.
- `system`: acceptance criteria AC-01 to AC-30 (README.md) exercised by an executed test.
- `code`: copied from the target's system report.

## Check it like the graders do

```sh
curl -s -X POST https://seclog.redinbo.win/tester/test/setup \
     -H 'Content-Type: application/json' -d '{"target_url": "https://seclog.redinbo.win"}'
# -> {"session_id": "<id>"}
curl -s -X POST https://seclog.redinbo.win/tester/test/run \
     -H 'Content-Type: application/json' -d '{"session_id": "<id>"}'
curl -s "https://seclog.redinbo.win/tester/test/report?session_id=<id>"
curl -s "https://seclog.redinbo.win/test/report?session_id=<id>"
```

`tests/test_testing_interface.py` replays this sequence in CI and applies the staff checker's format rules.

## What we send to the pod

The collector posts each high and critical report, and optionally each finished medium cluster, to the pod's incident-management API as `POST /api/v1/incidents` with `{title, log, occurredAt, source}` (DD-18; see README, "Posting incidents to the incident-management API"). Each report is sent once, and the returned incident ID is stored.
