# Acceptance criteria status

Status of AC-01 to AC-30 from the [README](../README.md#acceptance-criteria), as of 2026-10-31. Automated criteria run in CI on every push (`pytest`). The manual steps need team members. Each section below gives its procedure and a table to fill in.

| AC | Method | Status | Evidence |
|----|--------|--------|----------|
| AC-01 | Test, Auto | Pass | `test_req01_collection.py::test_one_cycle_collects_every_source`, `test_interval_bounds` |
| AC-02 | Test, Auto | Pass | `test_req01_collection.py::test_every_field_matches`, `test_fall_back_hour_is_first_occurrence`, `test_parsers.py` |
| AC-03 | Test, Auto | Pass | `test_req01_collection.py::test_no_loss_or_duplication` |
| AC-04 | Test, Auto | Pass | `test_req02_requester.py::test_requester_and_destination_fields`, `test_lookup` |
| AC-05 | Test, Auto | Pass | `test_req02_requester.py::test_forwarded_ip_trust` |
| AC-06 | Test, Auto | Pass | `test_req03_detection.py::test_rule_thresholds_and_windows` (12 cases) |
| AC-07 | Test, Auto | Pass | `test_req03_detection.py::test_detection_latency`: 20 runs, max 59 s (limit 300 s) |
| AC-08 | Demonstration + Inspection, Manual | Automated part passes; demonstration pending | `test_threshold_change_needs_only_config`; [procedure](#ac-08-thresholds-configurable-without-code-changes) |
| AC-09 | Test, Auto | Pass | `test_detection_triage.py::test_token_length_boundary`, `test_named_secrets_redacted` |
| AC-10 | Test, Auto | Pass | `test_detection_triage.py::test_triage_gating_and_advisory` |
| AC-11 | Test, Auto | Pass | `test_detection_triage.py::test_ac11_llm_failure_path_still_reports` |
| AC-12 | Inspection, Manual (non-blocking) | Pending: needs two raters | [procedure](#ac-12-ai-assessment-usefulness) |
| AC-13 | Test, Auto | Pass | `test_api.py::test_filters` |
| AC-14 | Test, Auto | Pass | `test_api.py::test_parameter_validation`, `test_thin_slice.py::test_ac14_report_by_id_errors` |
| AC-15 | Test, Auto | Pass | `test_thin_slice.py::test_ac15_thin_slice_ssh_bruteforce_to_report`, `test_detection_triage.py::test_ac15_medium_done_without_report_high_reported` |
| AC-16 | Inspection, Manual | Pending: needs a teammate who didn't write the report code | [procedure](#ac-16-report-readability) |
| AC-17 | Test, Auto | Pass | `test_collection_integrity.py::test_quarantine_and_health_warning` |
| AC-18 | Test, Auto | Pass | `test_collection_integrity.py::test_gap_opens_after_retries_and_closes` |
| AC-19 | Test, Auto | Pass | `test_collection_integrity.py::test_clock_anomaly_boundary` |
| AC-20 | Inspection + Test | Test passes; inspection done, sign-off pending | `test_raw_line_update_rejected`; [inspection](#ac-20-raw-lines-immutable) |
| AC-21 | Test, Auto | Pass | `test_collection_integrity.py::test_tamper_detection` |
| AC-22 | Test, Auto | Pass | `test_collection_integrity.py::test_retention_boundaries` |
| AC-23 | Test, Auto | Pass | `test_req09_tls.py::test_tls_enforcement` |
| AC-24 | Test + Inspection | Test passes; inspection done, sign-off pending | `test_api.py::test_auth`; [inspection](#ac-24-key-storage) |
| AC-25 | Test, Auto | Pass | `test_api.py::test_rate_limit` |
| AC-26 | Test, Auto | Pass | `test_api.py::test_audit_chain_and_fail_closed` |
| AC-27 | Test + Analysis | Test passes; outlier review pending | `test_req10_performance.py::test_query_performance`: p95 24 ms; [analysis](#ac-27-and-ac-28-analysis) |
| AC-28 | Test + Analysis | Test passes; analysis pending | `test_req11_accuracy.py::test_detection_accuracy`: 3 seeds, 28/28 detected, 0 false alarms; [analysis](#ac-27-and-ac-28-analysis) |
| AC-29 | Demonstration, Manual | Pending: needs a teammate on a clean machine | [procedure](#ac-29-clean-clone-startup) |
| AC-30 | Inspection, Manual | Inspection done, one fix made, sign-off pending | [inspection](#ac-30-single-configuration-file) |

## How the newer automated tests work

- **AC-07 and AC-28** use [tests/scenarios.py](../tests/scenarios.py). It writes attack and baseline traffic as log lines in the lab servers' formats, then collects them with `worker.collection_cycle`, the same call the collector service makes, while stepping a fixed clock one 60 s interval at a time. Parsing, storage and detection are production code; only the lab servers and the wall clock are simulated. Each attack comes from its own address, so ground truth matches clusters by (rule, client IP). The baseline includes near misses that stay just under each threshold: 4 failed logins, 15 distinct 404s, 8 MB of downloads. Lowering R1 or R4 makes those near misses show up as false alarms, so the scorer can fail.
- **AC-07** measures latency from the line that completes a rule's condition (for example, the 5th failed login) to the cluster's `created_at`.
- **AC-23** serves the API with the service's own uvicorn config (`sec450.api.__main__.server_config`) on a local port. A control server that accepts TLS 1.0 and 1.1 first proves that the local OpenSSL can still offer them. Otherwise the test skips instead of passing vacuously. The test fails if the TLS 1.2 floor is removed.
- **AC-27** seeds 100,800 events over 30 days: one hash-chained batch per source per hour, 439 clusters, and 335 reports for the high and critical ones. It then sends 200 mixed queries through the full `/v1` stack. The rate limit is raised for that test only, because AC-25 covers it separately.

## Manual steps

### AC-08 Thresholds configurable without code changes

On the stack host: in `config.yaml`, set R1's `threshold` from 5 to 3. Then run `docker compose up -d` and send 3 failed SSH logins from one address:

```sh
docker compose exec traffic-gen python -c "import traffic; [traffic.failed_ssh_login('nobody', 'wrong') for _ in range(3)]"
```

The `traffic-gen` container's own bursts also come from that address, so send these right after a `ground_truth` line in `docker compose logs traffic-gen`, while it is quiet. Wait for the next collection, then check `/v1/clusters` for an R1 cluster. `git status` should show no tracked file changed, because `config.yaml` is ignored by git. Set the threshold back afterward.

| Date | Who | Cluster created? | Tracked files changed | Result |
|------|-----|------------------|-----------------------|--------|
| | | | | |

### AC-12 AI assessment usefulness

Needs `triage.client: claude`; the mock's explanations don't count. Pull clusters that have an `ai_assessment` whose `model` is a Claude model:

```sh
curl -k -H "Authorization: Bearer <key>" "https://localhost/v1/clusters?limit=50"
```

Two team members each rate the same 10 explanations as reasonable or not reasonable, independently. Pass: at least 8 of 10 are rated reasonable by both. A failure is recorded as a finding, not a blocker.

| Cluster | Rule | Rater 1 | Rater 2 |
|---------|------|---------|---------|
| | | | |

### AC-16 Report readability

A teammate who didn't write `sec450/reports.py` gets one brute-force (R1), one injection (R3) and one large-transfer (R4) report from `/v1/reports/<id>`. Using only those reports, they answer who, what, where and when for each. Pass: all 12 answers are correct.

| Report | Who | What | Where | When | All correct? |
|--------|-----|------|-------|------|--------------|
| | | | | | |

### AC-29 Clean-clone startup

On a machine with only Docker, a teammate who didn't write the deployment files clones the repo. They run `cp config.example.yaml config.yaml`, optionally add `ANTHROPIC_API_KEY` to `.env`, then run `docker compose up --build -d`. They time how long it takes until `docker compose ps` shows collector and api healthy. Then they check for a brute-force report: `docker compose logs traffic-gen` shows the `ssh_bruteforce` ground truth, and `/v1/reports` lists an R1 report.

| Date | Who | Machine | Time to healthy (≤ 600 s) | R1 report? | Result |
|------|-----|---------|---------------------------|------------|--------|
| | | | | | |

### AC-27 and AC-28 analysis

On the reference host (4 CPU cores, 8 GB RAM), run with `-s` to print the numbers:

```sh
pytest -s tests/test_req10_performance.py tests/test_req11_accuracy.py
```

AC-27 prints p50, p95 and max, plus the 5 slowest queries for the outlier review. AC-28 prints each attack's ground-truth line and a per-seed score. Results on 2026-10-31 on a 4-core, 8 GB host: p95 24 ms, max 73 ms, with `/v1/logs?limit=1000` the slowest kind of query. Each of seeds 1, 2 and 3 gave 28/28 detected and 0/28 false alarms.

Limits to note in the analysis: the scenario set is synthetic (DD-03), so accuracy on real traffic would likely be lower. The live `traffic-gen` sends everything from one container address, so its `ground_truth` lines can't be scored per address the way the test scores them.

## Inspections

These were done on 2026-10-31 as input for the team's sign-off.

### AC-20 Raw lines immutable

No code path in `sec450/` runs `UPDATE` or `INSERT OR REPLACE` on `raw_line`. The only writes are the `INSERT` in `collector.py` and the cascading `DELETE` from retention (REQ-08). The `raw_line_no_update` trigger in `db.py` rejects any `UPDATE`, and `test_raw_line_update_rejected` checks it.

### AC-24 Key storage

`keys.py` stores only the SHA-256 hash, and the key is printed once. `config.example.yaml` holds no keys. On the running stack, all 10 rows in `api_key` are 64-character hex hashes, and no audit entry's parameters contain a key. The dashboard's own key is in `.env` (`DASHBOARD_API_KEY`). That is a client credential the dashboard sends (DD-16), not server-side key storage.

### AC-30 Single configuration file

All application settings come from `config.yaml` through `sec450.config.load_config()`. `SEC450_CONFIG` picks the file. Secrets come from `.env` by design: `ANTHROPIC_API_KEY`, and the dashboard's key as `SEC450_API_KEY`.

Fixed in this pass: the api healthcheck in `docker-compose.yml` hard-coded port 8443. It now reads `api.port` from `config.yaml`.

Compose and lab values that must match `config.yaml` but can't read it, because Compose doesn't parse YAML config files:

| Value | Where | Must match |
|-------|-------|------------|
| Container port `8443` in `443:8443` | `docker-compose.yml` (api) | `api.port` |
| `https://api:8443` | `docker/cloudflared/config.yml` | `api.port` |
| `172.20.0.10`, `172.20.0.0/24` | `docker-compose.yml` (lab-nginx, lab network) | `collector.trusted_proxies` |
| Hostnames `ssh01`, `web01`, `app01`; `TZ` | `docker-compose.yml` (lab servers) | `sources[].host`, `sources[].timezone` |
| Port `8501` | `docker-compose.yml` (dashboard), `docker/cloudflared/dashboard.yml` | Streamlit command line (not in `config.yaml`) |
| Tunnel IDs, `COMPOSE_PROFILES`, `DASHBOARD_PUBLIC_ORIGIN` | `.env` | Compose-level options, not application settings |

For sign-off, the team should either accept these as documented exceptions or narrow AC-30 to "every application setting".
