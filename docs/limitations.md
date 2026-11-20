# Known limitations

Known limitations of the SEC450 system as of 2026-11-19, after the move to PostgreSQL. Each item names the design decision (DD) it comes from, if any, and says whether it's a deliberate trade-off or a gap still open.

## Detection

1. **Only four fixed rules (DD-01, deliberate).** Anything outside brute force, 404 scans, injection patterns and large transfers isn't flagged.
2. **Rules group by a single client IP.** Attacks spread over many addresses get past R1, R2 and R4. So does one address that stays just under a threshold, such as 4 failed logins per 5 minutes or a slow scan. The AC-28 near-miss clients show exactly this.
3. **R3 checks the URL only.** Its patterns see the request target, never POST bodies or headers. Double-encoded or unusual payloads can slip through.
4. **Long attacks split (DD-09, deliberate).** A cluster freezes once it's triaged, so a long attack becomes several linked clusters and reports.
5. **Detect and report only (DD-14, deliberate).** Nothing is blocked automatically.

## Collection

6. **Single host (DD-04).** Logs are read from shared folders on the same machine. There are no remote shipping agents.
7. **One rotation only.** The collector follows `file` → `file.1`. If a log rotates twice within one interval, or the rotated file is compressed, lines are lost.
8. **SSH timestamps have no year.** Classic syslog lines get the current year, with a rollback at New Year.
9. **60 s batches (DD-05).** Collection isn't a stream, so detection lags by up to one interval.
10. **Four log formats.** nginx access, nginx error, SSH auth and the lab app's JSON.

## Storage and integrity

11. **One PostgreSQL instance, no backups (DD-06).**
    - There's no replica and no scheduled `pg_dump`. Losing the `pgdata` volume loses everything.
    - The old SQLite file on the `db` volume is a snapshot from the 2026-11-19 cutover, not an ongoing backup.
    - Postgres doesn't add write concurrency: an advisory lock keeps the collector and analysis writers one at a time, as SQLite did. Reads are concurrent.
12. **The hash chain can be rebuilt (DD-07, accepted).** Someone with full write access to the database could recompute the chain. Nothing is signed or anchored outside the database.
13. **Some tables grow forever.** Retention deletes old batches (with their raw lines and events) and old reports. Audit entries, gaps and cluster rows are never deleted.
14. **GeoIP data.** Offline GeoLite2 databases go slightly stale and must be supplied by hand. Without them, ASN and country are null (DD-13).

## API and access

15. **Keys are all-or-nothing (DD-11).** Keys are static bearer tokens, not OAuth or mTLS, and every key can read everything, including masked raw lines through `/v1/logs`. Keys are held outside Team 102 by the pod (`k_d8b1ba15039d`) and the other team (`k_fe76c0090479`).
16. **The rate limiter is in memory.** It resets when the API restarts and wouldn't hold across more than one API process.
17. **Unauthenticated requests aren't rate-limited.** Bad-key requests get 401, but each still adds an audit entry. Only Cloudflare stands in front of a flood.
18. **Public course endpoints.** `/test`, `/system/test` and `/tester` need no credentials, as the course requires. Test sessions are held in memory and are lost when the API restarts.
19. **The dashboard has no login (DD-16).** It relies on Cloudflare Access in front of its tunnel.
20. **The direct port uses a self-signed certificate.** Only the Cloudflare hostname has a publicly trusted one.
21. **Usage counts are partial.** `sec450.usage` counts audited `/v1` requests only. It leaves out `/health`, `/test`, and anything Cloudflare or TLS refuses first.

## AI triage

22. **Third-party LLM (DD-02).** Redacted clusters go to a hosted model. Redaction is pattern-based, so a secret in an unusual format could slip through, and the same masking protects `/v1/logs`.
23. **Triage is capped and varies.** The AI is advisory only, and its answers vary between runs. It sees at most 50 events per cluster. Once the daily cap is reached, clusters are marked "unavailable".
24. **AI usefulness isn't rated yet.** AC-12 is still pending.

## Testing and evidence

25. **The accuracy results are optimistic (DD-03).** 28/28 detected and 0 false alarms come from synthetic traffic; real traffic would likely do worse.
26. **AC-07 and AC-28 are simulated.** They run the real collection pipeline, but the lab servers and the clock are simulated.
27. **AC-27 skips network overhead.** It runs in-process, so TLS and Cloudflare time isn't included. It measured p95 20 ms on PostgreSQL and 24 ms on SQLite.
28. **The live lab can't be scored per attack.** `traffic-gen` sends everything from one address and runs about 3 attacks an hour.
29. **Running the tests needs PostgreSQL.** `pytest` creates a database per test on the server named by `SEC450_TEST_DATABASE_URL` (default `127.0.0.1:55432`). CI provides one as a service container.
30. **One live check can still skip.** The tester's `filter-source-ip` looks for a client IP among the latest 1,000 events. After about an hour of only sshd healthcheck lines, it skips.
31. **Manual criteria are still open.** AC-08, AC-12, AC-16 and AC-29 are pending, plus the sign-offs for AC-20, AC-24, AC-27, AC-28 and AC-30 ([acceptance.md](acceptance.md)).

## Integrations and operations

32. **The incident API is paused (DD-18).** `incidents.enabled` stays false until the pod API's host firewall stops returning 403 for incidents with attack strings. Report 441 (R3) is recorded as rejected.
33. **The incident forwarder sends unmasked lines.** It posts raw log lines unmodified, while `/v1/logs` masks credentials. On 2026-11-01 none of the 38 lines already sent held anything to mask, but the pod API is open to anyone (item 34), so masking should be added before forwarding is turned back on.
34. **The pod's incident API has flaws of its own.** These were found on 2026-11-01 with read-only checks:
    - It has no authentication: anyone can read every incident, including our log lines.
    - Anyone can call its reset endpoint, `POST /api/v1/test/reset`.
    - It has no course `/test/setup` interface, so our tester can't run against it.
    - It has no protection against duplicates. Two incidents share the source `sec450 R1 report 1`.
    - Its host firewall returns an undocumented HTML 403 for incidents with attack strings.
35. **SIEM push is off by default (DD-17).** When it's on, delivery is at-least-once, so Wazuh can receive duplicates.
36. **Some settings must be synced by hand.** A few Compose and lab values have to match `config.yaml`: the api's port 8443, the proxy IP, and the lab hostnames and timezones. They're listed under AC-30 in [acceptance.md](acceptance.md). `POSTGRES_PASSWORD` now lives in `.env`.
37. **Single host overall.** Rebuilding the API or collector takes the public API down briefly: about 10 s for an API-only rebuild, and about 1.5 minutes for the Postgres cutover. Public access depends on Cloudflare.
