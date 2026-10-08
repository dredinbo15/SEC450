# SEC450
![Domain model](docs/images/domain_model.jpg)
![Data diagram](docs/images/data_diagram_schema.jpg)

REQS
Core behavior
ID	Requirement	Source / need
REQ-01	The system shall collect new entries from each configured lab source (Nginx access and error, SSH auth, application) at a configurable interval, default 60 seconds and never more than 5 minutes, and parse each entry into the common event schema (Section 5) with timestamps converted to UTC using the source’s configured time zone.	NIST SP 800-92; NIST SP 800-53 AU-2, AU-3, AU-8
REQ-02	When an event is parsed, the system shall record the requester (client IP, authenticated username or API key ID if present, and ASN and country from an offline GeoIP database) and the data destination (client IP and bytes sent in the response). Forwarded-IP headers shall be trusted only from configured proxy addresses.	NIST SP 800-53 AU-3; stakeholder need: who made the request and where information went
REQ-03	When events are stored, the system shall evaluate them against configurable detection rules and flag matches within 5 minutes of collection. At minimum: ≥5 failed logins from one source in 5 min (high); ≥20 distinct 404s from one source in 1 min (medium); path traversal or injection patterns (high); >10 MB sent to one client IP in 10 min (critical).	NIST SP 800-53 AU-6, SI-4
REQ-04	When a rule flags a cluster at medium severity or higher, the system shall remove credentials, cookies, authorization headers, and API keys from it, submit the redacted cluster to the LLM, and store the result labeled as AI-generated and advisory, without changing the rule-assigned severity. If the LLM fails or does not respond within 30 seconds after 2 retries, then the system shall mark triage as “unavailable” and continue.	NIST SP 800-53 SA-9; data minimization; detection must not depend on an external service
REQ-05	The system shall provide an HTTPS query endpoint (Section 5) returning events, clusters, and reports filtered by time range, source IP, user, and severity. If a request has invalid parameters, then the endpoint shall return HTTP 400 with an error body and no partial data.	NIST SP 800-53 AU-7; RFC 9110; stakeholder need: on-demand investigation
REQ-06	When a cluster reaches high or critical severity, the system shall generate a report within 10 minutes containing a summary, requester, data destination, timeline, matched rule, AI assessment, raw log lines, and integrity check result.	NIST SP 800-53 AU-6, AU-7; NIST SP 800-61 Rev. 3

Failures, data, and security
ID	Requirement	Source / need
REQ-07	If an entry cannot be parsed, then the system shall quarantine it unchanged with the failure reason and continue. If a source is unreachable after 3 retries, then the system shall record a collection gap shown in affected queries and reports. If a timestamp is more than 5 minutes ahead of the collector clock, then the system shall flag a clock anomaly.	NIST SP 800-53 AU-5, AU-8
REQ-08	The system shall store every raw log line unmodified, linked to its parsed event, with each batch protected by a SHA-256 hash chain whose verification reports “intact” or the first mismatched batch. Events and raw lines shall be retained 30 days and reports 90 days (configurable), then deleted with each deletion recorded.	NIST SP 800-53 AU-9(3), AU-11; FIPS 180-4
REQ-09	The query endpoint shall accept only TLS 1.2 or later, require a read-only API key (stored only as a hash) on every request, limit each key to 60 requests per minute, return HTTP 401 or 429 on failure, and record every request (key ID, time, parameters, result count) in a hash-chained audit log.	NIST SP 800-53 IA-2, AC-3, SC-8, AU-2, AU-12; NIST SP 800-52 Rev. 2; RFC 9110; RFC 6585; OWASP API2:2023, API4:2023

Quality
ID	Requirement	Source / need
REQ-10	The query endpoint shall return results for queries spanning up to 7 days within 2 seconds at the 95th percentile, with up to 100,000 stored events, on the reference host (4 CPU cores, 8 GB RAM).	Stakeholder need: usable investigation
REQ-11	On the scripted attack scenario set, rule detection shall identify at least 90% of injected attacks, and no more than 10% of generated clusters shall be false alarms on baseline traffic.	Project evaluation need
REQ-12	The complete system and lab shall start from a clean repository clone with a single docker compose up in under 10 minutes, with all settings in one configuration file.	Maintainability; reproducible grading
