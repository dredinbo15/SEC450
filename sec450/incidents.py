"""Post detections to an external incident-management API (DD-18).

High and critical clusters have reports (REQ-06) and are sent from the report;
medium clusters get no report, so they are sent from the cluster once it is
finished (DONE). The API takes exactly {title, log, occurredAt, source} and
rejects extra fields, so each one is mapped into that shape:

  title       the summary line, cut to 200 characters
  log         the raw log lines, one per line, with credentials redacted (redact.py)
  occurredAt  the first event's time (UTC)
  source      "sec450 <rule id> report <id>" or "sec450 <rule id> cluster <id>"

Each report or cluster is handled once. A 2xx response records the returned incident id; a
4xx means the API refused that report and it is recorded as 'rejected' (sending it
again would fail the same way). A network error, timeout, 5xx, 408 or 429 stops the
cycle, and the report is retried on a later one, so an outage or rate limit delays
incidents instead of losing them.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable

import httpx

from .config import Config, IncidentsConfig
from .db import transaction
from .redact import redact_text
from .timeutil import Clock, iso

log = logging.getLogger(__name__)

# Client errors that say "not now" rather than "never": request timeout and rate limit.
RETRYABLE_4XX = (408, 429)

Poster = Callable[[IncidentsConfig, dict], httpx.Response]


def build_incident(report_id: int, body: dict) -> dict:
    rule = body.get("matched_rule", {})
    timeline = body.get("timeline", [])
    return {
        "title": (body.get("summary") or f"SEC450 report {report_id}")[:200],
        # Redacted like an LLM payload (REQ-04): the full lines stay behind the audited API.
        "log": "\n".join(redact_text(line["text"]) for line in body.get("raw_lines", [])) or body.get("summary", ""),
        "occurredAt": timeline[0]["ts"] if timeline else body.get("generated_at"),
        "source": f"sec450 {rule.get('id', '?')} report {report_id}"[:100],
    }


def http_post(cfg: IncidentsConfig, incident: dict) -> httpx.Response:
    return httpx.post(cfg.url, json=incident, timeout=cfg.timeout_seconds)


def build_cluster_incident(conn: sqlite3.Connection, cluster: sqlite3.Row, cfg: Config) -> dict:
    """For a cluster without a report (medium): the same summary style as reports.py."""
    rule = next((r for r in cfg.detection.rules if r.id == cluster["rule_id"]), None)
    rows = conn.execute(
        "SELECT e.ts, r.text FROM cluster_event ce JOIN event e USING (event_id) JOIN raw_line r USING (raw_id) "
        "WHERE ce.cluster_id = ? ORDER BY e.ts, e.event_id", (cluster["cluster_id"],)).fetchall()
    summary = (f"{rule.name if rule else cluster['rule_id']} ({cluster['severity']}): {len(rows)} events from "
               f"{cluster['group_key']} between {cluster['window_start']} and {cluster['window_end']}")
    return {
        "title": summary[:200],
        "log": "\n".join(redact_text(r["text"]) for r in rows) or summary,
        "occurredAt": rows[0]["ts"] if rows else cluster["window_start"],
        "source": f"sec450 {cluster['rule_id']} cluster {cluster['cluster_id']}"[:100],
    }


_TABLES = {"report": ("incident_delivery", "report_id"), "cluster": ("incident_cluster_delivery", "cluster_id")}


def _record(conn: sqlite3.Connection, kind: str, key: int, status: str, now: str,
            incident_id: str | None = None, detail: str | None = None) -> None:
    table, col = _TABLES[kind]
    with transaction(conn) as c:
        c.execute(f"INSERT OR REPLACE INTO {table} ({col}, status, incident_id, detail, handled_at) "  # noqa: S608  # nosec B608 - fixed names
                  "VALUES (?, ?, ?, ?, ?)", (key, status, incident_id, detail, now))


def _deliver(conn: sqlite3.Connection, icfg: IncidentsConfig, kind: str, key: int, incident: dict,
             now: str, post: Poster) -> str:
    """Post one incident and record the outcome: 'sent', 'rejected', or 'retry' (nothing recorded)."""
    extra = {f"{kind}_id": key}
    try:
        resp = post(icfg, incident)
    except httpx.HTTPError as exc:
        log.warning("incident API unreachable, will retry: %s", exc, extra=extra)
        return "retry"
    if resp.status_code >= 500 or resp.status_code in RETRYABLE_4XX:
        log.warning("incident API returned %d, will retry", resp.status_code, extra=extra)
        return "retry"
    if resp.status_code >= 400:
        _record(conn, kind, key, "rejected", now, detail=f"HTTP {resp.status_code}: {resp.text[:500]}")
        log.error("incident API rejected %s: HTTP %d", kind, resp.status_code, extra=extra)
        return "rejected"
    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    incident_id = None
    if isinstance(payload, dict):    # the spec doesn't name the id field; accept the usual spellings
        incident_id = payload.get("incidentId") or payload.get("incident_id") or payload.get("id")
    _record(conn, kind, key, "sent", now, incident_id=str(incident_id) if incident_id else None)
    log.info("%s sent to the incident API as %s", kind, incident_id, extra=extra)
    return "sent"


def forward_pending_incidents(conn: sqlite3.Connection, cfg: Config, clock: Clock,
                              post: Poster = http_post) -> list[int]:
    """Send reports not handled yet; returns the report ids sent this cycle."""
    icfg = cfg.incidents
    if not icfg.enabled:
        return []
    now = iso(clock.now())
    if conn.execute("SELECT 1 FROM incident_forwarding").fetchone() is None:
        # First run ever. Without backfill, everything that already exists is history, not new incidents.
        with transaction(conn) as c:
            c.execute("INSERT INTO incident_forwarding (id, enabled_at) VALUES (1, ?)", (now,))
            n = 0 if icfg.backfill else c.execute(
                "INSERT OR IGNORE INTO incident_delivery (report_id, status, detail, handled_at) "
                "SELECT report_id, 'skipped', 'existed before forwarding was enabled', ? FROM report",
                (now,)).rowcount
        log.info("incident forwarding enabled; %d existing reports will not be sent", n)
        if n:
            return []

    rows = conn.execute(
        "SELECT r.report_id, r.body_json FROM report r LEFT JOIN incident_delivery d USING (report_id) "
        "WHERE d.report_id IS NULL ORDER BY r.report_id LIMIT ?", (icfg.batch_size,)).fetchall()
    sent: list[int] = []
    for r in rows:
        body = json.loads(r["body_json"])
        severity = body.get("matched_rule", {}).get("severity")
        if severity not in icfg.severities:
            _record(conn, "report", r["report_id"], "skipped", now, detail=f"severity {severity} is not forwarded")
            continue
        outcome = _deliver(conn, icfg, "report", r["report_id"], build_incident(r["report_id"], body), now, post)
        if outcome == "retry":
            break
        if outcome == "sent":
            sent.append(r["report_id"])
    return sent


def forward_pending_cluster_incidents(conn: sqlite3.Connection, cfg: Config, clock: Clock,
                                      post: Poster = http_post) -> list[int]:
    """Send finished clusters that have no report (medium) when their severity is forwarded."""
    icfg = cfg.incidents
    wanted = [s for s in icfg.severities if s not in ("high", "critical")]   # high/critical go as reports
    started = conn.execute("SELECT enabled_at FROM incident_forwarding").fetchone()
    if not icfg.enabled or not wanted or started is None:
        return []
    since = "" if icfg.backfill else started["enabled_at"]
    rows = conn.execute(
        f"SELECT c.* FROM cluster c LEFT JOIN incident_cluster_delivery d USING (cluster_id) "
        f"WHERE d.cluster_id IS NULL AND c.state = 'DONE' AND c.created_at >= ? "
        f"AND c.severity IN ({','.join('?' * len(wanted))}) ORDER BY c.cluster_id LIMIT ?",  # noqa: S608  # nosec B608 - placeholders only
        [since, *wanted, icfg.batch_size]).fetchall()
    now = iso(clock.now())
    sent: list[int] = []
    for cl in rows:
        outcome = _deliver(conn, icfg, "cluster", cl["cluster_id"], build_cluster_incident(conn, cl, cfg), now, post)
        if outcome == "retry":
            break
        if outcome == "sent":
            sent.append(cl["cluster_id"])
    return sent
