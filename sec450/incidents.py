"""Post high and critical reports to an external incident-management API (DD-18).

The API takes exactly {title, log, occurredAt, source} and rejects extra fields,
so each report is mapped into that shape:

  title       the report summary, cut to 200 characters
  log         the report's raw log lines, one per line, unmodified
  occurredAt  the first event's time (UTC)
  source      "sec450 <rule id> report <report id>", to trace the incident back

Each report is handled once. A 2xx response records the returned incident id; a
4xx means the API refused that report and it is recorded as 'rejected' (sending it
again would fail the same way). A network error, timeout or 5xx stops the cycle,
and the report is retried on a later one, so an outage delays incidents instead of
losing them.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable

import httpx

from .config import Config, IncidentsConfig
from .db import transaction
from .timeutil import Clock, iso

log = logging.getLogger(__name__)

Poster = Callable[[IncidentsConfig, dict], httpx.Response]


def build_incident(report_id: int, body: dict) -> dict:
    rule = body.get("matched_rule", {})
    timeline = body.get("timeline", [])
    return {
        "title": (body.get("summary") or f"SEC450 report {report_id}")[:200],
        "log": "\n".join(line["text"] for line in body.get("raw_lines", [])) or body.get("summary", ""),
        "occurredAt": timeline[0]["ts"] if timeline else body.get("generated_at"),
        "source": f"sec450 {rule.get('id', '?')} report {report_id}"[:100],
    }


def http_post(cfg: IncidentsConfig, incident: dict) -> httpx.Response:
    return httpx.post(cfg.url, json=incident, timeout=cfg.timeout_seconds)


def _record(conn: sqlite3.Connection, report_id: int, status: str, now: str,
            incident_id: str | None = None, detail: str | None = None) -> None:
    with transaction(conn) as c:
        c.execute("INSERT OR REPLACE INTO incident_delivery (report_id, status, incident_id, detail, handled_at) "
                  "VALUES (?, ?, ?, ?, ?)", (report_id, status, incident_id, detail, now))


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
            _record(conn, r["report_id"], "skipped", now, detail=f"severity {severity} is not forwarded")
            continue
        try:
            resp = post(icfg, build_incident(r["report_id"], body))
        except httpx.HTTPError as exc:
            log.warning("incident API unreachable, will retry: %s", exc, extra={"report_id": r["report_id"]})
            break
        if resp.status_code >= 500:
            log.warning("incident API returned %d, will retry", resp.status_code, extra={"report_id": r["report_id"]})
            break
        if resp.status_code >= 400:
            _record(conn, r["report_id"], "rejected", now, detail=f"HTTP {resp.status_code}: {resp.text[:500]}")
            log.error("incident API rejected report: HTTP %d", resp.status_code, extra={"report_id": r["report_id"]})
            continue
        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        incident_id = None
        if isinstance(payload, dict):    # the spec doesn't name the id field; accept the usual spellings
            incident_id = payload.get("incidentId") or payload.get("incident_id") or payload.get("id")
        _record(conn, r["report_id"], "sent", now, incident_id=str(incident_id) if incident_id else None)
        log.info("report sent to the incident API as %s", incident_id, extra={"report_id": r["report_id"]})
        sent.append(r["report_id"])
    return sent
