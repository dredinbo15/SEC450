"""Incident reports for high and critical clusters (REQ-06, AC-15).

A report is generated once a cluster's triage has finished (successfully or
not), so it always carries either the AI assessment or an "unavailable" marker.
This step also moves finished clusters to their final state: high/critical
become REPORTED (in the same transaction as the report), medium become DONE.
"""
from __future__ import annotations

import json
import logging
import sqlite3

from . import hashchain
from .config import Config
from .db import transaction
from .timeutil import Clock, iso

log = logging.getLogger(__name__)

REPORT_VERSION = 1


def overlapping_gaps(conn: sqlite3.Connection, start: str, end: str) -> list[dict]:
    rows = conn.execute(
        'SELECT gap_id, source, start, "end", reason FROM gap '
        'WHERE start <= ? AND ("end" IS NULL OR "end" >= ?) ORDER BY start', (end, start)).fetchall()
    return [dict(r) for r in rows]


def build_report(conn: sqlite3.Connection, cluster: sqlite3.Row, cfg: Config) -> dict:
    rule = next((r for r in cfg.detection.rules if r.id == cluster["rule_id"]), None)
    events = conn.execute(
        "SELECT e.*, r.text AS raw_text, r.batch_id FROM event e "
        "JOIN cluster_event ce USING (event_id) JOIN raw_line r USING (raw_id) "
        "WHERE ce.cluster_id = ? ORDER BY e.ts, e.event_id", (cluster["cluster_id"],)).fetchall()

    def distinct(col: str) -> list:
        return sorted({e[col] for e in events if e[col] is not None})

    total_bytes = sum(e["bytes_sent"] for e in events)
    rule_name = rule.name if rule else cluster["rule_id"]
    if cluster["ai_received_at"] is not None:  # set only when Claude answered
        ai = {"status": "available", "label": "AI-generated, advisory only",
              "classification": cluster["ai_classification"],
              "recommended_severity": cluster["ai_recommended_severity"],
              "explanation": cluster["ai_explanation"], "model": cluster["ai_model"],
              "received_at": cluster["ai_received_at"]}
    else:
        ai = {"status": "unavailable", "label": "AI-generated, advisory only"}

    return {
        "report_version": REPORT_VERSION,
        "cluster_id": cluster["cluster_id"],
        "previous_cluster_id": cluster["prev_cluster_id"],
        "summary": (f"{rule_name} ({cluster['severity']}): {len(events)} events from "
                    f"{cluster['group_key']} between {cluster['window_start']} and {cluster['window_end']}; "
                    f"{total_bytes} bytes sent to the client."),
        "matched_rule": {
            "id": cluster["rule_id"], "name": rule_name, "severity": cluster["severity"],
            "threshold": rule.threshold if rule else None,
            "window_seconds": rule.window_seconds if rule else None,
        },
        "requester": {
            "client_ip": cluster["group_key"],
            "usernames": distinct("username"),
            "api_key_ids": distinct("api_key_id"),
            "asn": distinct("asn"),
            "country": distinct("country"),
        },
        "data_destination": {"client_ip": cluster["group_key"], "bytes_sent": total_bytes},
        "timeline": [
            {"ts": e["ts"], "source": e["source"], "host": e["host"], "action": e["action"],
             "target": e["target"], "outcome": e["outcome"], "status_code": e["status_code"],
             "bytes_sent": e["bytes_sent"], "clock_anomaly": bool(e["clock_anomaly"])}
            for e in events
        ],
        "ai_assessment": ai,
        "raw_lines": [{"raw_id": e["raw_id"], "batch_id": e["batch_id"], "source": e["source"],
                       "text": e["raw_text"]} for e in events],
        "integrity": hashchain.verify_batches(conn),
        "collection_gaps": overlapping_gaps(conn, cluster["window_start"], cluster["window_end"]),
    }


def generate_pending_reports(conn: sqlite3.Connection, cfg: Config, clock: Clock) -> list[int]:
    """Report every high/critical cluster whose triage finished; close finished medium ones."""
    with transaction(conn) as c:
        c.execute("UPDATE cluster SET state = 'DONE' WHERE severity = 'medium' "
                  "AND state IN ('TRIAGED', 'TRIAGE_UNAVAILABLE')")

    rows = conn.execute(
        "SELECT * FROM cluster WHERE severity IN ('high', 'critical') "
        "AND state IN ('TRIAGED', 'TRIAGE_UNAVAILABLE') ORDER BY cluster_id").fetchall()
    created = []
    for cluster in rows:
        body = build_report(conn, cluster, cfg)
        # Report row and state change commit together, so a crash never leaves a
        # REPORTED cluster without a report or a report for a cluster still waiting.
        with transaction(conn) as c:
            rid = c.execute(
                "INSERT INTO report (cluster_id, generated_at, body_json) VALUES (?, ?, ?)",
                (cluster["cluster_id"], iso(clock.now()), json.dumps(body, ensure_ascii=False))).lastrowid
            c.execute("UPDATE cluster SET state = 'REPORTED' WHERE cluster_id = ?", (cluster["cluster_id"],))
        created.append(rid)
        log.info("report %s generated for cluster %s", rid, cluster["cluster_id"])
    return created
