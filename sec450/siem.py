"""Push reports to a SIEM such as Wazuh (DD-17).

Each report goes out as one compact JSON line over TCP syslog. A report is
marked delivered only after the whole batch has been sent, so a SIEM outage
delays alerts instead of losing them: undelivered reports go out on a later
cycle (at-least-once delivery). The full report stays behind the API; the
alert carries the fields an analyst triages on plus a link back to it.
"""
from __future__ import annotations

import json
import logging
import socket
import sqlite3
from collections.abc import Callable

from .config import Config, SiemConfig
from .db import transaction
from .timeutil import Clock, iso

log = logging.getLogger(__name__)

Sender = Callable[[SiemConfig, list[bytes]], None]


def build_alert(report_id: int, generated_at: str, body: dict, cfg: SiemConfig) -> dict:
    """The SIEM's view of a report; every field sits under "sec450" except srcip."""
    timeline = body.get("timeline", [])
    requester = body.get("requester", {})
    ai = body.get("ai_assessment", {})
    rule = body.get("matched_rule", {})
    return {
        "srcip": requester.get("client_ip"),   # Wazuh's static field; enables its GeoIP enrichment
        "sec450": {
            "report_id": report_id,
            "cluster_id": body.get("cluster_id"),
            "previous_cluster_id": body.get("previous_cluster_id"),
            "generated_at": generated_at,
            "severity": rule.get("severity"),
            "summary": body.get("summary"),
            "rule": {"id": rule.get("id"), "name": rule.get("name")},
            "client_ip": requester.get("client_ip"),
            "usernames": requester.get("usernames", []),
            "country": requester.get("country", []),
            "asn": requester.get("asn", []),
            "event_count": len(timeline),
            "window_start": timeline[0]["ts"] if timeline else None,
            "window_end": timeline[-1]["ts"] if timeline else None,
            "bytes_sent": body.get("data_destination", {}).get("bytes_sent", 0),
            "ai": {"status": ai.get("status"), "reason": ai.get("reason"), "classification": ai.get("classification"),
                   "recommended_severity": ai.get("recommended_severity"), "model": ai.get("model")},
            "integrity": body.get("integrity", {}).get("status"),
            "collection_gaps": len(body.get("collection_gaps", [])),
            "report_url": f"{cfg.report_url}{report_id}" if cfg.report_url else None,
        },
    }


def tcp_syslog_send(cfg: SiemConfig, lines: list[bytes]) -> None:
    """One connection per batch, newline-framed (what Wazuh's TCP syslog input expects)."""
    with socket.create_connection((cfg.host, cfg.port), timeout=cfg.timeout_seconds) as sock:
        sock.sendall(b"".join(line + b"\n" for line in lines))


def forward_pending_reports(conn: sqlite3.Connection, cfg: Config, clock: Clock,
                            send: Sender = tcp_syslog_send) -> list[int]:
    """Send reports the SIEM has not received yet; returns the ids delivered this cycle."""
    if not cfg.siem.enabled:
        return []
    rows = conn.execute(
        "SELECT r.report_id, r.generated_at, r.body_json FROM report r "
        "LEFT JOIN siem_delivery d USING (report_id) WHERE d.report_id IS NULL "
        "ORDER BY r.report_id LIMIT ?", (cfg.siem.batch_size,)).fetchall()
    if not rows:
        return []
    lines = [json.dumps(build_alert(r["report_id"], r["generated_at"], json.loads(r["body_json"]), cfg.siem),
                        ensure_ascii=False, separators=(",", ":")).encode()
             for r in rows]
    try:
        send(cfg.siem, lines)
    except OSError as exc:
        log.warning("SIEM unreachable, %d reports will be retried: %s", len(rows), exc)
        return []
    ids = [r["report_id"] for r in rows]
    now = iso(clock.now())
    with transaction(conn) as c:
        c.executemany("INSERT OR IGNORE INTO siem_delivery (report_id, delivered_at) VALUES (?, ?)",
                      [(i, now) for i in ids])
    log.info("forwarded %d reports to the SIEM", len(ids), extra={"report_id": ids[-1]})
    return ids
