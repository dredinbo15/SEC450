"""Decides what needs a human look, from API responses only.

The system detects and reports but never acts (DD-14), and the AI only
advises (DD-01), so a person has to confirm anything serious, anything the
AI could not assess, and anything where the AI and the rule disagree.
"""
from __future__ import annotations

from ..config import SEVERITY_ORDER


def cluster_review_reasons(cluster: dict) -> list[str]:
    """Reasons a cluster (one /v1/clusters item) needs human review; empty if none."""
    reasons = []
    severity = cluster["severity"]
    if SEVERITY_ORDER[severity] >= SEVERITY_ORDER["high"]:
        reasons.append(f"{severity} severity: confirm and decide on a response")
    if cluster["state"].upper() == "TRIAGE_UNAVAILABLE":   # the API returns the stored state, upper case
        reasons.append("AI triage unavailable: no advisory assessment")
    ai = cluster.get("ai_assessment")
    if ai and ai.get("recommended_severity") in SEVERITY_ORDER:
        recommended = ai["recommended_severity"]
        if SEVERITY_ORDER[recommended] > SEVERITY_ORDER[severity]:
            reasons.append(f"AI rates it higher ({recommended}) than the rule ({severity})")
        elif SEVERITY_ORDER[recommended] < SEVERITY_ORDER[severity]:
            reasons.append(f"AI rates it lower ({recommended}) than the rule ({severity}): possible false alarm")
    return reasons


def system_alerts(integrity: dict, gaps: list[dict], events: list[dict]) -> list[str]:
    """Conditions that undermine trust in the data itself."""
    alerts = []
    batches = integrity.get("batches", {})
    if batches.get("status") == "broken":
        alerts.append(f"Log batch hash chain broken at batch {batches.get('batch_id')}: {batches.get('reason')}")
    audit = integrity.get("audit", {})
    if audit.get("status") == "broken":
        alerts.append(f"Audit log hash chain broken at entry {audit.get('entry_id')}")
    for g in gaps:
        if g["end"] is None:          # closed gaps are history, listed by past_gaps()
            alerts.append(f"Collection gap on {g['source']} since {g['start']}: {g['reason']}")
    anomalies = sum(1 for e in events if e.get("clock_anomaly"))
    if anomalies:
        alerts.append(f"{anomalies} event(s) have timestamps ahead of the collector clock")
    return alerts


def past_gaps(gaps: list[dict]) -> list[str]:
    """Closed collection gaps in the window: data from these spans is missing, but collection has recovered."""
    return [f"{g['source']} was unreadable from {g['start']} to {g['end']}: {g['reason']}"
            for g in gaps if g["end"] is not None]
