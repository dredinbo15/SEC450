"""Advisory AI triage of redacted clusters with Claude (REQ-04, DD-01, DD-02, DD-09).

The rule-assigned severity is never changed; Claude's answer is stored in the
cluster's ai_* columns. Any failure after the configured retries marks the
cluster triage_unavailable and processing continues.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import timedelta
from typing import Literal, Protocol

import anthropic
from pydantic import BaseModel, ValidationError

from .config import SEVERITY_ORDER, Config, TriageConfig
from .db import transaction
from .redact import redact_event, sample
from .timeutil import Clock, iso, parse_iso

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are assisting a security analyst who reviews alerts from a log analysis system.
A deterministic detection rule has already flagged the cluster of events you will see
and assigned its severity. Your assessment is advisory: it is shown to the analyst
next to the rule's verdict and never replaces it.

The events come from web server, SSH and application logs. Credentials and tokens
have been replaced with [REDACTED]. Base your assessment only on the events given.

Return:
- classification: a short label for the likely activity (for example
  "credential brute force", "directory scan", "SQL injection attempt",
  "bulk data download", or "likely benign").
- recommended_severity: low, medium, high or critical, from your own reading of the events.
- explanation: at most 500 characters for the analyst, saying what the events show and
  why you chose that severity. Mention anything that suggests a false positive."""

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "classification": {"type": "string"},
        "recommended_severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "explanation": {"type": "string"},
    },
    "required": ["classification", "recommended_severity", "explanation"],
    "additionalProperties": False,
}


class TriageResult(BaseModel):
    classification: str
    recommended_severity: Literal["low", "medium", "high", "critical"]
    explanation: str


class TriageError(Exception):
    pass


class LLMClient(Protocol):
    model: str

    def assess(self, payload: dict) -> TriageResult:
        """One attempt. Raises TriageError on any failure."""


class ClaudeTriageClient:
    def __init__(self, cfg: TriageConfig):
        self.cfg = cfg
        self.model = cfg.model
        # Retries are counted by triage_cluster so every failure type gets the same budget.
        self.client = anthropic.Anthropic(api_key=cfg.resolved_api_key(),
                                          timeout=cfg.timeout_seconds, max_retries=0)

    def assess(self, payload: dict) -> TriageResult:
        request = dict(
            model=self.cfg.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(payload, ensure_ascii=False)}],
            output_config={"effort": self.cfg.effort,
                           "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}},
        )
        try:
            if self.cfg.server_fallbacks:
                response = self.client.beta.messages.create(
                    **request, betas=["server-side-fallback-2026-07-01"], fallbacks="default")
            else:
                response = self.client.messages.create(**request)
        except anthropic.APITimeoutError as exc:
            raise TriageError(f"timed out after {self.cfg.timeout_seconds}s") from exc
        except anthropic.APIConnectionError as exc:
            raise TriageError(f"connection error: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise TriageError(f"HTTP {exc.status_code}") from exc

        if response.stop_reason in ("refusal", "max_tokens"):
            raise TriageError(f"stop_reason={response.stop_reason}")
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise TriageError("no text block in response")
        try:
            result = TriageResult.model_validate_json(text)
        except ValidationError as exc:
            raise TriageError(f"invalid triage JSON: {exc.errors()[0]['msg']}") from exc
        self.model = response.model  # record the model that actually answered (fallbacks)
        return result


def build_payload(conn: sqlite3.Connection, cluster: sqlite3.Row, cfg: Config) -> dict:
    rule = next((r for r in cfg.detection.rules if r.id == cluster["rule_id"]), None)
    rows = conn.execute(
        "SELECT e.* FROM event e JOIN cluster_event ce USING (event_id) "
        "WHERE ce.cluster_id = ? ORDER BY e.ts, e.event_id", (cluster["cluster_id"],)).fetchall()
    events = [redact_event(dict(r)) for r in rows]
    return {
        "cluster": {
            "rule_id": cluster["rule_id"],
            "rule_name": rule.name if rule else None,
            "rule_severity": cluster["severity"],
            "window_start": cluster["window_start"],
            "window_end": cluster["window_end"],
            "event_count": len(events),
        },
        "events": sample(events, cfg.triage.max_events),
    }


def triage_cluster(conn: sqlite3.Connection, cluster: sqlite3.Row, cfg: Config,
                   client: LLMClient, clock: Clock) -> str:
    payload = build_payload(conn, cluster, cfg)
    attempts = cfg.triage.retries + 1
    for attempt in range(1, attempts + 1):
        try:
            result = client.assess(payload)
        except TriageError as exc:
            log.warning("triage of cluster %s failed (attempt %d/%d): %s",
                        cluster["cluster_id"], attempt, attempts, exc)
            continue
        with transaction(conn) as c:
            c.execute(
                "UPDATE cluster SET state = 'triaged', ai_classification = ?, ai_recommended_severity = ?, "
                "ai_explanation = ?, ai_model = ?, ai_received_at = ? WHERE cluster_id = ?",
                (result.classification[:200], result.recommended_severity, result.explanation[:500],
                 client.model, iso(clock.now()), cluster["cluster_id"]))
        return "triaged"
    with transaction(conn) as c:
        c.execute("UPDATE cluster SET state = 'triage_unavailable' WHERE cluster_id = ?",
                  (cluster["cluster_id"],))
    return "triage_unavailable"


def run_triage(conn: sqlite3.Connection, cfg: Config, clock: Clock, client: LLMClient | None) -> None:
    """Freeze settled clusters and triage those at medium severity or higher.

    Clusters left in 'triaging' by a crash are picked up again here.
    """
    now = clock.now()
    settle = timedelta(seconds=cfg.triage.settle_seconds)
    max_wait = timedelta(seconds=cfg.triage.max_wait_seconds)
    rows = conn.execute(
        "SELECT * FROM cluster WHERE state IN ('open', 'triaging') ORDER BY cluster_id").fetchall()
    for cluster in rows:
        if cluster["state"] == "open":
            settled = now - parse_iso(cluster["window_end"]) >= settle
            if not settled and now - parse_iso(cluster["created_at"]) < max_wait:
                continue
            if SEVERITY_ORDER[cluster["severity"]] < SEVERITY_ORDER["medium"]:
                with transaction(conn) as c:
                    c.execute("UPDATE cluster SET state = 'closed' WHERE cluster_id = ? AND state = 'open'",
                              (cluster["cluster_id"],))
                continue
            with transaction(conn) as c:
                frozen = c.execute("UPDATE cluster SET state = 'triaging' WHERE cluster_id = ? AND state = 'open'",
                                   (cluster["cluster_id"],)).rowcount
            if not frozen:
                continue
            cluster = conn.execute("SELECT * FROM cluster WHERE cluster_id = ?",
                                   (cluster["cluster_id"],)).fetchone()
        if not cfg.triage.enabled or client is None:
            with transaction(conn) as c:
                c.execute("UPDATE cluster SET state = 'triage_unavailable' WHERE cluster_id = ?",
                          (cluster["cluster_id"],))
            continue
        triage_cluster(conn, cluster, cfg, client, clock)
