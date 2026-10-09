"""Mock LLM: a stand-in for Claude used by tests and local runs (test hook).

Select it at runtime with `triage.client: mock` in config.yaml; no API key is
needed and nothing leaves the machine. Tests construct it directly and pick a
mode to exercise the failure paths of REQ-04 / AC-11:

    ok             fixed, valid assessment
    timeout        the call times out (raised immediately; no real 30 s wait)
    http_error     the API returns HTTP 500
    bad_json       the model returns text that is not JSON
    missing_field  valid JSON without the required "explanation" field

Each assess() call is one attempt; the retry loop in triage.py is what is
being tested. Payloads are kept so tests can check redaction (AC-09).
"""
from __future__ import annotations

import json
from typing import Literal

from .triage import TriageError, TriageResult, parse_triage_text

MockMode = Literal["ok", "timeout", "http_error", "bad_json", "missing_field"]


class MockLLMClient:
    model = "mock-llm"

    def __init__(self, mode: MockMode = "ok", recommended_severity: str = "critical"):
        self.mode = mode
        # Defaults to "critical" on purpose: rules assign high, so tests and demos can
        # see the AI's opinion stored next to, never instead of, the rule severity (DD-01).
        self.recommended_severity = recommended_severity
        self.calls = 0
        self.payloads: list[dict] = []

    def assess(self, payload: dict) -> TriageResult:
        self.calls += 1
        self.payloads.append(payload)
        if self.mode == "timeout":
            raise TriageError("timed out after 30s (mock)")
        if self.mode == "http_error":
            raise TriageError("HTTP 500 (mock)")
        if self.mode == "bad_json":
            text = "Sorry, I cannot answer in JSON today."
        else:
            answer = {
                "classification": "credential brute force (mock)",
                "recommended_severity": self.recommended_severity,
                "explanation": f"Mock assessment of {payload['cluster']['event_count']} events. "
                               "Generated locally by the mock LLM; not a real AI opinion.",
            }
            if self.mode == "missing_field":
                del answer["explanation"]
            text = json.dumps(answer)
        return parse_triage_text(text)
