"""Removes credentials before anything leaves the system (REQ-04, DD-02, AC-09)."""
from __future__ import annotations

import re
from typing import Any

MASK = "[REDACTED]"

# Event fields allowed in an LLM payload. Raw lines, API key ids and anything
# not listed here are never sent.
ALLOWED_FIELDS = ("ts", "source", "client_ip", "username", "action", "target", "outcome",
                  "status_code", "bytes_sent", "asn", "country", "clock_anomaly")

SECRET_NAMES = (r"pass(?:word|wd)?|pwd|secret|token|access_token|refresh_token|id_token|"
                r"api[_-]?key|apikey|key|auth|authorization|session(?:id)?|sid|cookie|jwt|signature|sig")

PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Authorization / Cookie headers that ended up in a target or message
    (re.compile(r"(?i)\b(authorization|proxy-authorization)\s*[:=]\s*\S+(?:\s+\S+)?"), r"\1: " + MASK),
    (re.compile(r"(?i)\b(set-cookie|cookie)\s*[:=]\s*[^\r\n]+"), r"\1: " + MASK),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]+"), r"\1 " + MASK),
    # name=value pairs in query strings, form bodies and JSON-ish text
    (re.compile(rf"(?i)([?&;,\s\"']|^)({SECRET_NAMES})(\"?\s*[=:]\s*\"?)[^&;,\s\"']+"), r"\1\2\3" + MASK),
    # credentials embedded in URLs: scheme://user:pass@host
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:)[^@/\s]+@"), r"\1" + MASK + "@"),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), MASK),
    # Any long opaque token (API keys, session ids): 32+ characters
    (re.compile(r"[A-Za-z0-9_\-]{32,}"), MASK),
]


def redact_text(text: str) -> str:
    for pattern, repl in PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact_event(event: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ALLOWED_FIELDS:
        value = event.get(key)
        out[key] = redact_text(value) if isinstance(value, str) and key not in ("ts", "client_ip") else value
    return out


def sample(events: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Keep the first and last events when a cluster is larger than the payload limit."""
    if len(events) <= limit:
        return events
    head = limit // 2
    return events[:head] + events[-(limit - head):]
