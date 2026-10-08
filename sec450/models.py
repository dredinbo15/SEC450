"""Common event schema shared by every parser (REQ-01, REQ-02)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

Outcome = Literal["success", "failure", "unknown"]

# Actions counted by the failed-login rule (R1).
LOGIN_ACTIONS = ("ssh_login", "login")


@dataclass
class ParsedEvent:
    ts: datetime                      # UTC
    action: str
    target: str
    outcome: Outcome
    client_ip: str | None = None      # requester, after forwarded-IP trust is applied
    username: str | None = None
    api_key_id: str | None = None
    status_code: int | None = None
    bytes_sent: int = 0               # data destination is client_ip + bytes_sent
    extra: dict = field(default_factory=dict)


class ParseError(ValueError):
    """Raised when a line cannot be parsed; the message becomes the quarantine reason."""
