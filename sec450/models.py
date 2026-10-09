"""Common event schema shared by every parser (REQ-01, REQ-02)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

Outcome = Literal["success", "failure", "unknown"]

# Actions counted by the failed-login rule (R1).
LOGIN_ACTIONS = ("ssh_login", "login")

# Cluster lifecycle. Each state is stored as this exact text in cluster.state.
#
#   FLAGGED --(low)--------> DONE
#      |
#      +--(medium+)--> TRIAGE_PENDING --> TRIAGED or TRIAGE_UNAVAILABLE
#                                           |--(medium)----> DONE
#                                           +--(high+)-----> REPORTED
#
# A FLAGGED cluster still takes new matching events; once it leaves FLAGGED it
# is frozen and later matches start a new cluster linked by prev_cluster_id (DD-09).
# Whether triage succeeded is kept after DONE/REPORTED: ai_received_at is set
# only when Claude answered.
CLUSTER_STATES = ("FLAGGED", "TRIAGE_PENDING", "TRIAGED", "TRIAGE_UNAVAILABLE", "DONE", "REPORTED")


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
