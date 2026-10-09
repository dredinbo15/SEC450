"""Structured JSON logs to stdout, one object per line (`docker compose logs` friendly).

Add context to a log call with `extra`, for example:

    log.info("report generated", extra={"cluster_id": 7, "report_id": 3})

Only the fields in CONTEXT_FIELDS are copied into the JSON. Never pass API
keys, passwords or raw request headers: logs are not access-controlled.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime

from .timeutil import UTC, iso

CONTEXT_FIELDS = ("batch_id", "cluster_id", "report_id", "request_id", "source", "key_id",
                  "status_code", "path", "duration_ms")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": iso(datetime.fromtimestamp(record.created, UTC)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for field in CONTEXT_FIELDS:
            if hasattr(record, field):
                entry[field] = getattr(record, field)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_logging(level: str = "INFO") -> None:
    """Send every logger (ours, uvicorn's, the SDK's) through one JSON handler on stdout."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
