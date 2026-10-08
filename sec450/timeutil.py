"""UTC timestamp handling and the injectable clock used as a test hook."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

UTC = timezone.utc


class Clock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock(Clock):
    """Manually advanced clock for tests."""

    def __init__(self, start: datetime):
        self._now = start.astimezone(UTC)

    def now(self) -> datetime:
        return self._now

    def set(self, value: datetime) -> None:
        self._now = value.astimezone(UTC)

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


def to_utc(dt: datetime, tz_name: str) -> datetime:
    """Attach the source's zone to a naive timestamp, then convert to UTC.

    Ambiguous wall times (the DST fall-back hour) resolve to the first
    occurrence (fold=0) instead of raising.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo(tz_name))
    return dt.astimezone(UTC)


def iso(dt: datetime) -> str:
    """Fixed-width UTC ISO 8601 so string order equals time order in SQLite."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"timestamp {value!r} has no UTC offset")
    return dt.astimezone(UTC)
