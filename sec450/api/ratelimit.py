"""Per-key sliding-window rate limit (REQ-09, AC-25)."""
from __future__ import annotations

import math
import threading
from collections import defaultdict, deque

from ..timeutil import Clock

WINDOW_SECONDS = 60.0


class RateLimiter:
    def __init__(self, limit: int, clock: Clock):
        self.limit = limit
        self.clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key_id: str) -> int | None:
        """Record an accepted request and return None, or return Retry-After seconds.

        Rejected requests are not counted, so a client that backs off recovers
        exactly one window after its oldest accepted request.
        """
        now = self.clock.now().timestamp()
        with self._lock:
            hits = self._hits[key_id]
            while hits and now - hits[0] >= WINDOW_SECONDS:
                hits.popleft()
            if len(hits) >= self.limit:
                return max(1, math.ceil(hits[0] + WINDOW_SECONDS - now))
            hits.append(now)
            return None


class RefusedRequests:
    """Counts requests the unauthenticated rate limit refused, per client address.

    Writing an audit entry for each one would let a flood of keyless requests queue writes on
    the database the collector shares, so the audit log gets one summary entry per address:
    at the first refusal, then at most once per window, each counting the refusals since the last.
    """

    MAX_TRACKED = 10_000

    def __init__(self, clock: Clock):
        self.clock = clock
        self._pending: dict[str, tuple[int, float]] = {}   # address -> (refused since last entry, last entry)
        self._lock = threading.Lock()

    def add(self, address: str) -> int | None:
        """Count one refusal; returns the count to write to the audit log now, or None."""
        now = self.clock.now().timestamp()
        with self._lock:
            count, last = self._pending.get(address, (0, -math.inf))
            count += 1
            if now - last >= WINDOW_SECONDS:
                if len(self._pending) >= self.MAX_TRACKED:
                    self._pending = {a: v for a, v in self._pending.items() if now - v[1] < WINDOW_SECONDS}
                self._pending[address] = (0, now)
                return count
            self._pending[address] = (count, last)
            return None
