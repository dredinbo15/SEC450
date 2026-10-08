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
