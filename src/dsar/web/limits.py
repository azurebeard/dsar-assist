"""Rate limiting. In-process, bounded, no dependency.

Three things need it, for three different reasons:

  `/auth/login`   an unauthenticated endpoint that allocates server state. Each
                  call puts a pending flow in a bounded store, so without a
                  limit an attacker can churn it and push out a real operator's
                  in-progress sign-in.

  the API         every call spends the operator's Graph token. A runaway
                  browser tab is indistinguishable from abuse at the tenant end,
                  and Purview throttles the *account*, not the process — so a
                  loop here degrades the operator's other tools too.

  statistics      polling is the one call the UI makes on a timer. The plan
                  specified a server-side floor precisely so a client bug
                  cannot become a tenant problem.

A fixed window rather than a token bucket: the failure mode of a fixed window
is that a caller can send 2N across a boundary, which for these limits is
harmless, and it is twenty lines instead of sixty.
"""

from __future__ import annotations

import threading
import time
from collections import deque

__all__ = ["RateLimiter", "LOGIN_LIMIT", "API_LIMIT", "POLL_FLOOR_SECONDS"]

#: Generous for a human, ruinous for a loop. Sign-in is a browser redirect an
#: operator performs a handful of times a day.
LOGIN_LIMIT = (10, 60.0)

#: The UI polls statistics and refreshes a list; a working session sits well
#: under this.
API_LIMIT = (120, 60.0)

#: Minimum seconds between statistics reads for the same search. The UI already
#: backs off 10s → 30s → 60s; this is the floor that holds when the UI is wrong.
POLL_FLOOR_SECONDS = 5.0

#: Distinct callers tracked. Bounded so the limiter cannot itself become the
#: memory-exhaustion vector it exists to prevent.
MAX_KEYS = 4096


class RateLimiter:
    """Fixed-window counter, keyed by caller. Thread-safe."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self._limit = limit
        self._window = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> float | None:
        """Return None when allowed, else the seconds to wait.

        Records the event when allowing, so a caller that ignores a 429 does not
        get a free pass by continuing to hammer.
        """
        now = time.monotonic()
        with self._lock:
            self._evict_locked(now)
            events = self._events.setdefault(key, deque())
            while events and now - events[0] > self._window:
                events.popleft()
            if len(events) >= self._limit:
                return max(0.0, self._window - (now - events[0]))
            events.append(now)
            return None

    def _evict_locked(self, now: float) -> None:
        if len(self._events) <= MAX_KEYS:
            return
        stale = [
            key
            for key, events in self._events.items()
            if not events or now - events[-1] > self._window
        ]
        for key in stale:
            del self._events[key]
        # Still over after dropping the stale ones: the limiter is being used as
        # an attack surface. Drop everything rather than grow without bound —
        # a brief loss of accounting is better than an unbounded dict.
        if len(self._events) > MAX_KEYS:
            self._events.clear()


class MinInterval:
    """Refuse a repeat for the same key inside a floor. Thread-safe."""

    def __init__(self, seconds: float) -> None:
        self._seconds = seconds
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> float | None:
        now = time.monotonic()
        with self._lock:
            if len(self._last) > MAX_KEYS:
                self._last.clear()
            previous = self._last.get(key)
            if previous is not None and now - previous < self._seconds:
                return self._seconds - (now - previous)
            self._last[key] = now
            return None
