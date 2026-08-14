"""Server-side sessions and the pending-flow cache. No database.

Two stores, both in-process, both bounded, neither ever written to disk.

`FlowStore` holds the dict `initiate_auth_code_flow` returns — it carries the
PKCE verifier, the state and the nonce. Keeping it server-side, single-use and
short-lived is the real CSRF and session-fixation control on a shared instance;
`state` alone is not enough, because a `state` the attacker chose is a `state`
that matches.

`SessionStore` holds the MSAL token cache and the principal. The cookie carries
an opaque identifier and nothing else — never a token, never a JWT.

Both are in-process, which is why the hosted deployment pins to a single
replica. That is a real constraint and it is documented rather than hidden: a
revision update signs everyone out. For a handful of compliance operators
against an engine that is asynchronous anyway, it buys correctness that a
distributed session store would have to work to match.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import msal

from dsar.auth.provider import Principal

__all__ = [
    "Session",
    "SessionStore",
    "FlowStore",
    "FlowStoreFull",
    "SESSION_COOKIE",
    "FLOW_COOKIE",
]

#: `__Host-` is the strongest cookie prefix: it requires Secure, forbids Domain
#: and pins Path=/, so a subdomain cannot set or overwrite it. It is applied in
#: hosted mode. On desktop the origin is `http://localhost`, where Secure
#: cookies are a browser-dependent secure-context exception, so the prefix is
#: dropped and the deviation is documented rather than assumed to work.
SESSION_COOKIE_HOSTED = "__Host-dsar_session"
SESSION_COOKIE_DESKTOP = "dsar_session"
FLOW_COOKIE_HOSTED = "__Host-dsar_flow"
FLOW_COOKIE_DESKTOP = "dsar_flow"

SESSION_COOKIE = SESSION_COOKIE_HOSTED
FLOW_COOKIE = FLOW_COOKIE_HOSTED

#: 256 bits. Guessing is not the threat, but there is no reason to be cheap.
_ID_BYTES = 32

#: Inside CA04's 4-hour sign-in frequency plus slack, so Conditional Access
#: rather than this constant is what governs session lifetime.
ABSOLUTE_TTL_SECONDS = 8 * 60 * 60
IDLE_TTL_SECONDS = 60 * 60

#: A pending flow that is not completed in five minutes is abandoned, not
#: waiting. Long-lived pending flows are what session fixation feeds on.
FLOW_TTL_SECONDS = 5 * 60

#: Small on purpose. This is a tool for a handful of operators; an unbounded
#: dict keyed by anything a caller can cause to be created is a memory
#: exhaustion vector, and a cap makes that a refusal instead.
MAX_SESSIONS = 64
MAX_PENDING_FLOWS = 64


def new_id() -> str:
    return secrets.token_urlsafe(_ID_BYTES)


class FlowStoreFull(RuntimeError):
    """Too many sign-ins are in progress to accept another."""


@dataclass
class Session:
    id: str
    principal: Principal
    #: Never serialised. `msal.TokenCache` has no `serialize`, unlike
    #: `SerializableTokenCache` — which a structural test bans outright, so the
    #: in-memory property cannot be quietly downgraded later.
    cache: msal.TokenCache = field(default_factory=msal.TokenCache)
    created_at: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    #: Per-session Graph reader, built lazily on first API call. Declared here
    #: rather than attached with setattr so it is visible in the type, and
    #: typed `Any` to avoid importing the cases package into the auth package —
    #: a session should not know what the application does with it.
    #:
    #: Per-session, not global: its read cache holds one operator's cases, and
    #: sharing that between people is how a shared instance leaks a list.
    case_service: Any = None

    def expired(self, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        return (
            current - self.created_at > ABSOLUTE_TTL_SECONDS
            or current - self.last_seen > IDLE_TTL_SECONDS
        )


class SessionStore:
    """Bounded, in-process, LRU-evicting. Thread-safe."""

    def __init__(self, max_sessions: int = MAX_SESSIONS) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._max = max_sessions

    def create(self, principal: Principal, cache: msal.TokenCache) -> Session:
        session = Session(id=new_id(), principal=principal, cache=cache)
        with self._lock:
            self._evict_locked()
            if len(self._sessions) >= self._max:
                oldest = min(self._sessions.values(), key=lambda s: s.last_seen)
                del self._sessions[oldest.id]
            self._sessions[session.id] = session
        return session

    def get(self, session_id: str | None) -> Session | None:
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.expired():
                del self._sessions[session_id]
                return None
            session.last_seen = time.monotonic()
            return session

    def remove(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            self._sessions.pop(session_id, None)

    def _evict_locked(self) -> None:
        for key in [k for k, s in self._sessions.items() if s.expired()]:
            del self._sessions[key]

    def __len__(self) -> int:
        with self._lock:
            self._evict_locked()
            return len(self._sessions)


class FlowStore:
    """Pending authorization-code flows. Single-use, TTL-bounded, in-process."""

    def __init__(self, max_pending: int = MAX_PENDING_FLOWS) -> None:
        self._flows: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._max = max_pending

    def put(self, flow: dict[str, Any]) -> str:
        """Store a pending flow. Raises `FlowStoreFull` rather than evicting.

        The first version evicted the oldest entry to make room, which meant an
        unauthenticated caller hitting `/auth/login` repeatedly could push a
        real operator's in-progress sign-in out of the store — their callback
        then returned "sign-in expired" for no reason they could see.

        Refusing is the better failure: it is visible, it affects the caller
        causing it rather than a bystander, and combined with the five-minute
        TTL the store drains on its own. The rate limiter in `web/limits.py` is
        what stops it filling in the first place; this is the backstop for when
        that is misconfigured.
        """
        with self._lock:
            self._evict_locked()
            if len(self._flows) >= self._max:
                raise FlowStoreFull(
                    f"{self._max} sign-ins already in progress; try again shortly"
                )
            key = new_id()
            self._flows[key] = (time.monotonic(), flow)
        return key

    def take(self, key: str | None) -> dict[str, Any] | None:
        """Retrieve and **remove**. A flow may be redeemed exactly once.

        Single use is the point: replaying a callback against a still-valid
        pending flow is how an attacker turns an intercepted code into a
        session.
        """
        if not key:
            return None
        with self._lock:
            self._evict_locked()
            entry = self._flows.pop(key, None)
        return entry[1] if entry else None

    def _evict_locked(self) -> None:
        now = time.monotonic()
        for key in [k for k, (t, _) in self._flows.items() if now - t > FLOW_TTL_SECONDS]:
            del self._flows[key]

    def __len__(self) -> int:
        with self._lock:
            self._evict_locked()
            return len(self._flows)


def cookie_names(hosted: bool) -> tuple[str, str]:
    """(session cookie, flow cookie) for the mode.

    See the note on `__Host-` above: the prefix requires `Secure`, and `Secure`
    over `http://localhost` is a browser-dependent secure-context exception
    rather than a guarantee. Desktop therefore uses plain host-only cookies.
    """
    if hosted:
        return SESSION_COOKIE_HOSTED, FLOW_COOKIE_HOSTED
    return SESSION_COOKIE_DESKTOP, FLOW_COOKIE_DESKTOP
