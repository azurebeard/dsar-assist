"""Response hardening and the same-origin rule.

Ported from the predecessor's `ui/server.py`, which got this right and whose
reasoning is worth keeping in full:

Browsers do not send `Origin` on a same-origin `GET`. Applying "reject absent
Origin" to every request would reject the page load itself. So the rule is
applied to the API surface — which is where state changes and data live — and
the client issues every API call as a `POST`, which browsers *do* accompany
with `Origin` even same-origin. The result is the rule enforced as written on
every request that matters, rather than relaxed to "reject only a mismatch".

Static assets are served without the Origin check but are inert: HTML, CSS, JS
and one JSON file, no parameters, no state.
"""

from __future__ import annotations

import logging
import time
from typing import Any, MutableMapping

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

__all__ = [
    "SecurityHeadersMiddleware",
    "RequestLogMiddleware",
    "route_template",
    "origin_ok",
    "CSP",
    "SECURITY_HEADERS",
    "ALLOWED_STATIC",
]

log = logging.getLogger("dsar.request")

CSP = "; ".join(
    [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "font-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ]
)

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    # Added now rather than retrofitted after the auth flow exists (WS10
    # SEC-L-03). COOP severs the window reference between this document and
    # anything that opened it, which matters specifically because Phase 1
    # introduces a browser redirect to an identity provider and back.
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    # No feature this application uses appears here, so every one is denied.
    "Permissions-Policy": ", ".join(
        [
            "accelerometer=()",
            "camera=()",
            "geolocation=()",
            "gyroscope=()",
            "magnetometer=()",
            "microphone=()",
            "payment=()",
            "usb=()",
        ]
    ),
}

#: HSTS is hosted-only. Sending it over `http://localhost` would pin the
#: browser to HTTPS for localhost, which breaks every other local tool the
#: operator runs on that host — a genuinely unpleasant thing to do to someone.
HSTS_HEADER = ("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

#: An allowlist rather than a directory mount, so a file dropped into `static/`
#: is not served until someone names it here.
ALLOWED_STATIC: dict[str, str] = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/style.css": "style.css",
}


class SecurityHeadersMiddleware:
    """Attach the header set to every response, including error responses."""

    def __init__(self, app: ASGIApp, *, hosted: bool = False) -> None:
        self.app = app
        self.hosted = hosted

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                for name, value in SECURITY_HEADERS.items():
                    headers.append((name.encode("latin-1"), value.encode("latin-1")))
                if self.hosted:
                    name, value = HSTS_HEADER
                    headers.append((name.encode("latin-1"), value.encode("latin-1")))
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestLogMiddleware:
    """Log every request by *route template*, never by concrete path.

    Disabling access logging outright — the first shape of this, and what
    uvicorn's own logger is still turned off for — trades an OWASP A09 control
    for a privacy concern that has a better answer. Concrete paths carry case
    and search identifiers; the matched route template does not. Logging the
    template gives auth failures, 401s and 403s an observable record without
    creating a second, ungoverned copy of the identifiers the audit trail
    deliberately pseudonymises.

    A request that matches no route is logged as `<unmatched>` rather than
    with its path, so a scanner probing for `/admin` or `/.env` cannot write
    attacker-chosen strings into the log.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status = 0

        async def send_observing(message: MutableMapping[str, Any]) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, send_observing)
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            log.info(
                "%s %s -> %s in %.1fms",
                scope.get("method", "?"),
                route_template(scope),
                status or "no response",
                elapsed_ms,
            )


def route_template(scope: Scope) -> str:
    """The matched route with its parameter values substituted back out.

    Starlette does not put the route object in the scope, and the version that
    does is not something to depend on. Deriving the template from `path` and
    `path_params` is version-independent and makes the redaction explicit and
    testable: every captured value is replaced by its parameter name, so
    `/cases/01f85886-.../searches/9c2a` becomes
    `/cases/{case_id}/searches/{search_id}`.

    Over-replacement is possible if a parameter value also appears in a static
    segment. That is harmless — over-redaction never leaks.
    """
    if scope.get("endpoint") is None:
        # Nothing matched. Log a constant rather than the path, so a scanner
        # probing for `/.env` cannot write attacker-chosen strings into a log
        # that a human will later read.
        return "<unmatched>"

    path = str(scope.get("path", ""))
    params = scope.get("path_params") or {}
    for name, value in params.items():
        text = str(value)
        if text:
            path = path.replace(text, "{" + name + "}")
    return path or "/"


def origin_ok(request: Request, expected_origin: str) -> bool:
    """True when the request's `Origin` matches ours exactly.

    Absent counts as a mismatch. Applied to the API surface only, where every
    call is a POST and every browser therefore sends the header.
    """
    origin = request.headers.get("origin")
    return bool(origin) and origin == expected_origin


def build_response_headers(hosted: bool) -> dict[str, str]:
    """The header set, for handlers that construct a `Response` directly."""
    headers = dict(SECURITY_HEADERS)
    if hosted:
        headers[HSTS_HEADER[0]] = HSTS_HEADER[1]
    return headers


def harden(response: Response, hosted: bool = False) -> Response:
    response.headers.update(build_response_headers(hosted))
    return response
