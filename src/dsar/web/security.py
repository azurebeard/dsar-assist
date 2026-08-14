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

from typing import Any, MutableMapping

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

__all__ = [
    "SecurityHeadersMiddleware",
    "origin_ok",
    "CSP",
    "SECURITY_HEADERS",
    "ALLOWED_STATIC",
]

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
