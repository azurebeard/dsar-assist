"""The ASGI application and the `up` command behind it.

One server, two modes. The bind address is `0.0.0.0` and that is deliberate:
Docker publishes to the container's own interface, so a process that binds
loopback inside a container is unreachable from the host. The predecessor's
guarantee — a `127.0.0.1` literal in the source, checked by a test — cannot
survive containerisation, so it moved rather than being quietly dropped:

  desktop  the launcher's `-p 127.0.0.1:8765:8765` publishes to host loopback
           only, and a test asserts that flag is present in both launchers
  hosted   Container Apps ingress with `allowInsecure: false` plus
           `ipSecurityRestrictions`, asserted by the IaC tests

Both are testable. Neither is this line.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any
import webbrowser
from pathlib import Path

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from dsar import __version__
from dsar.config import Config, ConfigError, load_config
from dsar.auth.desktop import DesktopTokenProvider
from dsar.auth.msal_client import build_public_client
from dsar.auth.session import Session
from dsar.cases.service import CaseService
from dsar.graph.client import GraphClient
from dsar.graph.operations import GraphOperations
from dsar.web.api import handle
from dsar.web.auth_routes import AuthState, callback, current_principal, login, logout
from dsar.web.security import (
    ALLOWED_STATIC,
    RequestLogMiddleware,
    SecurityHeadersMiddleware,
    origin_ok,
)

__all__ = ["build_app", "serve", "BIND_HOST", "STATIC_DIR"]

log = logging.getLogger(__name__)

#: See the module docstring. Not a configuration option — there is no parameter
#: and no environment variable that changes it, because the control it used to
#: represent now lives in the launcher and the ingress.
BIND_HOST = "0.0.0.0"  # noqa: S104 — see module docstring

STATIC_DIR = Path(__file__).resolve().parent / "static"


async def healthz(request: Request) -> Response:
    """Liveness. Deliberately says nothing about identity or tenant.

    A health endpoint is the one route reachable without a session, so it must
    not become an unauthenticated disclosure of which tenant this instance
    serves.

    The version is withheld in hosted mode, where this endpoint is reachable
    from the internet and a version string is a free assist to CVE matching
    (WS10 SEC-L-01). On a desktop instance it is useful and the exposure is
    host loopback, so it stays.
    """
    config: Config = request.app.state.config
    body = {"status": "ok"}
    if not config.mode.is_hosted:
        body["version"] = __version__
    return JSONResponse(body)


async def static(request: Request) -> Response:
    name = ALLOWED_STATIC.get(request.url.path)
    if name is None:
        return PlainTextResponse("not found", status_code=404)
    path = STATIC_DIR / name
    if not path.is_file():
        # A packaging failure, not a routing one: the allowlist names a file
        # the installed package does not carry. Says so, because "404" would
        # send someone hunting through routes instead of the wheel.
        log.error("static asset %s is named in the allowlist but missing", name)
        return PlainTextResponse("asset missing from package", status_code=500)
    return FileResponse(path)


async def whoami(request: Request) -> Response:
    """Who is signed in, for the UI. 401 when nobody is.

    Returns `oid` and display name only — never a token, never a raw claim
    blob, and nothing about the tenant that a signed-out caller could read.
    """
    principal = current_principal(request)
    if principal is None:
        return JSONResponse({"signed_in": False}, status_code=401)
    return JSONResponse(
        {
            "signed_in": True,
            "oid": principal.oid,
            "upn": principal.upn,
            "roles": sorted(principal.roles),
            "can_write": principal.can_write,
        }
    )


async def api(request: Request) -> Response:
    """The one place the session and origin checks live.

    Not per-route. A check repeated at every handler is a check that will one
    day be missing from the newest one, and the newest one is exactly where
    nobody looks.
    """
    config: Config = request.app.state.config
    state = request.app.state.auth

    # Same-origin, enforced as written: absent counts as a mismatch. Every API
    # call is a POST precisely so the browser always sends the header.
    expected = config.base_url or f"http://localhost:{config.port}"
    if not origin_ok(request, expected.rstrip("/")):
        return JSONResponse({"error": "bad_origin"}, status_code=403)

    principal = current_principal(request)
    if principal is None:
        return JSONResponse({"error": "not_signed_in"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    session = state.sessions.get(request.cookies.get(state.session_cookie))
    assert session is not None  # current_principal just resolved it

    status, payload = handle(
        request.url.path,
        body,
        principal=principal,
        cases=_case_service(request, session),
        config=config,
    )
    return JSONResponse(payload, status_code=status)


def _case_service(request: Request, session: Session) -> CaseService:
    """One service per session, so its read cache is not shared between people."""
    if session.case_service is not None:
        return session.case_service  # type: ignore[no-any-return]

    config: Config = request.app.state.config
    app_client = build_public_client(config)
    # Rehydrate MSAL from the session's own cache: the token belongs to this
    # operator and to nobody else, and the provider is bound to that identity
    # at construction, so nothing downstream can name another account.
    app_client.token_cache = session.cache
    provider = DesktopTokenProvider(app_client, config, session.principal)
    service = CaseService(GraphOperations(GraphClient(provider)))
    session.case_service = service
    return service


def build_app(config: Config) -> Starlette:
    routes = [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/auth/login", login, methods=["GET"]),
        Route("/auth/callback", callback, methods=["GET"]),
        Route("/auth/logout", logout, methods=["POST"]),
        Route("/api/whoami", whoami, methods=["GET"]),
        Route("/api/requests", api, methods=["POST"]),
        Route("/api/me", api, methods=["POST"]),
        *[
            Route(path, static, methods=["GET"])
            for path in sorted(ALLOWED_STATIC)
        ],
    ]
    app = Starlette(routes=routes)
    app.state.config = config
    app.state.auth = AuthState(config)
    # Order matters: the header middleware wraps the logger so that headers are
    # attached to every response including those the logger observes, and the
    # logger sees the status the client actually receives.
    wrapped = SecurityHeadersMiddleware(
        RequestLogMiddleware(app), hosted=config.mode.is_hosted
    )
    # The ASGI callable is what uvicorn runs; `app` remains reachable for tests
    # and for `request.app.state`.
    return wrapped  # type: ignore[return-value]


def serve(port: int | None = None, open_browser: bool = True) -> int:
    try:
        config = load_config()
    except ConfigError as exc:
        log.error("%s", exc)
        log.error("Run `dsar doctor` for the full diagnosis.")
        return 1

    effective_port = port or config.port
    app = build_app(config)

    url = config.base_url or f"http://localhost:{effective_port}"
    log.info("dsar %s — %s mode (%s)", __version__, config.mode.value, config.mode_reason)
    log.info("listening on %s:%s — open %s", BIND_HOST, effective_port, url)

    # Inside a container there is no browser to open, and the port belongs to
    # the container's namespace rather than the host's. The launcher opens the
    # host browser instead.
    in_container = Path("/.dockerenv").exists() or os.environ.get("DSAR_IN_CONTAINER")
    if open_browser and not config.mode.is_hosted and not in_container:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    uvicorn.run(
        app,
        host=BIND_HOST,
        port=effective_port,
        log_config=None,  # our own handler, with the redaction filter attached
        # uvicorn's access logger writes the concrete path, which carries case
        # and search identifiers. RequestLogMiddleware logs the route template
        # instead — the A09 control without the disclosure.
        access_log=False,
        server_header=False,
        date_header=True,
    )
    return 0
