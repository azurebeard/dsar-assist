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
import webbrowser
from pathlib import Path

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from dsar import __version__
from dsar.config import Config, ConfigError, load_config
from dsar.web.security import (
    ALLOWED_STATIC,
    RequestLogMiddleware,
    SecurityHeadersMiddleware,
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


def build_app(config: Config) -> Starlette:
    routes = [
        Route("/healthz", healthz, methods=["GET"]),
        *[
            Route(path, static, methods=["GET"])
            for path in sorted(ALLOWED_STATIC)
        ],
    ]
    app = Starlette(routes=routes)
    app.state.config = config
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
