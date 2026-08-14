"""Sign-in, callback and sign-out.

Both modes drive the authorization-code flow from the application's own HTTP
server. MSAL's `acquire_token_interactive` opens a browser in the *process's*
environment and listens on a *process-local* loopback port; inside a container
there is no browser and the port belongs to the container's network namespace,
not the host's. Driving the flow from these routes is what lets one image serve
a laptop and Azure Container Apps without a second code path.
"""

from __future__ import annotations

import logging
from typing import Any

from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)

from dsar.audit.record import Action, Outcome
from dsar.audit.sink import build_sink
from dsar.audit.trail import AuditTrail
from dsar.auth.claims import RoleEnforcement, build_principal
from dsar.auth.errors import NotAssigned
from dsar.auth.msal_client import build_client, flow_extras, scopes_for
from dsar.auth.provider import Principal
from dsar.auth.session import (
    FlowStore,
    FlowStoreFull,
    SessionStoreFull,
    SessionStore,
    cookie_names,
)
from dsar.web.limits import (
    API_LIMIT,
    LOGIN_LIMIT,
    POLL_FLOOR_SECONDS,
    MinInterval,
    RateLimiter,
)
from dsar.web.security import origin_ok
from dsar.config import Config

__all__ = ["login", "callback", "logout", "current_principal", "AuthState"]

log = logging.getLogger(__name__)


class AuthState:
    """Everything the auth routes need, built once and hung off app.state."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.sessions = SessionStore()
        self.flows = FlowStore()
        self.login_limiter = RateLimiter(*LOGIN_LIMIT)
        # One trail per process: the sequence and the chain head are process
        # state, and two writers with two heads produce two chains that both
        # look valid and neither of which is the record.
        self.trail = AuditTrail(build_sink(config))
        self.api_limiter = RateLimiter(*API_LIMIT)
        self.poll_floor = MinInterval(POLL_FLOOR_SECONDS)
        self.session_cookie, self.flow_cookie = cookie_names(config.mode.is_hosted)
        # Role enforcement is a setting, not a hard-coded rule. The Phase 1
        # probe decides which: REQUIRED when the `roles` claim is emitted to
        # public clients, ADVISORY when it is not, in which case
        # appRoleAssignmentRequired at the identity provider is what admitted
        # the token and refusing here would lock out every legitimate operator.
        self.role_enforcement = (
            RoleEnforcement.REQUIRED
            if config.require_app_role
            else RoleEnforcement.ADVISORY
        )


def _set_cookie(
    response: Response, name: str, value: str, config: Config, max_age: int
) -> None:
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        httponly=True,
        # `Secure` and the `__Host-` prefix are hosted-only. Over
        # `http://localhost` a Secure cookie relies on a browser-dependent
        # secure-context exception, so desktop uses a plain host-only cookie
        # and the deviation is documented rather than assumed.
        secure=config.mode.is_hosted,
        samesite="lax",
        path="/",
    )


async def login(request: Request) -> Response:
    """Start the flow. Optionally carrying a claims challenge for a step-up."""
    state: AuthState = request.app.state.auth
    config = state.config

    # Unauthenticated and it allocates server state, so it is limited. Keyed on
    # the peer address: on the desktop that is always loopback and the limit is
    # a formality, but the endpoint is the same code in hosted mode where it is
    # not. Behind Container Apps ingress the peer is the ingress, so this bounds
    # the total rather than per-client — worth knowing before relying on it.
    peer = request.client.host if request.client else "unknown"
    wait = state.login_limiter.check(peer)
    if wait is not None:
        return _retry_later(
            "Too many sign-in attempts. Wait a moment and try again.", wait
        )

    claims = request.query_params.get("claims") or None
    app = build_client(config)

    flow: dict[str, Any] = app.initiate_auth_code_flow(
        scopes_for(config),
        redirect_uri=config.redirect_uri,
        claims_challenge=claims,
        **flow_extras(config),
    )
    if "auth_uri" not in flow:
        log.error("could not start the authorization flow: %s", flow.get("error"))
        return HTMLResponse("<h1>Sign-in unavailable</h1>", status_code=500)

    # The flow dict carries the PKCE verifier, the state and the nonce. It is
    # held server-side and the client gets only an opaque key: `state` alone is
    # not a CSRF control, because a `state` the attacker chose is a `state`
    # that matches.
    try:
        key = state.flows.put(flow)
    except FlowStoreFull:
        log.warning("pending sign-in store is full; refusing a new flow")
        return _retry_later(
            "Too many sign-ins are in progress. Try again shortly.", 30.0
        )

    response = RedirectResponse(flow["auth_uri"], status_code=302)
    _set_cookie(response, state.flow_cookie, key, config, max_age=300)
    return response


async def callback(request: Request) -> Response:
    """Redeem the code. One shot — the pending flow is consumed on lookup."""
    state: AuthState = request.app.state.auth
    config = state.config

    flow = state.flows.take(request.cookies.get(state.flow_cookie))
    if flow is None:
        # Expired, already used, or never ours. All three are the same answer.
        return HTMLResponse(
            "<h1>Sign-in expired</h1><p>Start again from the application.</p>",
            status_code=400,
        )

    app = build_client(config)
    result = app.acquire_token_by_auth_code_flow(flow, dict(request.query_params))

    if "access_token" not in result:
        error = result.get("error", "unknown")
        log.warning("token redemption failed: %s", error)
        return HTMLResponse(
            f"<h1>Sign-in failed</h1><p>{_escape(str(error))}</p>", status_code=400
        )

    try:
        principal = build_principal(
            result.get("id_token_claims") or {},
            expected_tenant_id=config.tenant_id,
            enforcement=state.role_enforcement,
        )
    except NotAssigned as exc:
        # A refused sign-in is recorded. A trail holding only successes
        # describes a system where nobody is ever turned away.
        state.trail.write(
            Action.SIGN_IN_REFUSED,
            Outcome.DENIED,
            actor_oid=str((result.get("id_token_claims") or {}).get("oid", "")),
            tenant_id=config.tenant_id,
            detail="no DSAR app role",
        )
        # Distinct from a Purview failure, and worth saying so: this is an
        # access request to whoever owns the enterprise app, not a role-group
        # question.
        return HTMLResponse(
            f"<h1>Not assigned</h1><p>{_escape(str(exc))}</p>"
            "<p>Ask for a DSAR role on this application in Microsoft Entra ID.</p>",
            status_code=403,
        )
    except Exception as exc:
        log.error("ID token validation failed: %s", type(exc).__name__)
        return HTMLResponse("<h1>Sign-in failed</h1>", status_code=400)

    try:
        session = state.sessions.create(principal, app.token_cache)
    except SessionStoreFull as exc:
        # Recorded as a refusal, not dropped. A trail holding only successes
        # describes a system where nobody is ever turned away — and this is
        # precisely the event an operator will report as "it just does
        # nothing" if it is not written down somewhere.
        state.trail.write(
            Action.SIGN_IN,
            Outcome.DENIED,
            actor_oid=principal.oid,
            actor_upn=principal.upn,
            tenant_id=principal.tenant_id,
            uti=principal.uti,
            detail="session store full",
        )
        log.warning("refused a sign-in: %s", exc)
        return HTMLResponse(
            f"<h1>Too many people signed in</h1><p>{_escape(str(exc))}</p>",
            status_code=503,
        )

    # After the session exists, so a trail entry never claims a sign-in that
    # was then refused.
    state.trail.write(
        Action.SIGN_IN,
        Outcome.OK,
        actor_oid=principal.oid,
        actor_upn=principal.upn,
        tenant_id=principal.tenant_id,
        uti=principal.uti,
        detail=", ".join(sorted(principal.roles)) or "no DSAR role",
    )
    log.info(
        "signed in: oid=%s roles=%s uti=%s",
        principal.oid,
        sorted(principal.roles) or "(none)",
        principal.uti,
    )

    response = RedirectResponse("/", status_code=302)
    _set_cookie(
        response, state.session_cookie, session.id, config, max_age=8 * 60 * 60
    )
    response.delete_cookie(state.flow_cookie, path="/")
    return response


async def logout(request: Request) -> Response:
    """Drop the local session. Entra sign-out is offered, never assumed.

    On a shared hosted instance, signing the operator out of Microsoft entirely
    is sometimes what they want and sometimes deeply unhelpful, so it is a
    choice. On the desktop it would sign them out of Outlook and the Purview
    portal on their own machine, which is disproportionate as a default.

    Origin-checked like every other POST. Forced sign-out is a nuisance rather
    than a compromise, so this is not urgent on its own merits — but every
    other state-changing POST enforces the rule, and an unexplained exception
    is how a rule stops being trusted and then stops being applied.
    """
    state: AuthState = request.app.state.auth
    config = state.config
    expected = (config.base_url or f"http://localhost:{config.port}").rstrip("/")
    if not origin_ok(request, expected):
        return JSONResponse({"error": "bad_origin"}, status_code=403)

    session = state.sessions.get(request.cookies.get(state.session_cookie))
    if session is not None:
        state.trail.write(
            Action.SIGN_OUT,
            Outcome.OK,
            actor_oid=session.principal.oid,
            actor_upn=session.principal.upn,
            tenant_id=session.principal.tenant_id,
            uti=session.principal.uti,
        )
    state.sessions.remove(request.cookies.get(state.session_cookie))

    response = RedirectResponse("/", status_code=302)
    response.delete_cookie(state.session_cookie, path="/")
    return response


def current_principal(request: Request) -> Principal | None:
    state: AuthState = request.app.state.auth
    session = state.sessions.get(request.cookies.get(state.session_cookie))
    return session.principal if session else None


def _retry_later(message: str, seconds: float) -> Response:
    response = HTMLResponse(
        f"<h1>Slow down</h1><p>{_escape(message)}</p>", status_code=429
    )
    response.headers["Retry-After"] = str(max(1, int(seconds) + 1))
    return response


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
