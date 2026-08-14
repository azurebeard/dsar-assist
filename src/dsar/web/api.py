"""The JSON API. All POST, all session-gated, all same-origin.

Every call is a POST even when it reads. That is not REST pedantry: browsers do
not send `Origin` on a same-origin GET, so a rule that rejects an absent
`Origin` would reject the application's own page loads. Making the API
all-POST means the rule can be enforced as written — reject absent or
mismatched — on every request that carries state, rather than relaxed to
"reject only a mismatch".

Handlers are transport-free: they take a principal and a body and return
`(status, payload)`. The predecessor did this too and it was the single thing
that made porting the web layer cheap — the framework changed entirely and this
file barely moved.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

from dsar.auth.provider import Principal
from dsar.cases.service import CaseScope, CaseService
from dsar.config import Config
from dsar.graph.errors import GraphError, PurviewRoleMissing
from dsar.auth.errors import ClaimsChallenge, ReauthRequired

__all__ = ["handle", "ApiResult"]

log = logging.getLogger(__name__)

ApiResult = tuple[int, dict[str, Any]]


def handle(
    path: str,
    body: Mapping[str, Any],
    *,
    principal: Principal,
    cases: CaseService,
    config: Config,
) -> ApiResult:
    handler = _ROUTES.get(path)
    if handler is None:
        return 404, {"error": "no such endpoint"}
    try:
        return handler(body, principal, cases, config)
    except ReauthRequired as exc:
        return 401, {"error": "reauth_required", "message": str(exc)}
    except ClaimsChallenge as exc:
        # The claims must reach the step-up, or the operator signs in
        # successfully and nothing changes — which reads as progress and is not.
        return 401, {
            "error": "claims_challenge",
            "message": str(exc),
            "step_up": "/auth/login",
            "claims": exc.claims,
        }
    except PurviewRoleMissing as exc:
        # Deliberately its own case. This is not fixed by signing in, and the
        # message says both things it could be rather than guessing.
        return 403, {"error": "purview_role", "message": str(exc)}
    except GraphError as exc:
        return 502, {"error": "graph", "message": str(exc)}


def _requests(
    body: Mapping[str, Any],
    principal: Principal,
    cases: CaseService,
    config: Config,
) -> ApiResult:
    """The request list, read from Graph rather than from a local store."""
    raw_scope = str(body.get("scope", CaseScope.MINE.value)).lower()
    scope = CaseScope.ALL if raw_scope == CaseScope.ALL.value else CaseScope.MINE

    listing = cases.list_requests(
        principal, scope=scope, force=bool(body.get("refresh"))
    )

    return 200, {
        "scope": scope.value,
        # Whether offering the toggle is useful at all: if every visible case
        # was created by this operator, ALL and MINE are the same list.
        "scope_toggle_useful": listing.scope_toggle_useful,
        "truncated": listing.truncated,
        "source": "Microsoft Graph",
        "requests": [
            {
                "case_id": case.id,
                "reference": case.reference,
                "display_name": case.display_name,
                "status": case.status,
                "created": case.created,
                "created_by": case.created_by_name,
                "mine": (not case.created_by_oid)
                or case.created_by_oid == principal.oid,
                "portal_url": _portal_url(case.id, config),
            }
            for case in listing.cases
        ],
    }


def _whoami(
    body: Mapping[str, Any],
    principal: Principal,
    cases: CaseService,
    config: Config,
) -> ApiResult:
    return 200, {
        "oid": principal.oid,
        "upn": principal.upn,
        "roles": sorted(principal.roles),
        "can_write": principal.can_write,
    }


def _portal_url(case_id: str, config: Config) -> str:
    from dsar.config import purview_case_url

    return purview_case_url(case_id, config.tenant_id)


_Handler = Callable[[Mapping[str, Any], Principal, CaseService, Config], ApiResult]

_ROUTES: dict[str, _Handler] = {
    "/api/requests": _requests,
    "/api/me": _whoami,
}
