"""The JSON API. All POST, all session-gated, all same-origin.

Every call is a POST even when it reads. That is not REST pedantry: browsers do
not send `Origin` on a same-origin GET, so a rule that rejects an absent
`Origin` would reject the application's own page loads. Making the API all-POST
means the rule can be enforced as written — reject absent or mismatched — on
every request that carries state, rather than relaxed to "reject only a
mismatch".

Handlers are transport-free: they take a context and return `(status, payload)`.
The predecessor did this too, and it was the single thing that made porting the
web layer cheap — the framework changed entirely and this file barely moved.

Error mapping lives in one place, at the top, because the distinctions matter to
the operator and are easy to flatten by accident. "Sign in again", "you have no
eDiscovery role", "your organisation's policy needs satisfying" and "that
reference is malformed" produce four different actions, and a handler that
returns 500 for all four wastes an afternoon.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Callable, Mapping

from dsar.auth.errors import ClaimsChallenge, NotAssigned, ReauthRequired
from dsar.auth.provider import Principal
from dsar.cases.model import Case
from dsar.cases.reference import InvalidReference
from dsar.cases.service import CaseScope, CaseService
from dsar.cases.workflow import (
    EXPANDED_SEARCH_NAME,
    NAIVE_SEARCH_NAME,
    NotPermitted,
    Workflow,
)
from dsar.config import Config, purview_case_url
from dsar.graph.errors import GraphError, PurviewRoleMissing
from dsar.identity.expand import ContractBlocked, build_subject
from dsar.identity.kql import KqlError
from dsar.identity.templates import (
    QueryTemplate,
    TemplateError,
    load_templates,
    render_template,
)

__all__ = ["handle", "ApiResult", "API_ENDPOINTS"]

log = logging.getLogger(__name__)

ApiResult = tuple[int, dict[str, Any]]


@dataclass(frozen=True)
class Context:
    body: Mapping[str, Any]
    principal: Principal
    cases: CaseService
    config: Config
    workflow: Workflow

    def text(self, key: str, default: str = "") -> str:
        value = self.body.get(key, default)
        return value.strip() if isinstance(value, str) else default


def handle(
    path: str,
    body: Mapping[str, Any],
    *,
    principal: Principal,
    cases: CaseService,
    config: Config,
    workflow: Workflow,
) -> ApiResult:
    handler = _ROUTES.get(path)
    if handler is None:
        return 404, {"error": "no_such_endpoint"}

    context = Context(body, principal, cases, config, workflow)
    try:
        return handler(context)
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
    except NotAssigned as exc:
        return 403, {"error": "not_assigned", "message": str(exc)}
    except NotPermitted as exc:
        # Enforced here, not merely hidden in the UI. A button that is not
        # rendered is not a control; the endpoint is still there.
        return 403, {"error": "not_permitted", "message": str(exc)}
    except PurviewRoleMissing as exc:
        # Its own case deliberately. Signing in does not fix this, and the
        # message names both things it could be rather than guessing.
        return 403, {"error": "purview_role", "message": str(exc)}
    except (InvalidReference, KqlError, TemplateError) as exc:
        return 400, {"error": "invalid_input", "message": str(exc)}
    except ContractBlocked as exc:
        return 400, {"error": "expansion_unavailable", "message": str(exc)}
    except GraphError as exc:
        return 502, {"error": "graph", "message": str(exc)}


# ------------------------------------------------------------------- reads


def _me(ctx: Context) -> ApiResult:
    return 200, {
        "oid": ctx.principal.oid,
        "upn": ctx.principal.upn,
        "roles": sorted(ctx.principal.roles),
        "can_write": ctx.principal.can_write,
        "identity_expansion": ctx.config.identity_expansion,
    }


def _requests(ctx: Context) -> ApiResult:
    """The request list, read from Graph rather than from a local store."""
    raw = str(ctx.body.get("scope", CaseScope.MINE.value)).lower()
    scope = CaseScope.ALL if raw == CaseScope.ALL.value else CaseScope.MINE

    listing = ctx.cases.list_requests(
        ctx.principal, scope=scope, force=bool(ctx.body.get("refresh"))
    )
    # Read once per request, so every row in one response is measured against
    # the same day. Computing it per case would let a list straddle midnight.
    today = datetime.now(timezone.utc).date()
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
                # The deadline, or nothing. Never derived from `created` — a
                # plausible wrong statutory date is the one outcome this must
                # not produce, so a case with no recorded receipt shows a gap.
                **_deadline_json(case, today),
                "mine": (not case.created_by_oid)
                or case.created_by_oid == ctx.principal.oid,
                "portal_url": purview_case_url(case.id, ctx.config.tenant_id),
            }
            for case in listing.cases
        ],
    }


def _templates(ctx: Context) -> ApiResult:
    """The standard DSAR narrowings, data-driven rather than coded.

    Every one narrows an existing query; none replaces it. The vocabulary in
    the employment-file sweep is a matter of local practice and is meant to be
    corrected in the JSON rather than in code.
    """
    return 200, {
        "templates": [
            {
                "id": t.id,
                "name": t.name,
                "purpose": t.purpose,
                "guidance": t.guidance,
                "caution": t.caution,
                # The interface acts on this: a narrowing that zeroes the site
                # count has to be visible where it is applied, not only in a
                # caution inside a panel the operator has already collapsed.
                "mailbox_only": t.mailbox_only,
                "inputs": [
                    {
                        "name": i.name,
                        "label": i.label,
                        "kind": i.kind,
                        "placeholder": i.placeholder,
                        "help": i.help,
                        "required": i.required,
                        "options": [
                            {"value": value, "label": label}
                            for value, label in i.options
                        ],
                    }
                    for i in t.inputs
                ],
            }
            for t in load_templates()
        ]
    }


def _deadline_json(case: Case, today: date) -> dict[str, Any]:
    deadline = case.deadline(today)
    if deadline is None:
        return {"received": None, "due": None, "days_remaining": None, "overdue": False}
    return {
        "received": deadline.received.isoformat(),
        "due": deadline.due.isoformat(),
        "days_remaining": deadline.days_remaining,
        "overdue": deadline.overdue,
    }


def _case_detail(ctx: Context) -> ApiResult:
    case_id = ctx.text("case_id")
    if not case_id:
        return 400, {"error": "invalid_input", "message": "case_id is required"}

    searches = ctx.cases.searches_for(case_id)
    return 200, {
        "case_id": case_id,
        "portal_url": purview_case_url(case_id, ctx.config.tenant_id),
        "searches": [_search_json(s) for s in searches],
    }


def _statistics(ctx: Context) -> ApiResult:
    """Poll one search's estimate.

    Read through `?$expand=lastEstimateStatisticsOperation`, so the numbers are
    this search's. The case-level operations collection carries no reference
    back to the search that produced each one, which is how the predecessor
    ended up reporting identical counts for every search in a case.
    """
    case_id, search_id = ctx.text("case_id"), ctx.text("search_id")
    if not case_id or not search_id:
        return 400, {
            "error": "invalid_input",
            "message": "case_id and search_id are required",
        }
    return 200, _search_json(ctx.cases.statistics_for(case_id, search_id))


# ------------------------------------------------------------------ writes


def _create_case(ctx: Context) -> ApiResult:
    reference = ctx.text("reference")
    # Optional, and refused rather than guessed if it is not a date. The clock
    # runs from receipt; `createdDateTime` is when somebody opened the case,
    # which is always later.
    received = _received_date(ctx.text("received"))
    case = ctx.workflow.create_case(reference, ctx.text("description"), received)
    ctx.cases.invalidate()  # the list is a cache; a new case must appear at once
    return 201, {
        "case_id": case.id,
        "reference": case.reference,
        "display_name": case.display_name,
        "received": received.isoformat() if received else None,
        "portal_url": purview_case_url(case.id, ctx.config.tenant_id),
    }


def _received_date(raw: str) -> date | None:
    """Parse an operator-supplied receipt date, or refuse it.

    Empty is fine — the received date is optional and its absence shows as
    "not recorded". A malformed one is NOT fine: silently dropping it would
    produce a case that looks like it has no receipt date when the operator
    believes they gave one, and the deadline would quietly not exist.
    """
    if not raw:
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise InvalidReference(
            f"the received date must be YYYY-MM-DD, got {raw!r}. The statutory "
            f"clock runs from the day the request arrived."
        ) from exc


def _expand(ctx: Context) -> ApiResult:
    """Resolve the subject and return BOTH queries for review.

    The naive query and the expanded one are returned together because the
    comparison is the demonstration — and it needs no item content to make its
    case, which is exactly the argument the product is making.

    Nothing is submitted here. The operator sees the query, and may edit it,
    before any search exists.
    """
    subject = build_subject(dict(ctx.body))
    expansion = ctx.workflow.expand(
        subject,
        identity_expansion=ctx.config.identity_expansion,
        case_id=ctx.text("case_id"),
    )
    return 200, expansion.to_json()


def _apply_template(ctx: Context) -> ApiResult:
    """Narrow a query the operator already has in front of them."""
    query = ctx.text("query")
    if not query:
        return 400, {"error": "invalid_input", "message": "query is required"}

    template_id = ctx.text("template_id")
    template = _find_template(template_id)
    values = ctx.body.get("values")
    narrowed = render_template(
        template, values if isinstance(values, dict) else {}, existing=query
    )
    return 200, {"query": narrowed}


def _find_template(template_id: str) -> QueryTemplate:
    for template in load_templates():
        if template.id == template_id:
            return template
    raise TemplateError(f"no such template: {template_id!r}")


def _create_search(ctx: Context) -> ApiResult:
    """Create a search from the query the operator approved.

    The query is taken from the request, never regenerated: a query the
    operator saw and a query that runs must be the same string, or the review
    step means nothing.
    """
    case_id, query = ctx.text("case_id"), ctx.text("query")
    if not case_id or not query:
        return 400, {
            "error": "invalid_input",
            "message": "case_id and query are required",
        }

    kind = ctx.text("kind", "expanded")
    default_name = NAIVE_SEARCH_NAME if kind == "naive" else EXPANDED_SEARCH_NAME
    name = ctx.text("name") or default_name

    search = ctx.workflow.create_search(case_id, name, query)
    if ctx.body.get("run", True):
        ctx.workflow.run_estimate(case_id, search.id)
    return 201, _search_json(search)


def _export(ctx: Context) -> ApiResult:
    case_id, search_id = ctx.text("case_id"), ctx.text("search_id")
    if not case_id or not search_id:
        return 400, {
            "error": "invalid_input",
            "message": "case_id and search_id are required",
        }

    handoff = ctx.workflow.initiate_export(
        case_id,
        search_id,
        ctx.text("name") or "DSAR export",
        purview_case_url(case_id, ctx.config.tenant_id),
    )
    return 202, {
        "case_id": handoff.case_id,
        "search_id": handoff.search_id,
        "portal_url": handoff.portal_url,
        "note": handoff.note,
    }


def _search_json(search: Any) -> dict[str, Any]:
    stats = search.statistics
    return {
        "search_id": search.id,
        "display_name": search.display_name,
        "created": search.created,
        "query": search.content_query,
        "statistics": {
            # None, never 0. "No estimate has run" and "the estimate found
            # nothing" are different facts, and a UI showing 0 for the first
            # is lying.
            "item_count": stats.item_count,
            "total_size": stats.total_size,
            "location_count": stats.location_count,
            "mailbox_count": stats.mailbox_count,
            "site_count": stats.site_count,
            "unindexed_count": stats.unindexed_count,
            "percent_progress": stats.percent_progress,
            "status": stats.status,
            "complete": stats.complete,
            "partial": stats.partial,
        },
    }


_Handler = Callable[[Context], ApiResult]

_ROUTES: dict[str, _Handler] = {
    "/api/me": _me,
    "/api/requests": _requests,
    "/api/templates": _templates,
    "/api/case": _case_detail,
    "/api/statistics": _statistics,
    "/api/case/create": _create_case,
    "/api/expand": _expand,
    "/api/template/apply": _apply_template,
    "/api/search/create": _create_search,
    "/api/export": _export,
}

#: Routed by the ASGI layer. Declared here so the route table and the handler
#: table cannot drift apart — an endpoint that exists in one and not the other
#: is a 404 nobody can explain.
API_ENDPOINTS: tuple[str, ...] = tuple(sorted(_ROUTES))
