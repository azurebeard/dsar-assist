"""The request list, rebuilt from Microsoft Graph.

This module is the fix for the defect that made the predecessor unable to move
between machines. There, the local SQLite store *was* the source of truth: the
UI listed rows from a database file and never read cases back from Graph, so a
correctly-installed second machine — signed into the right tenant, with the
case sitting in Purview — showed an empty queue. The documented remedy was to
copy the database between machines.

Here the list is Graph. A second machine sees the same cases because there is
nothing to copy. The only cache is per-session, in memory, and thirty seconds
long, so the UI can poll without hammering the tenant.
"""

from __future__ import annotations

import enum
import logging
import time
from dataclasses import dataclass
from typing import Any

from dsar.auth.provider import Principal
from dsar.cases.model import Case, Search, parse_case, parse_search
from dsar.cases.reference import PREFIX
from dsar.graph.operations import GraphOperations

__all__ = ["CaseScope", "CaseService", "CaseListing"]

log = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 30.0

#: Graph pages at 100. More than a few hundred DSAR cases in one tenant is a
#: different product, but an unbounded follow-the-nextLink loop against a
#: tenant with thousands of cases is a hang, so it is bounded and says so.
MAX_PAGES = 10


class CaseScope(str, enum.Enum):
    """Which cases to show.

    **This is a view filter, not a security boundary.** The boundary is Purview
    RBAC, which this application does not control and cannot elevate: an
    eDiscovery Manager is shown only cases they created because Purview returns
    only those, and an eDiscovery Administrator sees all of them because
    Purview returns all of them. Choosing MINE while holding the larger role
    hides rows in a UI; it does not restrict access to anything.

    Said plainly in the UI too, because a filter that looks like a permission
    is worse than no filter at all.
    """

    MINE = "mine"
    ALL = "all"


@dataclass(frozen=True)
class CaseListing:
    cases: tuple[Case, ...]
    #: When the underlying Graph read happened. Shown to the operator, because
    #: a list with no freshness stamp invites the assumption that it is live.
    fetched_at: float
    #: True when the operator's Purview role appears to return cases created by
    #: other people — i.e. the ALL scope would show something MINE does not.
    #: Inferred, not asserted: there is no API that reports the role.
    scope_toggle_useful: bool
    truncated: bool = False


class CaseService:
    """Reads cases and searches. Holds no durable state."""

    def __init__(self, operations: GraphOperations) -> None:
        self._ops = operations
        self._cache: tuple[float, tuple[Case, ...], bool] | None = None

    def list_requests(
        self,
        principal: Principal,
        *,
        scope: CaseScope = CaseScope.MINE,
        force: bool = False,
    ) -> CaseListing:
        cases, truncated = self._all_ours(force=force)

        # Whether the toggle is worth offering. If every case this operator can
        # see was created by them, ALL and MINE are the same list and a toggle
        # that changes nothing is a confusing control.
        others = any(
            case.created_by_oid and case.created_by_oid != principal.oid
            for case in cases
        )

        if scope is CaseScope.MINE:
            # Cases with no creator information are kept rather than dropped.
            # Graph does not always populate `createdBy` in the list
            # projection, and silently hiding a case an operator created is a
            # worse failure than showing one they did not.
            visible = tuple(
                case
                for case in cases
                if not case.created_by_oid or case.created_by_oid == principal.oid
            )
        else:
            visible = cases

        assert self._cache is not None
        return CaseListing(
            cases=visible,
            fetched_at=self._cache[0],
            scope_toggle_useful=others,
            truncated=truncated,
        )

    def searches_for(self, case_id: str) -> tuple[Search, ...]:
        """Every search in a case, each with its own estimate.

        `list_searches` does not carry statistics, so each search is read again
        individually. That is N+1 calls, and it is the right trade: the
        alternative is showing a case detail with no numbers on it, which is the
        screen the operator opened it for.
        """
        response = self._ops.list_searches(case_id=case_id)
        raw = response.get("value") or []
        searches = [parse_search(item) for item in raw if isinstance(item, dict)]
        return tuple(
            self.statistics_for(case_id, s.id) if s.id else s for s in searches
        )

    def statistics_for(self, case_id: str, search_id: str) -> Search:
        """Read one search's estimate, with a fallback when the expand is empty.

        The primary path is `?$expand=lastEstimateStatisticsOperation`, which is
        unambiguous by construction: the operation reached that way belongs to
        this search and no other.

        It is not always populated. When it is not, the case operations
        collection is the only other source — and the documented
        `ediscoveryEstimateOperation` carries a `search` relationship, so an
        operation can be attributed to its search rather than guessed at.

        That attribution is the whole point of the fallback. The predecessor
        matched "newest estimate operation in the case" instead, and with more
        than one search per case every search reported the same numbers. Six
        probe queries returning six identical counts is what eventually
        surfaced it. So this matches on the search reference and returns nothing
        rather than the newest: no number is recoverable from, and a
        wrong-but-plausible number is the worst failure this tool can have.
        """
        search = parse_search(
            self._ops.get_statistics(case_id=case_id, search_id=search_id).body
        )
        if search.statistics.status:
            return search

        operation = self._estimate_operation_for(case_id, search_id)
        if operation is None:
            return search
        merged = dict(self._ops.get_statistics(case_id=case_id, search_id=search_id).body)
        merged["lastEstimateStatisticsOperation"] = operation
        log.info(
            "statistics for search %s came from the operations collection; the "
            "expand returned none",
            search_id,
        )
        return parse_search(merged)

    def _estimate_operation_for(
        self, case_id: str, search_id: str
    ) -> dict[str, Any] | None:
        """The newest estimate operation that names this search, or None."""
        try:
            response = self._ops.list_operations(case_id=case_id)
        except Exception:  # a fallback must not turn a missing number into an error
            return None

        candidates = []
        for item in response.get("value") or []:
            if not isinstance(item, dict):
                continue
            if item.get("action") != "estimateStatistics":
                continue
            # Attributed, never guessed. An operation with no search reference
            # cannot be shown to belong to this search, so it is skipped.
            reference = item.get("search") or {}
            if not isinstance(reference, dict) or reference.get("id") != search_id:
                continue
            candidates.append(item)

        if not candidates:
            return None
        return max(candidates, key=lambda o: str(o.get("createdDateTime", "")))

    def invalidate(self) -> None:
        """Drop the read cache. Called after anything that creates a case."""
        self._cache = None

    def _all_ours(self, *, force: bool) -> tuple[tuple[Case, ...], bool]:
        now = time.monotonic()
        if not force and self._cache and now - self._cache[0] < CACHE_TTL_SECONDS:
            return self._cache[1], self._cache[2]

        collected: list[Case] = []
        skip_token = ""
        truncated = False

        for page in range(MAX_PAGES):
            response = self._ops.list_cases(skip_token=skip_token)
            for item in response.get("value") or []:
                if isinstance(item, dict):
                    case = parse_case(item)
                    # Filtered client-side. The documentation says the
                    # collection "supports some of the OData query parameters"
                    # without enumerating which, and eDiscovery collections
                    # have historically been thin on OData — so a server-side
                    # $filter is a later optimisation gated on a live probe,
                    # not an assumption to build on.
                    if case.is_ours:
                        collected.append(case)

            skip_token = _skip_token(response.get("@odata.nextLink"))
            if not skip_token:
                break
            if page == MAX_PAGES - 1:
                truncated = True
                log.warning(
                    "stopped after %d pages of cases; the list may be incomplete",
                    MAX_PAGES,
                )

        collected.sort(key=lambda c: c.created, reverse=True)
        cases = tuple(collected)
        self._cache = (time.monotonic(), cases, truncated)
        return cases, truncated


def _skip_token(next_link: Any) -> str:
    if not isinstance(next_link, str) or "$skiptoken=" not in next_link:
        return ""
    return next_link.split("$skiptoken=", 1)[1].split("&", 1)[0]
