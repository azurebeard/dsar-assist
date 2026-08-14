"""Typed wrappers for the operations this application permits, and nothing else.

The rule: *any operation not in this table MUST NOT be called.*

That is enforced structurally rather than by review. `OPERATIONS` is the only
source of paths in this module; `GraphOperations` builds every request from an
entry in it, and there is no method that takes a caller-supplied path. Adding a
call therefore means adding a table row, which is a visible diff — which is the
point.

`BETA_ENDPOINTS` is present and empty. Every operation listed is generally
available on `v1.0`, so nothing needs the beta channel today; the constant
exists so that if something ever does, there is one declared place for it and
one obvious thing to review.

Ported from the predecessor at 8652e638. Two changes:

  * The per-call `job_id` / `home_account_id` plumbing is gone. A
    `TokenProvider` is bound to one identity at construction, so a handler
    cannot name another account even by mistake — what used to be an invariant
    policed by discipline is now impossible by construction.
  * Two rows added, taking the table from nine operations to eleven:
    `list_cases` and `list_searches`. They are what let the request list be
    rebuilt from Microsoft Graph instead of a local database, which is the
    defect that made the predecessor unable to move between machines. Both are
    GA on v1.0 and need no permission beyond the one already held.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Mapping

from dsar.graph.client import GraphClient, GraphResponse
from dsar.graph.errors import PermanentGraphError

__all__ = [
    "GraphOperations",
    "OPERATIONS",
    "BETA_ENDPOINTS",
    "Operation",
    "USER_SELECT",
    "EXPORT_CRITERIA",
    "EXPORT_FORMAT",
    "EXPORT_ADDITIONAL_OPTIONS",
]

log = logging.getLogger(__name__)

# Path segments are Graph identifiers: GUIDs, or opaque base64-ish tokens.
# Anything containing a slash, a query or fragment marker, a dot-segment or
# whitespace is not an identifier and must not be interpolated into a URL.
#
# This matters because `case_id` and `search_id` arrive from a request body,
# which means an operator — or anything that got past the session check —
# chooses them. Without this, a crafted identifier could walk the path back up
# and reach an endpoint outside the table, which is the one thing the table
# exists to prevent.
_SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9._~%-]{1,256}$")


def _odata_string(value: str) -> str:
    """Quote a value as an OData string literal.

    A single quote is escaped by doubling it — the only escape OData defines.
    Control characters are refused rather than stripped: a filter is a query
    language, and a value that cannot be expressed in it must fail loudly
    rather than silently become a different query.
    """
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise PermanentGraphError(
            "directory lookup value contains a control character and cannot be "
            "expressed in an OData filter"
        )
    if len(value) > 256:
        raise PermanentGraphError("directory lookup value is implausibly long")
    return "'" + value.replace("'", "''") + "'"


class UnsafePathArgument(PermanentGraphError):
    """A path argument is not a well-formed Graph identifier."""

    def __init__(self, name: str, value: str) -> None:
        super().__init__(
            f"{name} is not a valid Graph identifier and will not be placed in "
            f"a request path (length {len(value)})"
        )


class UnknownOperation(RuntimeError):
    def __init__(self, name: str) -> None:
        super().__init__(
            f"{name!r} is not in the permitted-operations table. Calling it is a "
            f"contract breach; adding it needs an amendment and a visible diff."
        )


@dataclass(frozen=True)
class Operation:
    """One permitted Graph call."""

    name: str
    method: str
    template: str
    #: True when the call can create or change something in the tenant.
    mutating: bool = False


OPERATIONS: dict[str, Operation] = {
    # -- cases ---------------------------------------------------------------
    "list_cases": Operation("list_cases", "GET", "/security/cases/ediscoveryCases"),
    "create_case": Operation(
        "create_case", "POST", "/security/cases/ediscoveryCases", mutating=True
    ),
    "get_case": Operation("get_case", "GET", "/security/cases/ediscoveryCases/{caseId}"),
    # -- searches ------------------------------------------------------------
    "list_searches": Operation(
        "list_searches", "GET", "/security/cases/ediscoveryCases/{caseId}/searches"
    ),
    "create_search": Operation(
        "create_search",
        "POST",
        "/security/cases/ediscoveryCases/{caseId}/searches",
        mutating=True,
    ),
    "run_search": Operation(
        "run_search",
        "POST",
        "/security/cases/ediscoveryCases/{caseId}/searches/{searchId}/estimateStatistics",
        mutating=True,
    ),
    "get_statistics": Operation(
        "get_statistics",
        "GET",
        "/security/cases/ediscoveryCases/{caseId}/searches/{searchId}",
    ),
    # -- operations ----------------------------------------------------------
    "list_operations": Operation(
        "list_operations", "GET", "/security/cases/ediscoveryCases/{caseId}/operations"
    ),
    "get_operation": Operation(
        "get_operation",
        "GET",
        "/security/cases/ediscoveryCases/{caseId}/operations/{operationId}",
    ),
    # -- export --------------------------------------------------------------
    "initiate_export": Operation(
        "initiate_export",
        "POST",
        "/security/cases/ediscoveryCases/{caseId}/searches/{searchId}/exportResult",
        mutating=True,
    ),
    # -- directory -----------------------------------------------------------
    "find_users": Operation("find_users", "GET", "/users"),
}

#: Export parameters. All three are **required** by Graph v1.0; omitting them
#: returns `400 Invalid export criteria provided`, which is how this was found.
#:
#: Named constants rather than literals because in a subject access request the
#: export scope is a defensible decision someone may have to justify, not an
#: implementation detail buried in a request body.
#:
#: `searchHits` exports what the query matched. The alternative,
#: `partiallyIndexed`, additionally pulls items Purview could not index — a real
#: judgement call: it widens recall, and it increases both volume and (on E3)
#: cost. Left at `searchHits`, because quietly exporting more of someone's data
#: than the query matched is not a default a tool should choose on an
#: operator's behalf.
EXPORT_CRITERIA = "searchHits"

#: `pst` is the conventional mail export container. `eml` is deprecated in v1.0.
EXPORT_FORMAT = "pst"

#: `none` keeps the export to the items themselves — no Teams transcripts, no
#: extra document versions, no cloud attachments pulled in by side effect.
EXPORT_ADDITIONAL_OPTIONS = "none"

#: The `find_users` projection is part of the permitted operation, not a
#: caller's choice. A directory record also carries job title, manager, phone
#: numbers and office location; none of it is identity expansion's business,
#: and the no-excess-data property is easier to hold when that data never
#: enters the process at all.
USER_SELECT: tuple[str, ...] = (
    "displayName",
    "givenName",
    "surname",
    "mail",
    "userPrincipalName",
    "proxyAddresses",
    "otherMails",
    "employeeId",
)

#: Nothing needs beta. The constant is the declared place for it if that changes.
BETA_ENDPOINTS: frozenset[str] = frozenset()
BETA_BASE_URL = "https://graph.microsoft.com/beta"


class GraphOperations:
    """The typed surface callers use. One method per row."""

    def __init__(self, client: GraphClient) -> None:
        self.client = client

    def _call(
        self,
        name: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: Mapping[str, str] | None = None,
        **path_args: str,
    ) -> GraphResponse:
        operation = OPERATIONS.get(name)
        if operation is None:
            raise UnknownOperation(name)

        for key, value in path_args.items():
            if not _SAFE_PATH_SEGMENT.match(value or ""):
                # Not logged with its value: it is caller-influenced input, and
                # echoing it into the log is how a log becomes a payload.
                raise UnsafePathArgument(key, value or "")

        return self.client.request(
            operation.method,
            operation.template.format(**path_args),
            operation=operation.name,
            json_body=json_body,
            params=params,
        )

    # ----------------------------------------------------------------- cases

    def list_cases(self, *, top: int = 100, skip_token: str = "") -> GraphResponse:
        """GET /security/cases/ediscoveryCases.

        The request list is rebuilt from this rather than from a local store.
        A second machine, signed into the same tenant, therefore sees the same
        cases with nothing copied between them — which is the whole reason this
        row was added.

        Filtering happens client-side. The documentation says the collection
        "supports some of the OData query parameters" without enumerating
        which, and eDiscovery collections have historically been thin on OData,
        so a server-side `$filter` is treated as a later optimisation gated on
        a live probe rather than assumed.
        """
        params: dict[str, str] = {"$top": str(max(1, min(top, 100)))}
        if skip_token:
            params["$skiptoken"] = skip_token
        return self._call("list_cases", params=params)

    def create_case(self, *, display_name: str, external_id: str = "", description: str = "") -> GraphResponse:
        """POST /security/cases/ediscoveryCases.

        `externalId` carries the DSAR reference. It is the documented field for
        a customer case number, it is settable at creation and returned in the
        list response, and it survives someone renaming the case in the portal
        — which a `displayName` convention would not.
        """
        body: dict[str, Any] = {"displayName": display_name}
        if external_id:
            body["externalId"] = external_id
        if description:
            body["description"] = description
        return self._call("create_case", json_body=body)

    def get_case(self, *, case_id: str) -> GraphResponse:
        return self._call("get_case", caseId=case_id)

    # -------------------------------------------------------------- searches

    def list_searches(self, *, case_id: str) -> GraphResponse:
        return self._call("list_searches", caseId=case_id)

    def create_search(
        self,
        *,
        case_id: str,
        display_name: str,
        query: str,
        data_source_scopes: str = "allTenantMailboxes,allTenantSites",
    ) -> GraphResponse:
        """POST .../searches.

        `contentQuery` carries the KQL. It is sent, never logged and never
        audited as free text — the audit records that a search was created and
        its identifier, not what it looked for. The query names a real person
        and their aliases; a log line containing it is a second, ungoverned
        copy of exactly the data this tool exists to handle carefully.
        """
        return self._call(
            "create_search",
            json_body={
                "displayName": display_name,
                "contentQuery": query,
                "dataSourceScopes": data_source_scopes,
            },
            caseId=case_id,
        )

    def run_search(self, *, case_id: str, search_id: str) -> GraphResponse:
        """POST .../estimateStatistics.

        Estimation, not preview. Statistics are counts, volumes and location
        names — metadata, and in scope. Preview returns item content, is
        permanently out of scope, and is absent from this module, which is the
        only place it could have been added.
        """
        return self._call("run_search", caseId=case_id, searchId=search_id)

    def get_statistics(self, *, case_id: str, search_id: str) -> GraphResponse:
        """GET .../searches/{searchId}?$expand=lastEstimateStatisticsOperation.

        The `$expand` is what makes the answer *this search's*. A bare GET on
        the search returns no statistics at all, and the case-level operations
        collection carries no reference back to the search that produced each
        one — so with more than one search in a case there is no way to
        attribute an operation by listing.

        This was found the hard way. The operation reference arrives as
        `operations('id')` — OData key syntax — while the original code
        expected `operations/id`, so the match never succeeded and every poll
        fell back to "newest estimate operation in the case". With several
        searches per case, every one reported the same numbers. Six different
        probe queries returning six identical counts is what surfaced it.
        Expanding the search's own `lastEstimateStatisticsOperation` is correct
        by construction, and a wrong-but-plausible number is the worst failure
        this tool can have.
        """
        return self._call(
            "get_statistics",
            params={"$expand": "lastEstimateStatisticsOperation"},
            caseId=case_id,
            searchId=search_id,
        )

    # ------------------------------------------------------------ operations

    def list_operations(self, *, case_id: str) -> GraphResponse:
        return self._call("list_operations", caseId=case_id)

    def get_operation(self, *, case_id: str, operation_id: str) -> GraphResponse:
        return self._call("get_operation", caseId=case_id, operationId=operation_id)

    # ---------------------------------------------------------------- export

    def initiate_export(
        self,
        *,
        case_id: str,
        search_id: str,
        display_name: str,
        export_criteria: str = EXPORT_CRITERIA,
        export_format: str = EXPORT_FORMAT,
        additional_options: str = EXPORT_ADDITIONAL_OPTIONS,
    ) -> GraphResponse:
        """POST .../exportResult — initiate only.

        The tool starts the export and stops. It does not poll for a download
        URL, does not hold one, and could not use one: the application never
        requests the resource that carries the download permission. The
        operator collects from the Purview portal under their own identity,
        which is this product's defining property rather than a gap in it.
        """
        return self._call(
            "initiate_export",
            json_body={
                "displayName": display_name,
                "exportCriteria": export_criteria,
                "exportFormat": export_format,
                "additionalOptions": additional_options,
            },
            caseId=case_id,
            searchId=search_id,
        )

    # ------------------------------------------------------------- directory

    def find_users(
        self, *, addresses: list[str], employee_id: str = "", top: int = 25
    ) -> GraphResponse:
        """GET /users, projected to `USER_SELECT`.

        The `$select` is fixed here rather than accepted from the caller, so
        there is no code path that can widen the projection. `$top` bounds the
        response: an over-broad filter should return a small wrong answer the
        operator can see, not thousands of records the process then holds.

        Matching is on exact address and employee ID only. Proxy addresses are
        *read from* the returned records rather than filtered on — filtering
        `proxyAddresses/any(...)` needs an advanced query with
        `ConsistencyLevel: eventual`, and expansion does not need it: it starts
        from an address it already knows and wants the rest of that person's.
        """
        clauses = [f"mail eq {_odata_string(a)}" for a in addresses if a]
        clauses += [f"userPrincipalName eq {_odata_string(a)}" for a in addresses if a]
        if employee_id:
            clauses.append(f"employeeId eq {_odata_string(employee_id)}")
        if not clauses:
            raise PermanentGraphError(
                "find_users needs at least one address or employee id"
            )

        return self._call(
            "find_users",
            params={
                "$select": ",".join(USER_SELECT),
                "$filter": " or ".join(clauses),
                "$top": str(max(1, min(top, 100))),
            },
        )
