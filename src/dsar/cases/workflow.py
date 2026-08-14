"""The DSAR workflow: create a case, expand an identity, search, hand off.

Deliberately thin. Each step is one Graph call plus the decision about what to
do with the answer; the interesting logic lives in `identity/` (what to search
for) and `graph/operations.py` (what may be called at all).

The one thing this module insists on is the order:

    create case -> expand identity -> operator reviews KQL -> create search
                -> run estimate -> read statistics -> hand off to the portal

The review step is not a nicety. An expansion is a set of inferences about who
someone is, and inferences belong in front of the person accountable for the
search rather than inside it. Nothing here submits a query the operator has not
seen.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from dsar.auth.provider import Principal
from dsar.cases.model import Case, Search, parse_case, parse_search
from dsar.cases.reference import encode_reference
from dsar.graph.operations import GraphOperations
from dsar.identity.expand import (
    Expansion,
    GraphDirectoryResolver,
    Subject,
    expand_subject,
)

__all__ = ["Workflow", "NotPermitted", "ExportHandoff"]

log = logging.getLogger(__name__)

#: Purview refuses a duplicate search name within a case with a 409, so names
#: are distinguished rather than left to collide.
NAIVE_SEARCH_NAME = "Naive — primary address only"
EXPANDED_SEARCH_NAME = "Expanded — resolved identifiers and mentions"


class NotPermitted(PermissionError):
    """The operator holds no role that permits this action.

    Checked server-side, not merely hidden in the UI. A button that is not
    rendered is not a control — the endpoint is still there.
    """


@dataclass(frozen=True)
class ExportHandoff:
    """Where the operator goes to collect. This tool does not, and cannot."""

    case_id: str
    search_id: str
    portal_url: str
    #: Said plainly because it is the product's defining property rather than a
    #: limitation to apologise for.
    #: Stated as a fact about where the work happens, not as an apology for a
    #: missing feature. The handoff IS the security model; phrasing it as
    #: "this tool cannot" invites the reader to hear a limitation.
    note: str = (
        "The export runs in Microsoft Purview and is collected there, under "
        "your own identity."
    )


class Workflow:
    def __init__(self, operations: GraphOperations, principal: Principal) -> None:
        self._ops = operations
        self._principal = principal

    def _require_write(self, action: str) -> None:
        if not self._principal.can_write:
            raise NotPermitted(
                f"{action} needs the DSAR.Operator role. This account holds "
                f"{', '.join(sorted(self._principal.roles)) or 'no DSAR role'}."
            )

    # ------------------------------------------------------------------ case

    def create_case(self, reference: str, description: str = "") -> Case:
        """Create an eDiscovery case carrying the DSAR reference.

        The reference goes in `externalId`, which is what makes the case
        findable by this tool from any machine. `displayName` gets it too, so
        the case is recognisable to someone working in the Purview portal who
        has never heard of this application.
        """
        self._require_write("Creating a case")
        external_id = encode_reference(reference)
        response = self._ops.create_case(
            display_name=reference,
            external_id=external_id,
            description=description
            or "Raised via DSAR Assist. Control plane only; no item content is "
            "downloaded by this tool.",
        )
        case = parse_case(response.body)
        log.info("created case %s for reference %s", case.id, reference)
        return case

    # -------------------------------------------------------------- identity

    def expand(self, subject: Subject, *, identity_expansion: bool) -> Expansion:
        """Resolve the subject and build both queries.

        Returns the naive and expanded KQL together, because the comparison is
        the demonstration: it needs no item content to make its case, which is
        exactly the argument the product is making.
        """
        resolver = GraphDirectoryResolver(self._ops, enabled=identity_expansion)
        return expand_subject(subject, resolver)

    # -------------------------------------------------------------- searches

    def create_search(self, case_id: str, name: str, query: str) -> Search:
        """Create a search from the query **the operator approved**.

        `query` is whatever came back from the review step, edited or not. It is
        never regenerated here: a query the operator saw and a query that runs
        must be the same string, or the review means nothing.
        """
        self._require_write("Creating a search")
        response = self._ops.create_search(
            case_id=case_id, display_name=name, query=query
        )
        return parse_search(response.body)

    def run_estimate(self, case_id: str, search_id: str) -> None:
        """Start an estimate. Statistics arrive later, by polling.

        Estimation timing is wildly variable and not worth quoting a figure
        for — it depends on the tenant, the index state and how much Purview
        has to do. Do not create a search live in a demonstration and wait for
        it; run them beforehand and present completed statistics.
        """
        self._require_write("Running an estimate")
        self._ops.run_search(case_id=case_id, search_id=search_id)

    def statistics(self, case_id: str, search_id: str) -> Search:
        return parse_search(
            self._ops.get_statistics(case_id=case_id, search_id=search_id).body
        )

    # ---------------------------------------------------------------- export

    def initiate_export(
        self, case_id: str, search_id: str, name: str, portal_url: str
    ) -> ExportHandoff:
        """Start the export and stop.

        The tool does not poll for a download URL, does not hold one, and could
        not use one: the application never requests the resource that carries
        the download permission. The handoff is the security model made visible,
        not a gap in the workflow.
        """
        self._require_write("Initiating an export")
        self._ops.initiate_export(
            case_id=case_id, search_id=search_id, display_name=name
        )
        return ExportHandoff(
            case_id=case_id, search_id=search_id, portal_url=portal_url
        )
