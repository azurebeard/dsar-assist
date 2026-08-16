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
from datetime import date
from dataclasses import dataclass

from dsar.audit.record import Action, Outcome
from dsar.audit.trail import AuditTrail
from dsar.auth.provider import Principal
from dsar.cases.model import Case, Search, parse_case, parse_search
from dsar.cases.received import encode_received
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
    def __init__(
        self,
        operations: GraphOperations,
        principal: Principal,
        trail: AuditTrail | None = None,
    ) -> None:
        self._ops = operations
        self._principal = principal
        self._trail = trail

    def _record(
        self,
        action: Action,
        outcome: Outcome,
        *,
        target_id: str = "",
        subject_ref: str = "",
        detail: str = "",
    ) -> None:
        if self._trail is None:
            return
        self._trail.write(
            action,
            outcome,
            actor_oid=self._principal.oid,
            actor_upn=self._principal.upn,
            tenant_id=self._principal.tenant_id,
            target_id=target_id,
            subject_ref=subject_ref,
            uti=self._principal.uti,
            detail=detail,
        )

    def _require_write(self, action: str, audit_action: Action) -> None:
        if not self._principal.can_write:
            # A refusal is recorded. "Who tried and was told no" is exactly the
            # question an audit trail exists to answer, and a trail that only
            # holds successes describes a system where nothing is ever refused.
            self._record(audit_action, Outcome.DENIED, detail=action)
            raise NotPermitted(
                f"{action} needs the DSAR.Operator role. This account holds "
                f"{', '.join(sorted(self._principal.roles)) or 'no DSAR role'}."
            )

    # ------------------------------------------------------------------ case

    def create_case(
        self,
        reference: str,
        description: str = "",
        received: date | None = None,
    ) -> Case:
        """Create an eDiscovery case carrying the DSAR reference.

        The reference goes in `externalId`, which is what makes the case
        findable by this tool from any machine. `displayName` gets it too, so
        the case is recognisable to someone working in the Purview portal who
        has never heard of this application.
        """
        self._require_write("Creating a case", Action.CASE_CREATED)
        external_id = encode_reference(reference)
        # Written before the call goes out. A crash inside the request window
        # then leaves an `attempted` with no `ok`, which is a visible shape
        # rather than a silent absence.
        self._record(Action.CASE_CREATED, Outcome.ATTEMPTED, detail=reference)
        # The received date rides in the description, because it is the only
        # writable field on an ediscoveryCase not already carrying something
        # and there is deliberately no `update_case`. Write-once, exactly like
        # the reference — see `cases/received.py`.
        response = self._ops.create_case(
            display_name=reference,
            external_id=external_id,
            description=encode_received(received, description),
        )
        case = parse_case(response.body)
        self._record(
            Action.CASE_CREATED, Outcome.OK, target_id=case.id, detail=reference
        )
        log.info("created case %s for reference %s", case.id, reference)
        return case

    # -------------------------------------------------------------- identity

    def expand(
        self, subject: Subject, *, identity_expansion: bool, case_id: str = ""
    ) -> Expansion:
        """Resolve the subject and build both queries.

        Returns the naive and expanded KQL together, because the comparison is
        the demonstration: it needs no item content to make its case, which is
        exactly the argument the product is making.
        """
        resolver = GraphDirectoryResolver(self._ops, enabled=identity_expansion)
        expansion = expand_subject(subject, resolver)
        # How many identifiers were resolved, never which. The count is the
        # defensible fact — "expansion found four addresses for this subject" —
        # and the addresses themselves are the third-party personal data this
        # trail must not become a second copy of.
        self._record(
            Action.IDENTITY_EXPANDED,
            Outcome.OK,
            target_id=case_id,
            subject_ref=(
                self._trail.subject_ref(case_id, subject.primary_email)
                if self._trail and case_id
                else ""
            ),
            detail=(
                f"{len(expansion.identifiers)} identifier(s), "
                f"{len(expansion.mentions)} mention clause(s)"
            ),
        )
        return expansion

    # -------------------------------------------------------------- searches

    def create_search(self, case_id: str, name: str, query: str) -> Search:
        """Create a search from the query **the operator approved**.

        `query` is whatever came back from the review step, edited or not. It is
        never regenerated here: a query the operator saw and a query that runs
        must be the same string, or the review means nothing.
        """
        self._require_write("Creating a search", Action.SEARCH_CREATED)
        self._record(
            Action.SEARCH_CREATED, Outcome.ATTEMPTED, target_id=case_id, detail=name
        )
        response = self._ops.create_search(
            case_id=case_id, display_name=name, query=query
        )
        search = parse_search(response.body)
        # The search's name and identifier, never its query. The KQL names a
        # real person and their aliases; a durable copy of it here is the second
        # ungoverned store this tool exists to avoid.
        self._record(
            Action.SEARCH_CREATED, Outcome.OK, target_id=search.id, detail=name
        )
        return search

    def run_estimate(self, case_id: str, search_id: str) -> None:
        """Start an estimate. Statistics arrive later, by polling.

        Estimation timing is wildly variable and not worth quoting a figure
        for — it depends on the tenant, the index state and how much Purview
        has to do. Do not create a search live in a demonstration and wait for
        it; run them beforehand and present completed statistics.
        """
        self._require_write("Running an estimate", Action.ESTIMATE_STARTED)
        self._ops.run_search(case_id=case_id, search_id=search_id)
        self._record(Action.ESTIMATE_STARTED, Outcome.OK, target_id=search_id)

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
        self._require_write("Initiating an export", Action.EXPORT_INITIATED)
        # The one action with a data-protection consequence outside this tool:
        # after it, content exists in a package someone will collect. Recorded
        # before and after, so an interrupted export is distinguishable from one
        # that never started.
        self._record(
            Action.EXPORT_INITIATED, Outcome.ATTEMPTED, target_id=search_id, detail=name
        )
        self._ops.initiate_export(
            case_id=case_id, search_id=search_id, display_name=name
        )
        self._record(
            Action.EXPORT_INITIATED, Outcome.OK, target_id=search_id, detail=name
        )
        return ExportHandoff(
            case_id=case_id, search_id=search_id, portal_url=portal_url
        )
