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
import time
from datetime import date
from dataclasses import dataclass
from typing import Callable, TypeVar

_T = TypeVar("_T")

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
        metrics: Callable[[str, int, bool], None] | None = None,
    ) -> None:
        self._ops = operations
        self._principal = principal
        self._trail = trail
        #: `(operation, milliseconds, ok)`, called around each Graph mutation
        #: when timing capture is on. A callable rather than an import, so this
        #: module stays ignorant of where measurements go — and the recorder
        #: swallows its own failures, because telemetry must never take down
        #: the operation it measures.
        self._metrics = metrics

    def _timed(self, op: str, call: Callable[[], _T]) -> _T:
        """Run one Graph call, telling the recorder how long it took.

        The failure is recorded before the exception continues — a slow
        failure and a fast success are different facts, and the benchmark
        needs both.
        """
        if self._metrics is None:
            return call()
        started = time.monotonic()
        try:
            result = call()
        except Exception:
            self._tell(op, round((time.monotonic() - started) * 1000), False)
            raise
        self._tell(op, round((time.monotonic() - started) * 1000), True)
        return result

    def _tell(self, op: str, ms: int, ok: bool) -> None:
        """Invoke the recorder without letting it change anything.

        The caller's closure already swallows its own errors, but that promise
        lives in a different module — and a recorder that throws on the
        success path would report a case Purview really created as failed,
        with no audit record. The containment belongs where the consequence
        is (WS10 SEC-L-01).
        """
        if self._metrics is None:
            return
        try:
            self._metrics(op, ms, ok)
        except Exception:
            log.warning("metrics recorder failed for %s; continuing", op)

    def _record(
        self,
        action: Action,
        outcome: Outcome,
        *,
        target_id: str = "",
        case_id: str = "",
        subject_ref: str = "",
        correlation_id: str = "",
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
            case_id=case_id,
            subject_ref=subject_ref,
            uti=self._principal.uti,
            correlation_id=correlation_id,
            detail=detail,
        )

    def _require_write(
        self, action: str, audit_action: Action, case_id: str = ""
    ) -> None:
        if not self._principal.can_write:
            # A refusal is recorded. "Who tried and was told no" is exactly the
            # question an audit trail exists to answer, and a trail that only
            # holds successes describes a system where nothing is ever refused.
            #
            # Carrying the case is what makes it findable later. A denial with
            # no case attached is a record that answers the question in general
            # and never for the case somebody is actually asking about.
            self._record(audit_action, Outcome.DENIED, case_id=case_id, detail=action)
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
        response = self._timed(
            "case_create",
            lambda: self._ops.create_case(
                display_name=reference,
                external_id=external_id,
                description=encode_received(received, description),
            ),
        )
        case = parse_case(response.body)
        self._record(
            Action.CASE_CREATED,
            Outcome.OK,
            target_id=case.id,
            case_id=case.id,
            # Graph's echo for this exact request — what joins this record to
            # the Graph activity log at investigation time (B-25). ATTEMPTED
            # records stay empty: the id is minted per request inside the
            # client, so before the call there is nothing true to write.
            correlation_id=response.correlation_id,
            detail=reference,
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
            # Observed missing on the first live trail (seq 4 and 15,
            # 2026-08-17): target_id carried the case but `case_id` did not,
            # so the evidence pack's one-case filter dropped the expansion and
            # counted it unattributable. Those two records stay unattributed
            # forever — the trail is append-only — which is the honest cost of
            # finding this by reading a real trail instead of a fixture.
            case_id=case_id,
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

    # ------------------------------------------------------------- templates

    def record_template_applied(
        self, template_id: str, version: str, case_id: str = ""
    ) -> None:
        """A reviewed narrowing was rendered onto a query. Write it down.

        The render itself is local — no Graph call — but the search that
        eventually runs is recorded name-only, so this record is the only way
        the trail can say which reviewed narrowing shaped it, and at which
        version of the template file. The id and version are the whole
        payload: never the query, never the operator's input values, which
        carry exactly the subject data the trail must not hold.
        """
        self._record(
            Action.TEMPLATE_APPLIED,
            Outcome.OK,
            case_id=case_id,
            detail=f"{template_id} @ {version}",
        )

    # -------------------------------------------------------------- searches

    def create_search(self, case_id: str, name: str, query: str) -> Search:
        """Create a search from the query **the operator approved**.

        `query` is whatever came back from the review step, edited or not. It is
        never regenerated here: a query the operator saw and a query that runs
        must be the same string, or the review means nothing.
        """
        self._require_write("Creating a search", Action.SEARCH_CREATED, case_id)
        self._record(
            Action.SEARCH_CREATED,
            Outcome.ATTEMPTED,
            target_id=case_id,
            case_id=case_id,
            detail=name,
        )
        response = self._timed(
            "search_create",
            lambda: self._ops.create_search(
                case_id=case_id, display_name=name, query=query
            ),
        )
        search = parse_search(response.body)
        # The search's name and identifier, never its query. The KQL names a
        # real person and their aliases; a durable copy of it here is the second
        # ungoverned store this tool exists to avoid.
        self._record(
            Action.SEARCH_CREATED,
            Outcome.OK,
            target_id=search.id,
            case_id=case_id,
            correlation_id=response.correlation_id,
            detail=name,
        )
        return search

    def run_estimate(self, case_id: str, search_id: str) -> None:
        """Start an estimate. Statistics arrive later, by polling.

        Estimation timing is wildly variable and not worth quoting a figure
        for — it depends on the tenant, the index state and how much Purview
        has to do. Do not create a search live in a demonstration and wait for
        it; run them beforehand and present completed statistics.
        """
        self._require_write("Running an estimate", Action.ESTIMATE_STARTED, case_id)
        response = self._timed(
            "estimate_start",
            lambda: self._ops.run_search(case_id=case_id, search_id=search_id),
        )
        self._record(
            Action.ESTIMATE_STARTED,
            Outcome.OK,
            target_id=search_id,
            case_id=case_id,
            correlation_id=response.correlation_id,
        )

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
        self._require_write("Initiating an export", Action.EXPORT_INITIATED, case_id)
        # The one action with a data-protection consequence outside this tool:
        # after it, content exists in a package someone will collect. Recorded
        # before and after, so an interrupted export is distinguishable from one
        # that never started.
        self._record(
            Action.EXPORT_INITIATED,
            Outcome.ATTEMPTED,
            target_id=search_id,
            case_id=case_id,
            detail=name,
        )
        response = self._ops.initiate_export(
            case_id=case_id, search_id=search_id, display_name=name
        )
        self._record(
            Action.EXPORT_INITIATED,
            Outcome.OK,
            target_id=search_id,
            case_id=case_id,
            correlation_id=response.correlation_id,
            detail=name,
        )
        return ExportHandoff(
            case_id=case_id, search_id=search_id, portal_url=portal_url
        )
