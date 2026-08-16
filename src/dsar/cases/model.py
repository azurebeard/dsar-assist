"""Typed views over the Graph JSON this application reads.

Hand-written rather than generated or schema-validated, for the same reason the
rest of the validation in this codebase is hand-written: what matters is a
small number of fields whose absence or shape has a specific meaning, and a
model that shrugs at a missing field is exactly wrong here. A statistic that
silently reads zero because a key moved is the worst failure this tool can
have — the predecessor shipped that bug, and six probe queries returning six
identical counts is what eventually surfaced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Mapping

from dsar.cases.deadline import Deadline, deadline_for
from dsar.cases.received import decode_received
from dsar.cases.reference import decode_reference

__all__ = ["Case", "Search", "Statistics", "parse_case", "parse_search"]


@dataclass(frozen=True)
class Case:
    id: str
    display_name: str
    #: The DSAR reference, decoded from `externalId`. None when the case was
    #: not created by this tool — a person in the portal, or another tool.
    reference: str | None
    status: str
    created: str
    #: Object ID of the creator, when Graph supplies it. Used only to filter
    #: the *view* between "my cases" and "all cases"; it is not a boundary.
    #: The boundary is Purview RBAC, which this tool does not control.
    created_by_oid: str = ""
    created_by_name: str = ""
    #: When the request was RECEIVED, decoded from the case description. Not
    #: `created`, which is when somebody opened a case in Purview — always
    #: later, and the statutory clock runs from receipt. `None` when the case
    #: predates this, or when the marker was edited away in the portal.
    received: date | None = None

    @property
    def is_ours(self) -> bool:
        return self.reference is not None

    def deadline(self, today: date) -> Deadline | None:
        """The statutory deadline, or `None` when no receipt date is recorded.

        Never guesses from `created`. A plausible wrong statutory date is the
        one outcome this must not produce.
        """
        if self.received is None:
            return None
        return deadline_for(self.received, today)


@dataclass(frozen=True)
class Statistics:
    """Estimate results. Counts, volumes and location names — never content."""

    item_count: int | None = None
    #: Bytes. Graph reports `unindexedItemsSize` separately; both are metadata.
    total_size: int | None = None
    #: Mailboxes plus sites. Kept alongside the two components rather than
    #: replacing them, because "3 locations" and "1 mailbox and 2 sites" answer
    #: different questions and the second is the one that shows a naive query
    #: never looked at SharePoint.
    location_count: int | None = None
    mailbox_count: int | None = None
    site_count: int | None = None
    #: Items Purview could not index. Not added to `item_count`: they are a
    #: different kind of fact, and quietly inflating a total is how a DSAR
    #: response acquires a number nobody can defend.
    unindexed_count: int | None = None
    percent_progress: int | None = None
    status: str = ""
    #: True when an estimate has finished and these numbers mean something.
    complete: bool = False
    #: True when it finished against some locations but not all.
    partial: bool = False


@dataclass(frozen=True)
class Search:
    id: str
    display_name: str
    created: str
    #: The KQL. Held in memory to show the operator what will run and let them
    #: edit it. Never written to a log or an audit record: it names a real
    #: person and their aliases, and a log line containing it is a second,
    #: ungoverned copy of exactly the data this tool exists to handle carefully.
    content_query: str = ""
    statistics: Statistics = field(default_factory=Statistics)


def parse_case(raw: Mapping[str, Any]) -> Case:
    created_by = raw.get("createdBy") or {}
    user = created_by.get("user") if isinstance(created_by, dict) else {}
    user = user if isinstance(user, dict) else {}

    return Case(
        id=str(raw.get("id", "")),
        display_name=str(raw.get("displayName", "")),
        reference=decode_reference(raw.get("externalId")),
        status=str(raw.get("status", "")),
        created=str(raw.get("createdDateTime", "")),
        created_by_oid=str(user.get("id", "")),
        created_by_name=str(user.get("displayName", "")),
        received=decode_received(raw.get("description")),
    )


def parse_search(raw: Mapping[str, Any]) -> Search:
    return Search(
        id=str(raw.get("id", "")),
        display_name=str(raw.get("displayName", "")),
        created=str(raw.get("createdDateTime", "")),
        content_query=str(raw.get("contentQuery", "")),
        statistics=_parse_statistics(raw),
    )


def _parse_statistics(raw: Mapping[str, Any]) -> Statistics:
    """Read the estimate from the search's **own** expanded operation.

    `?$expand=lastEstimateStatisticsOperation` is what makes the answer this
    search's. A bare GET returns no statistics, and the case-level operations
    collection carries no reference back to the search that produced each one,
    so with several searches in a case there is no way to attribute an
    operation by listing them.

    Absence is represented as None, never as zero. "No estimate has run yet"
    and "the estimate found nothing" are different facts, and a UI that shows 0
    for the first is lying.
    """
    operation = raw.get("lastEstimateStatisticsOperation")
    if not isinstance(operation, dict):
        return Statistics()

    status = str(operation.get("status", ""))
    # Documented caseOperationStatus values: notStarted, submissionFailed,
    # running, succeeded, partiallySucceeded, failed, unknownFutureValue.
    #
    # `partiallySucceeded` was missing, and it is the one that matters: Purview
    # returns it when the estimate completed against some locations and not
    # others, which is normal on a tenant with a mailbox it could not reach. The
    # counts are real and the portal shows them, but this code called it
    # "running" and the UI waited forever for a state that had already arrived.
    complete = status.lower() in {"succeeded", "partiallysucceeded", "completed"}
    #: True when the estimate finished but not against everything it was asked
    #: to search. Surfaced rather than smoothed over: a DSAR response built on a
    #: partial count is a compliance problem, not a rounding error.
    partial = status.lower() == "partiallysucceeded"

    mailboxes = _int_or_none(operation.get("mailboxCount"))
    sites = _int_or_none(operation.get("siteCount"))
    # Sum rather than `or`: the original took the first truthy value, so a
    # search hitting 2 mailboxes and 3 sites reported 2 locations, and one
    # hitting 0 mailboxes and 3 sites reported 3 — inconsistently, depending on
    # which happened to be zero. "Locations" means both.
    locations = None if mailboxes is None and sites is None else (mailboxes or 0) + (sites or 0)

    return Statistics(
        item_count=_int_or_none(operation.get("indexedItemCount")),
        total_size=_int_or_none(operation.get("indexedItemsSize")),
        location_count=locations,
        mailbox_count=mailboxes,
        site_count=sites,
        unindexed_count=_int_or_none(operation.get("unindexedItemCount")),
        percent_progress=_int_or_none(operation.get("percentProgress")),
        status=status,
        complete=complete,
        partial=partial,
    )


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None
