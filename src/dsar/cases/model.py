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
from typing import Any, Mapping

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

    @property
    def is_ours(self) -> bool:
        return self.reference is not None


@dataclass(frozen=True)
class Statistics:
    """Estimate results. Counts, volumes and location names — never content."""

    item_count: int | None = None
    #: Bytes. Graph reports `unindexedItemsSize` separately; both are metadata.
    total_size: int | None = None
    location_count: int | None = None
    status: str = ""
    #: True when an estimate has completed and these numbers mean something.
    complete: bool = False


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
    complete = status.lower() in {"succeeded", "completed"}

    return Statistics(
        item_count=_int_or_none(operation.get("indexedItemCount")),
        total_size=_int_or_none(operation.get("indexedItemsSize")),
        location_count=_int_or_none(operation.get("mailboxCount"))
        or _int_or_none(operation.get("siteCount")),
        status=status,
        complete=complete,
    )


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None
