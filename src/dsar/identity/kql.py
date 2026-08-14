"""KQL generation for a resolved data subject.

Two queries are produced from every expansion, and the second one is the point:

* `naive` — the primary email address alone. What most people write.
* `expanded` — every resolved identifier, plus free-text mentions, plus date
  scoping.

Running both and comparing the item counts is the demonstration. It needs no
content to make its case, which is exactly the argument the product is making.

The generated query is shown to the operator and is editable before submission
— it is not a nicety. That is not a nicety: an expansion is a set of inferences about who
someone is, and inferences belong in front of the person accountable for the
search rather than inside it.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

__all__ = ["build_kql", "naive_kql", "quote_phrase", "KqlError", "DateRange"]

log = logging.getLogger(__name__)

_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Control characters and double quotes cannot appear inside a KQL phrase.
# Rejected rather than escaped: KQL has no portable escape for a quote inside a
# phrase, so "escaping" would mean silently changing what was searched for.
_ILLEGAL = re.compile(r'["\x00-\x1f\x7f]')


class KqlError(ValueError):
    """A value cannot be placed in a query without changing its meaning."""


@dataclass(frozen=True)
class DateRange:
    start: str | None = None
    end: str | None = None

    def __post_init__(self) -> None:
        for value in (self.start, self.end):
            if value is not None and not _ISO_DATE.match(value):
                raise KqlError(f"date must be YYYY-MM-DD, got {value!r}")
        if self.start and self.end and self.start > self.end:
            raise KqlError(f"date range starts after it ends: {self.start} > {self.end}")

    @property
    def is_set(self) -> bool:
        return bool(self.start or self.end)


def quote_phrase(value: str) -> str:
    """Wrap a value as a KQL phrase, refusing anything that would break out."""
    cleaned = value.strip()
    if not cleaned:
        raise KqlError("empty value")
    if _ILLEGAL.search(cleaned):
        raise KqlError(
            "value contains a quote or control character and cannot be searched "
            "verbatim; edit it in the query box before submitting"
        )
    return f'"{cleaned}"'


def _or_group(clauses: list[str]) -> str:
    if not clauses:
        return ""
    if len(clauses) == 1:
        return clauses[0]
    return "(" + " OR ".join(clauses) + ")"


def _date_clause(dates: DateRange) -> str:
    """Scope by date across both mail and file workloads.

    Mail items carry `sent`; SharePoint and OneDrive items carry
    `lastmodifiedtime`. Scoping on `sent` alone silently drops every file in
    range, which is the kind of miss a DSAR response cannot afford.
    """
    if not dates.is_set:
        return ""

    def bounds(field: str) -> str:
        parts = []
        if dates.start:
            parts.append(f"{field}>={dates.start}")
        if dates.end:
            parts.append(f"{field}<={dates.end}")
        return "(" + " AND ".join(parts) + ")"

    return _or_group([bounds("sent"), bounds("lastmodifiedtime")])


def naive_kql(primary_email: str) -> str:
    """The query an operator writes without expansion. The comparison baseline."""
    return f"participants:{quote_phrase(primary_email)}"


def build_kql(
    addresses: list[str],
    mentions: list[str] | None = None,
    dates: DateRange | None = None,
) -> str:
    """Build the expanded query.

    `addresses` become `participants:` clauses — items the subject sent or
    received. `mentions` become free-text clauses, which catch the case the
    participant clauses cannot: someone else discussing the subject by name or
    nickname in a thread the subject was never on.
    """
    participant_clauses = [
        f"participants:{quote_phrase(address)}" for address in _dedupe(addresses)
    ]
    if not participant_clauses:
        raise KqlError("at least one address is required to build a query")

    mention_clauses = [quote_phrase(mention) for mention in _dedupe(mentions or [])]

    who = _or_group(participant_clauses + mention_clauses)
    when = _date_clause(dates or DateRange())
    return f"{who} AND {when}" if when else who


def _dedupe(values: list[str]) -> list[str]:
    """Case-insensitive dedupe, order preserved. Blank and unusable values drop out."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        cleaned = (value or "").strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        if _ILLEGAL.search(cleaned):
            # Dropped rather than raising: one unusable alias out of twelve
            # should not fail the whole expansion. The operator sees the query
            # before it runs and can add it back by hand.
            log.debug("dropped an identifier that cannot be expressed in KQL")
            continue
        seen.add(key)
        out.append(cleaned)
    return out
