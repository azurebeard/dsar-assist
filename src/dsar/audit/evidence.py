"""The per-case evidence pack: what a data protection officer attaches.

`dsar audit verify` answers *"is the trail intact"*. That defends the tool. It
is not what someone responding to a subject access request needs to hand over,
which is narrower and about one case: **who searched, what for, when, and what
came back** — with something attesting that the record has not been edited.

Pure. Builds a structure and returns it; the rendering and the printing live in
`report.py`, which is one of the two files permitted to write to stdout.

## The integrity claim, and its exact shape

`verify_chain` is whole-chain only: it walks `prev_hash` linkage and sequence
ordering from the genesis record. Hand it a per-case subset and it reports a
break on nearly every record, because the first one is not `seq 1` and the
survivors are not contiguous.

So the pack **verifies the entire trail and then quotes the case's records**,
and it says which of those two things it did. The alternative — checking only
that each extracted record still hashes to itself — proves *"none of these was
edited"* and not *"none was removed from between them"*, and presenting that as
the integrity claim would be the seventh instance of this project's own
recurring defect.

If the whole chain does not verify, the pack refuses to present a clean
extract. A tampered trail cannot produce trustworthy evidence about part of
itself.

## What is not here, and why

No item content, no query terms, no subject identifiers. Those are absent from
the trail **by construction** — the record has no field that could hold them,
asserted by a structural test — so their absence here is not an omission to
apologise for. It is the design, and the pack says so rather than leaving a
reader to wonder what was withheld.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dsar.audit.record import Action, AuditRecord, Outcome
from dsar.audit.verify import VerifyResult

__all__ = ["EvidencePack", "SearchRecord", "build_evidence"]


@dataclass(frozen=True)
class SearchRecord:
    """One search, reassembled from the records that mention it."""

    name: str
    #: The Purview search id, from the record written after it was created.
    search_id: str = ""
    created_at: str = ""
    estimate_started_at: str = ""
    export_initiated_at: str = ""
    #: True when a create was attempted and no matching success followed — the
    #: shape of an interrupted write, which the trail exists to make visible.
    incomplete: bool = False


@dataclass(frozen=True)
class EvidencePack:
    case_id: str
    reference: str
    #: Verification of the WHOLE trail, not of the extract. See the module
    #: docstring: the extract's integrity derives from this.
    chain: VerifyResult
    events: tuple[AuditRecord, ...] = ()
    searches: tuple[SearchRecord, ...] = ()
    actors: tuple[str, ...] = ()
    subject_refs: tuple[str, ...] = ()
    refusals: tuple[AuditRecord, ...] = ()
    #: Records in the trail whose case could not be determined. Written before
    #: `case_id` existed, so a trail spanning that change has some — named
    #: rather than silently dropped, because "we found nothing" and "we could
    #: not tell" are different answers.
    unattributable: int = 0

    @property
    def trustworthy(self) -> bool:
        """Whether this extract can be relied on at all."""
        return self.chain.intact

    @property
    def first_seen(self) -> str:
        return self.events[0].ts if self.events else ""

    @property
    def last_seen(self) -> str:
        return self.events[-1].ts if self.events else ""


def build_evidence(
    records: list[AuditRecord], case_id: str, chain: VerifyResult
) -> EvidencePack:
    """Assemble the pack for one case from the whole trail.

    `records` is every record; `chain` is the result of verifying all of them.
    Both are passed in rather than read here, so this stays free of I/O and a
    caller cannot accidentally verify a subset.
    """
    mine = [r for r in records if r.case_id == case_id]

    # A case creation has no case id yet — the case does not exist when the
    # attempt is recorded. The reference in `detail` is the only link, so it is
    # recovered from the successful creation and used to find its own attempt.
    reference = next(
        (
            r.detail
            for r in mine
            if r.action == Action.CASE_CREATED.value and r.outcome == Outcome.OK.value
        ),
        "",
    )
    if reference:
        attempts = [
            r
            for r in records
            if r.action == Action.CASE_CREATED.value
            and r.outcome == Outcome.ATTEMPTED.value
            and r.detail == reference
            and r not in mine
        ]
        mine = sorted(mine + attempts, key=lambda r: r.seq)

    return EvidencePack(
        case_id=case_id,
        reference=reference,
        chain=chain,
        events=tuple(mine),
        searches=_searches(mine),
        actors=tuple(sorted({r.actor_upn or r.actor_oid for r in mine if r.actor_oid})),
        subject_refs=tuple(sorted({r.subject_ref for r in mine if r.subject_ref})),
        refusals=tuple(r for r in mine if r.outcome == Outcome.DENIED.value),
        unattributable=_unattributable(records, mine),
    )


#: Actions that concern a case. Sign-in and sign-out do not, so a record
#: without a case id is only *unattributable* if it is one of these.
_CASE_ACTIONS = frozenset(
    {
        Action.CASE_CREATED.value,
        Action.IDENTITY_EXPANDED.value,
        Action.SEARCH_CREATED.value,
        Action.ESTIMATE_STARTED.value,
        Action.EXPORT_INITIATED.value,
    }
)


def _unattributable(records: list[AuditRecord], mine: list[AuditRecord]) -> int:
    """Case events carrying no case id.

    Not simply "records with no case id" — the first run of this counted the
    sign-in and reported that a record could not be attributed, which is not
    true: a sign-in is not about a case and never was. Counting it invited a
    reader to wonder what was missing when nothing was.

    An attempted case creation is also excluded: the case does not exist when
    the attempt is recorded, so having no id is correct rather than lost.
    """
    seen = {id(r) for r in mine}
    return sum(
        1
        for r in records
        if not r.case_id
        and r.action in _CASE_ACTIONS
        and id(r) not in seen
        and not (
            r.action == Action.CASE_CREATED.value
            and r.outcome == Outcome.ATTEMPTED.value
        )
    )


def _searches(events: list[AuditRecord]) -> tuple[SearchRecord, ...]:
    """Reassemble each search from the records that mention it.

    Walked in sequence order and matched to the OPEN entry for a name, rather
    than to a single entry per name (WS10 SEC-H-04). Two searches sharing a
    name previously merged into one row that kept the second's creation time
    and the first's export time — an export timestamped before the search it
    exported, with one search id silently gone. In a document meant to be
    evidence that is not a cosmetic defect.

    The old defence — "the tool names them Naive and Expanded" — failed twice
    over: those names are constants, so re-running the workflow on one case
    collides on the ordinary path, and `/api/search/create` takes the name
    from the request body without constraining it.

    An entry closes when its creation succeeds and it has been exported, or
    when a new attempt appears for the same name. Records that arrive for a
    name with no open entry start one, so a trail that begins mid-case still
    reports what it can see.
    """
    entries: list[dict[str, object]] = []
    open_for_name: dict[str, dict[str, object]] = {}
    by_search_id: dict[str, dict[str, object]] = {}

    def start(name: str) -> dict[str, object]:
        entry: dict[str, object] = {
            "name": name, "search_id": "", "created_at": "",
            "estimate": "", "export": "", "attempted": False, "created": False,
        }
        entries.append(entry)
        open_for_name[name] = entry
        return entry

    for record in sorted(events, key=lambda r: r.seq):
        # A refusal carries the action DESCRIPTION in `detail`, not a search
        # name — it is reported separately.
        if record.outcome == Outcome.DENIED.value:
            continue

        if record.action == Action.SEARCH_CREATED.value and record.detail:
            name = record.detail
            if record.outcome == Outcome.ATTEMPTED.value:
                # A fresh attempt always starts a new search, even for a name
                # already seen. That is what makes a re-run two rows.
                start(name)["attempted"] = True
            elif record.outcome == Outcome.OK.value:
                entry = open_for_name.get(name) or start(name)
                entry["created"] = True
                entry["search_id"] = record.target_id
                entry["created_at"] = record.ts
                if record.target_id:
                    by_search_id[record.target_id] = entry

        elif record.action == Action.ESTIMATE_STARTED.value:
            found = by_search_id.get(record.target_id)
            if found is not None:
                found["estimate"] = record.ts

        elif record.action == Action.EXPORT_INITIATED.value:
            # Attributed by search id, never by name — the id is exact and a
            # name is not. An export whose search is not in this extract is
            # dropped rather than attached to the wrong row.
            found = by_search_id.get(record.target_id)
            if found is not None:
                found["export"] = record.ts

    return tuple(
        SearchRecord(
            name=str(entry["name"]),
            search_id=str(entry["search_id"]),
            created_at=str(entry["created_at"]),
            estimate_started_at=str(entry["estimate"]),
            export_initiated_at=str(entry["export"]),
            incomplete=bool(entry["attempted"]) and not bool(entry["created"]),
        )
        for entry in entries
    )
