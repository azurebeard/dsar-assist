"""The audit record, and the chain that makes tampering detectable.

Each record carries the hash of the one before it:

    hash = sha256(prev_hash || canonical_json(record without its own hash))

The genesis record's `prev_hash` is sixty-four zeros. Change any record and
every hash after it stops matching, so `dsar audit verify` can name the exact
`seq` where the trail was altered.

**Why a chain rather than a database constraint.** The predecessor enforced
append-only with SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers. That was
correct, and it was exactly the kind of guarantee that cannot travel: it lives
inside the engine, so the moment a record leaves the database it is just a row
in a file. A chain travels. Any sink, any host, one verifier — and tampering
becomes *detectable* rather than merely *prevented*, which for a defensibility
artefact is the stronger property. Prevention fails silently when someone has
filesystem access; detection does not.

**What must never be in here.** Subject identifiers, `proxyAddresses`,
`otherMails`, `employeeId`, and the KQL itself. Those are third-party personal
data, and writing them to a durable local file would create a second,
ungoverned copy of exactly what this tool exists to handle carefully — inside
the artefact whose purpose is to demonstrate restraint. The subject appears as
a case-scoped pseudonym and nowhere else.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from dsar.logging_setup import scrub

__all__ = [
    "Action",
    "Outcome",
    "AuditRecord",
    "GENESIS_HASH",
    "canonical_json",
    "case_pseudonym",
    "MAX_DETAIL_BYTES",
]

GENESIS_HASH = "0" * 64

#: Detail is a human-readable note, not a payload. Truncated so a caller cannot
#: turn the trail into a data store by accident or otherwise.
MAX_DETAIL_BYTES = 512


class Action(str, enum.Enum):
    """What happened. A closed vocabulary — a free-text verb is unsearchable."""

    SIGN_IN = "sign_in"
    SIGN_IN_REFUSED = "sign_in_refused"
    SIGN_OUT = "sign_out"
    CASE_CREATED = "case_created"
    IDENTITY_EXPANDED = "identity_expanded"
    #: A reviewed narrowing was rendered onto a query. The record carries the
    #: template id and the template file's version, never the query text — the
    #: search that eventually runs is recorded name-only, so this is the only
    #: place the trail can say which reviewed narrowing shaped it.
    TEMPLATE_APPLIED = "template_applied"
    SEARCH_CREATED = "search_created"
    ESTIMATE_STARTED = "estimate_started"
    EXPORT_INITIATED = "export_initiated"


class Outcome(str, enum.Enum):
    OK = "ok"
    DENIED = "denied"
    FAILED = "failed"
    #: Written *before* a mutating call goes out, so a crash inside the request
    #: window is visible on the next read rather than silently ambiguous. An
    #: `attempted` with no matching `ok` is the shape of an interrupted write.
    ATTEMPTED = "attempted"


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    ts: str
    action: str
    outcome: str
    #: Who. `oid` and `tid` because they are immutable; `upn` alongside for a
    #: human reading the trail, never as the key.
    actor_oid: str = ""
    actor_upn: str = ""
    tenant_id: str = ""
    #: The Purview case or search this concerns. An identifier, not content.
    target_id: str = ""
    #: The data subject, as a case-scoped pseudonym. Never their name, address
    #: or employee id.
    subject_ref: str = ""
    #: Per-token identifier from the ID token. Joins this record to the Entra
    #: sign-in log and to Graph activity logs at investigation time.
    uti: str = ""
    #: The `client-request-id` we sent to Graph, echoed back as `request-id`.
    correlation_id: str = ""
    detail: str = ""
    #: The case every record about a case belongs to, so the trail can answer
    #: "what happened to this one". `target_id` alone cannot: it holds the case
    #: id on some actions and the SEARCH id on others, and nothing at all on an
    #: attempted creation or a refusal.
    #:
    #: Added after the trail existed, which is why it is in ADDED_AFTER_V1
    #: below. Empty on sign-in and sign-out, which are not case events.
    case_id: str = ""
    prev_hash: str = GENESIS_HASH
    hash: str = ""

    def with_hash(self, prev_hash: str) -> AuditRecord:
        """Return this record chained onto `prev_hash`."""
        body = _hashed_body(asdict(self))
        body["prev_hash"] = prev_hash
        digest = hashlib.sha256(
            prev_hash.encode("ascii") + canonical_json(body).encode("utf-8")
        ).hexdigest()
        return AuditRecord(**{**{k: v for k, v in asdict(self).items() if k != "hash"},
                              "prev_hash": prev_hash, "hash": digest})

    def recompute(self) -> str:
        return hashlib.sha256(
            self.prev_hash.encode("ascii")
            + canonical_json(_hashed_body(asdict(self))).encode("utf-8")
        ).hexdigest()

    def to_json(self) -> str:
        return canonical_json(asdict(self))

    @staticmethod
    def from_json(line: str) -> AuditRecord:
        raw = json.loads(line)
        known = {f for f in AuditRecord.__dataclass_fields__}
        return AuditRecord(**{k: v for k, v in raw.items() if k in known})


#: Fields that did not exist when the first record was written.
#:
#: The hash covers whatever `asdict()` returns, so adding a field to this
#: dataclass changes the hash of every record ever written — including the ones
#: already sitting in an append blob under a 2555-day immutability policy,
#: which would then all verify as `altered`. That was measured before this
#: field was added, not assumed.
#:
#: So a field added later is hashed **only when it carries a value**. The
#: guarantee is unchanged in both directions:
#:
#:   * an old record has no value, the field is skipped, and its original hash
#:     still verifies;
#:   * a new record with a value hashes it, so changing that value is detected;
#:   * and CLEARING it on a new record is detected too, because the hash it was
#:     written with included it.
#:
#: The one thing this cannot detect is a field added to an old record and left
#: empty — which is a no-op, since an empty field says nothing.
ADDED_AFTER_V1: tuple[str, ...] = ("case_id",)


def _hashed_body(fields: dict[str, Any]) -> dict[str, Any]:
    """The fields that participate in the hash, in the shape they are hashed."""
    return {
        key: value
        for key, value in fields.items()
        if key != "hash" and not (key in ADDED_AFTER_V1 and not value)
    }


def canonical_json(value: Mapping[str, Any]) -> str:
    """One byte sequence per record, or the chain is unverifiable.

    Sorted keys and no whitespace, because a hash over a dict with an arbitrary
    ordering verifies on the machine that wrote it and nowhere else.
    `ensure_ascii=False` so a name with an accent in it hashes as the text it
    is rather than as escapes.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def case_pseudonym(case_id: str, identifier: str) -> str:
    """A stable stand-in for the data subject, scoped to one case.

    Keyed on the case, so the same person in two cases produces two different
    pseudonyms. That is deliberate: it lets a reader follow one subject through
    one case without the trail becoming a cross-case index of who has been
    searched for, which is a register nobody asked this tool to keep.

    Not reversible without the identifier — and the identifier is exactly what
    is not written down. Someone holding the trail alone learns that a subject
    was searched for, not who.
    """
    if not identifier:
        return ""
    digest = hmac.new(
        case_id.encode("utf-8"), identifier.strip().lower().encode("utf-8"), hashlib.sha256
    )
    return digest.hexdigest()[:16]


def build(
    *,
    seq: int,
    action: Action,
    outcome: Outcome,
    actor_oid: str = "",
    actor_upn: str = "",
    tenant_id: str = "",
    target_id: str = "",
    case_id: str = "",
    subject_ref: str = "",
    uti: str = "",
    correlation_id: str = "",
    detail: str = "",
) -> AuditRecord:
    """Build an unchained record, with `detail` scrubbed and truncated."""
    safe = scrub(detail or "")
    if isinstance(safe, str) and len(safe.encode("utf-8")) > MAX_DETAIL_BYTES:
        safe = safe.encode("utf-8")[:MAX_DETAIL_BYTES].decode("utf-8", "ignore")
    return AuditRecord(
        seq=seq,
        ts=now_iso(),
        case_id=case_id,
        action=action.value,
        outcome=outcome.value,
        actor_oid=actor_oid,
        actor_upn=actor_upn,
        tenant_id=tenant_id,
        target_id=target_id,
        subject_ref=subject_ref,
        uti=uti,
        correlation_id=correlation_id,
        detail=str(safe),
    )
