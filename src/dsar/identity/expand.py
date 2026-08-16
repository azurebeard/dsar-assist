"""Identity expansion (Phase 5, A-20).

A DSAR arrives with a name and an email address. The estate knows the person by
more than that: a UPN, a former surname from before a marriage, proxy addresses
accumulated over three mail migrations, a personal address they used once in a
thread, a nickname everyone actually calls them. A search on the primary
address alone misses all of it, and the miss is invisible — the search returns
results, just not the right ones.

Two resolvers, both live since contract v3.1.0:

* `GraphDirectoryResolver` reads the directory through `find_users`, the
  operation E-05 added to §7. Its `$select` is fixed in `operations.py`, so
  the retrieval is bounded to the eight fields expansion actually reads.
* `DirectoryResolver` expands against a snapshot the caller supplies. Used by
  the tests, by replay mode, and by an operator who would rather not turn on
  `User.Read.All` at all.

`User.Read.All` is not requested unless identity expansion is enabled, so the
v1 consent surface stays at the §5 v1 scopes for anyone who does not use this.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Protocol

from dsar.identity.kql import DateRange, KqlError, build_kql, naive_kql

__all__ = [
    "Subject",
    "Identifier",
    "Expansion",
    "DirectoryResolver",
    "GraphDirectoryResolver",
    "ContractBlocked",
    "build_subject",
    "expand_subject",
]

log = logging.getLogger(__name__)

#: Directory fields read during expansion. An allowlist, for the same reason
#: the statistics allowlist exists: a directory record holds a great deal that
#: is nobody's business here — job title, manager, phone numbers, office.
DIRECTORY_FIELDS: frozenset[str] = frozenset(
    {
        "displayName",
        "givenName",
        "surname",
        "mail",
        "userPrincipalName",
        "proxyAddresses",
        "otherMails",
        "employeeId",
        "id",
    }
)


class ContractBlocked(RuntimeError):
    """An operation the contract does not permit was requested."""


@dataclass(frozen=True)
class Subject:
    """What the operator knows about the data subject before expansion."""

    primary_email: str
    display_name: str = ""
    aliases: tuple[str, ...] = ()
    former_names: tuple[str, ...] = ()
    other_emails: tuple[str, ...] = ()
    employee_id: str = ""
    date_from: str | None = None
    date_to: str | None = None

    @property
    def dates(self) -> DateRange:
        return DateRange(self.date_from, self.date_to)


@dataclass(frozen=True)
class Identifier:
    """One resolved way of referring to the subject, and where it came from."""

    value: str
    kind: str
    source: str

    def to_json(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class Expansion:
    subject: Subject
    identifiers: tuple[Identifier, ...]
    mentions: tuple[str, ...]
    kql: str
    naive: str
    warnings: tuple[str, ...] = field(default=())

    @property
    def addresses(self) -> list[str]:
        return [i.value for i in self.identifiers]

    def to_json(self) -> dict[str, Any]:
        return {
            "primary_email": self.subject.primary_email,
            "display_name": self.subject.display_name,
            "identifiers": [i.to_json() for i in self.identifiers],
            "mentions": list(self.mentions),
            # Former names are inside `mentions` for the query; they are also
            # named separately so the interface can label them as what they
            # are, rather than leaving a former name indistinguishable from a
            # nickname in a document that an operator reviews for coverage.
            "former_names": [f for f in self.subject.former_names if f.strip()],
            # Used to match the directory record, never searched — the
            # interface says which, because a chip that looks searched and is
            # not would misstate the query's coverage.
            "employee_id": self.subject.employee_id,
            "kql": self.kql,
            "naive_kql": self.naive,
            "warnings": list(self.warnings),
            "editable": True,
        }


class Resolver(Protocol):
    """Supplies directory records matching a subject."""

    def lookup(self, subject: Subject) -> list[dict[str, Any]]: ...


class DirectoryResolver:
    """Expands against a directory snapshot held in memory.

    The snapshot is whatever the caller supplies: a synthetic fixture in tests
    (INV-10), a recorded response in replay mode, or an export the operator
    produced themselves. Nothing here reaches the network.
    """

    def __init__(self, records: Iterable[dict[str, Any]]) -> None:
        self.records = [_project(record) for record in records]

    def lookup(self, subject: Subject) -> list[dict[str, Any]]:
        needles = {
            value.lower()
            for value in (
                subject.primary_email,
                *subject.other_emails,
                *subject.aliases,
            )
            if value
        }
        matches: list[dict[str, Any]] = []
        for record in self.records:
            if self._matches(record, subject, needles):
                matches.append(record)
        return matches

    def _matches(
        self, record: dict[str, Any], subject: Subject, needles: set[str]
    ) -> bool:
        if subject.employee_id and str(record.get("employeeId") or "") == subject.employee_id:
            return True

        candidates = {
            str(record.get("mail") or "").lower(),
            str(record.get("userPrincipalName") or "").lower(),
        }
        for proxy in record.get("proxyAddresses") or []:
            candidates.add(_strip_proxy_prefix(str(proxy)).lower())
        for other in record.get("otherMails") or []:
            candidates.add(str(other).lower())
        candidates.discard("")

        if needles & candidates:
            return True

        # Display-name match is the weakest signal and is used only when the
        # operator gave one, because two people can share a name and picking
        # the wrong one is a data breach rather than a bad search.
        if subject.display_name:
            return str(record.get("displayName") or "").lower() == subject.display_name.lower()
        return False


class GraphDirectoryResolver:
    """The live resolver, against the `find_users` operation.

    The projection is fixed in `operations.py`, so this class cannot widen what
    the directory returns even if it wanted to — it receives records already
    narrowed to `USER_SELECT` and narrows them again through `DIRECTORY_FIELDS`
    on the way in. Two allowlists in series is not redundancy: one belongs to
    the operations table, one to this module, and they are maintained by
    different concerns.

    Identity expansion must be enabled for `User.Read.All` to have been
    consented. If it is not, this raises rather than issuing a call that would
    fail with a confusing 403.
    """

    def __init__(self, operations: Any, enabled: bool = True) -> None:
        self.operations = operations
        self.enabled = enabled

    def lookup(self, subject: Subject) -> list[dict[str, Any]]:
        if not self.enabled or self.operations is None:
            # This message once offered "pass a `directory` snapshot in the
            # request body" — an instruction nothing implemented. The offline
            # resolver exists (`DirectoryResolver`) but is not reachable from
            # the API, and an error message is documentation with the highest
            # possible readership at the worst possible moment.
            raise ContractBlocked(
                "Directory lookup needs identity expansion enabled and the "
                "User.Read.All scope consented. Set DSAR_IDENTITY_EXPANSION=1 "
                "and sign in again. Anything the directory would have added "
                "can be supplied by hand in the subject fields."
            )

        addresses = _unique([subject.primary_email, *subject.other_emails])
        response = self.operations.find_users(
            addresses=addresses, employee_id=subject.employee_id
        )
        records = response.get("value", [])
        if not isinstance(records, list):
            return []
        return [record for record in records if isinstance(record, dict)]


def build_subject(body: dict[str, Any]) -> Subject:
    """Read a subject out of an API request body."""
    return Subject(
        primary_email=str(body.get("primary_email") or "").strip(),
        display_name=str(body.get("display_name") or "").strip(),
        aliases=_tuple(body.get("aliases")),
        former_names=_tuple(body.get("former_names")),
        other_emails=_tuple(body.get("other_emails")),
        employee_id=str(body.get("employee_id") or "").strip(),
        date_from=_optional(body.get("date_from")),
        date_to=_optional(body.get("date_to")),
    )


def expand_subject(subject: Subject, resolver: Resolver) -> Expansion:
    """Resolve a subject to identifiers and mentions, and build both queries."""
    if not subject.primary_email:
        raise KqlError("a primary email address is required")

    identifiers: list[Identifier] = [
        Identifier(subject.primary_email, "primary", "operator")
    ]
    for value in subject.other_emails:
        identifiers.append(Identifier(value, "other_mail", "operator"))
    for value in subject.aliases:
        identifiers.append(Identifier(value, "alias", "operator"))

    warnings: list[str] = []
    try:
        records = resolver.lookup(subject)
    except ContractBlocked as exc:
        records = []
        warnings.append(str(exc))

    for record in records:
        identifiers.extend(_identifiers_from(record))

    mentions: list[str] = []
    for value in (subject.display_name, *subject.former_names, *subject.aliases):
        if value and "@" not in value:
            mentions.append(value)
    for record in records:
        for key in ("displayName", "givenName", "surname"):
            value = str(record.get(key) or "").strip()
            # A bare given name is too broad to search as free text — "Jane"
            # matches everyone called Jane. Surnames and full names are kept.
            if value and key != "givenName":
                mentions.append(value)

    addresses = _unique([i.value for i in identifiers if "@" in i.value])
    deduped_identifiers = _unique_identifiers(identifiers)

    if len(addresses) == 1 and not mentions:
        warnings.append(
            "Expansion found nothing beyond the address supplied. Either the "
            "directory snapshot is empty or this subject genuinely has one "
            "identifier — worth confirming before relying on the result."
        )

    return Expansion(
        subject=subject,
        identifiers=tuple(deduped_identifiers),
        mentions=tuple(_unique(mentions)),
        kql=build_kql(addresses, _unique(mentions), subject.dates),
        naive=naive_kql(subject.primary_email),
        warnings=tuple(warnings),
    )


# ------------------------------------------------------------------ helpers


def _identifiers_from(record: dict[str, Any]) -> list[Identifier]:
    out: list[Identifier] = []
    source = str(record.get("userPrincipalName") or record.get("id") or "directory")

    mail = str(record.get("mail") or "").strip()
    if mail:
        out.append(Identifier(mail, "mail", source))

    upn = str(record.get("userPrincipalName") or "").strip()
    if upn:
        out.append(Identifier(upn, "upn", source))

    for proxy in record.get("proxyAddresses") or []:
        address = _strip_proxy_prefix(str(proxy)).strip()
        if address:
            out.append(Identifier(address, "proxy_address", source))

    for other in record.get("otherMails") or []:
        address = str(other).strip()
        if address:
            # A personal address in otherMails is exactly the kind of thing a
            # naive search misses and a DSAR response is judged on.
            out.append(Identifier(address, "other_mail", source))

    return out


def _project(record: dict[str, Any]) -> dict[str, Any]:
    """Keep only the allowlisted directory fields."""
    return {key: value for key, value in record.items() if key in DIRECTORY_FIELDS}


def _strip_proxy_prefix(value: str) -> str:
    """`SMTP:jane@x` and `smtp:jane@x` both mean the address after the colon."""
    if ":" in value:
        prefix, _, rest = value.partition(":")
        if prefix.lower() in {"smtp", "sip", "x500", "eum"}:
            return rest
    return value


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        cleaned = (value or "").strip()
        if not cleaned or cleaned.lower() in seen:
            continue
        seen.add(cleaned.lower())
        out.append(cleaned)
    return out


def _unique_identifiers(identifiers: Iterable[Identifier]) -> list[Identifier]:
    seen: set[str] = set()
    out: list[Identifier] = []
    for identifier in identifiers:
        key = identifier.value.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(identifier)
    return out


def _tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


def _optional(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None
