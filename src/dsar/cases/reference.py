"""The DSAR reference, and how it travels in the case itself.

`ediscoveryCase.externalId` is Microsoft's documented field for a customer case
number. It is settable at creation, returned in the list response, and — unlike
a `displayName` convention — it survives someone renaming the case in the
Purview portal, which someone will.

The stored form is prefixed and versioned:

    DSAR-2026-0142   ->   dsar:v1:DSAR-2026-0142

The prefix lets `list_cases` identify the cases this tool created without
matching a name pattern. The version lets the convention change later without
orphaning everything created under the old one — a case whose `externalId` does
not parse simply is not ours, which is a cleaner rule than trying to migrate.
"""

from __future__ import annotations

import re

__all__ = [
    "PREFIX",
    "encode_reference",
    "decode_reference",
    "is_ours",
    "InvalidReference",
]

VERSION = "v1"
PREFIX = f"dsar:{VERSION}:"

#: A DSAR reference is an operator-supplied identifier from a ticketing system.
#: Deliberately permissive about shape and strict about characters: a colon
#: would break the prefix parse, and control characters have no business in a
#: value that reaches a URL, a Graph filter and an audit record.
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,62}[A-Za-z0-9]$")

MAX_LENGTH = 64


class InvalidReference(ValueError):
    """The reference is empty, too long, or carries characters it must not."""


def encode_reference(reference: str) -> str:
    """`DSAR-2026-0142` -> `dsar:v1:DSAR-2026-0142`."""
    cleaned = reference.strip()
    if not cleaned:
        raise InvalidReference("a DSAR reference is required")
    if len(cleaned) > MAX_LENGTH:
        raise InvalidReference(
            f"a DSAR reference must be {MAX_LENGTH} characters or fewer "
            f"(got {len(cleaned)})"
        )
    if ":" in cleaned:
        raise InvalidReference(
            "a DSAR reference must not contain a colon — it is the separator "
            "used to mark cases this tool created"
        )
    if not _REFERENCE.match(cleaned):
        raise InvalidReference(
            "a DSAR reference may contain letters, digits, spaces and the "
            "characters . _ / -, and must start and end with a letter or digit"
        )
    return f"{PREFIX}{cleaned}"


def decode_reference(external_id: str | None) -> str | None:
    """`dsar:v1:DSAR-2026-0142` -> `DSAR-2026-0142`, or None if not ours.

    None is the ordinary answer for a case created by a person in the portal,
    or by another tool. Not an error — this tenant is shared, and the request
    list showing only its own cases is the intended behaviour.
    """
    if not external_id or not external_id.startswith(PREFIX):
        return None
    reference = external_id[len(PREFIX) :].strip()
    return reference or None


def is_ours(external_id: str | None) -> bool:
    return decode_reference(external_id) is not None
