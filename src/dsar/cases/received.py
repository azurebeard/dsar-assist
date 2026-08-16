"""The received date, carried in the case's `description`.

The statutory clock runs from **receipt**, and a DSAR arrives by email days
before anyone opens a case — so `createdDateTime` is always later than the
truth and is the wrong answer. Being wrong about a statutory date is precisely
the failure a tool for answering subject access requests must not have.

So the date has to be stored, and the architecture's rule is that **Graph is
the source of truth** — there is no local database and a structural test bans
`sqlite3` outright. Of the three writable fields on an `ediscoveryCase`,
`displayName` and `externalId` are both taken:

  `displayName`  human-readable, and a person may rename it in the portal
  `externalId`   the machine key, `dsar:v1:<ref>`, whose colon separator is
                 guarded precisely so the parse is unambiguous
  `description`  written at creation and, until now, never read back

`description` it is. It costs no new operation and no format change to the key
that makes a case findable from another machine.

## Two properties this deliberately has

**Write-once.** There is no `update_case` in the permitted-operations table,
deliberately — the rule that keeps that table meaningful is that a case without
our marker simply is not ours. So the received date is fixed when the case is
created, exactly like the reference, and correcting it means the Purview
portal. That is a real limitation and the interface says so rather than letting
an operator discover it.

**Degrades to "not recorded".** `description` is free text a person can edit in
the portal, so the marker can be removed or mangled. Every failure to parse
returns `None`, which the interface renders as *"received date not recorded"* —
the same state as a case created before this existed. Corruption therefore
lands on a known, visible answer rather than a plausible wrong date.
"""

from __future__ import annotations

import re
from datetime import date

__all__ = ["MARKER", "encode_received", "decode_received", "BOILERPLATE"]

#: The marker, on its own first line. A prefix rather than a suffix so it
#: survives a person appending notes underneath it, which is the likeliest
#: edit — and so a truncated description loses the notes rather than the date.
MARKER = "DSAR-Received:"

#: What the tool has always written. Kept so a case with no received date is
#: byte-identical to one created before this module existed.
BOILERPLATE = (
    "Raised via DSAR Assist. Control plane only; no item content is "
    "downloaded by this tool."
)

#: Anchored to the start of a line, tolerant of surrounding whitespace and of
#: the marker's case, because it is read back out of a field a human can edit.
#: Shape only — `2026-13-45` matches here and is rejected by `date.fromisoformat`
#: below, which is the check that actually decides.
_MARKER_LINE = re.compile(
    rf"^\s*{re.escape(MARKER)}\s*(\d{{4}}-\d{{2}}-\d{{2}})\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def encode_received(received: date | None, description: str = "") -> str:
    """Build the case description, carrying `received` if there is one.

    With no received date the result is exactly the previous boilerplate, so
    nothing changes for a case created without one.
    """
    body = description.strip() or BOILERPLATE
    if received is None:
        return body
    return f"{MARKER} {received.isoformat()}\n{body}"


def decode_received(description: str | None) -> date | None:
    """The received date, or `None` for anything that is not one.

    Absent, mangled, hand-edited, or a well-formed-looking date that is not a
    real one — all return `None`. There is no partial answer and no guess: a
    caller gets a date it can rely on, or nothing.
    """
    if not description:
        return None
    match = _MARKER_LINE.search(description)
    if match is None:
        return None
    try:
        return date.fromisoformat(match.group(1))
    except ValueError:
        # Shape without substance — `2026-13-45` and friends. Someone edited
        # the description by hand and got it wrong, which is exactly the case
        # that must not produce a statutory deadline.
        return None
