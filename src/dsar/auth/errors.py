"""Auth domain errors and the claims-challenge parser.

`ReauthRequired` and `ClaimsChallenge` are distinct types because they call for
different operator action: the first needs a fresh sign-in, the second needs a
sign-in that satisfies a specific Conditional Access or CAE claim. Collapsing
them would lose that distinction exactly when it matters.

Ported from the predecessor at 8652e638, largely verbatim. `parse_claims_challenge`
handles both forms Entra actually sends and the regex comment records why — that
is the most expensive twenty lines in the old repository.

Dropped in the port: `UnknownAccount` (there is no account registry; a provider
is bound to one identity at construction) and `CachePersistenceUnavailable`
(there is no persistent cache, so there is nothing to be unavailable).
"""

from __future__ import annotations

import base64
import binascii
import json
import re

__all__ = [
    "AuthError",
    "ReauthRequired",
    "ClaimsChallenge",
    "NotAssigned",
    "parse_claims_challenge",
    "challenge_error_code",
]


class AuthError(Exception):
    """Base for every auth-layer failure."""


class ReauthRequired(AuthError):
    """Silent token acquisition failed. The operator must sign in again.

    Raised rather than prompting. Whatever is holding the request decides how
    to surface it; the auth layer never opens a browser on its own.
    """

    def __init__(self, reason: str = "silent acquisition failed") -> None:
        self.reason = reason
        super().__init__(f"reauth required: {reason}")


class ClaimsChallenge(AuthError):
    """A Conditional Access or CAE challenge was returned.

    `claims` is the **decoded JSON**, ready to pass to MSAL as
    `claims_challenge`. Entra sends it base64url-encoded and MSAL wants it
    decoded, so a caller that forwards the raw header value gets a challenge
    that silently never satisfies.
    """

    def __init__(
        self,
        claims: str,
        reason: str = "conditional access or CAE challenge",
    ) -> None:
        self.claims = claims
        self.reason = reason
        super().__init__(f"claims challenge: {reason}")


class NotAssigned(AuthError):
    """The signed-in operator holds no DSAR app role.

    Distinct from a Purview authorisation failure. This one means the operator
    is not assigned to *this application* in Entra, which is an access request
    to whoever owns the enterprise app — not a Purview role group question.
    """

    def __init__(self, upn: str = "") -> None:
        self.upn = upn
        super().__init__(
            f"{upn or 'the signed-in account'} is not assigned a DSAR role on this "
            f"application"
        )


# `WWW-Authenticate: Bearer realm="", ..., claims="eyJhY2Nlc3NfdG9rZW4i..."`
#
# The value is usually base64url, which contains no quotes. It is occasionally
# raw JSON with the inner quotes backslash-escaped, so the character class must
# admit escape pairs — a naive `[^"]+` truncates that form at the first `\"`
# and yields a fragment that looks like JSON but is not.
_CLAIMS_RE = re.compile(r'claims\s*=\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)
_ERROR_RE = re.compile(r'error\s*=\s*"([^"]+)"', re.IGNORECASE)


def parse_claims_challenge(www_authenticate: str | None) -> str | None:
    """Extract and decode the `claims` directive from a `WWW-Authenticate` header.

    Returns the decoded JSON string, or None when the header carries no claims
    directive — the ordinary case for a plain expired token, which is a
    `ReauthRequired` rather than a challenge.
    """
    if not www_authenticate:
        return None
    match = _CLAIMS_RE.search(www_authenticate)
    if not match:
        return None

    raw = match.group(1)
    # Some Entra endpoints send the JSON unencoded, with the inner quotes
    # escaped for the header. Unescape and take it, but only if it parses —
    # handing MSAL a malformed claims blob fails later and less clearly.
    if raw.lstrip().startswith("{"):
        candidate = raw.replace('\\"', '"').replace("\\\\", "\\")
        try:
            json.loads(candidate)
        except json.JSONDecodeError:
            return None
        return candidate

    padded = raw + "=" * (-len(raw) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None

    try:
        json.loads(decoded)
    except json.JSONDecodeError:
        return None
    return decoded


def challenge_error_code(www_authenticate: str | None) -> str | None:
    """Return the `error` directive of a `WWW-Authenticate` header, if present."""
    if not www_authenticate:
        return None
    match = _ERROR_RE.search(www_authenticate)
    return match.group(1) if match else None
