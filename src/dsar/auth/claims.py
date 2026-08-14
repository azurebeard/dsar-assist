"""ID-token claim validation. This part is ours, not MSAL's.

MSAL validates the ID token's signature, issuer, audience and nonce, and
refreshes signing keys. It does not decide whether *this* application should
let *this* person in. That decision is here.

Two properties are enforced regardless of configuration:

  - `tid` is pinned. The authority is already tenant-scoped rather than
    `/common`, so a foreign-tenant token should be impossible; pinning the
    claim as well costs one comparison and means the guarantee does not rest
    on a single configuration value being right.
  - The access token is never parsed. Microsoft's integration checklist is
    explicit that its format can change or become encrypted without notice.

Role enforcement is deliberately a *policy* rather than a hard-coded rule — see
`RoleEnforcement`.
"""

from __future__ import annotations

import enum
import logging
from typing import Any, Mapping

from dsar.auth.errors import NotAssigned
from dsar.auth.provider import KNOWN_ROLES, Principal

__all__ = ["RoleEnforcement", "build_principal", "ClaimError"]

log = logging.getLogger(__name__)


class ClaimError(Exception):
    """The ID token is missing something it must carry, or carries a wrong tenant."""


class RoleEnforcement(enum.Enum):
    """How to treat the `roles` claim.

    Microsoft documents app roles for applications that sign users in and for
    APIs, but does not state the behaviour for **public clients** specifically.
    The Phase 1 probe answers it live against the tenant. This enum exists so
    that the answer tunes a setting instead of forcing a rewrite either way,
    and so the decision is recorded in one place rather than implied by the
    absence of an `if`.

    REQUIRED  A DSAR role must be present. The strongest posture, and correct
              when the probe shows the claim is emitted.

    ADVISORY  Enforce when present, allow when absent. Correct when the claim
              is NOT emitted to public clients: `appRoleAssignmentRequired` on
              the service principal already gated entry — a token was only
              issued because the operator is assigned — so refusing here would
              lock out every legitimate operator to no benefit.

    On the desktop the in-process check was never a security boundary in any
    case: the operator controls the process. The boundary is Entra refusing to
    issue a token at all. What the check buys is a clear message instead of a
    confusing Purview failure three screens later.
    """

    REQUIRED = "required"
    ADVISORY = "advisory"


def build_principal(
    id_token_claims: Mapping[str, Any],
    *,
    expected_tenant_id: str,
    enforcement: RoleEnforcement = RoleEnforcement.ADVISORY,
) -> Principal:
    """Validate the claims this application depends on, and build a `Principal`."""
    tid = str(id_token_claims.get("tid", ""))
    if not tid:
        raise ClaimError("ID token carries no `tid` claim")
    if tid != expected_tenant_id:
        # Should be unreachable behind a tenant-scoped authority. Unreachable
        # is a good place for an assertion, not a reason to omit one.
        raise ClaimError(
            f"ID token is from tenant {tid}, expected {expected_tenant_id}"
        )

    oid = str(id_token_claims.get("oid", ""))
    if not oid:
        raise ClaimError("ID token carries no `oid` claim; cannot identify the operator")

    raw_roles = id_token_claims.get("roles") or []
    if isinstance(raw_roles, str):  # Entra sends a list; be liberal in what we accept
        raw_roles = [raw_roles]
    roles = frozenset(str(r) for r in raw_roles)

    unknown = roles - KNOWN_ROLES
    if unknown:
        # Not fatal: an extra role means the registration has gained something
        # the code does not model, which is worth saying out loud but is not a
        # reason to refuse a person their work.
        log.warning("ID token carries unrecognised app role(s): %s", sorted(unknown))

    recognised = roles & KNOWN_ROLES
    if not recognised:
        if enforcement is RoleEnforcement.REQUIRED:
            raise NotAssigned(str(id_token_claims.get("preferred_username", "")))
        log.info(
            "no DSAR app role in the ID token; proceeding on the strength of "
            "appRoleAssignmentRequired, which is what admitted this token"
        )

    acrs_raw = id_token_claims.get("acrs") or []
    if isinstance(acrs_raw, str):
        acrs_raw = [acrs_raw]

    amr_raw = id_token_claims.get("amr") or []
    if isinstance(amr_raw, str):
        amr_raw = [amr_raw]

    auth_time = id_token_claims.get("auth_time")

    return Principal(
        oid=oid,
        tenant_id=tid,
        upn=str(
            id_token_claims.get("preferred_username")
            or id_token_claims.get("upn")
            or ""
        ),
        roles=recognised,
        acrs=frozenset(str(a) for a in acrs_raw),
        amr=tuple(str(a) for a in amr_raw),
        auth_time=int(auth_time) if isinstance(auth_time, (int, float)) else None,
        uti=str(id_token_claims.get("uti", "")),
        login_hint=str(id_token_claims.get("login_hint", "")),
    )
