"""The identity seam. Nothing downstream knows which mode produced its token.

`TokenProvider` is bound to **one identity at construction**. The predecessor's
equivalent took a `home_account_id` on every call, because a shared worker
served many accounts and an invariant existed to stop a token being reused
across them. With no worker there is exactly one identity per request context —
the operator on the desktop, the session's user when hosted — so the bug that
invariant defended against is now impossible by construction rather than
prevented by discipline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

__all__ = ["Principal", "TokenProvider", "Role", "ROLE_OPERATOR", "ROLE_AUDITOR"]

ROLE_OPERATOR = "DSAR.Operator"
ROLE_AUDITOR = "DSAR.Auditor"

#: Every role this application understands. A token carrying a role outside
#: this set is a registration that has drifted from the code.
KNOWN_ROLES = frozenset({ROLE_OPERATOR, ROLE_AUDITOR})

Role = str


@dataclass(frozen=True)
class Principal:
    """Who is signed in, as read from the **ID token** and nowhere else.

    Never built from an access token. Microsoft's integration checklist is
    explicit that access-token format can change or become encrypted without
    notice, so an application that parses one is depending on an implementation
    detail it was told not to depend on.
    """

    #: Immutable per (user, tenant). The identity key everywhere — never `upn`,
    #: `email` or `preferred_username`, all of which are mutable and reassignable.
    oid: str
    tenant_id: str
    #: Display only. Appears in the UI and in audit records as a convenience
    #: alongside `oid`, never as the key.
    upn: str = ""
    roles: frozenset[str] = field(default_factory=frozenset)
    #: Satisfied Conditional Access authentication contexts.
    acrs: frozenset[str] = field(default_factory=frozenset)
    #: How authentication actually happened — recorded, not enforced.
    amr: tuple[str, ...] = ()
    auth_time: int | None = None
    #: Per-token GUID. Surfaces in Entra sign-in logs as Request ID and in
    #: Graph activity logs as SignInActivityId, which is what lets an audit
    #: record be joined back to the sign-in that produced it.
    uti: str = ""
    login_hint: str = ""
    #: Client capabilities the STS **agreed** to, read from `xms_cc` on the ID
    #: token. Declaring `cp1` is a promise this client will handle a claims
    #: challenge; whether Entra accepted it is only visible here.
    #:
    #: `msal_client.py` claimed `doctor` read this back. Nothing did — the
    #: comment was the whole implementation, and it was the sixth recorded
    #: instance of a stated guarantee with no check behind it (B-04, B-14).
    #: `doctor` could never have done it: it has no session and therefore no
    #: ID token. It belongs here, where the token is.
    client_capabilities: frozenset[str] = field(default_factory=frozenset)
    #: The scopes the STS actually granted, read from the **token response**
    #: body — OAuth response data, not the access token, so the rule above
    #: (never parse an access token) stays intact. The requested scopes are a
    #: choice this codebase makes; the granted scopes are Entra's answer, and
    #: only the answer can prove what the token carries.
    granted_scopes: frozenset[str] = field(default_factory=frozenset)

    @property
    def download_scope_granted(self) -> bool:
        """Was any download-capable scope granted?

        The eDiscovery download permission lives on a separate resource this
        codebase never names, so a Graph token response should never grant one
        — which is exactly why the check is cheap and the refusal absolute.
        README's no-data-plane claim cites a runtime check; this is it
        (INV-30). The comment used to be the whole implementation.
        """
        return any("download" in scope.lower() for scope in self.granted_scopes)

    @property
    def cae_negotiated(self) -> bool:
        """Was CAE agreement observed? False means UNOBSERVED, never declined.

        Read live for the first time 2026-08-17: a desktop sign-in with `cp1`
        declared carried no `xms_cc` on the ID token. That matches Microsoft's
        documentation, which places `xms_cc` on **access** tokens — it exists
        for the resource to read — and this application never parses an access
        token. So the agreement is structurally unobservable here, and this
        property is expected to stay False on current Entra behaviour.

        The consequence stands either way: **do not claim near-real-time
        revocation.** Declaring `cp1` still buys claims-challenge handling,
        which is kept at the Graph choke point regardless.
        """
        return "cp1" in self.client_capabilities

    @property
    def key(self) -> tuple[str, str]:
        return (self.oid, self.tenant_id)

    @property
    def can_write(self) -> bool:
        """May this operator create cases and searches, and initiate exports?

        An auditor may not. Note what this is and is not: a *user interface*
        decision plus a server-side refusal, layered over Purview RBAC, which
        is the actual boundary and which this application cannot elevate.
        """
        return ROLE_OPERATOR in self.roles

    def satisfies(self, auth_context: str) -> bool:
        return auth_context in self.acrs


class TokenProvider(Protocol):
    """One identity's access to Microsoft Graph."""

    @property
    def principal(self) -> Principal: ...

    def get_token(self, *, claims_challenge: str | None = None) -> str:
        """A Graph access token, refreshed silently where possible.

        Raises `ReauthRequired` when no silent path exists, and
        `ClaimsChallenge` when the challenge needs an interactive step-up that
        this provider cannot perform on its own.
        """
        ...

    def step_up_url(self, claims_challenge: str) -> str:
        """Where to send the operator to satisfy a challenge.

        The claims must be threaded into the authorization request. A step-up
        that drops them produces a sign-in that succeeds and changes nothing,
        which is worse than a failure because it looks like progress.
        """
        ...
