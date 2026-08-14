"""Domain error taxonomy for Microsoft Graph.

Pure types. No HTTP, nothing that can reach the network.

| Domain error          | Trigger                     | What the operator does   |
|-----------------------|-----------------------------|--------------------------|
| `ReauthRequired`      | silent token failure        | sign in again            |
| `ClaimsChallenge`     | CAE / Conditional Access    | sign in, satisfying a policy |
| `PurviewRoleMissing`  | 403, or 401 with no challenge | get an eDiscovery role, or check the case exists |
| `BillingNotConfigured`| export refused commercially | enable billing or change licence |
| `Throttled`           | 429 / 503 + `Retry-After`   | wait — honoured exactly  |
| `TransientGraphError` | 5xx, network                | retry                    |
| `PermanentGraphError` | 4xx other                   | nothing; it will not fix itself |

Ported from the predecessor at 8652e638 essentially verbatim, including the
long-form messages. Every one of them encodes something measured against a live
tenant rather than predicted from documentation, and the measurements cost days.
The reasoning is kept with the code because the messages look over-written until
you know why each clause is there.

`ReauthRequired` and `ClaimsChallenge` live in `dsar/auth/errors.py` and are
re-exported so the taxonomy reads as one table at the point of use.
"""

from __future__ import annotations

from dsar.auth.errors import ClaimsChallenge, ReauthRequired

__all__ = [
    "GraphError",
    "BillingNotConfigured",
    "Throttled",
    "TransientGraphError",
    "PermanentGraphError",
    "PurviewRoleMissing",
    "ReauthRequired",
    "ClaimsChallenge",
]


class GraphError(Exception):
    """Base for every Graph-layer failure."""

    def __init__(self, message: str, *, status: int | None = None, code: str | None = None):
        self.status = status
        self.code = code
        super().__init__(message)


class Throttled(GraphError):
    """429 or 503 carrying `Retry-After`. The caller waits.

    `retry_after` is honoured exactly : no jitter, no multiplier.
    """

    def __init__(self, retry_after: int, *, status: int = 429, code: str | None = None):
        self.retry_after = max(0, retry_after)
        super().__init__(
            f"throttled by Microsoft Graph; retry after {self.retry_after}s",
            status=status,
            code=code,
        )


class TransientGraphError(GraphError):
    """A 5xx without `Retry-After`, or a connection-level failure."""


class PermanentGraphError(GraphError):
    """A 4xx that retrying will not fix."""


class BillingNotConfigured(PermanentGraphError):
    """The call failed for a commercial reason, not a technical one.

    On a Microsoft 365 E3 tenant the Graph **Export** API requires a configured
    Azure pay-as-you-go subscription; case, search, hold and statistics calls do
    not. On E5 export is included. Verified against Microsoft Learn 2026-07-31.

    Kept distinct from `PurviewRoleMissing` for the same reason that one is
    distinct from token expiry: the symptom is identical — a call that ought to
    work does not — and the remedies share nothing. This one is not fixed by
    signing in, and not fixed by a role group either. Someone has to enable
    billing or change a licence.

    **A taxonomy member** (B-09, resolved 2026-08-02).
    Still implemented as a subclass of `PermanentGraphError` so the job state it
    produces stays `failed` — the amendment named it in the taxonomy; it did not
    give it a state of its own.
    """

    def __init__(
        self,
        *,
        status: int = 403,
        code: str | None = None,
        operation: str | None = None,
        detail: str = "",
    ):
        self.operation = operation
        what = f"{operation} " if operation else ""
        super().__init__(
            f"{what}was refused for a billing or licensing reason, not a "
            f"permissions one. On Microsoft 365 E3 the Graph export API needs an "
            f"Azure pay-as-you-go subscription configured for Microsoft Purview; "
            f"case, search and statistics calls do not, which is why everything "
            f"up to this point worked. On E5 export is included. Signing in "
            f"again will not help, and neither will an eDiscovery role change."
            + (f" Graph said: {detail}" if detail else ""),
            status=status,
            code=code,
        )


class PurviewRoleMissing(PermanentGraphError):
    """403 indicating the account lacks an eDiscovery role assignment.

    Distinct from token expiry on purpose (measured live, 2026-07-31). The two produce identical
    symptoms — a call that used to work stops working — but the remedies are
    unrelated: one needs a sign-in, the other needs a role group membership
    that only a compliance administrator can grant. Conflating them sends the
    operator to re-authenticate repeatedly against a problem sign-in cannot fix.
    """

    def __init__(
        self,
        *,
        username: str | None = None,
        status: int = 403,
        code: str | None = None,
        operation: str | None = None,
        inferred_from_401: bool = False,
        case_scoped: bool = False,
    ):
        self.username = username
        self.operation = operation
        self.inferred_from_401 = inferred_from_401
        self.case_scoped = case_scoped
        who = username or "this account"
        what = f" while calling {operation}" if operation else ""

        if inferred_from_401 and case_scoped:
            # Measured 2026-08-02: a deleted case, a case id that never
            # existed, and a role-less account all return **exactly** 401 /
            # `UnknownError` / no `WWW-Authenticate`. They are indistinguishable
            # at the HTTP layer, and deliberately so — telling them apart would
            # leak whether a given case exists.
            #
            # So this message must not pick one. Naming the likely cause first
            # and admitting the ambiguity beats a confident wrong answer that
            # sends an operator to a role group they are already in.
            super().__init__(
                f"{who} is authenticated, but Purview refused access to the case"
                f"{what}. Two different causes produce this identical response, and "
                f"Purview will not say which — distinguishing them would reveal "
                f"whether a case exists. In order of likelihood: (1) the case is "
                f"gone or was never there — deleted in the portal, or a stale id "
                f"from this queue; check it in Purview first. (2) the account holds "
                f"no eDiscovery role group — but if other cases work for this "
                f"account, it is not this. Signing in again fixes neither.",
                status=status,
                code=code,
            )
            return

        # No case in the path, so a missing case cannot be the explanation and
        # the diagnosis is unambiguous.
        evidence = (
            " Purview returned 401 with no WWW-Authenticate header, which is how"
            " it refuses an authenticated caller that holds no role — a genuine"
            " token failure carries that header."
            if inferred_from_401
            else ""
        )
        super().__init__(
            f"{who} is authenticated, but has no Microsoft Purview eDiscovery role"
            f"{what}. This is not a token problem — signing in again will not help."
            f"{evidence} Add the account to the eDiscovery Manager role group in "
            f"the Purview portal, then try again.",
            status=status,
            code=code,
        )
