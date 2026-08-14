"""The desktop token provider — one operator, one process, tokens in memory.

Implements `TokenProvider`. Bound to a single identity at construction, so
nothing downstream can name another account even by mistake.
"""

from __future__ import annotations

import logging
from typing import Any

import msal

from dsar.auth.errors import ClaimsChallenge, ReauthRequired
from dsar.auth.msal_client import scopes_for
from dsar.auth.provider import Principal
from dsar.config import Config

__all__ = ["DesktopTokenProvider"]

log = logging.getLogger(__name__)


class DesktopTokenProvider:
    """Silent-only token acquisition against one signed-in account.

    Interactive sign-in is the web layer's job — it owns the browser redirect —
    so this provider never prompts. When there is no silent path it raises,
    and the caller decides how to surface that. A library that opens a browser
    is a library that opens a browser in a container, at three in the morning,
    on a machine nobody is looking at.
    """

    def __init__(
        self,
        app: msal.ClientApplication,
        config: Config,
        principal: Principal,
        account: dict[str, Any] | None = None,
    ) -> None:
        self._app = app
        self._config = config
        self._principal = principal
        self._account = account

    @property
    def principal(self) -> Principal:
        return self._principal

    def get_token(self, *, claims_challenge: str | None = None) -> str:
        account = self._account or self._account_for_principal()
        if account is None:
            raise ReauthRequired(
                "no cached account matches the signed-in operator; sign in again"
            )

        result = self._app.acquire_token_silent_with_error(
            scopes_for(self._config),
            account=account,
            claims_challenge=claims_challenge,
        )

        if result and "access_token" in result:
            return str(result["access_token"])

        error = (result or {}).get("error", "")
        description = (result or {}).get("error_description", "")

        # A challenge that survives a silent attempt needs an interactive
        # step-up. Some Conditional Access grants — MFA, compliant device —
        # cannot be satisfied by a refresh token no matter how the request is
        # shaped, so retrying silently is a loop that never terminates.
        if claims_challenge:
            raise ClaimsChallenge(
                claims_challenge,
                reason="silent acquisition could not satisfy the challenge",
            )

        log.info("silent token acquisition failed: %s", error or "no result")
        raise ReauthRequired(description or error or "silent acquisition failed")

    def step_up_url(self, claims_challenge: str) -> str:
        """Where to send the operator. The claims must survive the round trip.

        The web layer builds the real authorize URL, because it owns the flow
        cache and the redirect URI. This returns the local route that starts
        that flow carrying the challenge — a step-up that drops the claims
        produces a sign-in which succeeds and changes nothing, which reads as
        progress and is not.
        """
        from urllib.parse import quote

        return f"/auth/login?claims={quote(claims_challenge, safe='')}"

    def _account_for_principal(self) -> dict[str, Any] | None:
        """The cached account belonging to THIS principal, or nothing.

        This used to return `accounts[0]` — positional, unfiltered, never
        compared to the principal. The class docstring claimed the provider was
        "bound to one identity at construction, so nothing downstream can name
        another account even by mistake", and it was bound only for auditing
        and the role check. Token acquisition was bound to position (WS10
        SEC-M-04).

        Unreachable today: one session, one cache, one account. The failure
        mode if it ever became reachable is not a wrong token — it is a Graph
        call made as operator A while every audit record for it names operator
        B, with the hash chain attesting to the wrong name. That is precisely
        the failure this audit trail exists to make impossible, so the claim
        is now enforced rather than described.

        Matched on `home_account_id`, whose leading segment is the user's
        object id — the same immutable `(oid, tid)` the principal is keyed on,
        and never `username`, which is mutable and reassignable.
        """
        wanted = self._principal.oid
        for account in self._app.get_accounts():
            home = str(account.get("home_account_id", ""))
            local = str(account.get("local_account_id", ""))
            if home.split(".", 1)[0] == wanted or local == wanted:
                return dict(account)

        # Refuse rather than fall back to position. A provider that guesses is
        # a provider that can be wrong silently, and this one is wired into
        # every audited action.
        accounts = self._app.get_accounts()
        if accounts:
            log.warning(
                "the token cache holds %d account(s), none matching the "
                "signed-in operator; refusing rather than choosing",
                len(accounts),
            )
        return None
