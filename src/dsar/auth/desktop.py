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
        account = self._account or self._first_account()
        if account is None:
            raise ReauthRequired("no account in the cache; sign in again")

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

    def _first_account(self) -> dict[str, Any] | None:
        accounts = self._app.get_accounts()
        return accounts[0] if accounts else None
