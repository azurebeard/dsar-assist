"""MSAL client construction. The only module that imports MSAL.

A structural test enforces that. Everything downstream takes a `TokenProvider`
and cannot discover which client class produced its token, which is what makes
one codebase serve both modes rather than two code paths wearing a shared name.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import msal

from dsar.auth.managed_identity import client_assertion_for
from dsar.config import Config, ConfigError

__all__ = [
    "build_client",
    "build_public_client",
    "build_confidential_client",
    "CLIENT_CAPABILITIES",
    "assert_no_broker_pop",
]

log = logging.getLogger(__name__)

#: Continuous Access Evaluation. Declaring `cp1` is a *promise*: it tells the
#: STS this client will handle a claims challenge, and in exchange the STS
#: issues long-lived tokens it can revoke in near real time rather than short
#: ones it cannot. The promise is kept at the single Graph choke point, which
#: is the only place a 401 can arrive.
#:
#: Declaring a capability and having the STS agree are different things, so
#: `xms_cc` is read back off the ID token at sign-in and surfaced on
#: `/api/whoami` and in the audit record — see `Principal.cae_negotiated`.
#:
#: This comment used to say `doctor` did that. Nothing did, and `doctor` never
#: could: it has no session and therefore no ID token. The comment was the
#: entire implementation for several weeks (B-04, B-14) and was the sixth
#: recorded instance of a stated guarantee with no check behind it.
CLIENT_CAPABILITIES = ["cp1"]


def build_public_client(
    config: Config, http_client: Any | None = None
) -> msal.PublicClientApplication:
    """The desktop client: public, PKCE, no credential of any kind.

    The token cache is `msal.TokenCache` — in memory, with no `serialize`
    method. `SerializableTokenCache` is banned by a structural test, so
    "tokens never touch disk" is a property of the build rather than a habit.

    That is the fix for the failure that motivated this rewrite. The
    predecessor persisted tokens through `msal-extensions`, whose libsecret
    backend needs a system package pip cannot install; inside a virtualenv the
    encrypted backend silently disappeared and the tool degraded to interactive
    sign-in on every launch, on hosts that had a perfectly good keyring.

    `http_client` exists for one reason: MSAL performs OIDC discovery when the
    application is constructed, so a test that builds one reaches the network.
    The suite forbids that — a test in the predecessor lost its HTTP mock, made
    a real call to Graph, and failed for a plausible-looking reason nobody
    attributed for twenty minutes. Injecting a client is MSAL's own supported
    seam for this. Production callers pass nothing.
    """
    kwargs: dict[str, Any] = {}
    if http_client is not None:
        kwargs["http_client"] = http_client
    return msal.PublicClientApplication(
        config.client_id,
        # Tenant-scoped, never `/common` or `/organizations`. A token from
        # another tenant cannot be silently accepted, and `tid` is pinned again
        # at claim validation so the guarantee does not rest on this line alone.
        authority=config.authority,
        client_capabilities=CLIENT_CAPABILITIES,
        token_cache=msal.TokenCache(),
        **kwargs,
    )


def build_confidential_client(
    config: Config,
    assertion: Callable[[], str],
    http_client: Any | None = None,
) -> msal.ConfidentialClientApplication:
    """The hosted client: confidential, and holding no secret.

    `client_credential` is a dict whose only key is `client_assertion`, and
    whose value is a **callable**. Both halves are load-bearing and both are
    asserted structurally:

    * A `str` here would be a client secret. The structural test requires a
      dict literal keyed exactly `"client_assertion"`, so the type system is
      not the only thing standing between this design and a secret.
    * A pre-computed string would be a managed identity token frozen at
      startup. MSAL invokes the callable lazily at redemption — verified
      offline, `verification/2026-08-14-fic-assertion-offline.md` — so a
      long-lived process re-mints rather than beginning to fail token refreshes
      some hours in, for reasons that look nothing like an expiry.

    Everything downstream receives a `TokenProvider` and cannot tell which
    client class produced its token. That is what makes this one codebase
    serving two modes rather than two code paths sharing a name.
    """
    kwargs: dict[str, Any] = {}
    if http_client is not None:
        kwargs["http_client"] = http_client
    return msal.ConfidentialClientApplication(
        config.client_id,
        authority=config.authority,
        client_credential={"client_assertion": assertion},
        client_capabilities=CLIENT_CAPABILITIES,
        token_cache=msal.TokenCache(),
        **kwargs,
    )


def build_client(
    config: Config, http_client: Any | None = None
) -> msal.ClientApplication:
    """The client for this deployment. The only place the mode is consulted.

    Three call sites used to name `build_public_client` directly. That is one
    per place a future confidential mode could be forgotten, and the newest one
    is exactly where nobody looks — the same argument the ASGI layer makes for
    keeping the session and origin checks in a single handler.

    Everything downstream takes a `TokenProvider` and cannot discover which
    class produced its token, so this is the whole of the difference.
    """
    if not config.mode.is_hosted:
        return build_public_client(config, http_client)
    if not config.uami_client_id:
        raise ConfigError(
            "hosted mode needs DSAR_UAMI_CLIENT_ID — the client assertion is "
            "minted by a user-assigned managed identity, and there is no "
            "secret to fall back to. This is the design working, not a gap."
        )
    return build_confidential_client(
        config, client_assertion_for(config.uami_client_id), http_client
    )


def assert_no_broker_pop(app: msal.ClientApplication) -> bool:
    """Report whether proof-of-possession is available. It is not, here.

    MSAL's public-client PoP goes through a broker — WAM on Windows, the macOS
    broker. There is no broker in a Linux container, so sender-constrained
    tokens are unavailable to this application whatever the deployment.

    Asserted rather than assumed, because the compensating controls in the
    design document are only honest if the thing they compensate for is really
    absent: in-memory-only tokens, `cp1` so an administrative revoke lands in
    minutes, and phishing-resistant MFA so a stolen refresh token cannot be
    re-minted on a new device.
    """
    probe = getattr(app, "is_pop_supported", None)
    if probe is None:
        return False
    try:
        supported = bool(probe())
    except Exception:  # a diagnostic must never take down the caller
        return False
    if supported:
        log.info(
            "proof-of-possession is available on this platform; the design "
            "assumes it is not, so revisit that assumption"
        )
    return supported


def scopes_for(config: Config) -> list[str]:
    """Graph scopes to request. Reserved OIDC scopes are MSAL's to add.

    `openid`, `profile` and `offline_access` are injected by MSAL and rejected
    if passed explicitly, so the list carries only resource scopes.
    """
    return list(config.scopes)


def flow_extras(config: Config) -> dict[str, Any]:
    """Extra authorize-request parameters.

    `prompt=select_account` is hosted-only and it is not cosmetic. Without it,
    a shared instance relies on whatever Entra session the browser already has,
    so operator B arriving after operator A signs in **as operator A** — silently,
    with a correct-looking UI. It is deliberately absent on the desktop, where
    a single operator re-selecting their account on every sign-in is friction
    with nothing to buy.
    """
    #
    # `response_mode` is deliberately left at Entra's default of `query`, and
    # this is a decision rather than an omission (WS10 SEC-L-02). RFC 9700
    # §4.3.1 prefers `form_post`, and MSAL warns about it on every call — but
    # `form_post` makes the callback a cross-site POST, and both cookies are
    # `SameSite=Lax`, which a browser does not send on one. Choosing it would
    # trade a code in a URL for a sign-in that silently fails to find its own
    # flow cookie.
    #
    # What makes `query` acceptable here, each checked rather than assumed:
    # PKCE `S256` with the verifier held server-side and single-use, so an
    # intercepted code is not redeemable; `Referrer-Policy: no-referrer` on
    # every response; and request logging by route template only — the live
    # instance logs `GET /auth/callback` with no query string.
    if config.mode.is_hosted:
        return {"prompt": "select_account"}
    return {}
