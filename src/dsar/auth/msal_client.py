"""MSAL client construction. The only module that imports MSAL.

A structural test enforces that. Everything downstream takes a `TokenProvider`
and cannot discover which client class produced its token, which is what makes
one codebase serve both modes rather than two code paths wearing a shared name.
"""

from __future__ import annotations

import logging
from typing import Any

import msal

from dsar.config import Config

__all__ = ["build_public_client", "CLIENT_CAPABILITIES", "assert_no_broker_pop"]

log = logging.getLogger(__name__)

#: Continuous Access Evaluation. Declaring `cp1` is a *promise*: it tells the
#: STS this client will handle a claims challenge, and in exchange the STS
#: issues long-lived tokens it can revoke in near real time rather than short
#: ones it cannot. The promise is kept at the single Graph choke point, which
#: is the only place a 401 can arrive.
#:
#: `doctor` reads `xms_cc` back off the issued token, because declaring a
#: capability and having the STS agree are different things.
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
    if config.mode.is_hosted:
        return {"prompt": "select_account"}
    return {}
