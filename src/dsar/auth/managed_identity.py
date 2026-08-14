"""Mint the client assertion from the Container Apps identity endpoint.

Hosted mode authenticates to Entra with a **federated identity credential**: a
user-assigned managed identity mints a token for `api://AzureADTokenExchange`,
and that token is presented as the client assertion when the app redeems an
authorization code for a delegated Graph token. No secret exists anywhere, so
there is nothing to store, rotate or leak.

Written against the documented REST contract rather than taken from an SDK, for
two reasons.

`msal.ManagedIdentityClient` does not list Container Apps among its supported
sources. It would very likely work — the contract is the App Service one — and
"very likely" is how the predecessor came to fail on a second machine. Thirty
lines against a contract that is written down beats an SDK path that happens to
work today.

And `azure-identity` brings `azure-core`, which brings its own HTTP stack, for
one GET. The dependency budget is asserted by a structural test precisely so
that trade has to be argued rather than absorbed.

This is one of three modules permitted to import an HTTP client. The others are
the Graph choke point and the append-blob audit sink.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass

import httpx

__all__ = [
    "AssertionError_",
    "ManagedIdentityToken",
    "client_assertion_for",
    "storage_token_for",
    "TOKEN_EXCHANGE_AUDIENCE",
    "STORAGE_RESOURCE",
    "IDENTITY_API_VERSION",
]

log = logging.getLogger(__name__)

#: The audience Entra requires on a federated credential assertion. Exactly
#: this string — the FIC's `audiences` must contain it and nothing else works.
#: Not a URL that resolves; an identifier.
TOKEN_EXCHANGE_AUDIENCE = "api://AzureADTokenExchange"

#: The audience for a data-plane token against Azure Storage. The audit
#: container is written with this, so the storage account can set
#: `allowSharedKeyAccess: false` and there is no account key or SAS anywhere —
#: the same reasoning as the client secret.
STORAGE_RESOURCE = "https://storage.azure.com/"

#: Container Apps speaks the App Service identity contract at this version.
IDENTITY_API_VERSION = "2019-08-01"

#: Re-mint this long before expiry. The assertion is used at the moment a token
#: is redeemed or refreshed, and a token minted 30 seconds before it expires
#: fails at Entra rather than here — where the error names a grant problem and
#: sends the reader in the wrong direction entirely.
_EXPIRY_SKEW_SECONDS = 300

#: The identity endpoint is on the local network namespace and answers fast or
#: not at all. A long timeout here turns an infrastructure fault into a hung
#: sign-in, which reads to an operator as the tool being broken.
_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)


class AssertionError_(RuntimeError):
    """The client assertion could not be minted.

    Named with a trailing underscore so it cannot shadow the builtin. Every
    message names the endpoint and what to check, because this fails at deploy
    time far more often than at run time, and the two causes — identity not
    attached, wrong client id — look identical from the application's side.
    """


@dataclass
class ManagedIdentityToken:
    """A callable returning a current managed-identity token for one resource.

    Two resources are used, and one mechanism serves both rather than the
    caching and expiry logic existing twice:

      `TOKEN_EXCHANGE_AUDIENCE`  the client assertion, presented to Entra
      `STORAGE_RESOURCE`         the data-plane token for the audit container

    A callable rather than a string, and this is the load-bearing part. MSAL
    invokes it lazily at redemption — verified offline, see
    `verification/2026-08-14-fic-assertion-offline.md`. A token computed once
    at startup would work in every test and begin failing token refreshes some
    hours into a deployment, for reasons that look nothing like an expiry.
    """

    uami_client_id: str
    resource: str = TOKEN_EXCHANGE_AUDIENCE
    http: httpx.Client | None = None

    def __post_init__(self) -> None:
        self._cached: str | None = None
        self._expires_at: float = 0.0
        # A refresh under concurrent sign-ins would otherwise mint several
        # tokens and race to store them. Harmless but wasteful, and it makes
        # the identity endpoint's request log unreadable when diagnosing.
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            now = time.time()
            if self._cached and now < self._expires_at:
                return self._cached
            token, expires_on = self._mint()
            self._cached = token
            self._expires_at = expires_on - _EXPIRY_SKEW_SECONDS
            log.info(
                "minted a managed identity token for %s, valid for %ds",
                self.resource,
                max(0, int(self._expires_at - now)),
            )
            return token

    # ------------------------------------------------------------------

    def _mint(self) -> tuple[str, float]:
        endpoint = os.environ.get("IDENTITY_ENDPOINT")
        header = os.environ.get("IDENTITY_HEADER")
        if not endpoint or not header:
            raise AssertionError_(
                "IDENTITY_ENDPOINT and IDENTITY_HEADER are not set, so no managed "
                "identity is attached to this container. Check the Container App "
                "has `identity: UserAssigned` and that the identity is the one in "
                "DSAR_UAMI_CLIENT_ID."
            )

        client = self.http or httpx.Client(timeout=_TIMEOUT)
        try:
            response = client.get(
                endpoint,
                params={
                    "resource": self.resource,
                    "api-version": IDENTITY_API_VERSION,
                    "client_id": self.uami_client_id,
                },
                # Not Authorization. The identity endpoint authenticates the
                # caller with this header, whose value the platform injects
                # into the container's environment.
                headers={"X-IDENTITY-HEADER": header},
            )
        except httpx.HTTPError as exc:
            raise AssertionError_(
                f"the identity endpoint at {endpoint} could not be reached: {exc}"
            ) from exc
        finally:
            if self.http is None:
                client.close()

        if response.status_code != 200:
            # The body is the platform's, not a user's, and it names the
            # specific misconfiguration — an identity that is not attached
            # reads differently from a client id that does not match one that
            # is. Worth surfacing rather than flattening to a status code.
            raise AssertionError_(
                f"the identity endpoint returned {response.status_code}. "
                f"Check DSAR_UAMI_CLIENT_ID names an identity assigned to this "
                f"container app. Response: {response.text[:400]}"
            )

        return _parse(response.json())


def _parse(payload: object) -> tuple[str, float]:
    """Pull the token and its expiry out of the identity endpoint's response.

    `expires_on` is documented as a string, and its *format* varies by host:
    epoch seconds on some, a human-readable date on others. Rather than parse
    both, an unrecognised value falls back to a short lifetime — the assertion
    is then re-minted more often than necessary, which costs a local HTTP call
    and cannot produce a wrong answer. Guessing a far-future expiry could.
    """
    if not isinstance(payload, dict):
        raise AssertionError_("the identity endpoint returned a non-object response")

    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise AssertionError_(
            "the identity endpoint returned no access_token. This is the "
            "response shape changing, not a configuration problem."
        )

    raw = payload.get("expires_on")
    try:
        expires_on = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        # The caller subtracts the skew from whatever this returns, so the
        # fallback has to be *twice* the skew to yield a usable window. Adding
        # one skew would net to zero and mint a fresh token on every single
        # call — a hot loop against the identity endpoint that still returns
        # correct answers, which is the kind that survives review.
        fallback = time.time() + (2 * _EXPIRY_SKEW_SECONDS)
        log.warning(
            "identity endpoint returned an unparsable expires_on (%r); "
            "caching the assertion for %ds instead",
            raw,
            _EXPIRY_SKEW_SECONDS,
        )
        return token, fallback

    return token, expires_on


def client_assertion_for(
    uami_client_id: str, http: httpx.Client | None = None
) -> ManagedIdentityToken:
    """The assertion presented to Entra when redeeming an authorization code."""
    return ManagedIdentityToken(uami_client_id, TOKEN_EXCHANGE_AUDIENCE, http)


def storage_token_for(
    uami_client_id: str, http: httpx.Client | None = None
) -> ManagedIdentityToken:
    """The data-plane token for the append-blob audit container."""
    return ManagedIdentityToken(uami_client_id, STORAGE_RESOURCE, http)
