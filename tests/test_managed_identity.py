"""The client assertion, and the confidential client that consumes it.

Hosted mode's whole no-secret claim rests on these two pieces: a managed
identity mints a token, and MSAL presents it as the client assertion. Half of
that is already verified against MSAL itself
(`verification/2026-08-14-fic-assertion-offline.md`); this covers the half we
wrote.

Nothing here reaches the network. `conftest.py` guards the socket, and the
identity endpoint is a fake — the contract is documented, so a fake that
follows it is the honest test. What cannot be tested offline is whether Entra
*accepts* the assertion, which needs a real Container App and is the one open
item in B-03.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest

from dsar.auth.managed_identity import (
    IDENTITY_API_VERSION,
    STORAGE_RESOURCE,
    TOKEN_EXCHANGE_AUDIENCE,
    AssertionError_,
    ManagedIdentityToken,
    client_assertion_for,
    storage_token_for,
)

ENDPOINT = "http://localhost:42356/msi/token"
UAMI = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def identity_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDENTITY_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("IDENTITY_HEADER", "the-platform-injected-secret")


def _client(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _ok(token: str = "assertion-jwt", expires_in: float = 3600) -> Any:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "access_token": token,
                "expires_on": str(int(time.time() + expires_in)),
                "resource": TOKEN_EXCHANGE_AUDIENCE,
                "token_type": "Bearer",
            },
        )

    handler.calls = calls  # type: ignore[attr-defined]
    return handler


# --------------------------------------------------------------- the request


def test_it_asks_for_the_token_exchange_audience(identity_env: None) -> None:
    """`api://AzureADTokenExchange` exactly. The federated credential's
    `audiences` must contain this and nothing else is accepted."""
    handler = _ok()
    assertion = ManagedIdentityToken(UAMI, http=_client(handler))
    assert assertion() == "assertion-jwt"

    request = handler.calls[0]  # type: ignore[attr-defined]
    assert request.url.params["resource"] == TOKEN_EXCHANGE_AUDIENCE
    assert request.url.params["api-version"] == IDENTITY_API_VERSION
    assert request.url.params["client_id"] == UAMI


def test_it_authenticates_with_the_identity_header_not_authorization(
    identity_env: None,
) -> None:
    """The platform injects `IDENTITY_HEADER` and the endpoint expects it in
    `X-IDENTITY-HEADER`. Sending `Authorization` instead is a 401 that reads
    like an identity problem and is not one."""
    handler = _ok()
    ManagedIdentityToken(UAMI, http=_client(handler))()

    request = handler.calls[0]  # type: ignore[attr-defined]
    assert request.headers["X-IDENTITY-HEADER"] == "the-platform-injected-secret"
    assert "authorization" not in {k.lower() for k in request.headers}


# ----------------------------------------------------------------- caching


def test_a_valid_assertion_is_reused(identity_env: None) -> None:
    handler = _ok()
    assertion = ManagedIdentityToken(UAMI, http=_client(handler))
    for _ in range(5):
        assert assertion() == "assertion-jwt"
    assert len(handler.calls) == 1  # type: ignore[attr-defined]


def test_an_assertion_near_expiry_is_re_minted(identity_env: None) -> None:
    """Re-minted well before expiry. A token minted thirty seconds before it
    expires fails at Entra rather than here, where the error names a grant
    problem and sends the reader somewhere else entirely."""
    handler = _ok(expires_in=60)  # inside the 300s skew
    assertion = ManagedIdentityToken(UAMI, http=_client(handler))
    assertion()
    assertion()
    assert len(handler.calls) == 2  # type: ignore[attr-defined]


def test_an_unparsable_expiry_does_not_become_a_hot_loop(
    identity_env: None, caplog: pytest.LogCaptureFixture
) -> None:
    """`expires_on` is documented as a string and its format varies by host.

    The fallback has to exceed the skew the caller subtracts, or it nets to
    zero and mints a fresh token on **every call** — a hot loop against the
    identity endpoint that still returns correct answers, which is the kind
    that survives review. It did, in the first version of this module.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        handler.calls.append(request)  # type: ignore[attr-defined]
        return httpx.Response(
            200,
            json={"access_token": "t", "expires_on": "Fri, 14 Aug 2026 20:00:00 GMT"},
        )

    handler.calls = []  # type: ignore[attr-defined]
    assertion = ManagedIdentityToken(UAMI, http=_client(handler))
    for _ in range(10):
        assertion()
    assert len(handler.calls) == 1, "re-minted on every call"  # type: ignore[attr-defined]
    assert "unparsable expires_on" in caplog.text


# ----------------------------------------------------------------- failures


def test_no_identity_attached_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    """The two causes — no identity attached, wrong client id — are
    indistinguishable from inside the application, so the message names both
    things to check rather than guessing between them."""
    monkeypatch.delenv("IDENTITY_ENDPOINT", raising=False)
    monkeypatch.delenv("IDENTITY_HEADER", raising=False)
    with pytest.raises(AssertionError_, match="no managed identity is attached"):
        ManagedIdentityToken(UAMI)()


def test_a_refusal_surfaces_the_platform_message(identity_env: None) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="Identity not found for client_id")

    with pytest.raises(AssertionError_) as exc:
        ManagedIdentityToken(UAMI, http=_client(handler))()
    assert "400" in str(exc.value)
    assert "Identity not found" in str(exc.value)
    assert "DSAR_UAMI_CLIENT_ID" in str(exc.value)


def test_an_unreachable_endpoint_is_not_a_traceback(identity_env: None) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(AssertionError_, match="could not be reached"):
        ManagedIdentityToken(UAMI, http=_client(handler))()


def test_a_response_without_a_token_is_named_as_a_contract_change(
    identity_env: None,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "Bearer"})

    with pytest.raises(AssertionError_, match="response shape changing"):
        ManagedIdentityToken(UAMI, http=_client(handler))()


# ------------------------------------------------- the confidential client


def test_the_confidential_client_holds_a_callable_never_a_string(
    config_env: dict[str, str],
) -> None:
    """A `str` here would be a client secret, and the design's central claim is
    that none exists.

    Asserted on the constructed application, not only structurally: the
    structural test proves the source says `client_assertion`, this proves the
    thing that reaches MSAL is a callable and that MSAL does not invoke it at
    construction. A pre-computed assertion would work in every test and start
    failing token refreshes hours into a deployment.
    """
    from dsar.auth.msal_client import build_confidential_client
    from dsar.config import load_config
    from tests.fakes import FakeHttpClient

    calls: list[int] = []

    def assertion() -> str:
        calls.append(1)
        return "assertion-jwt"

    config = load_config()
    app = build_confidential_client(config, assertion, http_client=FakeHttpClient())

    assert calls == [], "the assertion was minted at construction, not lazily"

    credential = app.client_credential
    assert set(credential) == {"client_assertion"}, (
        "the client credential carries something other than an assertion — "
        f"keys: {sorted(credential)}"
    )
    stored = credential["client_assertion"]
    assert callable(stored), f"a {type(stored).__name__} here would be a secret"
    assert stored is assertion
