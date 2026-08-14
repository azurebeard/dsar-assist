"""Half of the FIC spike, answerable offline.

    uv run python verification/probe_fic_assertion_offline.py

The hosted mode authenticates with a federated identity credential: a
user-assigned managed identity mints a token, that token is presented as the
client assertion, and the app redeems an authorization code for a DELEGATED
Graph token. Every Microsoft sample for federated-credential-by-managed-identity
uses `AcquireTokenForClient` — app-only. None does it with an authorization
code, which made this the largest unknown in the design.

The unknown decomposes, and only the second half needs infrastructure:

  A. Does MSAL send `client_assertion` and `client_assertion_type` when
     redeeming an AUTHORIZATION CODE, rather than only on a client-credentials
     grant? Answerable here, offline, by intercepting the request MSAL builds.

  B. Does Entra ACCEPT an assertion minted by a managed identity for that
     grant? Needs a real Container App and UAMI. Deferred to Phase 5, where
     the infrastructure exists anyway.

A was the part most likely to be a hard blocker — if MSAL simply does not send
a client assertion on this grant, no amount of Entra configuration helps and
the hosted design needs rethinking. Running it now costs nothing.

Nothing here contacts a network. The HTTP client is replaced with a recorder.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import msal

TENANT = "00000000-0000-0000-0000-000000000002"
CLIENT = "00000000-0000-0000-0000-000000000001"
FAKE_ASSERTION = "eyJhbGciOiJSUzI1NiJ9.fake-managed-identity-assertion.sig"

_requests: list[dict[str, Any]] = []


class Recorder:
    """Stands in for MSAL's HTTP client, recording what it is asked to send."""

    def __init__(self) -> None:
        self.assertion_calls = 0

    def post(self, url: str, params: Any = None, data: Any = None, **kwargs: Any):
        _requests.append({"url": url, "data": dict(data or {})})
        return _Response(_token_endpoint_body(url))

    def get(self, url: str, params: Any = None, **kwargs: Any):
        return _Response(_discovery_body(url))

    def close(self) -> None:
        pass


class _Response:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.status_code = 200
        self.text = json.dumps(payload)
        self.headers: dict[str, str] = {}

    def json(self) -> Any:
        return json.loads(self.text)

    def raise_for_status(self) -> None:
        pass


def _discovery_body(url: str) -> dict[str, Any]:
    base = f"https://login.microsoftonline.com/{TENANT}"
    return {
        "authorization_endpoint": f"{base}/oauth2/v2.0/authorize",
        "token_endpoint": f"{base}/oauth2/v2.0/token",
        "issuer": f"{base}/v2.0",
        "tenant_region_scope": "EU",
        "device_authorization_endpoint": f"{base}/oauth2/v2.0/devicecode",
    }


def _token_endpoint_body(url: str) -> dict[str, Any]:
    # Enough shape for MSAL to consider the exchange successful. The probe
    # cares about the REQUEST, not the response.
    return {
        "token_type": "Bearer",
        "access_token": "fake",
        "expires_in": 3600,
        "scope": "https://graph.microsoft.com/eDiscovery.ReadWrite.All",
    }


def main() -> int:
    calls = {"n": 0}

    def mint_assertion() -> str:
        """Stands in for the Container Apps identity endpoint.

        Passed as a CALLABLE deliberately. A pre-computed string expires, and a
        long-lived process would start failing token refreshes some time after
        startup for reasons that look nothing like an expiry.
        """
        calls["n"] += 1
        return FAKE_ASSERTION

    app = msal.ConfidentialClientApplication(
        CLIENT,
        authority=f"https://login.microsoftonline.com/{TENANT}",
        client_credential={"client_assertion": mint_assertion},
        client_capabilities=["cp1"],
        http_client=Recorder(),
        token_cache=msal.TokenCache(),
    )

    flow = app.initiate_auth_code_flow(
        ["https://graph.microsoft.com/eDiscovery.ReadWrite.All"],
        redirect_uri="https://dsar.example.co.uk/auth/callback",
    )
    if "auth_uri" not in flow:
        print(f"could not start the flow: {flow}", file=sys.stderr)
        return 1

    app.acquire_token_by_auth_code_flow(
        flow, {"code": "fake-authorization-code", "state": flow["state"]}
    )

    token_posts = [
        r for r in _requests if r["url"].endswith("/token") or "/token" in r["url"]
    ]
    if not token_posts:
        print("MSAL never reached a token endpoint — probe inconclusive.", file=sys.stderr)
        return 1

    body = token_posts[-1]["data"]
    grant = body.get("grant_type", "(none)")
    assertion = body.get("client_assertion")
    assertion_type = body.get("client_assertion_type", "")

    print("=" * 72)
    print("A. Does MSAL send a client assertion on an authorization_code grant?")
    print("=" * 72)
    print(f"  grant_type             {grant}")
    print(f"  client_assertion       {'PRESENT' if assertion else 'ABSENT'}")
    print(f"  client_assertion_type  {assertion_type or '(absent)'}")
    print(f"  assertion is ours      {assertion == FAKE_ASSERTION}")
    print(f"  callable invoked       {calls['n']} time(s) — lazily, not at construction")
    print(f"  client_secret sent     {'YES (WRONG)' if 'client_secret' in body else 'no'}")
    print()

    ok = (
        grant == "authorization_code"
        and assertion == FAKE_ASSERTION
        and assertion_type.endswith("jwt-bearer")
        and "client_secret" not in body
    )
    if ok:
        print("ANSWER: yes. MSAL authenticates the client with the assertion on an")
        print("authorization-code redemption, exactly as it does for client")
        print("credentials. Client authentication is orthogonal to grant type in")
        print("OAuth, and MSAL implements it that way.")
        print()
        print("Remaining unknown, deferred to Phase 5 with the infrastructure:")
        print("  B. whether Entra ACCEPTS a managed-identity-minted assertion for")
        print("     this grant. If it refuses, expect AADSTS700213 or")
        print("     AADSTS70021 rather than a silent fallback.")
        return 0

    print("ANSWER: no — the hosted design needs rethinking before Phase 5.")
    print(f"  full request body keys: {sorted(body)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
