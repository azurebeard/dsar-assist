"""Offline stand-ins, so the suite never reaches the network.

MSAL performs OIDC discovery when an application is constructed, so building
one in a test would hit `login.microsoftonline.com`. The socket guard in
`conftest.py` refuses that — which is the guard doing its job, not an obstacle
to route around. These fakes are the supported way past it.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["FakeHttpClient", "FakeResponse", "TENANT"]

TENANT = "66666666-7777-8888-9999-aaaaaaaaaaaa"


class FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self.status_code = status_code
        self.text = json.dumps(payload)
        self.headers: dict[str, str] = {}

    def json(self) -> Any:
        return json.loads(self.text)

    def raise_for_status(self) -> None:
        pass


class FakeHttpClient:
    """Serves OIDC discovery and records every request MSAL makes.

    Deliberately not a general-purpose mock. It answers the two endpoints MSAL
    touches while building an authorize URL, and records the rest so a test can
    assert on what was *sent* — which is usually the interesting half.
    """

    def __init__(self, tenant: str = TENANT) -> None:
        self.tenant = tenant
        self.requests: list[dict[str, Any]] = []

    @property
    def _base(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant}"

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.requests.append({"method": "GET", "url": url})
        return FakeResponse(
            {
                "authorization_endpoint": f"{self._base}/oauth2/v2.0/authorize",
                "token_endpoint": f"{self._base}/oauth2/v2.0/token",
                "issuer": f"{self._base}/v2.0",
                "device_authorization_endpoint": f"{self._base}/oauth2/v2.0/devicecode",
                "tenant_region_scope": "EU",
            }
        )

    def post(
        self, url: str, params: Any = None, data: Any = None, **kwargs: Any
    ) -> FakeResponse:
        self.requests.append({"method": "POST", "url": url, "data": dict(data or {})})
        return FakeResponse(
            {
                "token_type": "Bearer",
                "access_token": "fake-access-token",
                "expires_in": 3600,
                "scope": "https://graph.microsoft.com/eDiscovery.ReadWrite.All",
            }
        )

    def close(self) -> None:
        pass
