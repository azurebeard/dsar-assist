"""Shared fixtures, repo-root discovery, and the guards that keep tests honest."""

from __future__ import annotations

import os
import socket as _socket
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# --------------------------------------------------------------------------
# No test may reach the network.
#
# Ported verbatim from the predecessor, along with the reason it exists. A test
# that lost its HTTP-mocking decorator during an edit made a real call to
# Microsoft Graph and got a real 401 back. It failed for a plausible-looking
# reason — `needs_reauth` — which is exactly the kind of failure someone debugs
# for twenty minutes before noticing the request left the building.
#
# Loopback stays open because the web tests bind a real socket.
# --------------------------------------------------------------------------

_real_connect = _socket.socket.connect


def _loopback_only(self, address):  # type: ignore[no-untyped-def]
    host = address[0] if isinstance(address, tuple) else None
    if isinstance(host, str) and not (
        host.startswith("127.") or host in ("::1", "localhost", "0")
    ):
        raise AssertionError(
            f"a test tried to reach {host} — the suite runs with no network. "
            f"A missing HTTP mock is the usual cause."
        )
    return _real_connect(self, address)


@pytest.fixture(autouse=True)
def _no_external_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_socket.socket, "connect", _loopback_only)


# --------------------------------------------------------------------------
# The environment a test sees is the environment a test asked for.
#
# Config, mode detection and the identity plane all read os.environ. A
# developer's own DSAR_* or Azure Container Apps variables leaking into the
# suite makes tests pass locally and fail in CI, or worse, the reverse. This
# strips the lot; a test that wants one sets it explicitly.
#
# CONTAINER_APP_* is included because it is what mode detection keys on: a
# suite run inside Container Apps would otherwise silently switch every test to
# hosted mode.
# --------------------------------------------------------------------------

_STRIPPED_PREFIXES = ("DSAR_", "CONTAINER_APP_", "IDENTITY_")
_STRIPPED_EXACT = ("AZURE_CLIENT_SECRET", "CLIENT_SECRET", "AZURE_CLIENT_ID")


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith(_STRIPPED_PREFIXES) or name in _STRIPPED_EXACT:
            monkeypatch.delenv(name, raising=False)


@pytest.fixture
def config_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, str]:
    """A minimally valid desktop configuration, isolated to a temp directory."""
    values = {
        "DSAR_CLIENT_ID": "11111111-2222-3333-4444-555555555555",
        "DSAR_TENANT_ID": "66666666-7777-8888-9999-aaaaaaaaaaaa",
        "DSAR_HOME": str(tmp_path / "home"),
        "DSAR_AUDIT_DIR": str(tmp_path / "audit"),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return values


@pytest.fixture
def offline_msal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Build MSAL clients against a fake authority.

    MSAL performs OIDC discovery at construction, so any route that builds a
    client reaches the network — which the socket guard above refuses, by
    design. This substitutes a recorder for MSAL's HTTP client through the
    documented `http_client` seam, keeping the guard intact rather than
    weakening it for convenience.
    """
    from fakes import FakeHttpClient

    import dsar.web.app as web_app
    import dsar.web.auth_routes as auth_routes
    from dsar.auth import msal_client

    # Patched at `build_client`, the single factory that chooses public or
    # confidential — so a hosted-mode test exercises the confidential path
    # offline rather than silently falling back to the public one.
    real_build = msal_client.build_client

    def build_offline(config, http_client=None):  # type: ignore[no-untyped-def]
        return real_build(config, http_client=http_client or FakeHttpClient(config.tenant_id))

    monkeypatch.setattr(msal_client, "build_client", build_offline)
    monkeypatch.setattr(auth_routes, "build_client", build_offline)
    monkeypatch.setattr(web_app, "build_client", build_offline)
