"""The web surface: health, security headers, and the static allowlist."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from dsar.config import load_config
from dsar.web.app import build_app
from dsar.web.security import SECURITY_HEADERS


@pytest.fixture
def client(config_env) -> TestClient:
    return TestClient(build_app(load_config()))


@pytest.fixture
def hosted_client(monkeypatch, config_env) -> TestClient:
    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    return TestClient(build_app(load_config()))


def test_healthz_is_reachable(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_healthz_discloses_no_tenant(client: TestClient) -> None:
    """The one route reachable without a session must not say whose tenant this is."""
    body = client.get("/healthz").text
    assert "66666666" not in body
    assert "tenant" not in body.lower()


def test_security_headers_on_every_response(client: TestClient) -> None:
    for path in ("/healthz", "/", "/nope"):
        response = client.get(path)
        for name, value in SECURITY_HEADERS.items():
            assert response.headers.get(name) == value, f"{name} missing on {path}"


def test_csp_denies_by_default(client: TestClient) -> None:
    csp = client.get("/healthz").headers["Content-Security-Policy"]
    assert csp.startswith("default-src 'none'")
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_no_hsts_on_desktop(client: TestClient) -> None:
    """Sending HSTS over http://localhost pins the browser to HTTPS for
    localhost, breaking every other local tool the operator runs."""
    assert "Strict-Transport-Security" not in client.get("/healthz").headers


def test_hsts_on_hosted(hosted_client: TestClient) -> None:
    header = hosted_client.get("/healthz").headers.get("Strict-Transport-Security")
    assert header is not None and "max-age=" in header


def test_index_is_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "DSAR Assist" in response.text


def test_unlisted_static_path_is_not_served(client: TestClient) -> None:
    """A file dropped into static/ is not served until someone names it."""
    assert client.get("/style.css").status_code == 404


def test_no_server_header_leak(client: TestClient) -> None:
    assert "uvicorn" not in client.get("/healthz").headers.get("server", "").lower()
