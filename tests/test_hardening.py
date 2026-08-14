"""Regression tests for the WS10 pass-1 findings.

Each test names the finding it closes. A finding without a test is a fix that
can be undone silently, which is how the predecessor lost its bind-address
guarantee.
"""

from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from dsar.config import ConfigError, ensure_private_dir, load_config, secret_shaped_env
from dsar.web.app import build_app

POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="POSIX permission modes do not apply on this platform"
)


# ------------------------------------------------- SEC-M-01 audit directory


@POSIX_ONLY
def test_audit_directory_is_owner_only_when_created(tmp_path: Path) -> None:
    target = ensure_private_dir(tmp_path / "audit")
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


@POSIX_ONLY
def test_audit_directory_is_tightened_when_it_already_exists(tmp_path: Path) -> None:
    """`mkdir(exist_ok=True)` does not change an existing directory's mode.

    This is the half of the finding that a create-time-only fix would miss.
    """
    target = tmp_path / "audit"
    target.mkdir(mode=0o777)
    os.chmod(target, 0o777)  # mkdir's mode is masked by umask; force it
    ensure_private_dir(target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


@POSIX_ONLY
def test_doctor_reports_the_audit_directory_mode(config_env) -> None:
    from dsar.doctor.checks import Verdict, run_checks

    finding = {f.check: f for f in run_checks(offline=True)}["audit sink"]
    assert finding.verdict is Verdict.PASS
    assert "0o700" in finding.detail


# --------------------------------------------------- SEC-M-02 config trust


@POSIX_ONLY
@pytest.mark.parametrize("mode", [0o666, 0o664, 0o622, 0o777])
def test_config_writable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    """Whoever can write this file chooses which tenant the operator signs in to."""
    home = tmp_path / "home"
    home.mkdir()
    config = home / "config.json"
    config.write_text('{"client_id": "c", "tenant_id": "t"}', encoding="utf-8")
    os.chmod(config, mode)
    with pytest.raises(ConfigError, match="writable by group or other"):
        load_config(home=home, env={})


@POSIX_ONLY
@pytest.mark.parametrize("mode", [0o600, 0o644, 0o400])
def test_config_owned_privately_is_accepted(tmp_path: Path, mode: int) -> None:
    home = tmp_path / "home"
    home.mkdir()
    config = home / "config.json"
    config.write_text('{"client_id": "c", "tenant_id": "t"}', encoding="utf-8")
    os.chmod(config, mode)
    assert load_config(home=home, env={}).client_id == "c"


# ------------------------------------------------- SEC-M-03 request logging


def test_requests_are_logged(config_env, caplog) -> None:
    """Disabling access logging outright traded away an OWASP A09 control."""
    client = TestClient(build_app(load_config()))
    with caplog.at_level(logging.INFO, logger="dsar.request"):
        client.get("/healthz")
    assert any("/healthz" in r.getMessage() for r in caplog.records)


def test_request_log_records_the_route_template_not_the_path(
    config_env, caplog
) -> None:
    """Concrete paths carry case identifiers; the matched template does not.

    An unmatched path must not be logged either — otherwise a scanner probing
    for `/.env` writes attacker-chosen strings into the log.
    """
    client = TestClient(build_app(load_config()))
    with caplog.at_level(logging.INFO, logger="dsar.request"):
        client.get("/cases/01f85886-7bef-4a22-a27d-18bf9733bbc8")
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "01f85886" not in logged
    assert "<unmatched>" in logged


@pytest.mark.parametrize(
    "scope,expected",
    [
        # Nothing matched: log a constant, never the attacker-chosen path.
        ({"path": "/.env", "endpoint": None}, "<unmatched>"),
        ({"path": "/healthz", "endpoint": object(), "path_params": {}}, "/healthz"),
        (
            {
                "path": "/cases/01f85886-7bef-4a22-a27d-18bf9733bbc8",
                "endpoint": object(),
                "path_params": {"case_id": "01f85886-7bef-4a22-a27d-18bf9733bbc8"},
            },
            "/cases/{case_id}",
        ),
        (
            {
                "path": "/cases/abc/searches/def",
                "endpoint": object(),
                "path_params": {"case_id": "abc", "search_id": "def"},
            },
            "/cases/{case_id}/searches/{search_id}",
        ),
    ],
)
def test_route_template_strips_every_identifier(scope: dict, expected: str) -> None:
    """The redaction that keeps case identifiers out of logs. Tested directly,
    because it is the control rather than a convenience."""
    from dsar.web.security import route_template

    assert route_template(scope) == expected


# -------------------------------------------------- SEC-L-01 version leak


def test_healthz_withholds_version_when_hosted(monkeypatch, config_env) -> None:
    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    body = TestClient(build_app(load_config())).get("/healthz").json()
    assert body == {"status": "ok"}


def test_healthz_keeps_version_on_desktop(config_env) -> None:
    body = TestClient(build_app(load_config())).get("/healthz").json()
    assert body["status"] == "ok" and "version" in body


# ------------------------------------------------ SEC-L-02 secret coverage


@pytest.mark.parametrize(
    "name",
    [
        "DSAR_CLIENT_SECRET",
        "AZURE_CLIENT_SECRET",
        "SOMETHING_PASSWORD",
        "DSAR_CLIENT_ASSERTION",
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "APP_PRIVATE_KEY",
    ],
)
def test_secret_shaped_names_are_all_caught(name: str) -> None:
    assert secret_shaped_env({name: "value"}) == [name]


def test_empty_value_is_not_a_secret() -> None:
    """An exported-but-empty variable is not a credential."""
    assert secret_shaped_env({"DSAR_CLIENT_SECRET": ""}) == []


# ------------------------------------------------ SEC-L-03 origin isolation


@pytest.mark.parametrize(
    "header,value",
    [
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
    ],
)
def test_cross_origin_isolation_headers(config_env, header: str, value: str) -> None:
    """COOP matters specifically because Phase 1 adds an IdP redirect."""
    response = TestClient(build_app(load_config())).get("/")
    assert response.headers[header] == value


def test_permissions_policy_denies_every_named_feature(config_env) -> None:
    policy = TestClient(build_app(load_config())).get("/").headers["Permissions-Policy"]
    assert "camera=()" in policy and "microphone=()" in policy
    assert "*" not in policy and "self" not in policy
