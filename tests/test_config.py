"""Mode detection, configuration resolution, and the redirect URI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dsar.config import ConfigError, load_config, purview_case_url
from dsar.mode import Mode, ModeError, detect_mode


# ------------------------------------------------------------------ mode


def test_mode_defaults_to_desktop() -> None:
    mode, reason = detect_mode({})
    assert mode is Mode.DESKTOP
    assert "no DSAR_MODE" in reason


def test_container_apps_markers_imply_hosted() -> None:
    mode, reason = detect_mode({"CONTAINER_APP_NAME": "ca-dsar-prod-uks-01"})
    assert mode is Mode.HOSTED
    assert "CONTAINER_APP_NAME" in reason


def test_explicit_mode_beats_inference() -> None:
    """An operator override must win, because a wrong guess picks an auth path."""
    mode, reason = detect_mode(
        {"DSAR_MODE": "desktop", "CONTAINER_APP_NAME": "ca-dsar-prod-uks-01"}
    )
    assert mode is Mode.DESKTOP
    assert reason == "DSAR_MODE=desktop"


def test_unknown_mode_is_refused_loudly() -> None:
    with pytest.raises(ModeError, match="not a mode"):
        detect_mode({"DSAR_MODE": "production"})


# ---------------------------------------------------------------- config


def test_missing_registration_names_both_variables(monkeypatch) -> None:
    with pytest.raises(ConfigError) as exc:
        load_config(env={})
    message = str(exc.value)
    assert "DSAR_CLIENT_ID" in message and "DSAR_TENANT_ID" in message
    assert "neither is a secret" in message.lower()


def test_non_guid_tenant_is_accepted_by_load_but_flagged_by_doctor() -> None:
    """`load_config` does not validate GUID shape — `doctor` does, with a fix line.

    Deliberate split: config resolution should not decide policy, and a domain
    name in DSAR_TENANT_ID is a diagnosis worth explaining rather than a
    stacktrace at import time.
    """
    config = load_config(
        env={"DSAR_CLIENT_ID": "abc", "DSAR_TENANT_ID": "picnic-dev.co.uk"}
    )
    assert config.tenant_id == "picnic-dev.co.uk"


def test_authority_is_pinned_to_one_tenant() -> None:
    config = load_config(
        env={"DSAR_CLIENT_ID": "c", "DSAR_TENANT_ID": "t"}
    )
    assert config.authority == "https://login.microsoftonline.com/t"
    assert "/common" not in config.authority
    assert "/organizations" not in config.authority


def test_scopes_exclude_user_read_all_by_default() -> None:
    config = load_config(env={"DSAR_CLIENT_ID": "c", "DSAR_TENANT_ID": "t"})
    assert config.scopes == ("https://graph.microsoft.com/eDiscovery.ReadWrite.All",)


def test_identity_expansion_adds_exactly_one_scope() -> None:
    config = load_config(
        env={
            "DSAR_CLIENT_ID": "c",
            "DSAR_TENANT_ID": "t",
            "DSAR_IDENTITY_EXPANSION": "1",
        }
    )
    assert config.scopes == (
        "https://graph.microsoft.com/eDiscovery.ReadWrite.All",
        "https://graph.microsoft.com/User.Read.All",
    )


def test_no_scope_requests_download() -> None:
    for expansion in ("0", "1"):
        config = load_config(
            env={
                "DSAR_CLIENT_ID": "c",
                "DSAR_TENANT_ID": "t",
                "DSAR_IDENTITY_EXPANSION": expansion,
            }
        )
        assert not any("Download" in scope for scope in config.scopes)


def test_config_file_is_read_when_env_is_absent(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.json").write_text(
        json.dumps({"client_id": "from-file", "tenant_id": "t"}), encoding="utf-8"
    )
    config = load_config(home=home, env={})
    assert config.client_id == "from-file"
    assert config._source.endswith("config.json")


def test_env_beats_config_file(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.json").write_text(
        json.dumps({"client_id": "from-file", "tenant_id": "t"}), encoding="utf-8"
    )
    config = load_config(home=home, env={"DSAR_CLIENT_ID": "from-env"})
    assert config.client_id == "from-env"


def test_malformed_config_file_names_the_file(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(home=home, env={})


# --------------------------------------------------------- redirect URI


def test_desktop_redirect_uri_is_a_single_loopback_url() -> None:
    config = load_config(env={"DSAR_CLIENT_ID": "c", "DSAR_TENANT_ID": "t"})
    assert config.redirect_uri == "http://localhost:8765/auth/callback"


def test_hosted_redirect_uri_requires_configured_base_url() -> None:
    """Never derived from the Host header — a forwarded header is caller input."""
    config = load_config(
        env={"DSAR_CLIENT_ID": "c", "DSAR_TENANT_ID": "t", "DSAR_MODE": "hosted"}
    )
    with pytest.raises(ConfigError, match="never derived from the Host header"):
        _ = config.redirect_uri


def test_hosted_redirect_uri_uses_base_url() -> None:
    config = load_config(
        env={
            "DSAR_CLIENT_ID": "c",
            "DSAR_TENANT_ID": "t",
            "DSAR_MODE": "hosted",
            "DSAR_BASE_URL": "https://dsar.example.co.uk/",
        }
    )
    assert config.redirect_uri == "https://dsar.example.co.uk/auth/callback"


def test_port_must_be_a_valid_port() -> None:
    with pytest.raises(ConfigError, match="1..65535"):
        load_config(env={"DSAR_CLIENT_ID": "c", "DSAR_TENANT_ID": "t", "DSAR_PORT": "0"})
    with pytest.raises(ConfigError, match="integer"):
        load_config(env={"DSAR_CLIENT_ID": "c", "DSAR_TENANT_ID": "t", "DSAR_PORT": "x"})


# ------------------------------------------------------------- portal link


def test_purview_case_url_carries_the_tenant() -> None:
    """Without `tid` the link resolves against whichever tenant the browser
    last used — for anyone signed into more than one, that is a link that
    silently opens the wrong place."""
    url = purview_case_url("case-1", "tenant-1")
    assert "casespage/case-1" in url
    assert "tid=tenant-1" in url
    assert "viewid=Searches" in url


def test_purview_case_url_escapes_its_inputs() -> None:
    url = purview_case_url("a/b?c", "t&d")
    assert "a/b?c" not in url
    assert "t&d" not in url
