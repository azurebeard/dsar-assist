"""Doctor turns each known failure mode into a diagnosis with a fix."""

from __future__ import annotations

import pytest

from dsar.doctor.checks import Verdict, run_checks


def _by_name(offline: bool = True) -> dict[str, object]:
    return {f.check: f for f in run_checks(offline=offline)}


def test_offline_run_covers_every_check(config_env) -> None:
    findings = _by_name()
    expected = {
        "entry point",
        "version",
        "no keyring dependency",
        "mode",
        "exposure",
        "no secrets",
        "configuration",
        "redirect URI",
        "audit sink",
    }
    assert expected <= set(findings)


def test_valid_configuration_passes(config_env) -> None:
    findings = _by_name()
    failures = {
        name: f.detail  # type: ignore[attr-defined]
        for name, f in findings.items()
        if f.verdict is Verdict.FAIL  # type: ignore[attr-defined]
    }
    assert failures == {}


def test_missing_configuration_fails_with_a_fix(monkeypatch) -> None:
    findings = _by_name()
    config = findings["configuration"]
    assert config.verdict is Verdict.FAIL  # type: ignore[attr-defined]
    assert "DSAR_CLIENT_ID" in config.fix  # type: ignore[attr-defined]


def test_secret_shaped_variable_is_a_failure_not_a_warning(
    monkeypatch, config_env
) -> None:
    """Its presence means the deployment is not what the operator thinks."""
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "not-actually-used-anywhere")
    finding = _by_name()["no secrets"]
    assert finding.verdict is Verdict.FAIL  # type: ignore[attr-defined]
    assert "AZURE_CLIENT_SECRET" in finding.detail  # type: ignore[attr-defined]


def test_non_guid_identifiers_are_caught(monkeypatch, config_env) -> None:
    monkeypatch.setenv("DSAR_TENANT_ID", "picnic-dev.co.uk")
    finding = _by_name()["configuration"]
    assert finding.verdict is Verdict.FAIL  # type: ignore[attr-defined]
    assert "GUID" in finding.detail or "GUID" in finding.fix  # type: ignore[attr-defined]


def test_redirect_uri_is_printed_ready_to_paste(config_env) -> None:
    finding = _by_name()["redirect URI"]
    assert "http://localhost:8765/auth/callback" in finding.detail  # type: ignore[attr-defined]


def test_keyring_dependency_check_passes_when_absent(config_env) -> None:
    finding = _by_name()["no keyring dependency"]
    assert finding.verdict is Verdict.PASS  # type: ignore[attr-defined]


def test_hosted_without_audit_blob_url_fails(monkeypatch, config_env) -> None:
    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    finding = _by_name()["audit sink"]
    assert finding.verdict is Verdict.FAIL  # type: ignore[attr-defined]
    assert "DSAR_AUDIT_BLOB_URL" in finding.detail  # type: ignore[attr-defined]


def test_a_raising_check_does_not_hide_the_others(monkeypatch, config_env) -> None:
    """One broken check must not take the diagnosis down with it."""
    import dsar.doctor.checks as checks

    def _boom() -> None:
        raise RuntimeError("deliberate")

    monkeypatch.setattr(
        checks,
        "CHECKS",
        (checks.Check("boom", False, _boom), *checks.CHECKS),  # type: ignore[arg-type]
    )
    findings = {f.check: f for f in checks.run_checks(offline=True)}
    assert findings["boom"].verdict is Verdict.FAIL
    assert "deliberate" in findings["boom"].detail
    assert "configuration" in findings


def test_exit_code_is_nonzero_on_failure(capsys) -> None:
    from dsar.doctor.report import run_doctor

    assert run_doctor(offline=True) == 1  # no config in the stripped environment


def test_json_output_is_machine_readable(config_env, capsys) -> None:
    import json

    from dsar.doctor.report import run_doctor

    run_doctor(offline=True, as_json=True)
    payload = json.loads(capsys.readouterr().out)
    assert payload["failed"] == 0
    assert {f["check"] for f in payload["findings"]} >= {"mode", "configuration"}
