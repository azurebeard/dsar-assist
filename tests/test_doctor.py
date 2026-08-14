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


def test_hosted_checks_skip_on_the_desktop(config_env) -> None:
    """SKIP rather than PASS, deliberately.

    A check that reports success without having run is the mistake this
    project keeps rediscovering — a Trivy scan recorded as passed behind a
    failed job, a pip guard that could not fail, an `innerHTML` rule nothing
    enforced. Desktop mode has no managed identity to ask, so the honest
    verdict is that the question was not put.
    """
    from dsar.doctor.checks import Verdict, run_checks

    findings = {f.check: f for f in run_checks(offline=False)}
    for name in ("client assertion", "FIC exchange"):
        assert findings[name].verdict is Verdict.SKIP, findings[name].detail


def test_hosted_without_a_managed_identity_fails_rather_than_warns(
    monkeypatch, config_env
) -> None:
    """There is no secret to fall back to, so this is not a degraded mode."""
    from dsar.doctor.checks import Verdict, _check_client_assertion

    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    monkeypatch.delenv("DSAR_UAMI_CLIENT_ID", raising=False)

    finding = _check_client_assertion()
    assert finding.verdict is Verdict.FAIL
    assert "DSAR_UAMI_CLIENT_ID" in finding.detail


def test_the_assertion_check_reports_the_three_values_the_fic_must_match(
    monkeypatch, config_env
) -> None:
    """Microsoft's own warning is that a wrong subject is created without error
    and fails only at exchange. Printing aud/iss/sub is what makes the
    comparison possible at all."""
    import base64
    import json

    from dsar.doctor import checks as checks_module
    from dsar.doctor.checks import Verdict, _check_client_assertion

    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    monkeypatch.setenv("DSAR_UAMI_CLIENT_ID", "99999999-8888-7777-6666-555555555555")

    def fake_jwt(claims: dict) -> str:
        body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        return f"header.{body}.signature"

    token = fake_jwt(
        {
            "aud": "api://AzureADTokenExchange",
            "iss": "https://login.microsoftonline.com/tid/v2.0",
            "sub": "PRINCIPAL-ID-CASE-SENSITIVE",
        }
    )
    monkeypatch.setattr(
        checks_module, "load_config", checks_module.load_config
    )
    import dsar.auth.managed_identity as mi

    monkeypatch.setattr(mi, "client_assertion_for", lambda *a, **k: (lambda: token))

    finding = _check_client_assertion()
    assert finding.verdict is Verdict.PASS
    assert "api://AzureADTokenExchange" in finding.detail
    assert "PRINCIPAL-ID-CASE-SENSITIVE" in finding.detail
    assert "principal id" in finding.fix and "case-sensitive" in finding.fix


def test_the_platform_identity_variable_is_not_a_client_secret(
    monkeypatch, config_env
) -> None:
    """Container Apps injects `MSI_SECRET`, and it is not a secret of ours.

    It is the legacy name for the value authenticating a caller to the *local*
    managed identity endpoint — the same value as `IDENTITY_HEADER`, and the
    thing that makes the secretless design work at all. It authorises nothing
    against Entra and nothing against Graph.

    Found by deploying. Hosted mode failed `doctor` on its first real run, and
    would have failed on every Container Apps deployment it could ever have,
    because the check reasoned about variable names and this one is named like
    the thing it is not.
    """
    from dsar.doctor.checks import Verdict, _check_no_secrets

    monkeypatch.setenv("MSI_SECRET", "platform-injected-value")
    assert _check_no_secrets().verdict is Verdict.PASS


def test_a_real_client_secret_is_still_caught(monkeypatch, config_env) -> None:
    """Allowlisted by exact name, not by relaxing the suffix rule. The check
    that let MSI_SECRET through must still refuse the thing it was built for."""
    from dsar.doctor.checks import Verdict, _check_no_secrets

    monkeypatch.setenv("MSI_SECRET", "platform-injected-value")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "a-real-one")
    finding = _check_no_secrets()
    assert finding.verdict is Verdict.FAIL
    assert "AZURE_CLIENT_SECRET" in finding.detail
    assert "MSI_SECRET" not in finding.detail
