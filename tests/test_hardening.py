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


# ------------------------------------------ A04 / A07 rate limiting


def test_login_is_rate_limited(config_env, offline_msal) -> None:
    """Unauthenticated and it allocates server state, so it must be bounded."""
    from dsar.web.limits import LOGIN_LIMIT

    client = TestClient(build_app(load_config()), follow_redirects=False)
    limit, _ = LOGIN_LIMIT
    codes = [client.get("/auth/login").status_code for _ in range(limit + 3)]
    assert 429 in codes, f"no rate limit hit in {limit + 3} attempts: {set(codes)}"
    throttled = client.get("/auth/login")
    assert throttled.status_code == 429
    assert int(throttled.headers["Retry-After"]) >= 1


def test_pending_flows_are_refused_not_evicted() -> None:
    """Evicting made an unauthenticated caller able to cancel a real operator's
    in-progress sign-in — a bystander paying for someone else's traffic."""
    from dsar.auth.session import FlowStore, FlowStoreFull

    store = FlowStore(max_pending=3)
    victim = store.put({"state": "victim"})
    for _ in range(2):
        store.put({"state": "other"})
    with pytest.raises(FlowStoreFull):
        store.put({"state": "attacker"})
    assert store.take(victim) is not None, "the victim's flow was evicted"


def test_rate_limiter_records_denied_attempts() -> None:
    """A caller that ignores a 429 must not earn a free pass by continuing."""
    from dsar.web.limits import RateLimiter

    limiter = RateLimiter(2, 60.0)
    assert limiter.check("k") is None
    assert limiter.check("k") is None
    first = limiter.check("k")
    second = limiter.check("k")
    assert first is not None and second is not None


def test_poll_floor_blocks_a_fast_repeat() -> None:
    from dsar.web.limits import MinInterval

    floor = MinInterval(5.0)
    assert floor.check("search-1") is None
    assert floor.check("search-1") is not None
    assert floor.check("search-2") is None, "the floor must be per-key"


# --------------------------------------------------- A09 auth logging


def test_a_refused_authorisation_is_logged(caplog) -> None:
    """Without this, the only record that someone was turned away is the 403
    they saw, and one typo is indistinguishable from a hundred attempts."""
    from dsar.auth.claims import RoleEnforcement, build_principal
    from dsar.auth.errors import NotAssigned

    with caplog.at_level(logging.WARNING, logger="dsar.auth.claims"):
        with pytest.raises(NotAssigned):
            build_principal(
                {"tid": "t", "oid": "o", "preferred_username": "x@example.test"},
                expected_tenant_id="t",
                enforcement=RoleEnforcement.REQUIRED,
            )
    assert any("REFUSED" in r.getMessage() for r in caplog.records)


def test_a_wrong_tenant_token_is_logged(caplog) -> None:
    from dsar.auth.claims import ClaimError, build_principal

    with caplog.at_level(logging.WARNING, logger="dsar.auth.claims"):
        with pytest.raises(ClaimError):
            build_principal({"tid": "other", "oid": "o"}, expected_tenant_id="t")
    assert any("REFUSED" in r.getMessage() for r in caplog.records)


def test_the_poll_floor_covers_the_endpoint_the_ui_actually_polls() -> None:
    """The floor was on /api/statistics, which the UI never calls — it polls
    /api/case. A limit on an endpoint nobody calls is not a limit."""
    from dsar.web.app import _POLLED_ENDPOINTS

    assert "/api/case" in _POLLED_ENDPOINTS


# ------------------------------------------ A04 request body size


def _request_carrying(payload: bytes, chunk_size: int = 4096):
    """A real Starlette Request over a body delivered in chunks.

    Chunked on purpose: a single-shot body would let a Content-Length check
    pass for the wrong reason, and Content-Length is exactly what this must not
    depend on.
    """
    from starlette.requests import Request

    chunks = [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)]
    remaining = iter(chunks)

    async def receive() -> dict:
        try:
            return {"type": "http.request", "body": next(remaining), "more_body": True}
        except StopIteration:
            return {"type": "http.request", "body": b"", "more_body": False}

    return Request(
        {"type": "http", "method": "POST", "path": "/api/expand", "headers": []},
        receive,
    )


def test_a_request_body_is_capped() -> None:
    """Nothing else in the stack caps it. uvicorn imposes no body limit and
    `request.json()` buffers whatever arrives, so before this the ceiling on one
    authenticated POST was the operator's available memory.

    Rate limiting bounds how many requests arrive, not how large one is.
    """
    import asyncio

    from dsar.web.app import MAX_BODY_BYTES, _read_capped_body

    ok = b'{"reference":"' + b"x" * (MAX_BODY_BYTES // 2) + b'"}'
    assert asyncio.run(_read_capped_body(_request_carrying(ok))) == ok

    too_big = b"x" * (MAX_BODY_BYTES + 1)
    assert asyncio.run(_read_capped_body(_request_carrying(too_big))) is None


def test_the_cap_is_not_reachable_before_authentication() -> None:
    """The read happens after the session check, so an anonymous POST is
    refused without its body ever being buffered — the cap protects an
    authenticated operator from themselves and from a hostile tab, not the
    front door."""
    import inspect

    from dsar.web import app as web_app

    source = inspect.getsource(web_app.api)
    assert source.index("not_signed_in") < source.index("_read_capped_body")
