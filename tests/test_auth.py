"""Phase 1 identity plane: claims, sessions, flow cache, routes."""

from __future__ import annotations

import time

import pytest
from starlette.testclient import TestClient

from dsar.auth.claims import ClaimError, RoleEnforcement, build_principal
from dsar.auth.errors import (
    NotAssigned,
    challenge_error_code,
    parse_claims_challenge,
)
from dsar.auth.provider import ROLE_AUDITOR, ROLE_OPERATOR, Principal
from dsar.auth.session import FlowStore, SessionStore
from dsar.config import load_config
from dsar.web.app import build_app

TENANT = "66666666-7777-8888-9999-aaaaaaaaaaaa"


def _claims(**overrides: object) -> dict:
    base = {
        "tid": TENANT,
        "oid": "11111111-1111-1111-1111-111111111111",
        "preferred_username": "operator@example.test",
        "uti": "abc123",
    }
    base.update(overrides)
    return base


# ------------------------------------------------------- claims challenge


def test_base64url_claims_are_decoded() -> None:
    """Entra sends base64url; MSAL wants JSON. Forwarding the raw value gives a
    challenge that silently never satisfies."""
    header = (
        'Bearer realm="", authorization_uri="https://login.microsoftonline.com", '
        'error="insufficient_claims", '
        'claims="eyJhY2Nlc3NfdG9rZW4iOnsibmJmIjp7ImVzc2VudGlhbCI6dHJ1ZX19fQ=="'
    )
    decoded = parse_claims_challenge(header)
    assert decoded is not None
    assert decoded.startswith("{") and "access_token" in decoded


def test_raw_json_claims_with_escaped_quotes() -> None:
    """The form a naive `[^"]+` truncates at the first backslash-quote.

    Carried over from the predecessor with its test, because getting this wrong
    yields a fragment that looks like JSON and is not.
    """
    header = 'Bearer error="insufficient_claims", claims="{\\"access_token\\":{\\"nbf\\":{\\"essential\\":true}}}"'
    decoded = parse_claims_challenge(header)
    assert decoded == '{"access_token":{"nbf":{"essential":true}}}'


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer realm=\"\"",  # plain expired token — not a challenge
        'Bearer claims="not-base64-and-not-json"',
        'Bearer claims="eyJub3QtanNvbg=="',  # decodes, but is not JSON
    ],
)
def test_non_challenges_return_none(header: str | None) -> None:
    assert parse_claims_challenge(header) is None


def test_error_code_is_extracted() -> None:
    assert (
        challenge_error_code('Bearer error="insufficient_claims", realm=""')
        == "insufficient_claims"
    )


# --------------------------------------------------------------- claims


def test_tenant_is_pinned() -> None:
    with pytest.raises(ClaimError, match="expected"):
        build_principal(_claims(tid="99999999-9999-9999-9999-999999999999"),
                        expected_tenant_id=TENANT)


def test_missing_oid_is_refused() -> None:
    claims = _claims()
    del claims["oid"]
    with pytest.raises(ClaimError, match="oid"):
        build_principal(claims, expected_tenant_id=TENANT)


def test_principal_is_keyed_on_oid_and_tenant_not_upn() -> None:
    """`upn` and `preferred_username` are mutable and reassignable; `oid` is not."""
    principal = build_principal(_claims(), expected_tenant_id=TENANT)
    assert principal.key == (principal.oid, TENANT)
    assert principal.upn not in principal.key


def test_operator_role_grants_write() -> None:
    principal = build_principal(
        _claims(roles=[ROLE_OPERATOR]), expected_tenant_id=TENANT
    )
    assert principal.can_write is True


def test_auditor_role_does_not_grant_write() -> None:
    principal = build_principal(
        _claims(roles=[ROLE_AUDITOR]), expected_tenant_id=TENANT
    )
    assert principal.can_write is False
    assert principal.roles == frozenset({ROLE_AUDITOR})


def test_required_enforcement_refuses_a_roleless_token() -> None:
    with pytest.raises(NotAssigned):
        build_principal(
            _claims(), expected_tenant_id=TENANT,
            enforcement=RoleEnforcement.REQUIRED,
        )


def test_advisory_enforcement_admits_a_roleless_token() -> None:
    """The posture when the probe shows public clients get no `roles` claim.

    appRoleAssignmentRequired is what admitted the token; refusing here would
    lock out every legitimate operator to no benefit.
    """
    principal = build_principal(
        _claims(), expected_tenant_id=TENANT, enforcement=RoleEnforcement.ADVISORY
    )
    assert principal.roles == frozenset()
    assert principal.can_write is False


def test_unknown_roles_are_ignored_not_fatal() -> None:
    principal = build_principal(
        _claims(roles=[ROLE_OPERATOR, "DSAR.Invented"]), expected_tenant_id=TENANT
    )
    assert principal.roles == frozenset({ROLE_OPERATOR})


def test_a_single_role_string_is_accepted() -> None:
    principal = build_principal(
        _claims(roles=ROLE_OPERATOR), expected_tenant_id=TENANT
    )
    assert principal.can_write is True


# -------------------------------------------------------------- sessions


def test_session_cookie_carries_only_an_opaque_id(config_env) -> None:
    store = SessionStore()
    import msal

    # A realistic oid: a one-character value appears in any base64 string by
    # chance, so the original version of this test proved nothing.
    principal = Principal(oid="11111111-1111-1111-1111-111111111111", tenant_id=TENANT)
    session = store.create(principal, msal.TokenCache())
    assert len(session.id) >= 32
    assert principal.oid not in session.id
    assert TENANT not in session.id


def test_session_lookup_is_by_id_and_misses_are_none() -> None:
    store = SessionStore()
    import msal

    session = store.create(Principal(oid="o", tenant_id=TENANT), msal.TokenCache())
    assert store.get(session.id) is not None
    assert store.get("not-a-session") is None
    assert store.get(None) is None


def test_removed_session_is_gone() -> None:
    store = SessionStore()
    import msal

    session = store.create(Principal(oid="o", tenant_id=TENANT), msal.TokenCache())
    store.remove(session.id)
    assert store.get(session.id) is None


def test_session_store_is_bounded_and_evicts_lru() -> None:
    """An unbounded dict keyed by anything a caller can create is a memory
    exhaustion vector."""
    import msal

    store = SessionStore(max_sessions=3)
    ids = []
    for i in range(5):
        ids.append(store.create(Principal(oid=str(i), tenant_id=TENANT), msal.TokenCache()).id)
        time.sleep(0.001)
    assert len(store) <= 3
    assert store.get(ids[0]) is None      # evicted
    assert store.get(ids[-1]) is not None  # newest survives


# ------------------------------------------------------------ flow cache


def test_pending_flow_is_single_use() -> None:
    """Replaying a callback against a still-valid pending flow is how an
    intercepted code becomes a session."""
    store = FlowStore()
    key = store.put({"state": "s", "code_verifier": "v"})
    assert store.take(key) is not None
    assert store.take(key) is None


def test_flow_lookup_rejects_unknown_and_none() -> None:
    store = FlowStore()
    assert store.take("nope") is None
    assert store.take(None) is None


def test_flow_store_is_bounded_and_refuses_rather_than_evicts() -> None:
    """The bound is kept, but a full store now refuses instead of evicting.

    Evicting made an unauthenticated caller able to cancel a real operator's
    in-progress sign-in, which is a bystander paying for someone else's
    traffic. Refusing affects the caller causing it.
    """
    from dsar.auth.session import FlowStoreFull

    store = FlowStore(max_pending=3)
    for _ in range(3):
        store.put({"state": "s"})
    with pytest.raises(FlowStoreFull):
        store.put({"state": "one too many"})
    assert len(store) == 3


# ---------------------------------------------------------------- routes


@pytest.fixture
def client(config_env, offline_msal) -> TestClient:
    return TestClient(build_app(load_config()), follow_redirects=False)


def test_whoami_is_401_when_signed_out(client: TestClient) -> None:
    response = client.get("/api/whoami")
    assert response.status_code == 401
    assert response.json() == {"signed_in": False}


def test_whoami_discloses_no_tenant_when_signed_out(client: TestClient) -> None:
    assert TENANT not in client.get("/api/whoami").text


def test_login_redirects_to_entra_and_sets_a_flow_cookie(client: TestClient) -> None:
    response = client.get("/auth/login")
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://login.microsoftonline.com/")
    assert "code_challenge=" in location and "code_challenge_method=S256" in location
    assert "response_type=code" in location
    cookies = response.headers.get_list("set-cookie")
    assert any("dsar_flow" in c for c in cookies)
    # The cookie carries an opaque key, never the verifier itself.
    assert not any("code_verifier" in c for c in cookies)


def test_login_does_not_leak_the_pkce_verifier(client: TestClient) -> None:
    response = client.get("/auth/login")
    assert "code_verifier" not in response.headers["location"]


def test_callback_without_a_pending_flow_is_refused(client: TestClient) -> None:
    """No flow cookie means expired, already used, or never ours."""
    response = client.get("/auth/callback?code=stolen&state=guessed")
    assert response.status_code == 400
    assert "expired" in response.text.lower()


def test_logout_clears_the_session_cookie(client: TestClient) -> None:
    response = client.post("/auth/logout", headers={"Origin": "http://localhost:8765"})
    assert response.status_code == 302
    assert any(
        "dsar_session=" in c and "Max-Age=0" in c
        for c in response.headers.get_list("set-cookie")
    )


def test_desktop_omits_prompt_select_account(client: TestClient) -> None:
    """A single operator re-selecting their account every time is friction with
    nothing to buy."""
    assert "prompt=select_account" not in client.get("/auth/login").headers["location"]


def test_hosted_sends_prompt_select_account(monkeypatch, config_env, offline_msal) -> None:
    """Without it, operator B inherits operator A's Entra session and signs in
    as them — silently, with a correct-looking UI."""
    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    hosted = TestClient(build_app(load_config()), follow_redirects=False)
    assert "prompt=select_account" in hosted.get("/auth/login").headers["location"]


def test_hosted_cookies_are_secure_and_host_prefixed(monkeypatch, config_env, offline_msal) -> None:
    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    hosted = TestClient(build_app(load_config()), follow_redirects=False)
    cookies = hosted.get("/auth/login").headers.get_list("set-cookie")
    flow = next(c for c in cookies if "dsar_flow" in c)
    assert "__Host-" in flow
    lowered = flow.lower()
    assert "secure" in lowered and "httponly" in lowered and "samesite=lax" in lowered


def test_step_up_url_carries_the_claims() -> None:
    """A step-up that drops the claims succeeds and changes nothing, which
    reads as progress and is not."""
    from dsar.auth.desktop import DesktopTokenProvider

    provider = DesktopTokenProvider.__new__(DesktopTokenProvider)
    url = provider.step_up_url('{"access_token":{"nbf":{"essential":true}}}')
    assert url.startswith("/auth/login?claims=")
    assert "access_token" in url


def test_logout_requires_a_same_origin_post(client: TestClient) -> None:
    """Forced sign-out is a nuisance rather than a compromise — but every other
    state-changing POST enforces the origin rule, and an unexplained exception
    is how a rule stops being trusted."""
    assert client.post("/auth/logout").status_code == 403
    assert client.post(
        "/auth/logout", headers={"Origin": "https://evil.example"}
    ).status_code == 403
    assert client.post(
        "/auth/logout", headers={"Origin": "http://localhost:8765"}
    ).status_code == 302
