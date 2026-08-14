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


def test_an_operators_own_sessions_are_bounded_first() -> None:
    """One operator's habits cost that operator, not the instance.

    Their sessions beyond the per-principal cap evict their own oldest — a
    laptop, a phone and a second browser all keep working, and a fourth tab
    does not consume a colleague's slot.
    """
    import msal

    from dsar.auth.session import MAX_SESSIONS_PER_PRINCIPAL

    store = SessionStore(max_sessions=64)
    me = Principal(oid="operator-a", tenant_id=TENANT)
    ids = []
    for _ in range(MAX_SESSIONS_PER_PRINCIPAL + 3):
        ids.append(store.create(me, msal.TokenCache()).id)
        time.sleep(0.001)

    assert len(store) == MAX_SESSIONS_PER_PRINCIPAL
    assert store.get(ids[0]) is None       # their own oldest went
    assert store.get(ids[-1]) is not None   # their newest survives


def test_one_operator_cannot_evict_another(monkeypatch: pytest.MonkeyPatch) -> None:
    """B-06. The store used to evict the globally-oldest session to make room.

    On the desktop that is one operator and harmless. On a shared instance it
    means a signed-in operator opening tabs silently signs out a colleague,
    mid-case, with no message either of them can see — a bystander paying for
    someone else's traffic, which is the same defect the flow store had.
    """
    import msal

    from dsar.auth import session as session_module

    monkeypatch.setattr(session_module, "MAX_SESSIONS_PER_PRINCIPAL", 2)
    store = SessionStore(max_sessions=4)

    victim = store.create(Principal(oid="victim", tenant_id=TENANT), msal.TokenCache())
    time.sleep(0.001)

    noisy = Principal(oid="noisy", tenant_id=TENANT)
    for _ in range(10):
        store.create(noisy, msal.TokenCache())
        time.sleep(0.001)

    assert store.get(victim.id) is not None, "a bystander's session was evicted"


def test_a_genuinely_full_store_refuses_rather_than_evicting() -> None:
    """With every operator inside their own budget, a full store means too
    many people — not one person misbehaving. Refusing is visible and leaves
    every established session working; evicting a stranger is neither."""
    import msal

    from dsar.auth.session import SessionStoreFull

    store = SessionStore(max_sessions=3)
    held = [
        store.create(Principal(oid=f"op-{i}", tenant_id=TENANT), msal.TokenCache())
        for i in range(3)
    ]
    with pytest.raises(SessionStoreFull, match="already signed in"):
        store.create(Principal(oid="late", tenant_id=TENANT), msal.TokenCache())

    for session in held:
        assert store.get(session.id) is not None


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
    monkeypatch.setenv("DSAR_UAMI_CLIENT_ID", "99999999-8888-7777-6666-555555555555")
    hosted = TestClient(build_app(load_config()), follow_redirects=False)
    assert "prompt=select_account" in hosted.get("/auth/login").headers["location"]


def test_hosted_cookies_are_secure_and_host_prefixed(monkeypatch, config_env, offline_msal) -> None:
    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    monkeypatch.setenv("DSAR_UAMI_CLIENT_ID", "99999999-8888-7777-6666-555555555555")
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


def test_hosted_without_a_managed_identity_refuses_to_start(
    monkeypatch, config_env, offline_msal
) -> None:
    """There is no secret to fall back to, so there is nothing to fall back to.

    Before `build_client` existed, three call sites named `build_public_client`
    directly and a hosted deployment would have quietly authenticated as a
    public client — no client authentication at all, and every test still
    green. The refusal is the design working.
    """
    from dsar.config import ConfigError

    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    monkeypatch.delenv("DSAR_UAMI_CLIENT_ID", raising=False)
    hosted = TestClient(build_app(load_config()), follow_redirects=False)
    with pytest.raises(ConfigError, match="DSAR_UAMI_CLIENT_ID"):
        hosted.get("/auth/login")


def test_hosted_builds_a_confidential_client(monkeypatch, config_env, offline_msal) -> None:
    """The mode is consulted in exactly one place, so this is the whole of the
    difference between the two deployments."""
    import msal

    from dsar.auth.msal_client import build_client
    from tests.fakes import FakeHttpClient

    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    monkeypatch.setenv("DSAR_UAMI_CLIENT_ID", "99999999-8888-7777-6666-555555555555")
    app = build_client(load_config(), http_client=FakeHttpClient())
    assert isinstance(app, msal.ConfidentialClientApplication)
    assert set(app.client_credential) == {"client_assertion"}

    monkeypatch.setenv("DSAR_MODE", "desktop")
    desktop = build_client(load_config(), http_client=FakeHttpClient())
    assert isinstance(desktop, msal.PublicClientApplication)
    assert not getattr(desktop, "client_credential", None)


def test_the_provider_refuses_an_account_that_is_not_the_principal(
    config_env, offline_msal
) -> None:
    """WS10 SEC-M-04. Token acquisition must be bound to the audited actor.

    The provider took `accounts[0]` — positional, unfiltered, never compared to
    the principal — while its docstring claimed it was "bound to one identity
    at construction, so nothing downstream can name another account even by
    mistake".

    Unreachable today: one session, one cache, one account. The failure mode if
    it ever became reachable is not a wrong token — it is a Graph call made as
    operator A while every audit record for it names operator B, with the hash
    chain attesting to the wrong name. That is the one failure this audit trail
    exists to make impossible, so it is enforced rather than described.
    """
    from dsar.auth.desktop import DesktopTokenProvider
    from dsar.auth.errors import ReauthRequired
    from dsar.auth.msal_client import build_client
    from dsar.config import load_config
    from tests.fakes import FakeHttpClient

    class _TwoAccounts:
        """Someone else's account sits first in the cache."""

        def get_accounts(self):  # type: ignore[no-untyped-def]
            return [
                {"home_account_id": "someone-else.tid", "username": "victim@x.test"},
                {"home_account_id": "ours-oid.tid", "username": "ours@x.test"},
            ]

    config = load_config()
    app = build_client(config, http_client=FakeHttpClient())
    app.get_accounts = _TwoAccounts().get_accounts  # type: ignore[method-assign]

    ours = DesktopTokenProvider(app, config, Principal(oid="ours-oid", tenant_id=TENANT))
    chosen = ours._account_for_principal()
    assert chosen is not None
    assert chosen["home_account_id"] == "ours-oid.tid", "picked by position, not identity"

    # And an operator with no cached account is refused, never handed a
    # stranger's. Falling back to position is what made this possible.
    nobody = DesktopTokenProvider(
        app, config, Principal(oid="not-in-the-cache", tenant_id=TENANT)
    )
    assert nobody._account_for_principal() is None
    with pytest.raises(ReauthRequired, match="no cached account matches"):
        nobody.get_token()


def test_logout_clears_the_cookie_in_hosted_mode_too(
    monkeypatch, config_env, offline_msal
) -> None:
    """WS10 SEC-M-05. A `__Host-` cookie deletion without `Secure` is rejected.

    RFC 6265bis §4.1.3.2 requires a user agent to reject a `__Host-`-prefixed
    cookie that does not carry `Secure`, and Starlette's `delete_cookie`
    defaults to `secure=False` — so the deletion was discarded and the cookie
    survived sign-out for its full 8-hour Max-Age.

    Bounded: the server-side session is destroyed either way, so the retained
    value resolves to nothing. What was lost is the stated property.

    The existing test could not catch it — it runs against the desktop fixture,
    where the cookie has no prefix and the browser would accept the deletion.
    """
    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    monkeypatch.setenv("DSAR_UAMI_CLIENT_ID", "99999999-8888-7777-6666-555555555555")
    hosted = TestClient(build_app(load_config()), follow_redirects=False)

    response = hosted.post(
        "/auth/logout", headers={"Origin": "https://dsar.example.co.uk"}
    )
    deletions = [c for c in response.headers.get_list("set-cookie") if "Max-Age=0" in c]
    assert deletions, "logout set no deletion cookie"
    for cookie in deletions:
        assert "__Host-" in cookie
        # Without this the browser discards the deletion entirely.
        assert "Secure" in cookie, cookie
        assert "Path=/" in cookie
