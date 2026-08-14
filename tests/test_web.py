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
    assert client.get("/not-registered.js").status_code == 404
    assert client.get("/../config.json").status_code == 404


def test_front_page_offers_sign_in(client: TestClient) -> None:
    """The auth routes existed before anything linked to them, so the flow was
    unreachable from the UI. That is a defect the tests did not catch, because
    every test called /auth/login directly."""
    body = client.get("/").text
    assert "/auth/login" in body


def test_front_page_assets_are_served(client: TestClient) -> None:
    for path, marker in (("/app.js", "whoami"), ("/style.css", "--accent")):
        response = client.get(path)
        assert response.status_code == 200, path
        assert marker in response.text


def test_no_inline_script_would_survive_the_csp(client: TestClient) -> None:
    """script-src 'self' blocks inline handlers, so a page relying on one
    breaks silently in the browser and passes every server-side test."""
    body = client.get("/").text
    assert "onclick=" not in body.lower()
    assert "<script>" not in body.lower()


def test_no_server_header_leak(client: TestClient) -> None:
    assert "uvicorn" not in client.get("/healthz").headers.get("server", "").lower()


def test_status_region_is_announced(client: TestClient) -> None:
    """A screen reader user gets the same eleven-minute wait as everyone else
    and deserves to be told about it, so the live region is asserted rather
    than left to a visual check."""
    body = client.get("/").text
    assert 'role="status"' in body
    assert 'aria-live="polite"' in body


def test_every_submit_control_has_a_busy_path(client: TestClient) -> None:
    """A click that takes eleven minutes must not look like a click that did
    nothing. Every long-running action is wrapped so the button disables and
    relabels — which also makes a double click impossible, and a double click
    is separately how template narrowings got stacked."""
    script = client.get("/app.js").text
    for control in ("create-case", "expand", "run-both", "refresh-case"):
        assert f'$("{control}")' in script, control
    assert script.count("withBusy(") >= 4


def test_reduced_motion_is_respected(client: TestClient) -> None:
    assert "prefers-reduced-motion" in client.get("/style.css").text


def test_elapsed_counter_ticks_independently_of_the_graph_poll(
    client: TestClient,
) -> None:
    """The Graph poll backs off to 60s. Without a separate ticker the elapsed
    figure is stale for up to a minute — which is the interval over which a
    reader decides the page has stopped."""
    script = client.get("/app.js").text
    assert "startTicking" in script and "stopTicking" in script
    assert "setInterval(renderWaiting, 1000)" in script
    # Every exit from the case view must stop it, or it writes into a hidden
    # element and the next case inherits a running clock.
    assert script.count("stopTicking()") >= 4


def test_no_estimation_duration_is_claimed_in_the_ui(client: TestClient) -> None:
    """The eleven-minute figure was measured once, on one tenant. Quoting it in
    the interface turns a single observation into a promise."""
    for path in ("/", "/app.js"):
        text = client.get(path).text.lower()
        for claim in ("eleven minutes", "11 minutes", "cold index"):
            assert claim not in text, f"{claim!r} still in {path}"


def test_signing_out_tears_down_the_previous_session(client: TestClient) -> None:
    """A timer or status line that outlives a sign-out shows one operator
    something about another's work — on a shared machine, the next person saw
    the last person's case progress on the sign-in screen."""
    script = client.get("/app.js").text
    signed_out = script.split("function renderSignedOut()", 1)[1].split("\n  }", 1)[0]
    for teardown in ("clearTimeout(state.pollTimer)", "stopTicking()", "status(null)"):
        assert teardown in signed_out, f"renderSignedOut does not {teardown}"
    assert "state.case_id = null" in signed_out


def test_a_sustained_status_belongs_to_the_case_view(client: TestClient) -> None:
    """A spinner that never resolves is a lie anywhere the work is not ongoing.

    Guarded on the tracked view name rather than on an element's hidden
    attribute: an in-flight refresh that lands after the operator navigated
    away would otherwise write a status describing a page they are no longer
    looking at, which is what "the previous status is retained" was.
    """
    script = client.get("/app.js").text
    assert script.count('state.view !== "case"') >= 2
    assert "state.view = name" in script
    # Every status expires — asserted as the property rather than the exact
    # expression, because pinning the literal is how this test broke when the
    # expiry was improved from "non-busy only" to "both, with different
    # timeouts". A test that fails on a better implementation trains people to
    # edit tests rather than read them.
    status_fn = script.split("function status(text, busy)", 1)[1].split("\n  }", 1)[0]
    assert "state.statusTimer = setTimeout" in status_fn
    assert "status(null)" in status_fn


def test_export_message_says_where_not_what_it_cannot_do(client: TestClient) -> None:
    """The handoff IS the security model. Phrasing it as "this tool cannot"
    invites the reader to hear a limitation instead."""
    script = client.get("/app.js").text
    assert "Export started. Collect it in the Purview portal." in script
    # Scoped to the export message. "which this tool cannot change" survives
    # elsewhere and should: it describes where the Purview RBAC boundary is,
    # which is a fact about the system rather than an apology for the tool.
    export_line = next(
        line for line in script.splitlines() if "Export started." in line
    )
    assert "cannot" not in export_line


def test_a_busy_status_expires_if_it_is_not_renewed(client: TestClient) -> None:
    """A spinner is a claim that something is still happening. It has to be
    renewed to keep making it — otherwise any path that forgets to clear it
    leaves the interface asserting work that ended minutes ago, which is what a
    completed case did: "Estimating — 2m 38s" beside a table saying complete."""
    script = client.get("/app.js").text
    assert "busy ? 15000 : 4000" in script


def test_the_ticker_clears_rather_than_returning_bare(client: TestClient) -> None:
    """`if (!state.running) return;` left whatever was on screen. Nothing
    running means stop asserting that something is."""
    script = client.get("/app.js").text
    waiting = script.split("function renderWaiting()", 1)[1].split("function untilNextCheck", 1)[0]
    assert "if (!state.running) {" in waiting
    assert "stopTicking()" in waiting and "status(null)" in waiting


def test_countdown_to_the_next_check(client: TestClient) -> None:
    """The gap between polls stretches to a minute; without a countdown that
    pause is indistinguishable from a stall."""
    script = client.get("/app.js").text
    assert "next check in " in script
    assert "state.nextPollAt = Date.now() + state.pollDelay" in script
    # And it must not outlive the work it counts towards.
    assert script.count("state.nextPollAt = null") >= 3
