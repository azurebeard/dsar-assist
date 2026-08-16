"""The web surface: health, security headers, and the static allowlist."""

from __future__ import annotations

import shutil
import subprocess

import pytest
from starlette.testclient import TestClient

from dsar.config import load_config
from dsar.web.app import STATIC_DIR, build_app
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
    status_fn = script.split("function status(text, busy, epoch)", 1)[1].split("\n  }", 1)[0]
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
    assert "state.nextPollAt = Date.now() + POLL_INTERVAL_MS" in script
    # And it must not outlive the work it counts towards.
    assert script.count("state.nextPollAt = null") >= 3


def test_polling_is_a_flat_interval_not_a_ladder(client: TestClient) -> None:
    """Every poll spends the operator's own Graph token, and Purview throttles
    the account rather than the process — so a call made here is taken from
    their other tools. A ladder starting at ten seconds costs six times the
    calls to learn nothing has changed."""
    script = client.get("/app.js").text
    assert "const POLL_INTERVAL_MS = 60000;" in script
    # No back-off arithmetic left behind to drift from the constant.
    assert "pollDelay" not in script
    assert "* 3" not in script


def test_a_narrowing_can_reach_both_queries(client: TestClient) -> None:
    """The delta is only the expansion's contribution while the two queries
    differ by the expansion and nothing else.

    Applying to the expanded side alone was the only option there was, and it
    produced the measured inversion on DSAR-2026-0418a: naive 40 items and one
    site, expanded 4 and none, because `kind:email` is a mail-item property.
    Both queries is now the first button; one side is still available, because
    narrowing one side is a legitimate thing to want.
    """
    script = client.get("/app.js").text
    assert 'applyTemplate(template, readValues(), ["naive", "expanded"])' in script
    assert 'applyTemplate(template, readValues(), ["expanded"])' in script
    assert '"Apply to both queries"' in script


def test_the_delta_says_when_it_has_stopped_meaning_what_it_looks_like(
    client: TestClient,
) -> None:
    """A number that reads backwards is worse than no number, because it is
    believable. The interface cannot refuse a one-sided narrowing — it is
    sometimes what the operator wants — so it states what the delta measures.

    Asserted on the tracked state rather than on the wording: the sentence will
    improve, the property that a divergence is detected and reset clears it
    should not.
    """
    script = client.get("/app.js").text
    assert "state.narrowings" in script
    assert "function renderComparability()" in script
    # Every path that changes what is in a query box re-evaluates it: applying,
    # a partial failure part-way through applying, resetting, and a fresh
    # expansion. A stale warning is as misleading as a missing one.
    assert script.count("renderComparability()") >= 6
    reset = script.split('$("reset-queries").addEventListener', 1)[1].split("});", 1)[0]
    assert "state.narrowings = { naive: [], expanded: [] }" in reset


def test_a_mailbox_only_narrowing_explains_its_own_zero(client: TestClient) -> None:
    """`kind:`, `filetype:` and `hasattachment:` drop the site count to zero.
    Unexplained, that reads as an estate with no SharePoint in it — a
    conclusion a DSAR response cannot afford, and one the caution inside a
    collapsed panel did not prevent."""
    script = client.get("/app.js").text
    assert "template.mailbox_only" in script  # marked on the card, before the click
    assert "not an empty estate" in script    # explained in the banner, after it


def test_a_pasted_query_is_checked_as_well_as_a_clicked_one(
    client: TestClient,
) -> None:
    """The measured inversion came from a query built in the Purview query
    builder and pasted in. Tracking which templates were clicked is blind to
    that, so the text is scanned too — and both boxes re-check on input.

    Quoted phrases are blanked before the scan: a warning that fires on the
    phrase "kind: regards" is one an operator learns to dismiss, and then it is
    not there for the clause that matters.
    """
    script = client.get("/app.js").text
    assert "MAIL_ITEM_CLAUSE" in script
    assert "kind|filetype|hasattachment" in script
    assert 'replace(/"[^"]*"/g' in script
    assert 'addEventListener("input", renderComparability)' in script


def test_the_front_end_parses() -> None:
    """No bundler means no compile step, which is the right trade and leaves
    exactly one hole: a syntax error is served as happily as working code, and
    every server-side test still passes because they read the file as text.

    Skipped without node rather than routed around — CI runs it on all three
    operating systems unconditionally, so a skip here costs local feedback and
    not the guarantee.
    """
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed; CI runs this unconditionally")
    result = subprocess.run(
        [node, "--check", str(STATIC_DIR / "app.js")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_opening_a_case_clears_the_previous_one(client: TestClient) -> None:
    """The case view is reused, so the new case's title lands above the old
    case's searches until the fetch returns.

    On a case with no searches yet that reads as results which are not there;
    on a slow network it reads as a different case's results entirely. Reported
    from the deployed instance as "cached results page appeared after a new
    case was created".
    """
    script = client.get("/app.js").text
    assert "function clearCaseView()" in script
    open_case = script.split("async function openCase(item)", 1)[1].split("\n  }", 1)[0]
    # Before showView, not after — clearing after the paint is a flicker of the
    # wrong data rather than an absence of it.
    assert open_case.index("clearCaseView()") < open_case.index('showView("case")')


def test_the_spinner_cannot_outlive_the_ticker(client: TestClient) -> None:
    """A spinner claims work is ongoing; the ticker is what renews the claim.

    When the ticker stops the claim has to go with it, or the elapsed figure
    freezes while the spinner keeps turning beside a table that says complete —
    the most confusing state the interface can be in, because it looks like
    work and is not.

    Asserted on the coupling rather than on any one call site: there are
    several, and the next one added is the one that forgets.
    """
    script = client.get("/app.js").text
    stop = script.split("function stopTicking()", 1)[1].split("\n  }", 1)[0]
    assert "if (state.statusBusy) status(null)" in stop

    # startTicking must NOT go through stopTicking, or it would clear the busy
    # status renderWaiting sets immediately before it.
    start = script.split("function startTicking()", 1)[1].split("\n  }", 1)[0]
    assert "stopTicking()" not in start
    assert "clearTicker()" in start

    # And the flag has to be maintained, or the coupling above never fires.
    status_fn = script.split("function status(text, busy, epoch)", 1)[1].split("\n  }", 1)[0]
    assert "state.statusBusy = !!busy" in status_fn
    assert "state.statusBusy = false" in status_fn


def test_every_role_held_is_shown_not_just_the_effective_one(
    client: TestClient,
) -> None:
    """App roles in Entra are additive: a user assigned both carries both, and
    nothing "wins".

    Showing only the effect — the create button being enabled — made that look
    like a conflict resolved somewhere, which it is not. `DSAR.Operator`
    implies everything `DSAR.Auditor` allows, so holding both is redundant
    rather than contradictory, and the page should say which are held.
    """
    script = client.get("/app.js").text
    signed_in = script.split("function renderSignedIn(me)", 1)[1].split("\n  }", 1)[0]
    assert "me.roles" in signed_in
    assert "replaceChildren(...identity)" in signed_in


def test_a_status_cannot_land_on_a_page_the_operator_left(client: TestClient) -> None:
    """Every handler that settles a status after an `await` must drop the write
    if the view moved on meanwhile.

    `refreshCase` had guarded this since the first report. The five handlers
    that create a case, expand an identity, apply a template, run both searches
    and start an export had not — so "Estimating…" and "Export started." could
    land on the Requests list, describing a page the operator was no longer
    looking at. Each one was a separate place to remember, which is why the
    guard now lives in `status()` and the callers only pass the epoch.
    """
    script = client.get("/app.js").text
    guard = script.split("function status(text, busy, epoch)", 1)[1].split("\n  }", 1)[0]
    assert "if (epoch !== undefined && epoch !== state.viewEpoch) return" in guard

    # The epoch has to actually change, or the guard never fires.
    show_view = script.split("function showView(name)", 1)[1].split("\n  }", 1)[0]
    assert "state.viewEpoch += 1" in show_view
    assert "status(null)" in show_view  # navigating away clears it

    # And every deferred settle must carry one. Counted rather than named:
    # a new handler that forgets is the failure this is guarding.
    assert script.count("epoch)") >= 10


def test_completion_clears_the_status_rather_than_replacing_it(
    client: TestClient,
) -> None:
    """The operator asked for two conditions and only two: cleared when the
    estimates complete, and cleared when they navigate away.

    The table already says complete and the note above it says how long it
    took. A third copy in a bar that looks like progress is the thing that
    confused.
    """
    script = client.get("/app.js").text
    complete_branch = script.split(
        'setText("poll-note", "All estimates complete after "', 1
    )[1].split("} else {", 1)[0]
    assert "status(null)" in complete_branch
    # No status TEXT written on completion. Asserted on the call rather than on
    # the file, because the comment explaining the change names the string it
    # removed — the same way three earlier scans tripped over their own prose.
    assert 'status("' not in complete_branch


def test_the_hidden_attribute_actually_hides(client: TestClient) -> None:
    """`hidden` is a UA-stylesheet default, and it loses to any author rule
    that sets `display`. `.status { display: flex }` did exactly that: the
    status bar painted as an empty pill on every view while its `hidden`
    property read true. Found by screenshotting, not by the suite, because
    server-side tests read attributes and a browser paints computed style."""
    css = client.get("/style.css").text
    assert "[hidden] { display: none !important; }" in css
