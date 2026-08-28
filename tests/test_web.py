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
    open_case = script.split("async function openCase(item, seed)", 1)[1].split("\n  }", 1)[0]
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


def test_the_delta_checks_comparability_where_it_is_displayed(
    client: TestClient,
) -> None:
    """B-10's first residual: the delta banner rendered on the case view,
    away from the queries, so a number computed from two incomparable
    searches arrived with no warning beside it. The queries that actually
    ran come back from Graph on each search row, so the mail-item check runs
    at the point of display — on any machine, weeks later, including a query
    pasted into Purview's own builder that no click tracking ever saw.

    Asserted on the mechanism, not the wording: renderDelta consults
    hasMailItemClause on both ran queries before quoting a difference, and
    the not-comparable path exists.
    """
    script = client.get("/app.js").text
    delta = script.split("function renderDelta(", 1)[1].split("\n  }\n", 1)[0]
    assert delta.count("hasMailItemClause(") == 2, (
        "renderDelta no longer checks both ran queries"
    )
    assert "not comparable" in delta
    # And the second residual, honesty about scope: everywhere the mail-item
    # list drives a message, the message owns that it is a list, not a parser.
    assert script.count("not a KQL parser") >= 2


def test_readiness_names_the_purview_problem_before_work_starts() -> None:
    """B-18. `doctor` diagnoses everything a session is not needed for and
    could never check these two: it has no token. Whether the operator holds
    a DSAR role and whether Purview answers them are only knowable signed
    in — so they are checked at sign-in and the failure names the fix,
    instead of surprising the operator on their first attempt."""
    from dsar.auth.provider import Principal
    from dsar.graph.errors import PurviewRoleMissing
    from dsar.web.api import handle

    operator = Principal(
        oid="oid-1",
        tenant_id="66666666-7777-8888-9999-aaaaaaaaaaaa",
        roles=frozenset({"DSAR.Operator"}),
    )

    class _Ready:
        def list_requests(self, principal, *, scope, force=False):  # noqa: ANN001
            return object()

    status, payload = handle(
        "/api/readiness", {}, principal=operator,
        cases=_Ready(),  # type: ignore[arg-type]
        config=None,  # type: ignore[arg-type]
        workflow=None,  # type: ignore[arg-type]
    )
    assert (status, payload["ready"]) == (200, True)

    class _NoRole:
        def list_requests(self, principal, *, scope, force=False):  # noqa: ANN001
            raise PurviewRoleMissing(operation="list_cases")

    status, payload = handle(
        "/api/readiness", {}, principal=operator,
        cases=_NoRole(),  # type: ignore[arg-type]
        config=None,  # type: ignore[arg-type]
        workflow=None,  # type: ignore[arg-type]
    )
    assert (status, payload["ready"]) == (200, False)
    purview = next(c for c in payload["checks"] if c["name"] == "purview")
    assert not purview["ok"] and "eDiscovery role" in purview["note"]

    # No role in the token at all: not ready, and the note says where to ask.
    auditorless = Principal(
        oid="oid-2", tenant_id="66666666-7777-8888-9999-aaaaaaaaaaaa"
    )
    status, payload = handle(
        "/api/readiness", {}, principal=auditorless,
        cases=_Ready(),  # type: ignore[arg-type]
        config=None,  # type: ignore[arg-type]
        workflow=None,  # type: ignore[arg-type]
    )
    assert payload["ready"] is False
    role = next(c for c in payload["checks"] if c["name"] == "app role")
    assert "Entra" in role["note"]


def test_batch_validation_checks_rules_without_touching_graph_or_subjects() -> None:
    """B-17. The batch is client-driven; this endpoint is its one server
    piece — the two fields with server-owned rules, checked by the same code
    that enforces them at creation, so the dry run cannot drift from the
    run. A subject column arriving here is refused loudly: a validation
    endpoint that accepted names and addresses would be a subject-data sink
    with "validate" in its name."""
    from dsar.auth.provider import Principal
    from dsar.web.api import handle

    operator = Principal(
        oid="oid-1",
        tenant_id="66666666-7777-8888-9999-aaaaaaaaaaaa",
        roles=frozenset({"DSAR.Operator"}),
    )

    def validate(rows):  # noqa: ANN001, ANN202
        return handle(
            "/api/batch/validate", {"rows": rows}, principal=operator,
            cases=None,  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            workflow=None,  # type: ignore[arg-type]
        )

    status, payload = validate([
        {"reference": "DSAR-2026-0300", "received": "2026-08-01"},
        {"reference": "DSAR-2026-0300", "received": ""},          # duplicate
        {"reference": "", "received": "2026-08-01"},              # no reference
        {"reference": "DSAR-2026-0301", "received": "01/08/2026"},  # bad date
        {"reference": "DSAR-2026-0302", "primary_email": "a@x.test"},  # subject key
    ])
    assert status == 200 and payload["ok"] is False
    oks = [r["ok"] for r in payload["rows"]]
    assert oks == [True, False, False, False, False]
    assert "duplicate of row 1" in payload["rows"][1]["message"]
    assert "primary_email" in payload["rows"][4]["message"]

    # The cap, and the empty batch.
    status, payload = validate([{"reference": f"R-{i}", "received": ""} for i in range(101)])
    assert status == 400
    status, payload = validate([])
    assert status == 400


def test_the_batch_is_client_driven_and_resumes_without_repeating_writes(
    client: TestClient,
) -> None:
    """B-17's shape, held: the batch inherits the single flow's controls by
    RUNNING the single flow, and a retry resumes at the failed step rather
    than repeating a Graph write that succeeded. Asserted on the mechanism:
    each step is guarded by the state the previous one stored, and unknown
    CSV columns are refused, not dropped — a silently ignored column is how
    this page once lost every nickname an operator typed."""
    script = client.get("/app.js").text
    batch = script.split("batch (B-17)", 1)[1]
    # Resume guards: a row that holds a case id does not create again, an
    # expansion is not re-resolved, a started search is not restarted.
    assert "if (!row.case_id)" in batch
    assert "if (!row.expansion)" in batch
    assert 'if (row[kind + "Done"]) continue;' in batch
    # Unknown columns are refused.
    assert "Unknown column(s)" in batch
    # The rows go to the same per-case endpoints, not a batch executor.
    for endpoint in ("/api/case/create", "/api/expand", "/api/search/create"):
        assert endpoint in batch
    # And the only batch endpoint is validation.
    from dsar.web.api import API_ENDPOINTS

    batch_endpoints = [e for e in API_ENDPOINTS if "batch" in e]
    assert batch_endpoints == ["/api/batch/validate"]


# ------------------------------------------------------------------ B-30/31
# The UX round of 2026-08-28 (five reviewers over a live walkthrough) and the
# two source defects it surfaced: Graph calls on the event loop, and a busy
# status that expired before the work did.


def _signed_in(client: TestClient, roles: tuple[str, ...] = ("DSAR.Operator",)):  # noqa: ANN202
    """Seed a session straight into the app's store and hand the cookie to the
    client. The auth flow is tested elsewhere; here the session is a given."""
    import msal

    from dsar.auth.provider import Principal
    from dsar.auth.session import cookie_names

    core = client.app
    while not hasattr(core, "state"):
        core = core.app
    state = core.state.auth
    principal = Principal(
        oid="oid-web",
        tenant_id="66666666-7777-8888-9999-aaaaaaaaaaaa",
        upn="operator@example.test",
        roles=frozenset(roles),
    )
    session = state.sessions.create(principal, msal.TokenCache())
    name, _ = cookie_names(False)
    client.cookies.set(name, session.id)
    return session


def test_graph_handlers_run_off_the_event_loop(client: TestClient, monkeypatch) -> None:
    """B-31. `api()` is a coroutine and `handle()` drives a synchronous Graph
    client with a sixty-second read timeout. Called directly, every Graph
    call parked the event loop: two requests the browser sent together ran
    one after the other, the batch's "two in flight" was one at Graph, and
    in hosted mode one operator's thirty-second case create stalled every
    other operator's request. Measured, not read: the four-call submit took
    18.8 s where two chains of two should take half that.

    Two 0.4 s handlers from two threads must overlap. Serial is 0.8 s.
    """
    import threading
    import time

    import dsar.web.app as web_app

    _signed_in(client)

    def slow_handle(path, body, **kwargs):  # noqa: ANN001, ANN202
        time.sleep(0.4)
        return 200, {"path": path}

    monkeypatch.setattr(web_app, "handle", slow_handle)
    monkeypatch.setattr(web_app, "_session_services", lambda request, session: (None, None))

    codes: list[int] = []

    def call() -> None:
        codes.append(
            client.post(
                "/api/requests", json={}, headers={"Origin": "http://localhost:8765"}
            ).status_code
        )

    # One portal, one event loop, shared by both threads. Outside the context
    # manager the TestClient spins up a loop per request, which would let two
    # blocking handlers overlap for the wrong reason and prove nothing —
    # found by tampering: the un-threadpooled handler passed this test until
    # the requests were made to share a loop.
    started = time.monotonic()
    with client:
        threads = [threading.Thread(target=call) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    elapsed = time.monotonic() - started
    assert codes == [200, 200]
    assert elapsed < 0.7, (
        f"two 0.4 s handlers took {elapsed:.2f} s — they ran one after the other, "
        "so the handler is back on the event loop"
    )


def test_session_services_are_built_once_under_concurrency(client: TestClient, monkeypatch) -> None:
    """With handlers in a threadpool, two first calls on one session can race
    to build its Graph services — and one MSAL rehydration against the shared
    cache would be thrown away half done. Built once, under the session's own
    lock; the second caller gets the first's result."""
    import threading
    import time

    import dsar.web.app as web_app

    session = _signed_in(client)
    built: list[int] = []

    def slow_build(request, session):  # noqa: ANN001, ANN202
        time.sleep(0.2)
        built.append(1)
        return ("cases", "workflow")

    monkeypatch.setattr(web_app, "_build_services", slow_build)
    seen: list[object] = []
    threads = [
        threading.Thread(target=lambda: seen.append(web_app._session_services(None, session)))  # type: ignore[arg-type]
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert built == [1], f"services were built {len(built)} times"
    assert seen == [("cases", "workflow")] * 2
    assert session.case_service == ("cases", "workflow")


def test_a_query_without_the_subject_is_refused_until_confirmed(config_env) -> None:
    """WS10 SEC-M-01. Every generated query names the subject as a
    participant; a query without that clause is one the operator edited down
    to bare text, which for a common name is an estate-wide search under their
    delegated identity. Refused unless the page asked and they said yes. A
    shape check, not a parser — and a quoted phrase is a phrase."""
    from dsar.auth.provider import Principal
    from dsar.cases.model import Search, Statistics
    from dsar.config import load_config
    from dsar.web.api import handle

    operator = Principal(
        oid="oid-1",
        tenant_id="66666666-7777-8888-9999-aaaaaaaaaaaa",
        roles=frozenset({"DSAR.Operator"}),
    )
    created: list[str] = []

    class _Workflow:
        def create_search(self, case_id, name, query, *, note=""):  # noqa: ANN001, ANN202
            created.append((query, note))
            return Search(
                id="s-1", display_name=name, created="2026-08-28T00:00:00Z",
                content_query=query,
                statistics=Statistics(
                    item_count=None, total_size=None, location_count=None,
                    mailbox_count=None, site_count=None, status="", complete=False,
                ),
            )

        def run_estimate(self, case_id, search_id):  # noqa: ANN001, ANN202
            return None

    def create(query: str, **extra: object):  # noqa: ANN202
        return handle(
            "/api/search/create",
            {"case_id": "case-1", "kind": "expanded", "query": query, "run": False, **extra},
            principal=operator,
            cases=None,  # type: ignore[arg-type]
            config=load_config(),
            workflow=_Workflow(),  # type: ignore[arg-type]
        )

    status, payload = create('"Megan Bowen" OR "Meg"')
    assert status == 400 and payload["error"] == "unscoped_query"
    assert created == []

    # The clause inside a quoted phrase does not count.
    status, payload = create('"participants: all staff" OR "Meg"')
    assert status == 400 and payload["error"] == "unscoped_query"
    assert created == []

    # The generated shape passes without ceremony, and without a note.
    status, _ = create('participants:"meganb@example.test" OR "Meg"')
    assert status == 201 and created == [('participants:"meganb@example.test" OR "Meg"', "")]

    # The explicit answer lets an unscoped one through — and is written down
    # in the audit detail as a fixed phrase, never the query (WS10 gate
    # SEC-L-02, mirroring the smaller-export confirmation).
    status, _ = create('"Megan Bowen" OR "Meg"', confirm_unscoped=True)
    assert status == 201
    assert created[-1] == ('"Megan Bowen" OR "Meg"', "unscoped query run after explicit confirmation")

    # The flag on a scoped query records nothing: there was nothing to confirm.
    status, _ = create('participants:"meganb@example.test"', confirm_unscoped=True)
    assert status == 201 and created[-1][1] == ""


def test_a_confirmed_smaller_export_reaches_the_workflow_as_a_note(config_env) -> None:
    """WS10 SEC-M-02. The page gates the export of the smaller search behind a
    confirmation that states the difference; the choice travels as a flag and
    lands in the audit detail as a note — never a count, never a query, and
    never in Purview's export name."""
    from dsar.auth.provider import Principal
    from dsar.cases.workflow import ExportHandoff
    from dsar.config import load_config
    from dsar.web.api import handle

    operator = Principal(
        oid="oid-1",
        tenant_id="66666666-7777-8888-9999-aaaaaaaaaaaa",
        roles=frozenset({"DSAR.Operator"}),
    )
    seen: list[tuple[str, str]] = []

    class _Workflow:
        def initiate_export(self, case_id, search_id, name, portal_url, *, note=""):  # noqa: ANN001, ANN202
            seen.append((name, note))
            return ExportHandoff(case_id=case_id, search_id=search_id, portal_url=portal_url)

    for flag, expected in ((True, "smaller search exported after explicit confirmation"), (False, "")):
        status, _ = handle(
            "/api/export",
            {"case_id": "case-1", "search_id": "s-1", "name": "Naive", "confirmed_smaller": flag},
            principal=operator,
            cases=None,  # type: ignore[arg-type]
            config=load_config(),
            workflow=_Workflow(),  # type: ignore[arg-type]
        )
        assert status == 202
        assert seen[-1] == ("Naive", expected)


def test_the_page_signs_itself_out_at_the_idle_ttl(client: TestClient) -> None:
    """WS10 SEC-M-03. The server expired an idle session and the page found
    out on the next click — a resolved subject's aliases stayed on a shared
    screen for as long as nobody clicked. The TTL travels on whoami, from the
    constant the store enforces, and the page runs the same teardown a 401
    would when it lapses."""
    from dsar.auth.session import IDLE_TTL_SECONDS

    _signed_in(client)
    me = client.get("/api/whoami").json()
    assert me["idle_ttl_seconds"] == IDLE_TTL_SECONDS

    script = client.get("/app.js").text
    arm = script.split("function armIdleTimer()", 1)[1].split("\n  }", 1)[0]
    assert "state.idleTtlSeconds * 1000" in arm
    expired = script.split("function idleExpired()", 1)[1].split("\n  }", 1)[0]
    assert "renderSignedOut()" in expired
    # A timer sleeps with the machine; the wall-clock deadline is checked when
    # the page is looked at again (WS10 gate SEC-L-04).
    assert "state.idleDeadline" in arm
    assert 'addEventListener(event, () => {' in script and "Date.now() >= state.idleDeadline" in script
    # Re-armed by every API call, the same events the server counts.
    api_fn = script.split("async function api(path, body)", 1)[1].split("\n  }", 1)[0]
    assert "armIdleTimer()" in api_fn


def test_reads_show_a_status_like_writes(client: TestClient) -> None:
    """Frames 02 and 18 of the live walkthrough: a heading and a footer for
    four seconds after sign-in, and a title and two buttons on arriving in a
    case. Writes had a status bar; reads did not. Now both do, and the case
    view is seeded from the searches the page has just created."""
    script = client.get("/app.js").text
    load = script.split("async function loadRequests()", 1)[1].split("\n  }", 1)[0]
    assert 'sustained("Reading your cases' in load
    open_case = script.split("async function openCase(item, seed)", 1)[1].split("\n  }", 1)[0]
    assert 'status("Reading the case' in open_case
    assert "renderSearchRows(seed" in open_case
    # The seed comes from the create responses, not a guess.
    assert "outcomes.map((o) => o.search)" in script


def test_the_busy_status_is_renewed_for_as_long_as_the_request_runs(client: TestClient) -> None:
    """The fixed fifteen-second expiry fired mid-wait on half of real case
    creates (median 15 s, p90 29 s), leaving the button saying "Creating…"
    under a bar that had gone quiet. Long requests renew it until they
    settle; the expiry stays as the safety net."""
    script = client.get("/app.js").text
    sustained = script.split("function sustained(text, epoch)", 1)[1].split("\n  }", 1)[0]
    assert "setInterval" in sustained and "status(text, true, epoch)" in sustained
    assert script.count("sustained(") >= 5  # the definition plus four long waits
    assert script.count("finally { stop(); }") >= 4


def test_the_two_search_chains_run_together(client: TestClient) -> None:
    """The naive and expanded chains are independent; the second used to wait
    for the first to finish both of its calls. Half the submit wait — real
    only because the server runs handlers off its event loop (B-31)."""
    script = client.get("/app.js").text
    assert 'Promise.all([chain("naive"), chain("expanded")])' in script
    # A one-sided failure names the side and says the other search exists.
    assert "search could not be created." in script
    assert "was created and its estimate started" in script


def test_the_subject_can_be_typed_while_the_case_is_created(client: TestClient) -> None:
    """B-32. Step 2 was disabled for the fifteen to thirty seconds Purview
    takes to create the case, and the operator sat idle. Only the button that
    needs the case id waits for it."""
    html = client.get("/").text
    fieldset = html.split('<fieldset id="subject-fieldset"', 1)[1].split(">", 1)[0]
    assert "disabled" not in fieldset
    expand = html.split('id="expand"', 1)[1].split(">", 1)[0]
    assert "disabled" in expand
    script = client.get("/app.js").text
    assert '$("expand").disabled = false' in script
    reset = script.split("function resetNewRequestForm()", 1)[1].split("\n  }", 1)[0]
    assert '$("expand").disabled = true' in reset


def test_an_edited_query_says_so_and_a_subjectless_one_asks(client: TestClient) -> None:
    """WS10 SEC-M-01, client half. The KQL stays visible and editable —
    hiding it would remove the operator's accountability for what runs — but
    a box that differs from the generated text says so in place of its plain
    sentence, and a run whose query no longer includes the primary address
    asks before sending the flag the server requires."""
    script = client.get("/app.js").text
    assert "Edited by hand" in script
    scope = script.split("function confirmScope()", 1)[1].split("\n  }", 1)[0]
    assert "window.confirm(" in scope
    assert "state.current" in scope
    assert "confirm_unscoped: !!confirmUnscoped" in script
    # A plain sentence per query, from the same facts as the chips.
    assert "function renderQuerySummaries()" in script
    assert 'addEventListener("input", renderQuerySummaries)' in script


def test_the_smaller_search_export_asks_first(client: TestClient) -> None:
    """WS10 SEC-M-02, client half. Both Export links looked identical under a
    banner saying the naive search had missed items. When both estimates are
    complete and the expanded one found more, the naive row's export is the
    quiet control and it confirms, and the choice is sent as a flag."""
    script = client.get("/app.js").text
    rows = script.split("function renderSearchRows(rows)", 1)[1].split("\n  }", 1)[0]
    assert "naiveIsSmaller" in rows and "window.confirm(" in rows
    assert "fewer item" in rows
    assert "confirmed_smaller: !!confirmedSmaller" in script
    # And a started export stays visible on its row after the status expires.
    assert "state.exported.has(search.search_id)" in rows


def test_the_purview_handoff_is_a_link_not_a_url(client: TestClient) -> None:
    """Frame 19: the one thing the operator must do next was a 150-character
    URL to copy by hand. An anchor now, with the origin checked before the
    string becomes somewhere the browser will go, and the tenant-bearing
    address out of the visible text."""
    script = client.get("/app.js").text
    portal = script.split("function renderPortal(url, note)", 1)[1].split("\n  }", 1)[0]
    assert 'indexOf("https://purview.microsoft.com/") === 0' in portal
    assert 'link.rel = "noopener noreferrer"' in portal
    assert 'link.target = "_blank"' in portal
    assert 'setText("case-portal"' not in script


def test_the_error_region_is_announced_at_the_top(client: TestClient) -> None:
    """Errors rendered at the foot of a 2,700 px form, with no live region.
    Under the status bar now, `role="alert"`, scrolled to and focused."""
    html = client.get("/").text
    assert html.index('id="error"') < html.index('id="signed-out"')
    error = html.split('id="error"', 1)[1].split(">", 1)[0]
    assert 'role="alert"' in error
    script = client.get("/app.js").text
    fail_fn = script.split("function fail(payload, fallback)", 1)[1].split("\n  }", 1)[0]
    assert "scrollIntoView" in fail_fn and '$("error-title").focus' in fail_fn


def test_a_reference_carrying_the_name_is_refused_before_the_case_exists(client: TestClient) -> None:
    """WS10 SEC-M-05. The reference is free text that lands in a permanent
    audit record and the Purview case name; "DSAR Megan Bowen 2026" is a
    valid reference. Refused while the case does not yet exist, warned once
    it does, and refused in a batch row."""
    script = client.get("/app.js").text
    assert "function referenceCarriesName(reference, name)" in script
    create = script.split('$("create-case").addEventListener', 1)[1].split("withBusy(", 1)[0]
    assert "checkReference()" in create
    assert "referenceCarriesName(row.reference, row.display_name)" in script
    html = client.get("/").text
    assert "never the person's name" in html


def test_permissions_policy_denies_capture_and_clipboard(client: TestClient) -> None:
    """WS10 SEC-L-06: neither is used, and both matter on a page showing a
    data subject's aliases."""
    policy = client.get("/healthz").headers["Permissions-Policy"]
    assert "display-capture=()" in policy
    assert "clipboard-read=()" in policy


def test_the_requests_list_filters_and_orders_in_memory(client: TestClient) -> None:
    """Forty flat rows with no filter, sort or closed state (frame 21). All of
    it is a view over the list already read — no request, no storage."""
    script = client.get("/app.js").text
    render = script.split("function renderRequests()", 1)[1].split("\n  }", 1)[0]
    assert "state.requests" in render
    assert "api(" not in render
    assert "localStorage" not in script and "sessionStorage" not in script
    html = client.get("/").text
    for control in ("requests-filter", "requests-order", "requests-closed"):
        assert f'id="{control}"' in html, control


def test_the_batch_file_input_has_a_name(client: TestClient) -> None:
    """The one axe critical of the walkthrough: a file input with no label."""
    html = client.get("/").text
    assert '<label for="batch-file">' in html
    # And the empty action headers say what they are to a screen reader.
    assert html.count('<span class="visually-hidden">Actions</span>') == 2


def test_no_handler_shadows_the_status_function(client: TestClient) -> None:
    """`const { status, payload } = await api(...)` inside `refreshCase`
    shadowed the `status()` live-region function, so the completion branch's
    `status(null)` threw a TypeError the surrounding catch swallowed — and
    everything after it, including the Purview hand-off, never rendered for
    a case opened from the list. A running poll reached the hand-off by a
    different branch and left it in the DOM, which hid the defect from every
    walkthrough until a completed case was opened cold. Every response is
    destructured as `code` now, and this holds it there."""
    script = client.get("/app.js").text
    assert "{ status, payload }" not in script
    assert script.count("{ status: code, payload }") >= 3
