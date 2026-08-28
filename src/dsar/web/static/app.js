// DSAR Assist — front end.
//
// No framework, no bundler, no npm. Nothing here needs one, and a build step is
// one more thing that works only on the machine it was set up on.
//
// Two rules the Content-Security-Policy imposes, worth stating because
// violating either fails silently in a browser and passes every server test:
//   * `script-src 'self'` — no inline handlers, so everything is addEventListener
//   * `form-action 'none'` — no form submissions, so everything is fetch()
//
// And one rule of our own: textContent, never innerHTML. Values here include a
// data subject's name and aliases. Provenance reasoning at each call site is
// how the one that matters gets missed.
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const show = (id) => $(id).removeAttribute("hidden");
  const hide = (id) => $(id).setAttribute("hidden", "");
  const setText = (id, value) => { $(id).textContent = value; };

  let state = {
    case_id: null, reference: null, canWrite: false,
    pollTimer: null, pollStarted: null, generated: null,
    tickTimer: null, running: 0, total: 0, statusTimer: null, view: null,
    nextPollAt: null, statusBusy: false, viewEpoch: 0,
    //: Opt-in workflow timing (DSA-A02). The server says whether capture is
    //: on; `timing` is one workflow's milestones, integers only, posted once
    //: when both estimates complete. An abandoned flow never posts.
    metricsEnabled: false, timing: null,
    //: Batch rows (B-17): browser memory only, for this session, never
    //: persisted and never uploaded as a file.
    batch: { rows: [] },
    //: Which narrowings have been applied to each query, by template id. The
    //: delta is only the expansion's contribution while these two agree; see
    //: renderComparability().
    narrowings: { naive: [], expanded: [] },
    //: The last machine-produced text of each query — generated, or generated
    //: plus applied narrowings. A box whose value differs from this has been
    //: edited by hand, and the page says so above it (WS10 SEC-M-01).
    current: null,
    //: What the expansion said about the person, for the plain reading of
    //: each query: the primary address, how many addresses, which mentions.
    subject: null,
    //: The request list as last read, so filter and order are applied in
    //: memory without another Graph call.
    requests: [],
    //: Search ids whose export this page started, so the row keeps saying so
    //: after the transient status has gone.
    exported: new Set(),
    //: The server's idle expiry, from whoami. The page clears itself at the
    //: same moment the session dies (WS10 SEC-M-03).
    idleTtlSeconds: 0, idleTimer: null, idleDeadline: null,
  };

  //: How long between automatic checks. See schedulePoll() for why it is flat.
  const POLL_INTERVAL_MS = 60000;

  // Every API call is a POST, even the reads. Browsers do not send Origin on a
  // same-origin GET, so an all-POST surface is what lets the server enforce
  // "reject absent or mismatched Origin" as written rather than relaxed.
  async function api(path, body) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body || {}),
    });
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401 && payload.error === "claims_challenge") {
      // The claims must reach the step-up, or the operator signs in
      // successfully and nothing changes — which reads as progress and is not.
      window.location = payload.step_up + "?claims=" + encodeURIComponent(payload.claims);
      throw new Error("stepping up");
    }
    if (response.status === 401) { renderSignedOut(); throw new Error("signed out"); }
    armIdleTimer();
    return { status: response.status, payload };
  }

  // ------------------------------------------------- metrics (DSA-A02)
  // Milestone durations and counts, and nothing else: no reference, no
  // subject value, no query ever leaves through this path, and the server
  // refuses any field not on its allowlist. `waiting` accumulates time spent
  // inside requests so active_ms can approximate operator attention — the
  // number the productivity claim is actually about — rather than repeating
  // Microsoft's processing time back as if it were ours.

  function startTiming() {
    state.timing = {
      flowStarted: performance.now(), waiting: 0, interactions: 0, posted: false,
    };
  }

  async function timed(field, work) {
    const t = state.timing;
    const t0 = performance.now();
    try {
      return await work();
    } finally {
      if (t) {
        const ms = performance.now() - t0;
        t.waiting += ms;
        t[field] = Math.round(ms);
      }
    }
  }

  function interaction(count) {
    if (state.timing) state.timing.interactions += count || 1;
  }

  async function postMetrics(fields) {
    if (!state.metricsEnabled) return;
    try {
      await api("/api/metrics", fields);
    } catch (err) { /* telemetry never interrupts the work it measures */ }
  }

  // The error region sits under the status bar and is announced. It is also
  // scrolled to and focused: the form after a resolve is 2,700 px tall, and an
  // error that renders where the operator is not looking is an error nobody
  // sees.
  function fail(payload, fallback) {
    setText("error-detail", (payload && payload.message) || fallback);
    show("error");
    status(null);
    $("error").scrollIntoView({ block: "nearest" });
    $("error-title").focus({ preventScroll: true });
  }

  function clearError() { hide("error"); }

  // One live region for "what is happening now". `role="status"` +
  // aria-live="polite" so it is announced rather than only seen.
  //
  // Two rules about how long it lives, both learned the hard way:
  //
  //   * A message with no spinner is transient and clears itself. "Case
  //     created." is worth reading once; leaving it on screen through the next
  //     three actions makes the region furniture rather than information.
  //   * A sustained message belongs to the case view alone, because that is
  //     the only place with something genuinely ongoing. Anywhere else, a
  //     spinner that never resolves is a lie.
  //
  // And it is cleared on sign-out unconditionally. It previously survived,
  // which on a shared machine meant the next person saw the last person's
  // case progress on the sign-in screen.
  // `epoch` is the view generation the caller was on when it started. A
  // status written after the operator navigated away describes a page they are
  // no longer looking at — which is how "Estimating…" came to sit on the
  // Requests list. `refreshCase` had guarded against this since the first
  // report of it; the five async handlers that settle a status after an await
  // had not, and each was one more place to forget.
  function status(text, busy, epoch) {
    if (epoch !== undefined && epoch !== state.viewEpoch) return;
    const bar = $("status");
    if (state.statusTimer) { clearTimeout(state.statusTimer); state.statusTimer = null; }
    if (!text) { state.statusBusy = false; bar.setAttribute("hidden", ""); return; }
    state.statusBusy = !!busy;
    setText("status-text", text);
    $("status-spinner").toggleAttribute("hidden", !busy);
    bar.removeAttribute("hidden");
    // Both kinds expire, for different reasons. A finished message is read once
    // and then becomes furniture. A spinner is a claim that something is still
    // happening, and it has to be renewed to keep making it — otherwise any
    // path that forgets to clear it leaves the interface asserting work that
    // ended minutes ago, which is what happened here.
    state.statusTimer = setTimeout(() => status(null), busy ? 15000 : 4000);
  }

  // A busy status that a request keeps alive for as long as the request runs.
  // The fixed expiry above is a safety net; it fired mid-wait on half of real
  // case creates (median 15 s, p90 29 s), leaving the button saying
  // "Creating…" under a bar that had gone quiet. Renewed every ten seconds
  // until `stop()`, which the caller does in a `finally`.
  function sustained(text, epoch) {
    status(text, true, epoch);
    const timer = setInterval(() => status(text, true, epoch), 10000);
    return () => clearInterval(timer);
  }

  // Disables the button for the duration and restores its label afterwards.
  // Two things at once: it says the click landed, and it makes a double click
  // impossible — which is separately how the template narrowings got stacked.
  async function withBusy(button, label, work) {
    const original = button.textContent;
    button.disabled = true;
    button.textContent = label;
    try {
      return await work();
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  }

  function markStep(step, state) {
    const node = document.querySelector(`#run-progress li[data-step="${step}"]`);
    if (node) node.className = state;
  }

  // The wizard's stepper: stages before the current one are done.
  const STAGES = ["request", "subject", "queries", "run"];
  function setStage(stage) {
    const at = STAGES.indexOf(stage);
    for (const li of document.querySelectorAll(".stepper li")) {
      const i = STAGES.indexOf(li.dataset.stage);
      li.className = i < at ? "done" : (i === at ? "current" : "");
    }
  }

  // ------------------------------------------------------------- views

  function showView(name) {
    clearError();
    for (const section of document.querySelectorAll(".view")) {
      section.setAttribute("hidden", "");
    }
    state.view = name;
    state.viewEpoch += 1;
    // Each entry to the form is a fresh measurement; a flow abandoned before
    // both estimates complete simply never posts.
    if (name === "new-request") startTiming();
    $("view-" + name).removeAttribute("hidden");
    for (const tab of document.querySelectorAll(".tab")) {
      const active = tab.dataset.view === name;
      tab.classList.toggle("active", active);
      if (active) tab.setAttribute("aria-current", "page");
      else tab.removeAttribute("aria-current");
    }
    if (name !== "case") {
      if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
      stopTicking();
      state.running = 0;
    }
    status(null);
    // Focus follows the view. A screen-reader user who activated a tab was
    // otherwise left on the tab with the new content somewhere below.
    const heading = document.querySelector("#view-" + name + " h2[tabindex]");
    if (heading) heading.focus({ preventScroll: true });
  }

  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => {
      showView(tab.dataset.view);
      if (tab.dataset.view === "requests") loadRequests();
    });
  }

  // --------------------------------------------------------- identity

  function renderSignedOut() {
    // Everything belonging to the previous session goes, not just the view.
    // A timer or a status line that outlives a sign-out shows one operator
    // something about another's work.
    if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
    stopTicking();
    status(null);
    if (state.idleTimer) { clearTimeout(state.idleTimer); state.idleTimer = null; }
    state.idleDeadline = null;
    state.case_id = null;
    state.reference = null;
    state.generated = null;
    state.current = null;
    state.subject = null;
    state.running = 0;
    state.total = 0;
    state.canWrite = false;
    state.requests = [];
    state.exported = new Set();

    // Subject data especially (WS10 SEC-M-01): a batch holds up to a hundred
    // subjects' rows and the form holds one — on a shared browser, either
    // surviving a sign-out shows the next operator the last one's subjects.
    // Emptied, not merely hidden; hidden DOM is still DOM.
    state.batch = { rows: [] };
    $("batch-input").value = "";
    $("batch-file").value = "";
    $("batch-body").replaceChildren();
    hide("batch-table");
    hide("batch-note");
    $("requests-body").replaceChildren();
    $("requests-filter").value = "";
    $("searches-body").replaceChildren();
    $("case-portal").replaceChildren();
    setText("case-title", "Case");
    setText("poll-note", "");
    resetNewRequestForm();
    setText("readiness", "");
    hide("readiness");

    $("identity").replaceChildren(el("span", "not signed in", "muted"));
    hide("nav");
    for (const section of document.querySelectorAll(".view")) {
      section.setAttribute("hidden", "");
    }
    clearError();
    show("signed-out");
  }

  // The server expires an idle session after a fixed time; until now the page
  // found out on the next click, which on a shared machine left a resolved
  // subject's aliases on screen for as long as nobody clicked. The timer is
  // re-armed by every API call — the same events the server counts — and
  // fires the same teardown a 401 would, with a line saying why.
  function armIdleTimer() {
    if (!state.idleTtlSeconds) return;
    if (state.idleTimer) clearTimeout(state.idleTimer);
    state.idleDeadline = Date.now() + state.idleTtlSeconds * 1000;
    state.idleTimer = setTimeout(idleExpired, state.idleTtlSeconds * 1000);
  }

  function idleExpired() {
    state.idleTimer = null;
    const minutes = Math.round(state.idleTtlSeconds / 60);
    fetch("/auth/logout", { method: "POST", credentials: "same-origin", redirect: "manual" })
      .catch(() => {});
    renderSignedOut();
    status("Signed out after " + minutes + " minutes without activity. Sign in again to continue.", false);
  }

  // A timer does not run while the machine sleeps or the tab is throttled in
  // the background, so a laptop closed on a resolved subject and opened next
  // morning would show it until the timer caught up. The wall-clock deadline
  // is checked the moment the page is looked at again (WS10 gate SEC-L-04).
  for (const event of ["visibilitychange", "focus"]) {
    window.addEventListener(event, () => {
      if (document.hidden || !state.idleDeadline || !state.idleTimer) return;
      if (Date.now() >= state.idleDeadline) idleExpired();
    });
  }

  // First-run readiness (B-18): the two checks that need a session, run once
  // at sign-in. Failure is loud and names the fix; success is one quiet line,
  // because a first-run operator wants the confirmation and a daily operator
  // stops seeing a constant.
  async function renderReadiness() {
    try {
      const { status: code, payload } = await api("/api/readiness", {});
      if (code !== 200) return;
      const notes = (payload.checks || []).map((c) => c.note).join(" · ");
      setText("readiness", (payload.ready ? "Ready — " : "Not ready: ") + notes);
      $("readiness").className = payload.ready ? "muted small" : "warn small";
      show("readiness");
    } catch (err) { /* handled in api() */ }
  }

  // What each app role lets the operator do, in words. The raw role name
  // stays on hover for whoever administers the assignment.
  const ROLE_WORDS = {
    "DSAR.Operator": "can create and run searches",
    "DSAR.Auditor": "can read the record",
  };

  function renderSignedIn(me) {
    state.canWrite = !!me.can_write;
    state.metricsEnabled = !!me.metrics_enabled;
    state.idleTtlSeconds = Number(me.idle_ttl_seconds) || 0;
    armIdleTimer();
    // Every role held, not the one that decided the outcome. App roles in
    // Entra are ADDITIVE — a user assigned both carries both in the token, and
    // nothing "wins". Showing only the effect made that look like a conflict
    // being resolved somewhere, which it is not: DSAR.Operator simply implies
    // everything DSAR.Auditor allows, so holding both is redundant rather than
    // contradictory. Saying so on the page is cheaper than explaining it.
    //
    // The name part of the sign-in address is shown; the full address is on
    // hover. Screenshots of this page go into case files and tickets, and the
    // less they carry that needs redacting, the better (WS10 SEC-L-01).
    const upn = me.upn || me.oid;
    const who = el("strong", upn.split("@")[0]);
    who.title = upn;
    const identity = [who];
    for (const role of me.roles || []) {
      const chip = el("span", ROLE_WORDS[role] || role, "chip");
      chip.title = role;
      identity.push(chip);
    }
    const idle = state.idleTtlSeconds ? Math.round(state.idleTtlSeconds / 60) : 0;
    const out = el("button", "Sign out", "linklike");
    out.type = "button";
    if (idle) out.title = "Signs out by itself after " + idle + " minutes without activity";
    out.addEventListener("click", signOut);
    identity.push(out);
    $("identity").replaceChildren(...identity);
    hide("signed-out");
    show("nav");
    if (!state.canWrite) {
      // Server-enforced too. Hiding a button is not a control — the endpoint
      // is still there — so this is a courtesy, not the boundary.
      for (const id of ["create-case", "batch-run", "batch-retry"]) {
        $(id).disabled = true;
        $(id).title = "Needs the DSAR.Operator role";
      }
    }
    showView("requests");
    // The list first, then the readiness probe: both read the same cached
    // list, and the table is what the operator is waiting to see.
    loadRequests();
    renderReadiness();
    loadTemplates();
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  // A date the operator can read at a glance. ISO stays in the data; this is
  // display only, and it follows the browser's locale rather than imposing one.
  function humanDate(iso) {
    if (!iso) return "";
    const parts = iso.split("-").map(Number);
    if (parts.length !== 3 || parts.some(isNaN)) return iso;
    return new Date(parts[0], parts[1] - 1, parts[2])
      .toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
  }

  // --------------------------------------------------------- requests

  async function loadRequests() {
    const epoch = state.viewEpoch;
    // The first read after sign-in took four seconds on the live tenant and
    // the page showed a heading and a footer meanwhile. Reads get a status
    // line too, not only writes.
    const stop = sustained("Reading your cases from Microsoft Purview…", epoch);
    try {
      const { status: code, payload } = await api("/api/requests", { scope: $("scope").value });
      if (code !== 200) return fail(payload, "The request list could not be read.");
      state.requests = payload.requests || [];
      renderRequests();

      // A list with no freshness stamp invites the assumption that it is live.
      let note = "Read from " + (payload.source || "Microsoft Graph") + " at " +
        new Date().toLocaleTimeString() +
        ". Nothing is stored locally — the same list appears on any machine you sign in from.";
      if (payload.truncated) note += " The list was truncated; there are more cases than shown.";
      setText("requests-source", note);

      // Only offer the scope toggle when it would change something.
      $("scope-controls").toggleAttribute("hidden", !payload.scope_toggle_useful);
      if (payload.scope_toggle_useful) {
        setText("scope-note",
          "This is a display filter, not a permission. What you can see at all is " +
          "decided by your Microsoft Purview role, which this tool cannot change.");
        show("scope-note");
      } else {
        hide("scope-note");
      }
      status(null, false, epoch);
    } catch (err) { /* handled in api() */ } finally { stop(); }
  }

  // Filter, order and the closed toggle apply to the list already in memory:
  // no request, no storage, nothing the server has to know about.
  function renderRequests() {
    const all = state.requests;
    const wanted = $("requests-filter").value.trim().toLowerCase();
    const showClosed = $("requests-closed").checked;
    const closed = all.filter((r) => r.status && r.status !== "active").length;
    let rows = all.filter((r) =>
      (showClosed || !r.status || r.status === "active") &&
      (!wanted || (r.reference || r.display_name || "").toLowerCase().indexOf(wanted) !== -1));
    if ($("requests-order").value === "due") {
      // Nearest deadline first; cases with no recorded receipt go last, since
      // their deadline is unknown rather than distant.
      rows = rows.slice().sort((a, b) => {
        if (!a.due && !b.due) return 0;
        if (!a.due) return 1;
        if (!b.due) return -1;
        return a.due < b.due ? -1 : (a.due > b.due ? 1 : 0);
      });
    }

    const body = $("requests-body");
    body.replaceChildren();
    $("list-controls").toggleAttribute("hidden", all.length === 0);
    $("requests-table").toggleAttribute("hidden", rows.length === 0);
    $("requests-empty").toggleAttribute("hidden", all.length !== 0);
    if (closed && !showClosed) {
      setText("requests-hidden", closed + " closed case" + (closed === 1 ? "" : "s") + " hidden.");
      show("requests-hidden");
    } else if (all.length && !rows.length) {
      setText("requests-hidden", "No cases match the filter.");
      show("requests-hidden");
    } else {
      hide("requests-hidden");
    }

    for (const item of rows) {
      const tr = document.createElement("tr");
      const ref = el("td", item.reference || "—");
      // The case name repeats the reference on every case this tool made, so
      // it is shown only when it differs; the status likewise only when it is
      // not the one every open case has.
      if (item.display_name && item.display_name !== item.reference) {
        ref.appendChild(el("span", item.display_name, "sub"));
      }
      if (item.status && item.status !== "active") {
        ref.appendChild(el("span", item.status, "chip status"));
      }
      tr.appendChild(ref);
      tr.appendChild(el("td", item.received ? humanDate(item.received) : "—"));
      tr.appendChild(dueCell(item));

      const actions = document.createElement("td");
      const open = el("button", "Open", "linklike");
      open.type = "button";
      open.addEventListener("click", () => openCase(item));
      actions.appendChild(open);
      tr.appendChild(actions);
      body.appendChild(tr);
    }
  }

  $("scope").addEventListener("change", loadRequests);
  $("requests-filter").addEventListener("input", renderRequests);
  $("requests-order").addEventListener("change", renderRequests);
  $("requests-closed").addEventListener("change", renderRequests);

  // -------------------------------------------------------- new case

  // A DSAR cannot arrive in the future. The bound catches the day/month
  // transposition a mis-localised browser invites; the echo says what will be
  // recorded, in words, since the control shows the browser's own format.
  $("received").max = new Date().toISOString().slice(0, 10);
  $("received").addEventListener("change", () => {
    const value = $("received").value;
    setText("received-echo", value ? "Recorded as " + humanDate(value) + "." : "");
  });

  // A reference that carries the person's name lands in a permanent audit
  // record and in the Purview case name (WS10 SEC-M-05). Checked wherever
  // both values are known: refused before the case exists, warned after.
  function referenceCarriesName(reference, name) {
    const ref = (reference || "").toLowerCase();
    if (!ref) return false;
    return (name || "").toLowerCase().split(/[^a-z0-9]+/)
      .some((token) => token.length >= 4 && ref.indexOf(token) !== -1);
  }

  function checkReference() {
    const reference = $("reference").value.trim();
    const name = $("display-name").value.trim();
    if (referenceCarriesName(reference, name)) {
      setText("reference-warning",
        "This reference looks like it contains the person’s name. Use a " +
        "ticket or file number instead: the reference is written to a " +
        "permanent audit record" +
        (state.case_id ? ", and this case’s record already carries it — rename the case in Purview." : "."));
      show("reference-warning");
      return true;
    }
    hide("reference-warning");
    return false;
  }
  $("reference").addEventListener("input", checkReference);
  $("display-name").addEventListener("input", checkReference);

  $("create-case").addEventListener("click", async () => {
    clearError();
    const reference = $("reference").value.trim();
    if (!reference) return fail(null, "A DSAR reference is required.");
    if (!state.case_id && checkReference()) {
      return fail(null, "The reference appears to contain the person’s name. Change it before creating the case.");
    }
    await withBusy($("create-case"), "Creating…", async () => {
      const epoch = state.viewEpoch;
      const stop = sustained("Creating the eDiscovery case in Microsoft Purview…", epoch);
      try {
        interaction($("received").value ? 3 : 2); // button + filled fields
        const result = await timed("case_create_ms", () => api("/api/case/create", {
          reference,
          // Empty means "not recorded"; a malformed one is refused by the
          // server rather than silently dropped.
          received: $("received").value,
        }));
        if (result.status !== 201) {
          return fail(result.payload, "The case could not be created.");
        }
        state.case_id = result.payload.case_id;
        state.reference = result.payload.reference;
        // Step 1 folds to one line. The values stay in their inputs for the
        // reset; the operator sees the fact, not the form.
        setText("request-summary",
          "Case " + result.payload.display_name + " created in Purview" +
          (result.payload.received ? " · received " + humanDate(result.payload.received) : " · no received date recorded") +
          ".");
        show("request-summary");
        $("request-fieldset").classList.add("done");
        setStage("subject");
        setText("case-created",
          "Case created in Purview: " + result.payload.display_name +
          ". Reference stored on the case, so it appears on any machine you " +
          "sign in from. Now identify the person.");
        show("case-created");
        setText("subject-hint", "");
        $("expand").disabled = false;
        if (!$("primary-email").value) $("primary-email").focus();
        status("Case created.", false, epoch);
      } catch (err) { /* handled in api() */ } finally { stop(); }
    });
  });

  // ------------------------------------------------------- expansion

  const lines = (id) => $(id).value.split("\n").map((s) => s.trim()).filter(Boolean);

  $("expand").addEventListener("click", async () => {
    clearError();
    await withBusy($("expand"), "Looking…", () => doExpand());
  });

  async function doExpand() {
    const epoch = state.viewEpoch;
    const stop = sustained("Looking the person up in the directory…", epoch);
    try {
      const filled = ["primary-email", "display-name", "other-emails",
                      "nicknames", "employee-id"]
        .filter((id) => $(id).value.trim()).length;
      interaction(1 + filled); // the button, plus each field the operator used
      const { status: code, payload } = await timed("expand_ms", () => api("/api/expand", {
        case_id: state.case_id,
        primary_email: $("primary-email").value.trim(),
        display_name: $("display-name").value.trim(),
        other_emails: lines("other-emails"),
        // The server reads `aliases`; this sent `nicknames` and NOTHING read
        // it, so every nickname the operator typed was silently dropped from
        // the expanded query — the exact material the delta exists to show.
        // Found while grouping the preview by provenance; a structural test
        // now holds these keys to the ones the server actually reads.
        aliases: lines("nicknames"),
        employee_id: $("employee-id").value.trim(),
      }));
      if (code !== 200) return fail(payload, "The person could not be resolved.");
      renderExpansion(payload);
      checkReference();
      const found = (payload.identifiers || []).length;
      const mentions = (payload.mentions || []).length;
      setText("expand-note",
        "Found " + found + " address" + (found === 1 ? "" : "es") +
        " and " + mentions + " name" + (mentions === 1 ? "" : "s") +
        " to search for. Check them below — nothing has run yet.");
      show("expand-note");
      setStage("queries");
      // The result appears a screen below the button that produced it.
      $("expansion").scrollIntoView({ behavior: "smooth", block: "start" });
      $("expansion-title").focus({ preventScroll: true });
      status("Check the names and addresses below are all this person, then run.", false, epoch);
    } catch (err) { /* handled */ } finally { stop(); }
  }

  // What each identifier kind means to a reader who is not an Entra
  // specialist. The backend has carried `kind` from the start; the interface
  // used to throw it away and print `source` instead — which for a directory
  // hit is the record's own UPN, so most chips read "address · same address"
  // and a proxy address was indistinguishable from a supplied alias.
  const KIND_LABELS = {
    primary: "primary address",
    other_mail: "other address on record",
    alias: "alias",
    mail: "directory mail address",
    upn: "sign-in name",
    proxy_address: "also known to the directory as",
  };

  function renderExpansion(data) {
    const box = $("identifiers");
    box.replaceChildren();

    const group = (title, chips) => {
      if (!chips.length) return;
      box.appendChild(el("p", title, "chip-group"));
      const row = el("div");
      for (const chip of chips) row.appendChild(chip);
      box.appendChild(row);
    };
    const chip = (identifier, withSource) => el(
      "span",
      identifier.value + "  ·  " + (KIND_LABELS[identifier.kind] || identifier.kind) +
        (withSource ? "  ·  " + identifier.source : ""),
      "chip");

    const identifiers = data.identifiers || [];
    // Operator-supplied identifiers without an @ are searched as text and
    // already appear under mentions; repeating them here as addresses would
    // overstate the participant clauses.
    const operator = identifiers.filter(
      (i) => i.source === "operator" && i.value.indexOf("@") !== -1);
    const directory = identifiers.filter((i) => i.source !== "operator");
    // The record's own UPN is only worth printing when more than one
    // directory record matched — otherwise every chip repeats one address.
    const manyRecords = new Set(directory.map((i) => i.source)).size > 1;

    group("Addresses you supplied — searched as sender, recipient or participant",
          operator.map((i) => chip(i, false)));
    group("Addresses the directory knows — searched the same way",
          directory.map((i) => chip(i, manyRecords)));

    const formerNames = data.former_names || [];
    const mentionChips = (data.mentions || [])
      .filter((m) => formerNames.indexOf(m) === -1)
      .map((m) => el("span", '"' + m + '"  ·  as words in an item', "chip mention"));
    const formerChips = formerNames.map(
      (m) => el("span", '"' + m + '"  ·  former name, as words', "chip mention"));
    group("Names searched as text, in case the person is discussed rather than included",
          mentionChips.concat(formerChips));

    if (data.employee_id) {
      // Matched, not searched — and the label says which. A chip that looks
      // searched and is not would misstate the query's coverage.
      group("Used to match the directory record — not searched",
            [el("span", data.employee_id + "  ·  employee ID", "chip")]);
    }

    if ((data.warnings || []).length) {
      setText("expansion-warnings", data.warnings.join(" "));
      show("expansion-warnings");
    } else {
      hide("expansion-warnings");
    }

    const primary = identifiers.find((i) => i.kind === "primary");
    state.subject = {
      primary: primary ? primary.value : "",
      addresses: identifiers.filter((i) => i.value.indexOf("@") !== -1).length,
      mentions: (data.mentions || []).slice(),
    };

    $("kql-naive").value = data.naive_kql || "";
    $("kql-expanded").value = data.kql || "";
    // Keep the pristine generated query so a narrowing can be undone. Templates
    // stack by design, but a stacked query is easy to get wrong by hand and
    // impossible to un-stack without this.
    state.generated = { naive: data.naive_kql || "", expanded: data.kql || "" };
    state.current = { naive: data.naive_kql || "", expanded: data.kql || "" };
    state.narrowings = { naive: [], expanded: [] };
    renderQuerySummaries();
    renderComparability();
    show("expansion");
  }

  // One plain sentence per query, generated from the same facts as the chips,
  // so the person accountable for the search can read what it does without
  // reading KQL. The KQL stays beneath it, visible and editable: hiding it
  // would remove the operator's accountability for what runs, and the review
  // step is the only human control on what is collected. An edited box says
  // so here, in place of the sentence, because the sentence would then be
  // describing a query that no longer exists.
  function quoteList(items) {
    const quoted = items.map((m) => "“" + m + "”");
    if (quoted.length <= 1) return quoted.join("");
    return quoted.slice(0, -1).join(", ") + " or " + quoted[quoted.length - 1];
  }

  function renderQuerySummaries() {
    const s = state.subject;
    if (!s) return;
    for (const side of ["naive", "expanded"]) {
      const node = $("summary-" + side);
      const edited = state.current && $(BOX[side]).value !== state.current[side];
      node.classList.toggle("edited", !!edited);
      if (edited) {
        node.textContent = "Edited by hand — the text below is exactly what will run.";
      } else if (side === "naive") {
        node.textContent = "Items where " + (s.primary || "the primary address") +
          " was the sender, a recipient or a participant.";
      } else {
        let text = "Items where any of " + s.addresses + " address" +
          (s.addresses === 1 ? "" : "es") + " was the sender, a recipient or a participant";
        if (s.mentions.length) text += ", or where the text mentions " + quoteList(s.mentions);
        node.textContent = text + ".";
      }
      const chips = $("narrowings-" + side);
      chips.replaceChildren();
      for (const id of state.narrowings[side]) {
        chips.appendChild(el("span", "narrowed: " + nameOf(id).replace(/[“”]/g, ""), "chip"));
      }
    }
  }

  $("reset-queries").addEventListener("click", () => {
    clearError();
    if (!state.generated) return;
    $("kql-naive").value = state.generated.naive;
    $("kql-expanded").value = state.generated.expanded;
    state.current = { naive: state.generated.naive, expanded: state.generated.expanded };
    state.narrowings = { naive: [], expanded: [] };
    renderQuerySummaries();
    renderComparability();
    status("Back to the generated queries.", false);
  });

  // ------------------------------------------------- delta comparability

  //: Templates by id, kept so the warning can name them and read `mailbox_only`.
  const templatesById = new Map();

  //: Mail-item properties. Measured 2026-08-02 and again on DSAR-2026-0418a:
  //: any of these reduces the site count to zero, including on a query that
  //: touches three sites. They are not "email filters" — they silently exclude
  //: SharePoint and OneDrive from the count.
  const MAIL_ITEM_CLAUSE = /\b(?:kind|filetype|hasattachment)\s*:/i;

  const SIDE = { naive: "naive", expanded: "expanded" };

  // The demonstration is the *difference* between two searches. That difference
  // is the identity expansion only while the queries are otherwise identical —
  // so a narrowing on one side turns the delta into a measurement of the
  // narrowing. Measured with `kind:email` on the expanded side alone: naive 40
  // items and one site, expanded 4 and none. The expanded query was the
  // narrower one and the delta read backwards.
  //
  // Two signals, because they catch different mistakes. The applied-template
  // list catches a click. Scanning the text catches a query pasted in from the
  // Purview query builder, which is how this was actually hit and which the
  // click tracking is blind to.
  //
  // Neither refuses anything. Narrowing one side is a legitimate thing to want;
  // what the operator cannot do is find out afterwards that the number meant
  // something else.
  function renderComparability() {
    const lines = [];

    const naive = state.narrowings.naive;
    const expanded = state.narrowings.expanded;
    const lopsided = expanded.filter((id) => naive.indexOf(id) === -1)
      .concat(naive.filter((id) => expanded.indexOf(id) === -1));
    if (lopsided.length) {
      lines.push(
        lopsided.map(nameOf).join(", ") +
        (lopsided.length === 1 ? " is" : " are") +
        " on one query and not the other, so the delta measures that narrowing " +
        "rather than the expansion — and can come out negative. Apply it to " +
        "both queries, or reset.");
    }

    const inNaive = hasMailItemClause($("kql-naive").value);
    const inExpanded = hasMailItemClause($("kql-expanded").value);
    if (inNaive !== inExpanded) {
      const side = inExpanded ? SIDE.expanded : SIDE.naive;
      lines.push(
        "Only the " + side + " query carries a mail-item clause " +
        "(kind:, filetype:, hasattachment:). That side counts mailbox content " +
        "and reports zero sites, so the two searches are not measuring the " +
        "same estate and the delta can read backwards. Those are the three " +
        "known mail-item properties — this check is a list, " +
        "not a KQL parser, so an unlisted one would pass unnoticed.");
    } else if (inNaive) {
      lines.push(
        "Both queries carry a mail-item clause, so both site counts will read " +
        "zero. That is the clause working, not an empty estate — the delta " +
        "is still the expansion, within mailboxes.");
    }

    if (!lines.length) return hide("comparability");
    setText("comparability", lines.join(" "));
    show("comparability");
  }

  // Quoted phrases are blanked first. "kind: regards" in an employment
  // vocabulary is a phrase, not a property clause, and a warning that fires on
  // one is a warning people learn to close.
  function hasMailItemClause(query) {
    return MAIL_ITEM_CLAUSE.test((query || "").replace(/"[^"]*"/g, '""'));
  }

  function nameOf(id) {
    const template = templatesById.get(id);
    return "“" + ((template && template.name) || id) + "”";
  }

  // A pasted query is the case the click tracking cannot see, so the check has
  // to run on what is in the box rather than on what put it there.
  for (const id of ["kql-naive", "kql-expanded"]) {
    $(id).addEventListener("input", renderComparability);
    $(id).addEventListener("input", renderQuerySummaries);
  }

  // -------------------------------------------------------- templates

  async function loadTemplates() {
    try {
      const { status: code, payload } = await api("/api/templates", {});
      if (code !== 200) return;
      const box = $("templates");
      box.replaceChildren();
      templatesById.clear();
      for (const template of payload.templates || []) {
        templatesById.set(template.id, template);
        box.appendChild(renderTemplate(template));
      }
    } catch (err) { /* handled */ }
  }

  // One card per template, closed until chosen. Six open cards at once, each
  // with its own caution in amber, stopped reading as six choices and started
  // reading as a wall — and the one a small organisation usually wants, a
  // date window, was buried under the rest.
  function renderTemplate(template) {
    const wrap = el("details", undefined, "template");
    const summary = el("summary", template.name +
      (template.mailbox_only ? "  ·  mailbox only" : ""));
    summary.appendChild(el("span", "  —  " + template.purpose, "muted"));
    wrap.appendChild(summary);
    if (template.guidance) wrap.appendChild(el("p", template.guidance, "muted small"));
    if (template.caution) wrap.appendChild(el("p", template.caution, "warn small"));

    const fields = {};
    for (const input of template.inputs || []) {
      const label = el("label", input.label);
      wrap.appendChild(label);
      let field;
      if ((input.options || []).length) {
        field = document.createElement("select");
        for (const option of input.options) {
          const node = document.createElement("option");
          node.value = option.value;
          node.textContent = option.label;
          field.appendChild(node);
        }
      } else {
        field = document.createElement("input");
        field.type = input.kind === "date" ? "date" : "text";
        field.placeholder = input.placeholder || "";
        field.autocomplete = "off";
        // Template values are vocabulary, names and addresses about the
        // subject; enhanced spell-check would send them elsewhere.
        field.spellcheck = false;
      }
      wrap.appendChild(field);
      if (input.help) wrap.appendChild(el("p", input.help, "muted small"));
      fields[input.name] = field;
    }

    const readValues = () => {
      const values = {};
      for (const [name, field] of Object.entries(fields)) values[name] = field.value;
      return values;
    };

    // Both queries by default. Narrowing one side alone is a legitimate thing
    // to want — the workload split is most informative on the expanded query —
    // but it is the exception, so it is the second button rather than the only
    // one. Until this existed, it was the only one.
    const both = el("button", "Apply to both queries", "button secondary small");
    both.type = "button";
    both.addEventListener("click", () => {
      applyTemplate(template, readValues(), ["naive", "expanded"]);
    });
    wrap.appendChild(both);

    const only = el("button", "Expanded only", "button subtle small");
    only.type = "button";
    only.addEventListener("click", () => {
      applyTemplate(template, readValues(), ["expanded"]);
    });
    wrap.appendChild(only);
    return wrap;
  }

  const BOX = { naive: "kql-naive", expanded: "kql-expanded" };

  async function applyTemplate(template, values, targets) {
    clearError();
    // Applying the same narrowing twice yields
    //   (... AND kind:email) AND kind:email
    // which is valid KQL, redundant, and unreadable — and for the date
    // template two ranges can contradict each other outright. A repeat is
    // almost always a double click, so it is refused rather than stacked.
    // Tracked by template id rather than by matching the appended text: with
    // two target boxes that string arithmetic gained a second way to be wrong.
    const pending = targets.filter(
      (t) => state.narrowings[t].indexOf(template.id) === -1);
    if (!pending.length) {
      return fail(null,
        "That narrowing is already on the " + targets.join(" and ") +
        " query. Use Reset to start from the generated one, or edit the text " +
        "directly.");
    }

    try {
      interaction(1);
      const epoch = state.viewEpoch;
      status("Applying “" + template.name + "”…", true, epoch);
      // One box at a time, and the failure message names how far it got. A
      // partial application reported as a plain failure is exactly how the two
      // queries diverge without anyone knowing they have.
      const applied = [];
      for (const target of pending) {
        const { status: code, payload } = await api("/api/template/apply", {
          query: $(BOX[target]).value,
          template_id: template.id,
          values,
          // So the audit record lands under the case: the trail states which
          // reviewed narrowing shaped the search, and "which case" is what
          // makes that findable later.
          case_id: state.case_id,
        });
        if (code !== 200) {
          renderComparability();
          renderQuerySummaries();
          return fail(payload, applied.length
            ? "Applied to the " + applied.join(" and ") +
              " query, then failed on the rest."
            : "The template could not be applied.");
        }
        $(BOX[target]).value = payload.query;
        if (state.current) state.current[target] = payload.query;
        state.narrowings[target].push(template.id);
        applied.push(target);
      }
      renderComparability();
      renderQuerySummaries();
      status("Applied “" + template.name + "” to the " +
             applied.join(" and ") + " quer" +
             (applied.length > 1 ? "ies" : "y") + ".", false, epoch);
    } catch (err) { renderComparability(); renderQuerySummaries(); }
  }

  // ---------------------------------------------------------- search

  // Before anything is created: an edited query that no longer names the
  // subject as a participant is a text search across every mailbox and site
  // the operator can reach. The page asks; the server refuses without the
  // answer (WS10 SEC-M-01). Returns the flag to send, or null to stop.
  function confirmScope() {
    const primary = ((state.subject || {}).primary || "").toLowerCase();
    const missing = ["naive", "expanded"].filter((side) => {
      const query = $(BOX[side]).value;
      const edited = state.current && query !== state.current[side];
      return edited && primary && query.toLowerCase().indexOf(primary) === -1;
    });
    if (!missing.length) return false;
    const ok = window.confirm(
      "The " + missing.join(" and ") + " quer" + (missing.length > 1 ? "ies" : "y") +
      " no longer include" + (missing.length > 1 ? "" : "s") + " " + primary + ".\n\n" +
      "A search without the person's address looks for the words alone, in every " +
      "mailbox and site you can reach. Run it anyway?");
    return ok ? true : null;
  }

  $("run-both").addEventListener("click", async () => {
    clearError();
    if (!state.case_id) return fail(null, "Create the case first.");
    const confirmUnscoped = confirmScope();
    if (confirmUnscoped === null) return;
    const epoch = state.viewEpoch;
    await withBusy($("run-both"), "Running…", async () => {
      show("run-progress");
      for (const step of ["naive", "naive-run", "expanded", "expanded-run"]) {
        markStep(step, "");
      }
      const stop = sustained("Creating both searches in Purview…", epoch);
      try {
        interaction(1);
        const submitStart = performance.now();
        // The query sent is whatever is in the box — edited or not. A query the
        // operator saw and a query that runs must be the same string, or the
        // review step means nothing.
        //
        // The two chains are independent, so they run together: each is a
        // create followed by an estimate start, and the second chain used to
        // wait for the first to finish both. Half the submit wait, and the
        // server runs handlers off its event loop so "together" is real.
        const chain = async (kind) => {
          markStep(kind, "doing");
          const result = await api("/api/search/create", {
            case_id: state.case_id, kind,
            query: $(BOX[kind]).value, run: true,
            confirm_unscoped: !!confirmUnscoped,
          });
          if (result.status !== 201) {
            markStep(kind, "failed");
            return { kind, failed: result.payload };
          }
          markStep(kind, "done");
          markStep(kind + "-run", "done");
          return { kind, search: result.payload };
        };
        const outcomes = await Promise.all([chain("naive"), chain("expanded")]);
        const failed = outcomes.filter((o) => o.failed);
        if (failed.length) {
          const which = failed.map((o) => o.kind).join(" and ");
          const other = outcomes.find((o) => o.search);
          return fail(failed[0].failed,
            "The " + which + " search could not be created." +
            (other ? " The " + other.kind + " search was created and its estimate started; open the case from the Requests list to see it." : ""));
        }

        const t = state.timing;
        if (t) {
          const submitMs = performance.now() - submitStart;
          t.waiting += submitMs;
          t.searches_submit_ms = Math.round(submitMs);
          // Operator attention: time on the form minus time inside requests.
          // The estimate waits from here on are Microsoft's processing time,
          // reported separately and never claimed as ours.
          t.active_ms = Math.round(performance.now() - t.flowStarted - t.waiting);
          t.submittedAt = performance.now();
          t.templates_applied = new Set(
            state.narrowings.naive.concat(state.narrowings.expanded)).size;
        }

        setStage("run");
        // The two searches just created seed the case view, so it is never
        // blank while the first read runs.
        openCase({ case_id: state.case_id, reference: state.reference },
                 outcomes.map((o) => o.search));
        // The workflow is submitted; the form's job is done. Without this the
        // next visit to New request showed the PREVIOUS subject — name,
        // aliases, employee ID — still sitting in the fields, with a stale
        // reference one click away from a duplicate case. Cleared on
        // successful submission only: an abandoned half-done flow keeps its
        // typed data, because losing an operator's input is its own failure.
        resetNewRequestForm();
      } catch (err) { /* handled */ } finally { stop(); }
    });
  });

  function resetNewRequestForm() {
    for (const id of ["reference", "received", "primary-email", "display-name",
                      "other-emails", "nicknames", "employee-id",
                      "kql-naive", "kql-expanded"]) {
      $(id).value = "";
    }
    // Template inputs are rendered dynamically, so they are swept by query
    // rather than by id — a new template's field must not survive either.
    for (const field of document.querySelectorAll(
        "#templates input, #templates textarea")) {
      field.value = "";
    }
    for (const select of document.querySelectorAll("#templates select")) {
      select.selectedIndex = 0;
    }
    $("expand").disabled = true;
    $("request-fieldset").classList.remove("done");
    setText("request-summary", "");
    hide("request-summary");
    setText("received-echo", "");
    setText("subject-hint", "You can fill this in while the case is being created.");
    hide("reference-warning");
    setStage("request");
    // Emptied, not merely hidden: the chips carry the subject's aliases as
    // textContent, and hidden DOM is still DOM.
    $("identifiers").replaceChildren();
    $("narrowings-naive").replaceChildren();
    $("narrowings-expanded").replaceChildren();
    setText("summary-naive", "");
    setText("summary-expanded", "");
    for (const id of ["case-created", "expand-note", "expansion", "run-progress"]) {
      hide(id);
    }
    state.generated = null;
    state.current = null;
    state.subject = null;
    state.narrowings = { naive: [], expanded: [] };
  }

  // ----------------------------------------------------- case detail

  // Everything the previous case left on the page. The view is reused, so
  // without this the new case's title sits above the OLD case's searches,
  // statistics and delta until the fetch returns — which on a case with no
  // searches yet reads as results that are not there, and on a slow network
  // reads as the wrong case's results entirely.
  function clearCaseView() {
    $("searches-body").replaceChildren();
    for (const id of ["searches-table", "delta", "poll-note"]) hide(id);
    hide("searches-empty");
    $("case-portal").replaceChildren();
  }

  // `seed` is the searches this page has just created, rendered before the
  // first read so the view is never a title and two buttons (frame 18 of the
  // walkthrough). A case opened from the list has no seed and shows the
  // reading status instead.
  async function openCase(item, seed) {
    state.case_id = item.case_id;
    state.pollStarted = Date.now();
    state.running = 0;
    state.total = 0;
    setText("case-title", item.reference || item.display_name || "Case");
    // Before the view is shown, not after — a clear that happens after the
    // paint is a flicker of the wrong data rather than an absence of it.
    clearCaseView();
    showView("case");
    const epoch = state.viewEpoch;
    if (seed && seed.length) {
      renderSearchRows(seed.filter(Boolean));
      setText("poll-note", "Both estimates are starting in Purview. This page updates on its own; you can leave it.");
      show("poll-note");
    }
    status("Reading the case from Microsoft Purview…", true, epoch);

    const done = await refreshCase();
    if (!done) schedulePoll();
  }

  // A flat sixty seconds, not a ladder.
  //
  // Every poll spends the operator's own Graph token, and Purview throttles the
  // ACCOUNT rather than the process — so a call made here is taken from the
  // operator's other tools. An estimate takes minutes; checking every ten
  // seconds for the first minute buys at most a few seconds of earlier notice
  // and costs six times the calls to find out nothing has changed.
  //
  // Impatience is served by "Refresh now" instead, which is one deliberate call
  // rather than a standing cost, and by the countdown that says when the next
  // one lands. The first read is immediate on opening the case, so the interval
  // only governs the wait AFTER something is already on screen.
  function schedulePoll() {
    if (state.pollTimer) clearTimeout(state.pollTimer);
    state.nextPollAt = Date.now() + POLL_INTERVAL_MS;
    state.pollTimer = setTimeout(async () => {
      state.nextPollAt = null;
      const done = await refreshCase();
      if (done) {
        state.pollTimer = null;
        return;
      }
      schedulePoll();
    }, POLL_INTERVAL_MS);
  }

  //: Tears down the interval and nothing else. Separate from stopTicking()
  //: because that one also clears a busy status, and startTicking calls it
  //: immediately before renderWaiting sets one.
  function clearTicker() {
    if (state.tickTimer) { clearInterval(state.tickTimer); state.tickTimer = null; }
    state.nextPollAt = null;
  }

  function startTicking() {
    clearTicker();
    // One second, and it touches only text already on the page — no request,
    // no token spent. The Graph poll backs off to a minute, so without this the
    // counter is stale for up to a minute, which is the interval over which a
    // reader decides the page has stopped.
    state.tickTimer = setInterval(renderWaiting, 1000);
  }

  function stopTicking() {
    clearTicker();
    // A spinner is a claim that something is still happening, and the ticker
    // is what renews that claim. When the ticker stops, the claim has to go
    // with it — otherwise the elapsed figure freezes while the spinner keeps
    // turning beside a table that says complete, which is the most confusing
    // state the interface can be in: it looks like work, and it is not.
    //
    // Tied to the ticker rather than fixed at each call site, because there
    // are several call sites and the next one added is the one that forgets.
    if (state.statusBusy) status(null);
  }

  function renderWaiting() {
    if (!state.running) {
      // Nothing is running any more, so stop asserting that something is.
      // The previous version returned without clearing, which left the last
      // "Estimating — 2m 38s" on screen beside a table saying "complete".
      stopTicking();
      status(null);
      return;
    }
    if (state.view !== "case") {
      // The view moved on. Stop rather than narrating a page nobody is looking
      // at — and stop the clock with it.
      stopTicking();
      status(null);
      return;
    }
    setText("poll-note",
      state.running + " of " + state.total + " estimate" +
      (state.total === 1 ? "" : "s") + " still running — " + elapsed() +
      " so far. This page updates on its own; you can leave it.");
    show("poll-note");
    status("Estimating — " + elapsed() + " elapsed" + untilNextCheck(), true);
  }

  function untilNextCheck() {
    // The gap between polls stretches to a minute. Without a countdown that
    // pause is indistinguishable from a stall, which is the same doubt the
    // elapsed counter was added to remove.
    if (!state.nextPollAt) return "";
    const seconds = Math.max(0, Math.round((state.nextPollAt - Date.now()) / 1000));
    if (!seconds) return " · checking…";
    return " · next check in " + seconds + "s";
  }

  function elapsed() {
    return formatSeconds(
      Math.round((Date.now() - (state.pollStarted || Date.now())) / 1000));
  }

  function formatSeconds(seconds) {
    if (seconds < 60) return seconds + "s";
    return Math.floor(seconds / 60) + "m " + (seconds % 60) + "s";
  }

  $("refresh-case").addEventListener("click", async () => {
    await withBusy($("refresh-case"), "Refreshing…", async () => {
      const done = await refreshCase();
      if (!done) schedulePoll();
    });
  });

  $("back").addEventListener("click", () => {
    if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
    stopTicking();
    showView("requests");
    loadRequests();
  });

  const isNaive = (s) => /naive/i.test(s.display_name || "");
  const isExpanded = (s) => /expanded/i.test(s.display_name || "");

  // The table, from a list of searches. Naive first: the baseline reads above
  // the comparison, and the banner beneath reads top to bottom.
  function renderSearchRows(rows) {
    const ordered = rows.slice().sort((a, b) => (isNaive(b) ? 1 : 0) - (isNaive(a) ? 1 : 0));
    const body = $("searches-body");
    body.replaceChildren();
    $("searches-table").toggleAttribute("hidden", ordered.length === 0);
    $("searches-empty").toggleAttribute("hidden", ordered.length !== 0);

    // Whether the smaller search is one click from becoming the response
    // (WS10 SEC-M-02): both complete, and the expanded one found more.
    const naive = ordered.find(isNaive), expanded = ordered.find(isExpanded);
    const a = naive && naive.statistics, b = expanded && expanded.statistics;
    const naiveIsSmaller = !!(a && b && a.complete && b.complete &&
      a.item_count !== null && b.item_count !== null && b.item_count > a.item_count);

    for (const search of ordered) {
      const stats = search.statistics || {};
      const tr = document.createElement("tr");
      tr.appendChild(el("td", readableName(search.display_name)));
      // null, not 0 — "no estimate yet" and "found nothing" are different.
      tr.appendChild(el("td", stats.item_count === null || stats.item_count === undefined ? "—" : String(stats.item_count)));
      // Mailboxes and sites shown separately: "1 mailbox" versus "1 mailbox,
      // 2 sites" is the difference between a naive query and one that looked
      // at SharePoint, and that difference is the demonstration.
      let locations = "—";
      if (stats.location_count !== null && stats.location_count !== undefined) {
        const parts = [];
        if (stats.mailbox_count) parts.push(stats.mailbox_count + " mailbox" + (stats.mailbox_count === 1 ? "" : "es"));
        if (stats.site_count) parts.push(stats.site_count + " site" + (stats.site_count === 1 ? "" : "s"));
        locations = parts.length ? parts.join(", ") : String(stats.location_count);
      }
      tr.appendChild(el("td", locations));

      // Purview's own duration, from the operation's timestamps — exact,
      // where this page's elapsed counter is quantised by the poll.
      const took = (typeof stats.run_seconds === "number")
        ? " in " + formatSeconds(stats.run_seconds) : "";
      let statusText;
      if (stats.partial) {
        // Not smoothed over. A DSAR response built on a partial count is a
        // compliance problem, not a rounding error.
        statusText = "complete" + took + " (partial — some locations not searched)";
      } else if (stats.complete) {
        statusText = "complete" + took;
      } else if (stats.percent_progress) {
        statusText = (stats.status || "running") + " — " + stats.percent_progress + "%";
      } else {
        statusText = stats.status || "starting";
      }
      const statusCell = el("td", statusText);
      if (stats.partial) statusCell.className = "warn";
      tr.appendChild(statusCell);

      const actions = document.createElement("td");
      if (state.exported.has(search.search_id)) {
        actions.appendChild(el("span", "Export started · collect in Purview", "muted small"));
      } else if (state.canWrite && stats.complete) {
        const smaller = naiveIsSmaller && isNaive(search);
        const exportBtn = el("button", "Export", smaller ? "button subtle small" : "linklike");
        exportBtn.type = "button";
        if (smaller) {
          exportBtn.title = "This search found fewer items than the expanded one";
          exportBtn.addEventListener("click", () => {
            const fewer = b.item_count - a.item_count;
            const ok = window.confirm(
              "This search found " + fewer + " fewer item" + (fewer === 1 ? "" : "s") +
              " than the expanded one. A response built on it may be incomplete.\n\n" +
              "Export it anyway?");
            if (ok) startExport(search, true);
          });
        } else {
          exportBtn.addEventListener("click", () => startExport(search, false));
        }
        actions.appendChild(exportBtn);
      }
      tr.appendChild(actions);
      body.appendChild(tr);
    }
  }

  // The search names are stable in Purview and matched by the delta; the
  // table shows them in the operator's words.
  function readableName(name) {
    if (/naive/i.test(name || "")) return "Primary address only";
    if (/expanded/i.test(name || "")) return "Everything known";
    return name || "";
  }

  async function refreshCase() {
    try {
      // `code`, never `status`: a destructured `status` here shadowed the
      // status() function, so the completion branch's status(null) threw a
      // TypeError the catch below swallowed — and the portal link after it
      // never rendered for a case opened from the list. Found by the live
      // checks, not the suite; a structural test now bans the shadow.
      const { status: code, payload } = await api("/api/case", { case_id: state.case_id });
      if (code !== 200) { fail(payload, "The case could not be read."); return true; }

      const rows = payload.searches || [];
      let complete = true;
      for (const search of rows) {
        if (!(search.statistics || {}).complete) complete = false;
      }
      renderSearchRows(rows);
      renderDelta(rows);

      state.running = rows.filter((s) => !(s.statistics || {}).complete).length;
      state.total = rows.length;

      // Metrics milestones for the workflow this page belongs to. Guarded on
      // submittedAt so a case opened from the list — no live workflow — never
      // measures anything.
      const t = state.timing;
      if (t && t.submittedAt && !t.posted && rows.length) {
        const now = performance.now();
        if (!t.first_estimate_ms && rows.some((s) => (s.statistics || {}).complete)) {
          t.first_estimate_ms = Math.round(now - t.submittedAt);
        }
        if (rows.every((s) => (s.statistics || {}).complete)) {
          t.both_estimates_ms = Math.round(now - t.submittedAt);
          t.total_ms = Math.round(now - t.flowStarted);
          t.posted = true;
          // Purview's own per-search durations, echoed from the operation
          // timestamps — exact where first/both_estimates_ms are quantised
          // by this page's sixty-second poll.
          const naiveRow = rows.find(isNaive);
          const expandedRow = rows.find(isExpanded);
          if (naiveRow && typeof (naiveRow.statistics || {}).run_seconds === "number") {
            t.naive_estimate_s = naiveRow.statistics.run_seconds;
          }
          if (expandedRow && typeof (expandedRow.statistics || {}).run_seconds === "number") {
            t.expanded_estimate_s = expandedRow.statistics.run_seconds;
          }
          const fields = { interactions: t.interactions };
          for (const key of ["active_ms", "case_create_ms", "expand_ms",
                             "searches_submit_ms", "first_estimate_ms",
                             "both_estimates_ms", "total_ms", "templates_applied",
                             "naive_estimate_s", "expanded_estimate_s"]) {
            if (typeof t[key] === "number") fields[key] = t[key];
          }
          postMetrics(fields);
        }
      }

      // A refresh started on the case view can land after the operator has
      // gone back to the list. Writing the result then leaves a stale status
      // on a page it does not describe — which is what "the previous status is
      // retained" was.
      if (state.view !== "case") {
        stopTicking();
        status(null);
        return true;
      }

      if (rows.length && state.running) {
        renderWaiting();
        startTicking();
      } else if (rows.length) {
        stopTicking();
        state.nextPollAt = null;
        setText("poll-note", "All estimates complete after " + elapsed() + ".");
        show("poll-note");
        // Cleared, not replaced with "Estimates complete." The table says
        // complete, the note above says how long it took, and a third copy in
        // a bar that looks like progress is the thing that confused.
        status(null);
      } else {
        stopTicking();
        state.nextPollAt = null;
        hide("poll-note");
        status(null);
      }

      renderPortal(payload.portal_url, "");
      return complete && rows.length > 0;
    } catch (err) { return true; }
  }

  // The hand-off to Purview as a link, not a URL to copy. The address is
  // built server-side from configuration and the case id; it is still checked
  // here before it becomes an href, because an anchor is the one place this
  // page turns a string into somewhere the browser will go.
  function renderPortal(url, note) {
    const box = $("case-portal");
    box.replaceChildren();
    if (note) box.appendChild(el("span", note + "  ", "muted small"));
    if (typeof url === "string" && url.indexOf("https://purview.microsoft.com/") === 0) {
      const link = el("a", "Open this case in Microsoft Purview", "button secondary small");
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      box.appendChild(link);
      box.appendChild(el("span", "Exports are collected there, under your own sign-in.", "muted small"));
    }
  }

  // The statutory deadline, or an honest gap. A case with no recorded receipt
  // shows "not recorded" rather than a date derived from when somebody opened
  // the case in Purview — that is always later than the truth, and a plausible
  // wrong statutory date is the one thing this must not show.
  function dueCell(item) {
    if (!item.due) {
      const cell = el("td", "not recorded", "muted");
      cell.title = "No received date on this case. The clock runs from the day "
        + "the request arrived, which this tool cannot infer.";
      return cell;
    }
    const days = item.days_remaining;
    let text = humanDate(item.due);
    if (item.overdue) {
      text += "  ·  overdue by " + (-days) + " day" + (days === -1 ? "" : "s");
    } else if (days === 0) {
      text += "  ·  due today";
    } else {
      text += "  ·  " + days + " day" + (days === 1 ? "" : "s") + " left";
    }
    const cell = el("td", text);
    // Overdue, and the last week before it, share the existing warn colour
    // rather than introducing a third state to learn.
    if (item.overdue || days <= 7) cell.className = "warn";
    return cell;
  }

  function renderDelta(rows) {
    // The comparison is the demonstration, and it needs no item content to
    // make its case — which is exactly the argument the product is making.
    const naive = rows.find(isNaive);
    const expanded = rows.find(isExpanded);
    const a = naive && naive.statistics, b = expanded && expanded.statistics;
    if (!a || !b || !a.complete || !b.complete || a.item_count === null || b.item_count === null) {
      hide("delta");
      return;
    }
    // B-10: this banner used to render away from the queries, so a delta
    // computed from two searches an operator had made incomparable arrived
    // with no warning beside it. The queries that actually RAN come back
    // from Graph on each row, so the same mail-item check the form runs can
    // run here — on any machine, on a case opened weeks later, on a query
    // pasted straight into Purview's own builder.
    const naiveMail = hasMailItemClause(naive.query);
    const expandedMail = hasMailItemClause(expanded.query);
    $("delta").classList.toggle("warn", naiveMail !== expandedMail);
    if (naiveMail !== expandedMail) {
      setText("delta",
        "These two searches are not comparable: only the " +
        (expandedMail ? "expanded" : "naive") + " query carries a mail-item " +
        "clause (kind:, filetype:, hasattachment:), which counts mailbox " +
        "content and reports zero sites. The difference below measures that " +
        "clause, not the identity expansion. These are the three known " +
        "mail-item properties — the check is a list, not a KQL parser.");
      show("delta");
      return;
    }
    const extra = b.item_count - a.item_count;
    if (extra <= 0) {
      setText("delta", "Searching everything known found no more than the primary address alone on this data.");
      show("delta");
      return;
    }
    const pct = a.item_count ? Math.round((extra / a.item_count) * 100) : 0;
    let text = "The primary-address search alone would have missed " + extra + " item" + (extra === 1 ? "" : "s") +
               " (" + pct + "% more than it found)";
    if (b.location_count !== null && a.location_count !== null && b.location_count > a.location_count) {
      text += ", and " + (b.location_count - a.location_count) + " location" +
              (b.location_count - a.location_count === 1 ? "" : "s") + " it never looked at";
    }
    setText("delta", text + ".");
    show("delta");
  }

  async function startExport(search, confirmedSmaller) {
    clearError();
    const epoch = state.viewEpoch;
    status("Starting the export in Purview…", true, epoch);
    try {
      const { status: code, payload } = await api("/api/export", {
        case_id: state.case_id, search_id: search.search_id, name: search.display_name,
        // Recorded in the audit detail, so the trail can answer why the
        // smaller search was exported. Never a count, never a query.
        confirmed_smaller: !!confirmedSmaller,
      });
      if (code !== 202) return fail(payload, "The export could not be started.");
      state.exported.add(search.search_id);
      renderPortal(payload.portal_url, payload.note);
      // The row keeps saying so after the status has gone.
      refreshCase();
      status("Export started. Collect it in the Purview portal.", false, epoch);
    } catch (err) { /* handled */ }
  }

  // ------------------------------------------------------------ batch (B-17)
  // Client-driven by design: the rows live in this page's memory, the file is
  // read locally and never uploaded, and every step runs through the same
  // audited per-case endpoints as the single flow — so the batch inherits the
  // trail, the role checks, the correlation ids and the op metrics instead of
  // duplicating them. Two rows in flight; a failed row remembers which step
  // failed and replays from there, never repeating a Graph write that
  // succeeded.

  const BATCH_COLUMNS = ["reference", "received", "primary_email",
                         "display_name", "nicknames", "other_emails",
                         "employee_id"];

  function parseCsv(text) {
    const rows = []; let row = []; let field = ""; let quoted = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quoted) {
        if (c === '"') {
          if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false;
        } else field += c;
      } else if (c === '"') quoted = true;
      else if (c === ",") { row.push(field); field = ""; }
      else if (c === "\n" || c === "\r") {
        if (c === "\r" && text[i + 1] === "\n") i++;
        row.push(field); field = "";
        if (row.some((f) => f.trim() !== "")) rows.push(row);
        row = [];
      } else field += c;
    }
    row.push(field);
    if (row.some((f) => f.trim() !== "")) rows.push(row);
    return rows;
  }

  const semis = (value) => (value || "").split(";").map((s) => s.trim()).filter(Boolean);

  function parseBatch(text) {
    const raw = parseCsv(text);
    if (raw.length < 2) return { error: "Nothing to do: a header row and at least one data row are needed." };
    const header = raw[0].map((h) => h.trim().toLowerCase());
    // Unknown columns are refused, not dropped. A silently ignored column is
    // how this page once lost every nickname an operator typed.
    const unknown = header.filter((h) => BATCH_COLUMNS.indexOf(h) === -1);
    if (unknown.length) return { error: "Unknown column(s): " + unknown.join(", ") + ". Known: " + BATCH_COLUMNS.join(", ") };
    for (const required of ["reference", "primary_email"]) {
      if (header.indexOf(required) === -1) return { error: "The " + required + " column is required." };
    }
    return {
      rows: raw.slice(1).map((cells) => {
        const record = { status: "parsed", note: "", case_id: null,
                         expansion: null, naiveDone: false, expandedDone: false };
        header.forEach((name, i) => { record[name] = (cells[i] || "").trim(); });
        return record;
      }),
    };
  }

  function batchStatusCell(row) {
    if (row.status === "failed") return "failed at " + row.failedAt + ": " + row.note;
    if (row.status === "invalid") return "invalid: " + row.note;
    if (row.status === "done") return "case + both searches started";
    return row.status;
  }

  function renderBatch() {
    const rows = (state.batch && state.batch.rows) || [];
    const body = $("batch-body");
    body.replaceChildren();
    for (const row of rows) {
      const tr = document.createElement("tr");
      tr.appendChild(el("td", row.reference || ""));
      tr.appendChild(el("td", row.received || ""));
      const subject = el("td", row.primary_email || "");
      if (row.display_name) subject.appendChild(el("span", row.display_name, "sub"));
      tr.appendChild(subject);
      const cell = el("td", batchStatusCell(row));
      if (row.status === "failed" || row.status === "invalid") cell.className = "warn";
      if (row.status === "done") cell.className = "ok";
      tr.appendChild(cell);
      body.appendChild(tr);
    }
    $("batch-table").toggleAttribute("hidden", rows.length === 0);
    const failed = rows.filter((r) => r.status === "failed").length;
    const done = rows.filter((r) => r.status === "done").length;
    const valid = rows.filter((r) => r.status === "valid").length;
    $("batch-run").disabled = valid === 0 || !state.canWrite;
    $("batch-retry").disabled = !state.canWrite;
    $("batch-retry").toggleAttribute("hidden", failed === 0);
    if (rows.length) {
      setText("batch-note",
        rows.length + " row" + (rows.length === 1 ? "" : "s") +
        (valid ? " · " + valid + " ready" : "") +
        (done ? " · " + done + " done" : "") +
        (failed ? " · " + failed + " failed" : ""));
      show("batch-note");
    } else hide("batch-note");
  }

  $("batch-header").addEventListener("click", () => {
    const box = $("batch-input");
    if (!box.value.trim()) box.value = BATCH_COLUMNS.join(",") + "\n";
    box.focus();
  });

  $("batch-file").addEventListener("change", () => {
    const file = $("batch-file").files[0];
    if (!file) return;
    const reader = new FileReader();
    // Into the visible textarea, deliberately: what will run is what the
    // operator can read, same rule as the two queries.
    reader.onload = () => { $("batch-input").value = String(reader.result || ""); };
    reader.readAsText(file);
  });

  $("batch-parse").addEventListener("click", async () => {
    clearError();
    const parsed = parseBatch($("batch-input").value);
    if (parsed.error) { state.batch = { rows: [] }; renderBatch(); return fail(null, parsed.error); }
    state.batch = { rows: parsed.rows };
    // Client shape checks for the columns with no server rule...
    for (const row of parsed.rows) {
      const problems = [];
      if (!row.primary_email || row.primary_email.indexOf("@") === -1) {
        problems.push("primary_email must be an address");
      }
      if (referenceCarriesName(row.reference, row.display_name)) {
        problems.push("the reference appears to contain the person’s name");
      }
      if (problems.length) { row.status = "invalid"; row.note = problems.join("; "); }
    }
    // ...and the server's own rules for the two fields it owns, checked by
    // the same code that will enforce them at creation. No subject data in
    // this call — references and dates only.
    try {
      const { status: code, payload } = await api("/api/batch/validate", {
        rows: parsed.rows.map((r) => ({ reference: r.reference || "", received: r.received || "" })),
      });
      if (code !== 200) return fail(payload, "The rows could not be validated.");
      payload.rows.forEach((verdict, i) => {
        const row = parsed.rows[i];
        if (!verdict.ok) {
          row.status = "invalid";
          row.note = row.note ? row.note + "; " + verdict.message : verdict.message;
        } else if (row.status === "parsed") {
          row.status = "valid";
          row.note = "";
        }
      });
    } catch (err) { return; }
    renderBatch();
  });

  async function runBatchRow(row) {
    const step = async (name, work) => {
      row.status = name; renderBatch();
      await work();
    };
    try {
      if (!row.case_id) {
        await step("creating case", async () => {
          const { status: code, payload } = await api("/api/case/create", {
            reference: row.reference, received: row.received || "",
          });
          if (code !== 201) throw { at: "case", payload };
          row.case_id = payload.case_id;
        });
      }
      if (!row.expansion) {
        await step("resolving identity", async () => {
          const { status: code, payload } = await api("/api/expand", {
            case_id: row.case_id,
            primary_email: row.primary_email,
            display_name: row.display_name || "",
            aliases: semis(row.nicknames),
            other_emails: semis(row.other_emails),
            employee_id: row.employee_id || "",
          });
          if (code !== 200) throw { at: "identity", payload };
          row.expansion = { naive: payload.naive_kql, expanded: payload.kql };
        });
      }
      for (const kind of ["naive", "expanded"]) {
        if (row[kind + "Done"]) continue;
        await step("starting " + kind + " search", async () => {
          const { status: code, payload } = await api("/api/search/create", {
            case_id: row.case_id, kind,
            query: kind === "naive" ? row.expansion.naive : row.expansion.expanded,
            run: true,
          });
          if (code !== 201) throw { at: kind + " search", payload };
          row[kind + "Done"] = true;
        });
      }
      row.status = "done"; row.note = "";
    } catch (failure) {
      row.status = "failed";
      row.failedAt = (failure && failure.at) || "unknown step";
      row.note = (failure && failure.payload && failure.payload.message) || "request failed";
    }
    renderBatch();
  }

  async function runBatch(rows) {
    const queue = rows.slice();
    // Two in flight. Purview throttles the account, not the process, and at
    // the observed latencies two workers keep well under any plausible limit
    // while a 25-row batch still lands inside a coffee.
    const workers = [];
    const width = Math.min(2, queue.length);
    for (let i = 0; i < width; i++) {
      workers.push((async () => {
        while (queue.length) await runBatchRow(queue.shift());
      })());
    }
    await Promise.all(workers);
    const failed = (state.batch.rows || []).filter((r) => r.status === "failed").length;
    status(failed
      ? "Batch finished: " + failed + " row" + (failed === 1 ? "" : "s") + " failed. Retry runs only those, resuming at the failed step."
      : "Batch finished. Review each case from the Requests list.", false);
  }

  $("batch-run").addEventListener("click", async () => {
    clearError();
    await withBusy($("batch-run"), "Running…", () =>
      runBatch(state.batch.rows.filter((r) => r.status === "valid")));
  });

  $("batch-retry").addEventListener("click", async () => {
    clearError();
    await withBusy($("batch-retry"), "Retrying…", () =>
      runBatch(state.batch.rows.filter((r) => r.status === "failed")));
  });

  $("batch-clear").addEventListener("click", () => {
    state.batch = { rows: [] };
    $("batch-input").value = "";
    $("batch-file").value = "";
    renderBatch();
    // Honest about what was cleared: this page. The CSV the operator chose is
    // still on their disk, outside anything this tool controls.
    status("Cleared from this page. If you chose a CSV file, it is still on your computer — delete it when the batch is done.", false);
  });

  // ---------------------------------------------------------- session

  async function signOut() {
    await fetch("/auth/logout", { method: "POST", credentials: "same-origin", redirect: "manual" });
    renderSignedOut();
  }

  $("signout").addEventListener("click", signOut);

  (async function start() {
    try {
      const response = await fetch("/api/whoami", {
        credentials: "same-origin", headers: { Accept: "application/json" },
      });
      if (response.status === 401) return renderSignedOut();
      renderSignedIn(await response.json());
    } catch (err) {
      fail(null, "Could not reach the local server.");
    }
  })();
})();
