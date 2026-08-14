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
    //: Which narrowings have been applied to each query, by template id. The
    //: delta is only the expansion's contribution while these two agree; see
    //: renderComparability().
    narrowings: { naive: [], expanded: [] },
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
    return { status: response.status, payload };
  }

  function fail(payload, fallback) {
    setText("error-detail", (payload && payload.message) || fallback);
    show("error");
    status(null);
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

  // ------------------------------------------------------------- views

  function showView(name) {
    clearError();
    for (const section of document.querySelectorAll(".view")) {
      section.setAttribute("hidden", "");
    }
    state.view = name;
    state.viewEpoch += 1;
    $("view-" + name).removeAttribute("hidden");
    for (const tab of document.querySelectorAll(".tab")) {
      tab.classList.toggle("active", tab.dataset.view === name);
    }
    if (name !== "case") {
      if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
      stopTicking();
      state.running = 0;
    }
    status(null);
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
    state.case_id = null;
    state.reference = null;
    state.generated = null;
    state.running = 0;
    state.total = 0;
    state.canWrite = false;

    $("identity").replaceChildren(el("span", "not signed in", "muted"));
    hide("nav");
    for (const section of document.querySelectorAll(".view")) {
      section.setAttribute("hidden", "");
    }
    clearError();
    show("signed-out");
  }

  function renderSignedIn(me) {
    state.canWrite = !!me.can_write;
    // Every role held, not the one that decided the outcome. App roles in
    // Entra are ADDITIVE — a user assigned both carries both in the token, and
    // nothing "wins". Showing only the effect made that look like a conflict
    // being resolved somewhere, which it is not: DSAR.Operator simply implies
    // everything DSAR.Auditor allows, so holding both is redundant rather than
    // contradictory. Saying so on the page is cheaper than explaining it.
    const identity = [el("strong", me.upn || me.oid)];
    for (const role of me.roles || []) {
      identity.push(el("span", role, "chip"));
    }
    $("identity").replaceChildren(...identity);
    hide("signed-out");
    show("nav");
    if (!state.canWrite) {
      // Server-enforced too. Hiding a button is not a control — the endpoint
      // is still there — so this is a courtesy, not the boundary.
      $("create-case").disabled = true;
      $("create-case").title = "Needs the DSAR.Operator role";
    }
    showView("requests");
    loadRequests();
    loadTemplates();
  }

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  // --------------------------------------------------------- requests

  async function loadRequests() {
    try {
      const { status, payload } = await api("/api/requests", { scope: $("scope").value });
      if (status !== 200) return fail(payload, "The request list could not be read.");

      const body = $("requests-body");
      body.replaceChildren();
      const rows = payload.requests || [];
      $("requests-table").toggleAttribute("hidden", rows.length === 0);
      $("requests-empty").toggleAttribute("hidden", rows.length !== 0);

      for (const item of rows) {
        const tr = document.createElement("tr");
        tr.appendChild(el("td", item.reference || "—"));
        tr.appendChild(el("td", item.display_name || ""));
        tr.appendChild(el("td", item.status || ""));
        tr.appendChild(el("td", (item.created || "").slice(0, 10)));

        const actions = document.createElement("td");
        const open = el("button", "Open", "linklike");
        open.type = "button";
        open.addEventListener("click", () => openCase(item));
        actions.appendChild(open);
        tr.appendChild(actions);
        body.appendChild(tr);
      }

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
    } catch (err) { /* handled in api() */ }
  }

  $("scope").addEventListener("change", loadRequests);

  // -------------------------------------------------------- new case

  $("create-case").addEventListener("click", async () => {
    clearError();
    const reference = $("reference").value.trim();
    if (!reference) return fail(null, "A DSAR reference is required.");
    await withBusy($("create-case"), "Creating\u2026", async () => {
      const epoch = state.viewEpoch;
      status("Creating the eDiscovery case in Microsoft Purview\u2026", true, epoch);
      try {
        const result = await api("/api/case/create", { reference });
        if (result.status !== 201) {
          return fail(result.payload, "The case could not be created.");
        }
        state.case_id = result.payload.case_id;
        state.reference = result.payload.reference;
        setText("case-created",
          "Case created in Purview: " + result.payload.display_name +
          ". Reference stored on the case, so it appears on any machine you " +
          "sign in from. Now identify the subject.");
        show("case-created");
        $("subject-fieldset").disabled = false;
        $("primary-email").focus();
        status("Case created.", false, epoch);
      } catch (err) { /* handled in api() */ }
    });
  });

  // ------------------------------------------------------- expansion

  const lines = (id) => $(id).value.split("\n").map((s) => s.trim()).filter(Boolean);

  $("expand").addEventListener("click", async () => {
    clearError();
    await withBusy($("expand"), "Resolving\u2026", () => doExpand());
  });

  async function doExpand() {
    try {
      const epoch = state.viewEpoch;
      status("Looking the subject up in the directory\u2026", true, epoch);
      const { status: code, payload } = await api("/api/expand", {
        case_id: state.case_id,
        primary_email: $("primary-email").value.trim(),
        display_name: $("display-name").value.trim(),
        other_emails: lines("other-emails"),
        nicknames: lines("nicknames"),
        employee_id: $("employee-id").value.trim(),
      });
      if (code !== 200) return fail(payload, "The subject could not be resolved.");
      renderExpansion(payload);
      const found = (payload.identifiers || []).length;
      const mentions = (payload.mentions || []).length;
      setText("expand-note",
        "Resolved " + found + " identifier" + (found === 1 ? "" : "s") +
        " and " + mentions + " mention clause" + (mentions === 1 ? "" : "s") +
        ". Review the queries below — nothing has run yet.");
      show("expand-note");
      status("Subject resolved. Review the queries before running them.", false, epoch);
    } catch (err) { /* handled */ }
  }

  function renderExpansion(data) {
    const box = $("identifiers");
    box.replaceChildren();
    for (const identifier of data.identifiers || []) {
      const chip = el("span", identifier.value + "  ·  " + identifier.source, "chip");
      box.appendChild(chip);
    }
    for (const mention of data.mentions || []) {
      box.appendChild(el("span", '"' + mention + '"  ·  mention', "chip mention"));
    }

    if ((data.warnings || []).length) {
      setText("expansion-warnings", data.warnings.join(" "));
      show("expansion-warnings");
    } else {
      hide("expansion-warnings");
    }

    $("kql-naive").value = data.naive_kql || "";
    $("kql-expanded").value = data.kql || "";
    // Keep the pristine generated query so a narrowing can be undone. Templates
    // stack by design, but a stacked query is easy to get wrong by hand and
    // impossible to un-stack without this.
    state.generated = { naive: data.naive_kql || "", expanded: data.kql || "" };
    state.narrowings = { naive: [], expanded: [] };
    renderComparability();
    show("expansion");
  }

  $("reset-queries").addEventListener("click", () => {
    clearError();
    if (!state.generated) return;
    $("kql-naive").value = state.generated.naive;
    $("kql-expanded").value = state.generated.expanded;
    state.narrowings = { naive: [], expanded: [] };
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
        "rather than the expansion \u2014 and can come out negative. Apply it to " +
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
        "same estate and the delta can read backwards.");
    } else if (inNaive) {
      lines.push(
        "Both queries carry a mail-item clause, so both site counts will read " +
        "zero. That is the clause working, not an empty estate \u2014 the delta " +
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
    return "\u201c" + ((template && template.name) || id) + "\u201d";
  }

  // A pasted query is the case the click tracking cannot see, so the check has
  // to run on what is in the box rather than on what put it there.
  for (const id of ["kql-naive", "kql-expanded"]) {
    $(id).addEventListener("input", renderComparability);
  }

  // -------------------------------------------------------- templates

  async function loadTemplates() {
    try {
      const { status, payload } = await api("/api/templates", {});
      if (status !== 200) return;
      const box = $("templates");
      box.replaceChildren();
      templatesById.clear();
      for (const template of payload.templates || []) {
        templatesById.set(template.id, template);
        box.appendChild(renderTemplate(template));
      }
    } catch (err) { /* handled */ }
  }

  function renderTemplate(template) {
    const wrap = el("div", undefined, "template");
    // The caution below says this at length, inside a panel the operator has
    // usually already collapsed. This is the version that gets read.
    wrap.appendChild(el("h4", template.name +
      (template.mailbox_only ? "  \u00b7  mailbox only" : "")));
    wrap.appendChild(el("p", template.purpose, "muted small"));
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
      const epoch = state.viewEpoch;
      status("Applying \u201c" + template.name + "\u201d\u2026", true, epoch);
      // One box at a time, and the failure message names how far it got. A
      // partial application reported as a plain failure is exactly how the two
      // queries diverge without anyone knowing they have.
      const applied = [];
      for (const target of pending) {
        const { status: code, payload } = await api("/api/template/apply", {
          query: $(BOX[target]).value,
          template_id: template.id,
          values,
        });
        if (code !== 200) {
          renderComparability();
          return fail(payload, applied.length
            ? "Applied to the " + applied.join(" and ") +
              " query, then failed on the rest."
            : "The template could not be applied.");
        }
        $(BOX[target]).value = payload.query;
        state.narrowings[target].push(template.id);
        applied.push(target);
      }
      renderComparability();
      status("Applied \u201c" + template.name + "\u201d to the " +
             applied.join(" and ") + " quer" +
             (applied.length > 1 ? "ies" : "y") + ".", false, epoch);
    } catch (err) { renderComparability(); }
  }

  // ---------------------------------------------------------- search

  $("run-both").addEventListener("click", async () => {
    clearError();
    if (!state.case_id) return fail(null, "Create the case first.");
    const epoch = state.viewEpoch;
    await withBusy($("run-both"), "Running\u2026", async () => {
      show("run-progress");
      for (const step of ["naive", "naive-run", "expanded", "expanded-run"]) {
        markStep(step, "");
      }
      try {
        // The query sent is whatever is in the box — edited or not. A query the
        // operator saw and a query that runs must be the same string, or the
        // review step means nothing.
        status("Creating the naive search\u2026", true, epoch);
        markStep("naive", "doing");
        const naive = await api("/api/search/create", {
          case_id: state.case_id, kind: "naive",
          query: $("kql-naive").value, run: true,
        });
        if (naive.status !== 201) {
          markStep("naive", "failed");
          return fail(naive.payload, "The naive search could not be created.");
        }
        markStep("naive", "done");
        markStep("naive-run", "done");

        status("Creating the expanded search\u2026", true, epoch);
        markStep("expanded", "doing");
        const expanded = await api("/api/search/create", {
          case_id: state.case_id, kind: "expanded",
          query: $("kql-expanded").value, run: true,
        });
        if (expanded.status !== 201) {
          markStep("expanded", "failed");
          return fail(expanded.payload, "The expanded search could not be created.");
        }
        markStep("expanded", "done");
        markStep("expanded-run", "done");

        status("Both estimates started. Watching for results\u2026", true, epoch);
        openCase({ case_id: state.case_id, reference: state.reference });
      } catch (err) { /* handled */ }
    });
  });

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
    setText("case-portal", "");
  }

  async function openCase(item) {
    state.case_id = item.case_id;
    state.pollStarted = Date.now();
    state.running = 0;
    state.total = 0;
    setText("case-title", item.reference || item.display_name || "Case");
    // Before the view is shown, not after — a clear that happens after the
    // paint is a flicker of the wrong data rather than an absence of it.
    clearCaseView();
    showView("case");

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
      (state.total === 1 ? "" : "s") + " still running \u2014 " + elapsed() +
      " so far. This page updates on its own; you can leave it.");
    show("poll-note");
    status("Estimating \u2014 " + elapsed() + " elapsed" + untilNextCheck(), true);
  }

  function untilNextCheck() {
    // The gap between polls stretches to a minute. Without a countdown that
    // pause is indistinguishable from a stall, which is the same doubt the
    // elapsed counter was added to remove.
    if (!state.nextPollAt) return "";
    const seconds = Math.max(0, Math.round((state.nextPollAt - Date.now()) / 1000));
    if (!seconds) return " \u00b7 checking\u2026";
    return " \u00b7 next check in " + seconds + "s";
  }

  function elapsed() {
    const seconds = Math.round((Date.now() - (state.pollStarted || Date.now())) / 1000);
    if (seconds < 60) return seconds + "s";
    return Math.floor(seconds / 60) + "m " + (seconds % 60) + "s";
  }

  $("refresh-case").addEventListener("click", async () => {
    await withBusy($("refresh-case"), "Refreshing\u2026", async () => {
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

  async function refreshCase() {
    try {
      const { status, payload } = await api("/api/case", { case_id: state.case_id });
      if (status !== 200) { fail(payload, "The case could not be read."); return true; }

      const rows = payload.searches || [];
      const body = $("searches-body");
      body.replaceChildren();
      $("searches-table").toggleAttribute("hidden", rows.length === 0);
      $("searches-empty").toggleAttribute("hidden", rows.length !== 0);

      let complete = true;
      for (const search of rows) {
        const stats = search.statistics || {};
        if (!stats.complete) complete = false;
        const tr = document.createElement("tr");
        tr.appendChild(el("td", search.display_name || ""));
        // null, not 0 — "no estimate yet" and "found nothing" are different.
        tr.appendChild(el("td", stats.item_count === null ? "—" : String(stats.item_count)));
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

        let statusText;
        if (stats.partial) {
          // Not smoothed over. A DSAR response built on a partial count is a
          // compliance problem, not a rounding error.
          statusText = "complete (partial — some locations not searched)";
        } else if (stats.complete) {
          statusText = "complete";
        } else if (stats.percent_progress) {
          statusText = (stats.status || "running") + " — " + stats.percent_progress + "%";
        } else {
          statusText = stats.status || "running";
        }
        const statusCell = el("td", statusText);
        if (stats.partial) statusCell.className = "warn";
        tr.appendChild(statusCell);

        const actions = document.createElement("td");
        if (state.canWrite && stats.complete) {
          const exportBtn = el("button", "Export", "linklike");
          exportBtn.type = "button";
          exportBtn.addEventListener("click", () => startExport(search));
          actions.appendChild(exportBtn);
        }
        tr.appendChild(actions);
        body.appendChild(tr);
      }

      renderDelta(rows);

      state.running = rows.filter((s) => !(s.statistics || {}).complete).length;
      state.total = rows.length;

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

      setText("case-portal", "Collect exports in the Microsoft Purview portal: " + payload.portal_url);
      return complete && rows.length > 0;
    } catch (err) { return true; }
  }

  function renderDelta(rows) {
    // The comparison is the demonstration, and it needs no item content to
    // make its case — which is exactly the argument the product is making.
    const naive = rows.find((s) => /naive/i.test(s.display_name));
    const expanded = rows.find((s) => /expanded/i.test(s.display_name));
    const a = naive && naive.statistics, b = expanded && expanded.statistics;
    if (!a || !b || !a.complete || !b.complete || a.item_count === null || b.item_count === null) {
      hide("delta");
      return;
    }
    const extra = b.item_count - a.item_count;
    if (extra <= 0) {
      setText("delta", "The expanded query found no more than the naive one on this data.");
      show("delta");
      return;
    }
    const pct = a.item_count ? Math.round((extra / a.item_count) * 100) : 0;
    let text = "The naive query missed " + extra + " item" + (extra === 1 ? "" : "s") +
               " — " + pct + "% more";
    if (b.location_count !== null && a.location_count !== null && b.location_count > a.location_count) {
      text += ", and " + (b.location_count - a.location_count) + " location" +
              (b.location_count - a.location_count === 1 ? "" : "s") + " it never looked at";
    }
    setText("delta", text + ".");
    show("delta");
  }

  async function startExport(search) {
    clearError();
    const epoch = state.viewEpoch;
    status("Starting the export in Purview\u2026", true, epoch);
    try {
      const { status: code, payload } = await api("/api/export", {
        case_id: state.case_id, search_id: search.search_id, name: search.display_name,
      });
      if (code !== 202) return fail(payload, "The export could not be started.");
      setText("case-portal", payload.note + "  " + payload.portal_url);
      status("Export started. Collect it in the Purview portal.", false, epoch);
    } catch (err) { /* handled */ }
  }

  // ---------------------------------------------------------- session

  $("signout").addEventListener("click", async () => {
    await fetch("/auth/logout", { method: "POST", credentials: "same-origin", redirect: "manual" });
    renderSignedOut();
  });

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
