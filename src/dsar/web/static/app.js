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
    pollTimer: null, pollDelay: 10000, pollStarted: null, generated: null,
  };

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
  // aria-live="polite" so it is announced rather than only seen — an operator
  // running a screen reader gets the same eleven-minute wait everyone else does
  // and deserves to be told about it.
  function status(text, busy) {
    const bar = $("status");
    if (!text) { bar.setAttribute("hidden", ""); return; }
    setText("status-text", text);
    $("status-spinner").toggleAttribute("hidden", !busy);
    bar.removeAttribute("hidden");
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
    $("view-" + name).removeAttribute("hidden");
    for (const tab of document.querySelectorAll(".tab")) {
      tab.classList.toggle("active", tab.dataset.view === name);
    }
    if (state.pollTimer && name !== "case") {
      clearTimeout(state.pollTimer);
      state.pollTimer = null;
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
    $("identity").replaceChildren(el("span", "not signed in", "muted"));
    hide("nav");
    for (const section of document.querySelectorAll(".view")) {
      section.setAttribute("hidden", "");
    }
    show("signed-out");
  }

  function renderSignedIn(me) {
    state.canWrite = !!me.can_write;
    $("identity").replaceChildren(el("strong", me.upn || me.oid));
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
      status("Creating the eDiscovery case in Microsoft Purview\u2026", true);
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
        status("Case created.", false);
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
      status("Looking the subject up in the directory\u2026", true);
      const { status: code, payload } = await api("/api/expand", {
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
      status("Subject resolved. Review the queries before running them.", false);
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
    show("expansion");
  }

  $("reset-queries").addEventListener("click", () => {
    clearError();
    if (!state.generated) return;
    $("kql-naive").value = state.generated.naive;
    $("kql-expanded").value = state.generated.expanded;
  });

  // -------------------------------------------------------- templates

  async function loadTemplates() {
    try {
      const { status, payload } = await api("/api/templates", {});
      if (status !== 200) return;
      const box = $("templates");
      box.replaceChildren();
      for (const template of payload.templates || []) {
        box.appendChild(renderTemplate(template));
      }
    } catch (err) { /* handled */ }
  }

  function renderTemplate(template) {
    const wrap = el("div", undefined, "template");
    wrap.appendChild(el("h4", template.name));
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

    const apply = el("button", "Apply to expanded query", "button secondary small");
    apply.type = "button";
    apply.addEventListener("click", async () => {
      const values = {};
      for (const [name, field] of Object.entries(fields)) values[name] = field.value;
      try {
        status("Applying \u201c" + template.name + "\u201d\u2026", true);
        const { status: code, payload } = await api("/api/template/apply", {
          query: $("kql-expanded").value,
          template_id: template.id,
          values,
        });
        if (code !== 200) return fail(payload, "The template could not be applied.");
        // Applying the same narrowing twice yields
        //   (... AND kind:email) AND kind:email
        // which is valid KQL, redundant, and unreadable — and for the date
        // template two ranges can contradict each other outright. A repeat is
        // almost always a double click, so it is refused rather than stacked.
        const current = $("kql-expanded").value;
        const added = payload.query.slice(current.length).trim();
        if (added && current.indexOf(added.replace(/^AND\s+/, "")) !== -1) {
          return fail(null,
            "That narrowing is already in the query. Use Reset to start from the " +
            "generated one, or edit the text directly.");
        }
        $("kql-expanded").value = payload.query;
        status("Applied \u201c" + template.name + "\u201d to the expanded query.", false);
      } catch (err) { /* handled */ }
    });
    wrap.appendChild(apply);
    return wrap;
  }

  // ---------------------------------------------------------- search

  $("run-both").addEventListener("click", async () => {
    clearError();
    if (!state.case_id) return fail(null, "Create the case first.");
    await withBusy($("run-both"), "Running\u2026", async () => {
      show("run-progress");
      for (const step of ["naive", "naive-run", "expanded", "expanded-run"]) {
        markStep(step, "");
      }
      try {
        // The query sent is whatever is in the box — edited or not. A query the
        // operator saw and a query that runs must be the same string, or the
        // review step means nothing.
        status("Creating the naive search\u2026", true);
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

        status("Creating the expanded search\u2026", true);
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

        status("Both estimates started. Watching for results\u2026", true);
        openCase({ case_id: state.case_id, reference: state.reference });
      } catch (err) { /* handled */ }
    });
  });

  // ----------------------------------------------------- case detail

  async function openCase(item) {
    state.case_id = item.case_id;
    state.pollStarted = Date.now();
    state.pollDelay = 10000;
    setText("case-title", item.reference || item.display_name || "Case");
    showView("case");

    const done = await refreshCase();
    if (!done) schedulePoll();
  }

  // The ladder: brisk while an estimate might land, then patient. Estimation is
  // wildly variable — around eleven minutes against a cold index, under a
  // minute after — so the elapsed counter matters more than the interval. A
  // screen that has said "running" for nine minutes with no clock on it is
  // indistinguishable from a screen that has hung.
  function schedulePoll() {
    if (state.pollTimer) clearTimeout(state.pollTimer);
    state.pollTimer = setTimeout(async () => {
      const done = await refreshCase();
      if (done) {
        state.pollTimer = null;
        return;
      }
      state.pollDelay = Math.min(state.pollDelay * 3, 60000);
      schedulePoll();
    }, state.pollDelay);
  }

  function elapsed() {
    const seconds = Math.round((Date.now() - (state.pollStarted || Date.now())) / 1000);
    if (seconds < 60) return seconds + "s";
    return Math.floor(seconds / 60) + "m " + (seconds % 60) + "s";
  }

  $("refresh-case").addEventListener("click", async () => {
    await withBusy($("refresh-case"), "Refreshing\u2026", async () => {
      const done = await refreshCase();
      if (!done) { state.pollDelay = 10000; schedulePoll(); }
    });
  });

  $("back").addEventListener("click", () => {
    if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
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
        tr.appendChild(el("td", stats.location_count === null ? "—" : String(stats.location_count)));
        tr.appendChild(el("td", stats.complete ? "complete" : (stats.status || "running")));

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

      const running = rows.filter((s) => !(s.statistics || {}).complete).length;
      if (rows.length && running) {
        setText("poll-note",
          running + " of " + rows.length + " estimate" +
          (rows.length === 1 ? "" : "s") + " still running \u2014 " + elapsed() +
          " so far. Purview takes around eleven minutes on a cold index and " +
          "under a minute afterwards. This page updates on its own; you can " +
          "leave it.");
        show("poll-note");
        status("Estimating \u2014 " + elapsed() + " elapsed", true);
      } else if (rows.length) {
        setText("poll-note", "All estimates complete after " + elapsed() + ".");
        show("poll-note");
        status("Estimates complete.", false);
      } else {
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
    status("Starting the export in Purview\u2026", true);
    try {
      const { status: code, payload } = await api("/api/export", {
        case_id: state.case_id, search_id: search.search_id, name: search.display_name,
      });
      if (code !== 202) return fail(payload, "The export could not be started.");
      setText("case-portal", payload.note + "  " + payload.portal_url);
      status("Export started. Collect it in the Purview portal — this tool cannot.", false);
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
