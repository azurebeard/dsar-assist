// DSAR Assist — front end.
//
// No framework, no bundler, no npm. Nothing here needs one, and a build step
// is one more thing that works on the machine it was set up on.
//
// The Content-Security-Policy is `default-src 'none'` with `script-src 'self'`,
// so there are no inline handlers. It also sets `form-action 'none'`, which is
// why sign-out is a fetch() rather than a form POST — a form submission would
// be blocked by the policy, silently, and look like a broken button.
"use strict";

(function () {
  const show = (id) => document.getElementById(id).removeAttribute("hidden");
  const hide = (id) => document.getElementById(id).setAttribute("hidden", "");
  const setText = (id, value) => {
    // textContent, never innerHTML. Claim values come from a token we
    // validated, but the rule is worth holding everywhere rather than
    // reasoning about provenance at each call site.
    document.getElementById(id).textContent = value;
  };

  function renderSignedOut() {
    document.getElementById("identity").innerHTML = "";
    const span = document.createElement("span");
    span.className = "muted";
    span.textContent = "not signed in";
    document.getElementById("identity").appendChild(span);
    show("signed-out");
    hide("signed-in");
    hide("requests");
  }

  function renderSignedIn(me) {
    const identity = document.getElementById("identity");
    identity.innerHTML = "";
    const strong = document.createElement("strong");
    strong.textContent = me.upn || me.oid;
    identity.appendChild(strong);

    setText("fact-upn", me.upn || "(no UPN in the token)");
    setText("fact-oid", me.oid);
    setText(
      "fact-roles",
      me.roles && me.roles.length
        ? me.roles.join(", ")
        : "none in the token — access is gated by assignment in Entra ID"
    );
    setText("fact-write", me.can_write ? "yes" : "no");

    hide("signed-out");
    show("signed-in");
    show("requests");
    loadRequests();
  }

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
    return { status: response.status, payload: await response.json() };
  }

  function renderRequests(data) {
    const body = document.getElementById("requests-body");
    body.replaceChildren();

    const rows = data.requests || [];
    document.getElementById("requests-table").toggleAttribute("hidden", rows.length === 0);
    document.getElementById("requests-empty").toggleAttribute("hidden", rows.length !== 0);

    for (const item of rows) {
      const tr = document.createElement("tr");
      const cells = [
        item.reference || "—",
        item.display_name || "",
        item.status || "",
        (item.created || "").slice(0, 10),
      ];
      for (const value of cells) {
        const td = document.createElement("td");
        td.textContent = value; // never innerHTML
        tr.appendChild(td);
      }
      const actions = document.createElement("td");
      const link = document.createElement("a");
      link.href = item.portal_url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Open in Purview";
      actions.appendChild(link);
      tr.appendChild(actions);
      body.appendChild(tr);
    }

    // The freshness stamp is not decoration. A list with no timestamp invites
    // the assumption that it is live, and this one is a read of Graph that
    // happened at a point in time.
    const stamp = new Date().toLocaleTimeString();
    let note = "Read from " + (data.source || "Microsoft Graph") + " at " + stamp +
               ". Nothing is stored locally — the same list appears on any machine " +
               "you sign in from.";
    if (data.truncated) {
      note += " The list was truncated; there are more cases than shown.";
    }
    document.getElementById("requests-source").textContent = note;

    // Only offer the toggle when it would change something. A control that
    // does nothing is worse than no control.
    const controls = document.getElementById("scope-controls");
    controls.toggleAttribute("hidden", !data.scope_toggle_useful);
    const scopeNote = document.getElementById("scope-note");
    if (data.scope_toggle_useful) {
      scopeNote.textContent =
        "This is a display filter, not a permission. What you can see at all is " +
        "decided by your Microsoft Purview role, which this tool cannot change.";
      scopeNote.removeAttribute("hidden");
    } else {
      scopeNote.setAttribute("hidden", "");
    }
  }

  async function loadRequests() {
    try {
      const scope = document.getElementById("scope").value;
      const { status, payload } = await api("/api/requests", { scope });
      if (status === 200) {
        renderRequests(payload);
        return;
      }
      if (status === 401 && payload.error === "claims_challenge") {
        // The claims must reach the step-up or the operator signs in
        // successfully and nothing changes.
        window.location = payload.step_up + "?claims=" + encodeURIComponent(payload.claims);
        return;
      }
      if (status === 401) {
        renderSignedOut();
        return;
      }
      renderError(payload.message || "The request list could not be read.");
    } catch (err) {
      renderError("Could not reach the local server.");
    }
  }

  function renderError(detail) {
    setText("error-detail", detail);
    show("error");
  }

  async function refresh() {
    try {
      const response = await fetch("/api/whoami", {
        // Same-origin only. There is no CORS anywhere in this application and
        // there is no configuration that adds it.
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (response.status === 401) {
        renderSignedOut();
        return;
      }
      if (!response.ok) {
        renderError("The server returned " + response.status + ".");
        return;
      }
      renderSignedIn(await response.json());
    } catch (err) {
      renderError("Could not reach the local server.");
    }
  }

  document.getElementById("scope").addEventListener("change", loadRequests);

  document.getElementById("signout").addEventListener("click", async () => {
    // POST, so the browser sends an Origin header even same-origin. The API
    // surface is all-POST for exactly that reason: a same-origin GET carries
    // no Origin, so a rule that rejects an absent Origin would reject the
    // application's own requests.
    await fetch("/auth/logout", {
      method: "POST",
      credentials: "same-origin",
      redirect: "manual",
    });
    await refresh();
  });

  refresh();
})();
