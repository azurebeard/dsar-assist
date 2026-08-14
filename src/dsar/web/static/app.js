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
