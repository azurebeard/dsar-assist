# Phase 1 identity plane — live against picnicdev

**Date:** 2026-08-14 · **Tenant:** `764279e8-66e9-49b4-901f-a7592435ae1d`
**App:** `DSAR Assist (Desktop)` · `d043d9be-1173-4024-8975-52fcf08d3551`
**Operator:** `bth.priv@picnicdev.onmicrosoft.com`, assigned `DSAR.Operator`
**Method:** full authorization-code flow through the application's own
`/auth/login` → `/auth/callback`, then `/api/whoami`

Both questions the plan flagged as unanswerable from documentation are now
answered against a live tenant.

---

## Q1 — Is the `roles` claim emitted in a **public client's** ID token?

**Yes.** Observed: `DSAR.Operator`, and `can_write` resolved to true.

Microsoft documents app roles for applications that sign users in and for APIs,
but does not state the behaviour for public clients specifically, which is why
this was built as a setting rather than a hard-coded rule.

**Consequence:** `RoleEnforcement.REQUIRED` is viable and becomes the default.
`DSAR_REQUIRE_APP_ROLE=0` remains available for a tenant whose registration is
shaped differently, but the secure posture is now the one you get without
configuring anything.

The `ADVISORY` path is kept rather than deleted. It is the correct behaviour
for any tenant where the claim does not arrive, and removing it would mean
rediscovering this question the next time the application is deployed
somewhere new.

**Caveat worth keeping:** on the desktop this check was never a security
boundary — the operator controls the process. The boundary is Entra refusing to
issue a token at all, via `appRoleAssignmentRequired`. What the check buys is a
clear refusal at sign-in instead of a confusing Purview failure three screens
later.

---

## Q2 — Does Entra ignore the **port** when matching a loopback redirect?

**Yes.** The probe listened on `9876` while `http://localhost:8765/auth/callback`
was the only registered redirect URI, and the flow completed — reaching token
acquisition and returning access-token scopes.

Consistent with RFC 8252 §7.3 and with Microsoft's reply-URL documentation.

**Consequence:** the launcher's `--port` override is safe, and exactly one
loopback URI stays registered. Do **not** register a second one differing only
by port — the login server chooses between them arbitrarily.

### A method that looked right and was wrong

The first attempt tried to answer this **without a sign-in**, on the theory
that Entra validates `redirect_uri` before authenticating. It does not. A
deliberately wrong *host* — `http://evil.example/auth/callback` — returned the
ordinary sign-in page, HTTP 200, `<title>Sign in to your account</title>`,
byte-for-byte indistinguishable from a good one. The probe reported all seven
cases "accepted", **including both controls**, which is the tell that the
method rather than the tenant was broken.

Deleted rather than kept. Recorded because it is the same trap the predecessor
documented: *a comparison that varies one input proves that input sufficient,
never necessary.* Controls exist so that a broken method announces itself; this
one did its job.

---

## Also observed

```
Access token scopes:
  User.Read
  User.Read.All
  eDiscovery.ReadWrite.All
  email
  openid
  profile

  no download scope: YES
```

- **No download scope, proven at runtime on an issued token.** Materially
  stronger evidence than a screenshot of the permissions blade, and it is the
  check `doctor` will run on every instance.
- `User.Read.All` is present, so identity expansion has consent in this tenant.
  It remains optional in the application: a 403 degrades to UPN/mail-only
  search rather than failing.
- Sign-out was exercised and returns the UI to the signed-out state.

---

## Still open

`xms_cc` was not captured in this run — the authorize request carries
`claims={"access_token":{"xms_cc":{"values":["cp1"]}}}`, confirmed in the live
redirect, but whether the STS **agreed** is only readable from the issued
token. `doctor` reports it once the identity checks land. Until it is observed,
do not claim CAE is negotiated — declaring a capability and having it honoured
are different things, and the eDiscovery namespace's CAE behaviour is
undocumented either way.
