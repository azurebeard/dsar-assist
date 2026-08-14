# Design

Why this exists, and why each part is shaped the way it is. Every decision
below traces to something the predecessor lost.

---

## 1. What went wrong last time

`dsar-orchestrator` (mission `8652e638`) was a good tool: 11,390 lines, 246
tests, `mypy --strict` clean, a passed security review, and a genuinely novel
product claim. It failed to move to a Mac for a customer demo and the reason
was never diagnosed. The code itself was portable — no absolute paths, no
secrets in tree, three pinned dependencies. Four things anchored it to one
machine.

**The OS-keyring token cache.** `msal-extensions` reaches libsecret through
PyGObject, which is a *system* package pip cannot install. Inside a virtualenv
it disappears, so the tool correctly reported "no encrypted backend" on a host
that had a perfectly good one — and, having no plaintext fallback by design,
degraded to interactive sign-in on every launch. The workaround was a
hand-made symlink into site-packages, documented in prose and reproduced by no
install step. On macOS the equivalent was an interactive Keychain prompt that,
if missed, produced the same silent degradation.

**The local queue was the source of truth.** The UI listed rows from a local
SQLite file and never read cases back from Graph. A correctly-installed second
machine, signed into the right tenant, with the demo case sitting in Purview,
showed an empty queue. The documented remedy was to copy the database file
between machines.

**No lockfile, no container, no IaC.** Three direct pins; transitives floated
and resolved differently per platform.

**The console script was never installed.** `pip install -e .` had not been
run, so `dsar` was not on `PATH` — while every line of documentation assumed it
was.

There was also a live bug (B-15) where starting a second worker marked the
first worker's in-flight jobs failed, even though they had succeeded in
Purview.

---

## 2. What is kept

The predecessor's best properties are not portability problems and are carried
forward wholesale:

- **The no-data-plane claim**, which is the product.
- **The structural test harness**, including the trick of assembling forbidden
  literals at runtime so the scanner does not trip its own scan — because
  excluding the scanner from the sweep creates a blind spot exactly where a
  violation is easiest to hide.
- **The socket guard in `conftest.py`**, and the reason it exists: a test lost
  its HTTP-mocking decorator, made a real call to Microsoft Graph, and failed
  for a plausible-looking reason that took twenty minutes to attribute.
- **The security headers and the same-origin rule**, including the reasoning
  that browsers do not send `Origin` on a same-origin GET, so the rule is
  applied to an all-POST API surface rather than relaxed.
- **The explicit static allowlist** — a file dropped into `static/` is not
  served until someone names it.
- **The Purview portal deep link**, measured against a real case URL. Both
  halves of the original guess were wrong.
- **The `verification/` convention**: dated files recording what was actually
  observed against a live tenant, not what the specification predicted.

---

## 3. Decisions

### One image, two modes

The delivery vehicle is a container that runs identically on an operator's
laptop and on Azure Container Apps. This forced one non-obvious consequence:
**MSAL's `acquire_token_interactive` cannot be used.** It opens a browser in
the *process's* environment and listens on a *process-local* loopback port;
inside a container there is no browser, and the port belongs to the container's
network namespace, not the host's.

Both modes therefore drive the authorization-code flow from the application's
own `/auth/login` → `/auth/callback`, and the host browser hits the published
port. This is what makes the mode abstraction real rather than a veneer over
two genuinely different flows.

### Two delivery paths, not one

Docker Desktop is frequently blocked or unlicensed on a locked-down client
laptop. `uv` is a single static binary that installs without admin rights, and
all four dependencies are pure-Python wheels, so `uvx dsar up` works
everywhere. Both are first-class and both are in CI. Making Docker a single
point of failure on a presenter's machine would repeat the original mistake in
a new costume.

### Tokens in memory only

No keyring, no file cache, no fallback, and `msal.SerializableTokenCache` is
banned by a structural test. Sign-in does not survive a process restart.

This is not a regression, for three reasons. It deletes the entire failure
class described above. The unit of lifetime is a long-running `dsar up`, not an
invocation — with CAE declared, tokens are long-lived enough that one sign-in
covers a working week. And it aligns *better* with Conditional Access: a
keyring-encrypted refresh token on disk is a local re-implementation of session
lifetime that CA cannot see, cannot shorten and cannot revoke, and which
survives reboots, disk images and file copies. An in-memory token dies with the
process.

### Microsoft Graph is the source of truth

`GET /security/cases/ediscoveryCases` is GA on v1.0 and needs no scope we do
not already hold. `ediscoveryCase.externalId` is settable at creation and
returned in the list response, so the DSAR reference travels in the case
itself (`dsar:v1:DSAR-2026-0142`) rather than in a `displayName` convention
someone will edit in the portal.

Nothing durable is cached locally. A second machine shows the same list because
the list *is* Graph. This also removes B-15 by construction: with no worker,
no claim and no crash-recovery pass, no code exists that could mark another
process's in-flight work as failed.

### The bind address, honestly

The predecessor guaranteed a `127.0.0.1` bind with a literal in the source and
a test that grepped for the alternative. **That guarantee cannot survive
containerisation** — Docker publishes to the container's interface, so a
process binding loopback inside a container is unreachable. Pretending
otherwise would be dishonest.

The control moved rather than being dropped:

| | Before | Now |
|---|---|---|
| Desktop | `127.0.0.1` literal in `server.py` | `-p 127.0.0.1:8765:8765` in both launchers |
| Hosted | forbidden | ingress with `allowInsecure: false`, `ipSecurityRestrictions`, Conditional Access |

Both are testable, and both are tested. `doctor` reports the effective exposure
rather than implying a guarantee that no longer exists.

### Four direct dependencies, up from three

`msal`, `httpx`, `starlette`, `uvicorn`. Starlette rather than FastAPI because
this codebase's validation is hand-written and better than a schema — a
Pydantic model cannot express *"a file extension is the one value that reaches
a query unquoted, so it is allowlisted rather than escaped"*, and that comment
is the most valuable line in the ported template module. httpx rather than
requests because a synchronous call inside an ASGI handler blocks the event
loop.

`msal` pulls `requests` transitively. That is visible in `uv.lock` and is not
hidden — but the dependency-budget test asserts on the **declared** set, not on
what resolves. The predecessor maintained a hand-written allowlist of resolved
transitives, and it did not survive dependency churn: a Dependabot bump was
closed because the audit tripped on two new indirect packages.

The count went up by one. The package that caused 100% of the observed
portability failures is gone.

---

## 4. What is not available, stated plainly

Three controls that sound right for a tool handling other people's personal
data, and cannot be used here:

- **Token protection / sign-in session token binding.** Supported resources are
  Exchange Online, SharePoint Online and Teams, plus AVD and Windows 365 on
  Windows. Browser support is preview and only for Azure Resource Manager. It
  cannot be scoped to a custom application or to Microsoft Graph.
- **DPoP (RFC 9449).** Entra's proof-of-possession is a different mechanism
  (RFC 7800 plus signed HTTP request). No DPoP support.
- **mTLS-bound tokens (RFC 8705).** Documented as not currently supported.

MSAL's own PoP support goes through a broker — WAM on Windows, the macOS
broker. There is no broker in a Linux container, and `doctor` asserts that
rather than assuming it.

Compensating controls, which are real: tokens in memory only and never
serialised; CAE declared so an administrative revoke lands in minutes;
phishing-resistant MFA so a stolen refresh token cannot be re-minted on a new
device; a short application session; and an optional IP-based named location on
the hosted egress.

---

## 5. Does hosting break the security story?

Yes, partly — and reframing beats denying.

Locally the demo's power was *"you can watch it not do the thing"*: loopback,
egress blocked, packet capture. Hosted, two things exist that did not before —
an internet-facing endpoint, and a server-side session holding a delegated
token. Both should be said out loud.

What is unchanged is the actual core claim: **there is still no data plane**,
and it is stronger than the predecessor stated, because the tool never requests
the resource that carries the download permission at all. Hosting adds an
endpoint; it does not add a data path — and `doctor` proves that at runtime on
the hosted instance by inspecting the issued token's scopes, which is better
evidence than a screenshot of the permissions blade.

The story becomes: *the tool holds no content; the blast radius of the one
thing it does hold — a single delegated session — is governed by your
Conditional Access policies, gated by an app-role assignment, visible in your
sign-in logs, and every action is recorded in an append-only audit trail that
joins back to those logs by token identifier.*

A better enterprise story and a worse demo story. Both halves are true.
**Keep desktop mode as the demo**, run from the container on the presenter's
laptop with egress blocked, and present hosted as the deployment option for
teams. The narrative that sells and the architecture that scales do not have to
be the same artefact — they only have to be the same image, and now they are.

---

## 6. Known limits to state rather than overclaim

- **Global Administrators bypass `appRoleAssignmentRequired`.** "Only assigned
  users get in" has that hole.
- **Entra roles override administrative-unit scoping.** An operator who also
  holds Compliance Administrator loses any AU scoping for overlapping
  capabilities, so operators should not hold it.
- **CAE does not cover role or group changes** — those take up to a day to
  propagate. A 403 from Purview is the real signal that a role was removed, and
  it is surfaced as a specific message rather than a stack trace.
- **The queue scope toggle is a display filter, not a security boundary.** The
  boundary is Purview RBAC, which this tool does not control and cannot
  elevate.
- **A hosted revision update signs every operator out**, because sessions are
  in-process and the app runs a single replica. Documented property, not a
  surprise.
