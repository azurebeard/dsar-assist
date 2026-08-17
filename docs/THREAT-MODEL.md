# Threat model

**Scope:** the application in both modes. Desktop is the primary deployment;
hosted adds an internet-facing endpoint and multi-operator sessions, and its
additional boundaries are covered in their own sections.

Method: STRIDE over the trust boundaries, with each mitigation named as either
*enforced* (a test or a control proves it), *inherited* (Microsoft's, not
ours), or *accepted* (a stated trade). Enforcement is by the tests named in
[`CLAIMS.md`](CLAIMS.md).

---

## What this system is

A control plane. It creates Purview eDiscovery cases, resolves who a data
subject is, builds a search, reads counts, and hands off to the portal.

**It has no data plane.** It never requests the resource carrying the
eDiscovery download permission, no download or preview call exists in the
eleven-operation table, and the export is collected by a human from Purview
under their own identity. That is the single most important sentence here,
because it removes item content — the highest-value asset in the domain — from
scope entirely.

## Assets

| Asset | Where it lives | Worst case |
|---|---|---|
| The operator's delegated Graph token | Process memory only | Impersonation of the operator against Purview, bounded by their own permissions |
| Session identifier | `HttpOnly` cookie, opaque | Session hijack |
| The data subject's identity and aliases | Memory and the KQL, in flight | A second ungoverned copy of third-party personal data |
| The audit trail | `0600` JSONL, hash-chained | Repudiation, or a falsified record of who searched for whom |
| Case and search metadata | Microsoft Graph | Disclosure of which subjects are under request |
| **Item content** | **Never touched** | **Out of scope by construction** |

## Trust boundaries

```
  Operator's browser ──1── the application ──2── Microsoft Graph
                             │
                             ├──3── the audit file on disk
                             └──4── Microsoft Entra ID
```

---

## 1 · Browser → application

**Spoofing.** Session cookie is an opaque 256-bit value, `HttpOnly`, never a
JWT and never carrying a token. Fresh identifier at every callback, so a
pre-set cookie cannot be adopted. *Enforced.*

**Tampering / CSRF.** Every state-changing call is a POST, so the browser
always sends `Origin` — which is why the surface is all-POST: a rule rejecting
an *absent* Origin would otherwise reject the application's own page loads.
Absent counts as a mismatch, on every state-changing route including
`/auth/logout`. *Enforced.*

**Repudiation.** Sign-in, sign-out, case creation, expansion, search creation,
estimate and export are recorded with actor `oid`, the token's `uti`, and a
hash chain. Refusals are recorded too — a trail holding only successes
describes a system where nobody is ever turned away. *Enforced.*

**Information disclosure.** `textContent` throughout, never `innerHTML`,
held by a structural test over every script the app serves. CSP
`default-src 'none'`, no `unsafe-inline`. `/healthz`
discloses no tenant, and withholds the version when hosted. A 500 returns a
21-byte body — no traceback, no exception type, no path (verified). *Enforced.*

**Denial of service.** `/auth/login` is unauthenticated and allocates server
state: rate-limited 10/min, and the pending-flow store **refuses** rather than
evicting, so one caller cannot cancel another's in-progress sign-in. The API
is limited to 120/min per operator and a request body is capped at 64 KiB;
rate limiting bounds how many requests arrive, the cap bounds how large one
is. The body is read *after* the session check, so an anonymous POST is
refused without being buffered. *Enforced.*

**Elevation of privilege.** Write actions check the app role **server-side** —
a button that is not rendered is not a control, the endpoint is still there.
*Enforced.*

> **Accepted:** on the desktop the operator controls the process, so no
> in-process check is a boundary. The boundary is Entra refusing to issue a
> token via `appRoleAssignmentRequired`. The check buys a clear refusal instead
> of a confusing Purview failure three screens later.

---

## 2 · Application → Microsoft Graph

**Tampering — reaching an unpermitted endpoint.** Every path comes from the
eleven-row operations table; no public method accepts a path argument. Path
segments are validated and cannot contain a dot-segment or percent-encoding — `caseId=".."` previously resolved to
`/security/cases/searches`, outside the table, *through* the check meant to
prevent it. *Enforced, 14-vector test.*

**Injection.** KQL values that cannot be expressed in a phrase are **refused,
not escaped** — KQL has no portable escape for a quote inside a phrase, so
escaping would silently change what was searched for. OData quotes are doubled,
the only escape OData defines. *Enforced.*

**Information disclosure.** Response bodies are never logged or written to
disk. The KQL is never audited: it names a real person and their aliases.
*Enforced by test.*

**Elevation.** The token is delegated, so nothing can exceed the operator's own
Purview permissions. Scopes are `eDiscovery.ReadWrite.All` plus optional
`User.Read.All`; at every sign-in the scopes the identity platform actually
granted are read from the token response, and a download-capable scope refuses
the sign-in outright (`test_a_download_scope_in_the_token_response_refuses_sign_in`).
An earlier version of this paragraph said `doctor` performed this check;
nothing did, and `doctor` never could — it has no session and no token.
*Inherited + enforced.*

> **Accepted, and the most important trade here:** authorisation is **entirely
> Purview's**. `/api/case` does not re-check that a case belongs to the caller.
> A local copy of an authority we do not own would be a weaker second
> implementation. The consequence is that this tool inherits whatever Purview's
> RBAC gets wrong.

---

## 3 · Application → the audit file

**Tampering.** Records are hash-chained; an edit is reported as `altered` at a
named `seq`, a deletion as `broken link` + `out of order`. Detection rather
than prevention, deliberately: prevention fails silently against anyone with
filesystem access, detection does not. The sink Protocol has no update, delete
or truncate — not guarded, absent — and an AST test bans `open(...,"w")`,
`truncate`, `unlink` in the package. *Enforced.*

**Information disclosure.** The record has **no field** that could hold a
subject's name, address, employee ID or the query. The subject is an HMAC keyed
on the *case*, so the same person in two cases yields two pseudonyms — otherwise
the trail becomes a cross-case index of who has been searched for. Directory
`0700`, files `0600`. *Enforced by structural test.*

> **Residual:** an attacker with write access to the file can delete the whole
> trail. The chain makes truncation detectable only if a copy of a later head
> exists — hence the stderr sink, which on Container Apps lands in Log
> Analytics — **a different data plane in the same subscription and the same
> resource group**, not a different trust domain. One
> management-plane actor can delete both. Its retention is 90 days against the
> trail's 2555, so the second copy also expires first. On the desktop there is
> no second copy at all.
> **Accepted** for desktop; hosted deployments use the append-blob sink under
> a WORM policy, which is that second copy.

---

## 4 · Application → Microsoft Entra ID

**Spoofing.** Authorization Code + PKCE (S256). Authority pinned to one tenant;
`tid` pinned *again* at claim validation so the guarantee does not rest on one
configuration value. Principal keyed on `(oid, tid)` — never `upn`, which is
mutable and reassignable. The access token is never parsed. *Enforced.*

**Tampering — flow interception.** The pending flow is held server-side,
single-use, 5-minute TTL. `state` alone is not treated as a control, because a
`state` the attacker chose is a `state` that matches. *Enforced.*

**Elevation — consent.** No secret exists anywhere; `doctor` **fails** if a
secret-shaped variable is set. Both registrations hold zero credentials,
asserted mechanically. *Enforced.*

---

## 5 · Who may attach the managed identity — hosted only

The design says the federated credential means
"no secret to store, rotate or leak", and that is true. It also relocates the
credential rather than removing it: **anyone who can run code as the
user-assigned identity can mint the client assertion**, and that is a
management-plane question the application cannot see or influence.

The identity itself is minimal — verified: exactly one role assignment
subscription-wide (Storage Blob Data Contributor at *container* scope), and the
app registration holds **no application permissions**. So the assertion buys
client authentication and nothing else; every Graph call still requires a
signed-in operator's delegated token.

The blast radius is therefore not the identity's permissions. It is the set of
principals who can attach it to compute they control, and that set is
**8+ Owner/Contributor principals including three standing `#EXT#` guest Owners
at the tenant root**. The same principals can replace the container image on a
process holding live operator sessions.

**Not mitigated in this repository, and not mitigable here.** It is tenant
governance: remove standing external Owners, or accept that the hosted trust
boundary includes them. Stated so the FIC's security story is not read as
stronger than it is.

---

## 6 · The batch, and why it adds no boundary

Batch mode looks like new surface and is deliberately not. The rows — the
subject columns included — are parsed by the operator's browser from a file
that is never uploaded, live in page memory for the session, and execute
through the same per-case endpoints as the single flow, two at a time. Every
step therefore inherits the session gate, the role check, the audit record,
the correlation id and the operation metric that already existed; there is no
server-side batch queue, no batch file handling, and no persistence of a row
anywhere. A failed row replays from its failed step using ids it already
holds, so a retry never repeats a Graph write that succeeded.

The one server-side addition is `/api/batch/validate`: reference and
received-date rule checks by the same code that enforces them at creation.
Its rows accept exactly those two keys — a subject column arriving there is
refused loudly, not ignored — and the row count is capped. It makes no Graph
call and creates nothing. *Enforced by test.*

## Not mitigated, and said plainly

| Threat | Why not | Compensating |
|---|---|---|
| **Token theft from process memory** | Sender-constrained tokens (DPoP, mTLS, Entra PoP) are unavailable — MSAL's public-client PoP needs a broker, and there is none in a Linux container. `doctor` asserts this rather than assuming it | **In-memory only, never serialised** is the control the application provides. The rest is tenant policy and must be checked, not assumed: phishing-resistant MFA, a sign-in frequency, and Conditional Access scoped to the applications are only compensating controls where the tenant actually enforces them. Whether the STS agreed to CAE (`cp1`) is observable per sign-in via `cae_negotiated`; where it reports false, do not claim near-real-time revocation |
| **A malicious operator** | They already hold the Purview permissions. The tool grants nothing they lack | The audit trail records what they did, and it is tamper-evident |
| **A compromised operator endpoint** | Out of scope for an application control | Conditional Access device compliance, where the tenant enforces it. Note that Conditional Access cannot target a public client, so on the desktop this can only be applied tenant-wide to the user |
| **Under-disclosure from a bad query** | A correctness risk with compliance consequences, not a security one — but the sharper edge in practice. `kind:email` silently zeroes the site count | The query is shown and editable before anything runs; a narrowing applies to both queries by default, and both are scanned for mail-item clauses so a one-sided narrowing is named before the run; templates carry cautions, are marked *mailbox only* where a clause excludes site content, and are compiled in at build time so every template is reviewed before it can shape a search |
| **Purview RBAC being wrong** | Not ours to fix | Stated, not hidden |

---

## Changes that would reopen this

Each of these would invalidate a claim above and needs a fresh review:

1. Requesting the eDiscovery **download** resource — removes the central claim.
2. Adding a **twelfth operation**, particularly preview or content.
3. Persisting a **token** anywhere, including "just a cache".
4. Adding a **durable local store** of case data — the defect this project exists to fix.
5. Recording **subject identifiers or KQL** in the audit trail.
6. **Deploying hosted mode**: it adds an internet-facing endpoint and
   server-side sessions holding delegated tokens for multiple operators, so a
   deployment of it warrants a review against the hosted sections above.

---

## Reviews

A security review runs before any change to the surfaces above is finalised.
The review working documents are maintained privately; every finding they
raised is either closed by a test named in [`CLAIMS.md`](CLAIMS.md) or stated
in this document as an accepted residual.
