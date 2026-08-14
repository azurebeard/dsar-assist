# Threat model

**Date:** 2026-08-14 · **Scope:** Phases 0–4 as built (desktop mode). Hosted
mode is designed and unbuilt; its threats are marked and deferred to B-03.

Method: STRIDE over the trust boundaries, with each mitigation named as either
*enforced* (a test or a control proves it), *inherited* (Microsoft's, not ours),
or *accepted* (a stated trade). Findings already closed cite their review.

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
Absent counts as a mismatch. `/auth/logout` was the one exception and is now
covered (WS10 SEC-L-05). *Enforced.*

**Repudiation.** Sign-in, sign-out, case creation, expansion, search creation,
estimate and export are recorded with actor `oid`, the token's `uti`, and a
hash chain. Refusals are recorded too — a trail holding only successes
describes a system where nobody is ever turned away. *Enforced.*

**Information disclosure.** `textContent` throughout, never `innerHTML` — a
rule the front end had stated in a comment and nothing enforced until a
structural test was added and proven by tampering. CSP `default-src 'none'`, no `unsafe-inline`. `/healthz`
discloses no tenant, and withholds the version when hosted. A 500 returns a
21-byte body — no traceback, no exception type, no path (verified). *Enforced.*

**Denial of service.** `/auth/login` is unauthenticated and allocates server
state: rate-limited 10/min, and the pending-flow store now **refuses** rather
than evicting, so one caller cannot cancel another's in-progress sign-in
(OWASP A04-02). API limited 120/min per operator, and a request body capped at
64 KiB — rate limiting bounds how many requests arrive, not how large one is,
and nothing else in the stack capped it. The body is read *after* the session
check, so an anonymous POST is refused without being buffered. *Enforced.*

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
segments are validated and, since WS10 SEC-H-02, cannot contain a dot-segment
or percent-encoding — `caseId=".."` previously resolved to
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
`User.Read.All`; `doctor` proves at runtime that no download scope is present.
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
> Analytics, a different trust domain. On the desktop there is no second copy.
> **Accepted** for desktop; the append-blob sink with a WORM policy is B-03.

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

## Not mitigated, and said plainly

| Threat | Why not | Compensating |
|---|---|---|
| **Token theft from process memory** | Sender-constrained tokens (DPoP, mTLS, Entra PoP) are unavailable — MSAL's public-client PoP needs a broker, and there is none in a Linux container. `doctor` asserts this rather than assuming it | In-memory only, never serialised; `cp1` so an admin revoke lands in minutes; phishing-resistant MFA so a stolen refresh token cannot be re-minted on a new device; short session |
| **A malicious operator** | They already hold the Purview permissions. The tool grants nothing they lack | The audit trail records what they did, and it is tamper-evident |
| **A compromised operator endpoint** | Out of scope for an application control | Conditional Access device compliance (B-05), which is the decision still open |
| **Under-disclosure from a bad query** | A correctness risk with compliance consequences, not a security one — but the sharper edge in practice. `kind:email` silently zeroes the site count | The query is shown and editable before anything runs; a narrowing applies to both queries by default, and both are scanned for mail-item clauses so a one-sided narrowing is named before the run; templates carry cautions and are marked *mailbox only*; B-02 was parked to build-time JSON so a template gets reviewed before it can shape a search |
| **Purview RBAC being wrong** | Not ours to fix | Stated, not hidden |

---

## Changes that would reopen this

Each of these would invalidate a claim above and needs a fresh review:

1. Requesting the eDiscovery **download** resource — removes the central claim.
2. Adding a **twelfth operation**, particularly preview or content.
3. Persisting a **token** anywhere, including "just a cache".
4. Adding a **durable local store** of case data — the defect this project exists to fix.
5. Recording **subject identifiers or KQL** in the audit trail.
6. **Hosted mode** (B-03): adds an internet-facing endpoint and server-side sessions holding delegated tokens for multiple operators. Designed, unbuilt, unreviewed.

---

## Reviews

`WS10-review-2026-08-14.md` (Phase 0) · `WS10-review-phases1-4-2026-08-14.md` ·
`OWASP-top10-2026-08-14.md` · `WS10-review-comparability-2026-08-14.md`. Every finding across all three is closed; the open
items are in `BACKLOG.md`.
