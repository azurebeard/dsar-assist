# Security Review — DSAR Assist, Phases 1–4

**Artefact type:** Code (identity plane, Graph client, API surface, front end)
**Technology stack:** Python 3.12/3.13 · MSAL · Starlette · httpx · vanilla JS
**Checks applied:** Entra ID / MSAL · Python general · Injection (KQL, OData, path) · Access control · React/JavaScript (vanilla equivalent) · Security logging
**Date:** 2026-08-14
**Reviewer:** WS10 Security Reviewer
**Commits reviewed:** `38c4b02` … `3ad3dcd`

---

## Verdict: **Conditional approval** → **Approved** on remediation

One High and one Low, both closed and both with a regression test. The High is
worth reading even now that it is fixed, because it was inherited from a
codebase that had already passed a security review.

---

## High findings

### SEC-H-02 — The operations allowlist could be escaped by a dot-segment
**Severity:** High · **Status:** RESOLVED
**Location:** `src/dsar/graph/operations.py` — `_SAFE_PATH_SEGMENT`
**Finding:** `case_id`, `search_id` and `operation_id` arrive in an API request
body and are interpolated into a URL template. The guard was
`^[A-Za-z0-9._~%-]{1,256}$`, which permits `..` — and an HTTP client normalises
dot segments before the request is sent. So an authenticated caller could reach
Graph endpoints that are not in the permitted-operations table, through the very
check written to prevent it.

**Evidence** — measured, httpx 0.28:

```
caseId=".."   /security/cases/ediscoveryCases/{caseId}
              -> https://graph.microsoft.com/v1.0/security/cases

caseId=".."   /security/cases/ediscoveryCases/{caseId}/searches
              -> https://graph.microsoft.com/v1.0/security/cases/searches
```

`%2e%2e` also survived the pattern.

**What makes this worth a High rather than a Medium:** the operations table is
*the* structural control in this design. The no-data-plane claim, the
"eleven operations and no more" claim, and the review discipline that says
adding a call must be a visible diff all rest on the premise that no other path
can be reached. That premise was false.

**What limits it:** the caller must already hold an authenticated session, and
the token is delegated — so no request can exceed the operator's own Purview
permissions. The download permission lives on a *different resource* requiring a
different token, so the no-data-plane claim survives intact. This was a breach
of the allowlist discipline, not a data exposure.

**The part that should worry us most:** the module's own comment said

> *"Anything containing a slash, a query or fragment marker, **a dot-segment** or
> whitespace is not an identifier and must not be interpolated into a URL."*

The comment described a guarantee the regex did not provide, and it was
convincing enough that the code was ported into this project unchanged and
re-read twice without anyone testing the claim. **A comment asserting a security
property is not evidence of it.** This was inherited from `8652e638`, which
carried a passed WS10 verdict.

**Reference:** OWASP Top 10 2021: A01 — Broken Access Control · A03 — Injection
· CWE-22 (Path Traversal) · CWE-1286 (Improper Validation of Syntactic Correctness)

**Resolution applied:**
- `%` removed from the permitted character class. Nothing in this codebase
  percent-encodes anything, so a `%` in a value about to be interpolated is an
  encoded separator or a mistake.
- A segment consisting only of dots is refused outright — the property the
  comment always claimed.
- `_is_safe_segment()` replaces the bare regex match, so the rule has one name
  and one place.

**Verified by:** a structural test asserting all fourteen vectors are refused
*and* that a spy client records no request, plus that a real GUID still resolves
— a fix that broke legitimate identifiers would be a denial of service on the
product.

---

## Low findings

### SEC-L-05 — `/auth/logout` accepted a cross-origin POST
**Severity:** Low · **Status:** RESOLVED
**Finding:** Every API POST is origin-checked in one place; `/auth/logout` was
routed separately and was not. A third-party page could force sign-out.
**Evidence:** `curl -X POST -H 'Origin: https://evil.example' .../auth/logout` → `302`
**Why fix a nuisance:** forced sign-out is annoying rather than dangerous, so
this is Low on its own merits. It is worth fixing because every other
state-changing POST enforces the rule, and an unexplained exception is how a
rule stops being trusted and then stops being applied.
**Reference:** OWASP Top 10 2021: A01 · CWE-352 (CSRF)
**Verified by:** a test asserting 403 for absent and foreign Origin, 302 for our own.

---

## Probed and clean

Recorded because coverage is a claim, and an unstated check is an unmade one.

| Surface | Vectors | Result |
|---|---|---|
| **KQL injection** | quote break-out, escaped-quote break-out, NUL, CR, LF, clause injection | All **refused**. Values that cannot be expressed in a phrase are rejected, never escaped — KQL has no portable escape for a quote inside a phrase, so escaping would silently change what was searched for |
| **OData injection** (`find_users` filter) | `' or startswith(...)`, `'--`, NUL, 300-char value | Single quotes correctly **doubled** (the only escape OData defines); control characters and over-long values refused |
| **Path traversal** | 14 vectors | All refused after SEC-H-02; no crafted identifier reaches the client |
| **Write authorisation** | `DSAR.Auditor` and no-roles against create-case, create-search, run-estimate, initiate-export | All four **refused** for both. Enforced server-side in `Workflow._require_write`, not merely hidden in the UI — a button that is not rendered is not a control |
| **Subject data in logs** | full expansion + KQL build with a debug-level capture handler | **Zero** records containing the subject's name, address or any query text |
| **Tokens in responses** | every response construction in `api.py`, `app.py`, `auth_routes.py` | None. The session cookie carries an opaque 256-bit id and nothing else |
| **Session handling** | fixation, replay, expiry | New session id minted at each callback; pending flows are single-use and 5-minute TTL; server-side removal on logout |
| **XSS** | rendering path for subject-controlled values | `textContent` throughout, no `innerHTML` on dynamic values; CSP is `default-src 'none'` with no `unsafe-inline` |
| **Error mapping** | four distinct auth/authorisation failures | Kept distinct — "sign in again", "no eDiscovery role", "policy needs satisfying" and "malformed reference" produce different operator actions and are not flattened |

---

## Observations, not findings

- **`kind:` collapses the site count to zero.** The `workload` template's own
  caution records this, measured 2026-08-02. Applying it to the expanded query
  drops SharePoint content and inverts the delta the demonstration rests on.
  Correctly surfaced in the UI; noted here because it is a *correctness* trap
  with security-adjacent consequences for a DSAR response — under-disclosure is
  a compliance failure, not a cosmetic one.
- **Template narrowings stack.** Applying one twice produced
  `(... AND kind:email) AND kind:email`. Valid, redundant, and for the date
  template two ranges can contradict. Fixed with a Reset control and a
  duplicate guard.
- **CI was red for four commits** and the failure was a stale assertion in a
  shell script duplicating a pytest assertion that had been updated. Process
  finding rather than a code one; the duplication is now labelled with why it
  exists and uses a path that cannot become legitimate.

---

## Checks performed

| Check area | Applied | Result |
|---|---|---|
| Entra ID / MSAL | Yes | Clean — PKCE S256, tenant-pinned authority, `tid` pinned again at validation, ID-token-only claims, access token never parsed, `cp1` declared |
| Access control | Yes | Clean after SEC-L-05; write actions enforced server-side |
| Injection — KQL | Yes | Clean |
| Injection — OData | Yes | Clean |
| Injection — path | Yes | **SEC-H-02**, resolved |
| Session management | Yes | Clean |
| Secrets | Yes | Clean — none in source, none in responses, none in the environment |
| Logging | Yes | Clean — route templates only, no subject data, no query text |
| XSS / CSP | Yes | Clean |
| Dependency scan | Yes | Trivy in CI: zero fixable High or Critical |

---

## Conditions, all met

| Condition | Verified by |
|---|---|
| SEC-H-02 resolved | 14-vector structural test; spy client records no request; real GUID still resolves |
| SEC-L-05 resolved | Origin test: 403 absent, 403 foreign, 302 own |

**155 tests, `mypy --strict` clean, CI green.**

---

## Carried forward

1. **Phase 3 (audit) is not built**, so there is currently no durable record of
   who ran which search. For a tool whose value proposition includes
   defensibility, that gap should not reach a customer engagement without being
   stated plainly.
2. **`xms_cc` still unobserved** — CAE is declared but not proven negotiated.
   Do not claim near-real-time revocation until a token is inspected.
3. **Phase 5 (hosted) is unreviewed** and introduces the confidential client,
   the federated credential and server-side sessions for multiple operators.
   A fresh review is required before it ships.
4. **The lesson from SEC-H-02 generalises.** Two structural tests in this
   repository assert properties by scanning comments and prose. Prefer checks
   that exercise behaviour: this one was found by running fourteen strings
   through the real function, not by reading the regex again.
