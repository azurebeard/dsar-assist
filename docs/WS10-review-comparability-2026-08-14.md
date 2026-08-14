# WS10 Security Review — query comparability

**Date:** 2026-08-14 · **Scope:** the delta since `194102e`
**Verdict:** **APPROVED** — two findings raised and closed during the review,
two residuals stated below and carried to the backlog.

Reviews the change that stops a one-sided narrowing being reported as an
identity-expansion delta. Prior reviews (`WS10-review-2026-08-14`,
`WS10-review-phases1-4-2026-08-14`, `OWASP-top10-2026-08-14`) remain the
baseline; only the deltas are assessed here.

---

## What changed

| File | Change |
|---|---|
| `identity/query_templates.json` | `mailbox_only: true` on `workload` and `attachments` |
| `identity/templates.py` | `QueryTemplate.mailbox_only`, parsed and defaulted false |
| `web/api.py` | `mailbox_only` added to the `/api/templates` projection |
| `web/static/app.js` | Per-query narrowing tracking; apply to both queries or one; `renderComparability()`; mail-item clause scan on input |
| `web/static/index.html` | `#comparability` warning region; guidance on the templates panel |
| `web/static/style.css` | `.button.subtle`, adjacent-button spacing |
| `.github/workflows/ci.yml` | `node --check` on `app.js` |
| `web/app.py` | `MAX_BODY_BYTES`, `_read_capped_body`, 413 on oversize |
| `tests/` | `test_templates.py` (18 new); 4 new in `test_web.py`; 1 in `test_structural.py`; 2 in `test_hardening.py` |

**No endpoint was added. No Graph operation was added. No scope changed.** The
operations table is still eleven rows and the requested scopes are unchanged.

---

## Assessment

### Does it weaken the no-data-plane claim?

**No.** Nothing here reads, requests or transports item content. The change is
entirely about how two counts are described. `T-02`'s scan for
`MicrosoftPurviewEDiscovery` and the eleven-row operations assertion both still
pass, and the runtime scope check in `doctor` is untouched.

### Injection

`mailbox_only` is a boolean read from a file in the repository and consumed as
a boolean. It reaches no query, no path segment and no header.

The mail-item scan is a **read-only regular expression over a textarea's
value**. It builds nothing and sends nothing. `replace(/"[^"]*"/g, '""')`
operates on a local copy, and neither textarea is written by it — so the query
the operator sees and the query that runs are still the same string, taken from
the request and never regenerated (`_create_search`).

Backtracking was considered: both patterns are linear with no nested
quantifier. They run in the browser, on a string the operator typed, and cost
that operator's own tab.

### Cross-site scripting

Every new value reaches the DOM through `setText` (`textContent`) or
`el(tag, text, class)`, which also assigns `textContent`. `nameOf()`
interpolates `template.name`, which originates in a repository file served
through the API, and is still rendered as text.

**One finding, raised and closed during this review.** `app.js` opens by
declaring *"textContent, never innerHTML"* — and nothing enforced it. That is
the shape of SEC-H-02: a comment asserting a guarantee the code does not
provide, which survived two readings and a passed review in the predecessor.
Closed by `test_the_front_end_never_assigns_html`, an AST-free line scan over
`static/*.js` for `innerHTML`, `outerHTML`, `insertAdjacentHTML` and
`document.write`, with the forbidden literals assembled at runtime so the
scanner does not match itself.

**Verified by tampering, not by reading.** A line assigning `innerHTML` was
appended to `app.js`; the test failed naming `app.js:858`; the file was
restored and it passed. A guard nobody has watched fail is a guard nobody
should trust.

### Request body size — second finding, raised and closed

Checking the sentence *"bounded by the server's existing query length limit"*
found there was no such limit. `request.json()` buffers whatever arrives,
uvicorn imposes no body cap, and rate limiting bounds how many requests arrive
rather than how large one is — so the ceiling on a single authenticated POST
was the process's available memory.

Closed by `MAX_BODY_BYTES` (64 KiB) and `_read_capped_body`, which counts while
streaming rather than trusting `Content-Length`: a chunked request sends none,
and one that does send it can be lying. Over the cap returns **413**.

Severity is low and stated as such: the read happens **after** the session
check, so an anonymous POST is refused without its body ever being buffered.
This bounds an authenticated operator, a hostile tab in their browser, and — on
a shared hosted instance — one operator's effect on another. That last case is
the same neighbourhood as **B-06**.

Both properties are asserted: the cap by feeding `_read_capped_body` a real
chunked Starlette request either side of the limit, and the ordering by
asserting the session check appears before the read in `api()`.

### Request volume and rate limiting

"Apply to both queries" issues **two** `/api/template/apply` calls where there
was one. `/api/template/apply` performs no Graph call — it renders a string —
and sits under the existing 120/min per-operator API limiter. Doubling a
manual click is not a meaningful change to that budget, and the 5-second poll
floor on `/api/case` is untouched.

The calls are sequential, not concurrent, so a partial failure is reported
naming which query was already narrowed. A partial application reported as a
plain failure was the alternative, and it silently diverges the two queries —
the defect this change exists to prevent.

### Audit trail

**Unchanged, and deliberately.** `render_template` still logs the template id
and never the values; the id is a category, the values are the most
identifying thing in the tool. No new record type, no new field, and nothing
in this change can put a subject identifier or KQL into the trail. The
structural test asserting that still passes.

### Authorisation

No new decision. The templates endpoint is a read of a shipped file requiring
only a session, as before. `mailbox_only` is advisory to the operator, not a
permission.

### Availability

The `input` listener runs two regular expressions per keystroke on a bounded
string. No timer, no network call, no allocation that survives the handler.

---

## Residuals

**R-1 · The warning is advice, not a control.** It never refuses a run. That
is deliberate — narrowing one side is a legitimate thing to want, and a tool
that refuses it teaches the operator to work around it — but it means an
operator who ignores the banner can still start two searches that are not
comparable. Compensating: the banner sits directly above the run button, the
queries are visible and editable, and the counts are reported per search rather
than only as a delta.

**R-2 · The mail-item list is a list, not a parser.** `kind:`, `filetype:` and
`hasattachment:` are the three measured on 2026-08-02. A fourth mail-item
property would not be detected, and the tool does not parse KQL. Stated rather
than implied: this catches the clause that caused a measured inversion, not
every clause that could cause one. A false negative leaves the operator exactly
where they were before this change; there is no state in which it makes the
tool worse.

Both are carried to `BACKLOG.md` as **B-10** rather than closed silently.

---

## Not a finding, but noted

`node --check` in CI closes a real gap: the front end has no build step, so a
syntax error in `app.js` was served as happily as working code and passed the
entire suite, which reads the file as text. That has been true since Phase 0.
It is not a security defect, but "the page half-renders and the security
controls in the second half of the file never bind" is not a comfortable
failure mode for a CSP-dependent front end.

---

## Verdict

**APPROVED.** 237 tests pass, `mypy --strict` is clean over 41 source files,
and the front end parses. No control was removed, relaxed or made conditional.
The change adds a correctness signal to a tool whose sharpest real risk —
recorded in the threat model as *under-disclosure from a bad query* — is
exactly this class of mistake.
