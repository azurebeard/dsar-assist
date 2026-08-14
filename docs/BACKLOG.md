# Backlog

Ordered by what unblocks the most, not by what is most interesting. Items
carried forward from `WS10-review-phases1-4`, `OWASP-top10` and the phase
reviews are consolidated here so they stop living in three documents.

---

## B-01 · Phase 3 — the audit trail ✅ DONE 2026-08-14

Built. Hash-chained JSONL, `dsar audit verify` names the first break by `seq`,
`dsar audit tail` reads it offline with no network and no sign-in. Verified end
to end: an edited record is reported as `altered`, a deleted one produces
`broken link` + `out of order`, and the subject's identity appears nowhere —
only a case-scoped pseudonym.

Original entry below, kept for the reasoning.

**Size:** ~1 day · **Blocks:** the product claim

The largest open gap, and the only one flagged by **both** security reviews.
There is no durable record of who created which case or ran which search — the
evidence exists only in process logs, which do not survive a container restart.

For a tool whose value proposition includes defensibility, this should not
reach a customer engagement without being declared. It was deferred
deliberately to reach the demo; that was the right call and it is still the
right call to close it next.

Design is already settled in the plan: append-only JSONL locally, append blob
when hosted, records chained by `sha256(prev_hash || canonical_json(record))`
so tampering is *detectable* rather than merely prevented. The chain is what
makes it portable — the predecessor enforced append-only with SQLite triggers,
which is a guarantee that cannot travel.

Must exclude, and this is the part to get right: subject identifiers,
`proxyAddresses`, `otherMails`, `employeeId` and the KQL itself. Those are
third-party personal data, and recording them creates a second ungoverned copy
inside the tool built to control that risk. Store a case-scoped pseudonym.

---

## B-02 · Template builder — PARKED, shape decided

**Decision 2026-08-14:** parked as a runtime feature. If custom templates are
wanted, they arrive as **JSON compiled in at build time** — a file in the repo,
reviewed and shipped with the image.

That is a better shape than the runtime builder analysed below, for two reasons
the analysis surfaced:

* **It deletes the persistence problem outright.** No local file to go missing
  on the second machine, no new Graph consent to justify, no store that exists
  in one mode and not the other. A template ships with the image, so every
  operator running that image has it.
* **It keeps the review gate.** The scope risk below is real — a template that
  narrows too far under-discloses, and under-disclosure is a compliance
  failure. A template arriving through a pull request gets read by someone
  before it can shape a search. A template built at runtime does not.

The cost is that an operator cannot invent one mid-request, which is the right
trade for an artefact that decides what a subject access response contains.

The analysis below is kept because it is what led to that decision, and because
the scope and trust problems still apply to a build-time file.

**Size if revisited:** 2–3 days · **Requested:** 2026-08-14

Let an operator compose their own narrowing, name it, and reuse it — so a
recurring shape of request (employment grievance, third-party disclosure, a
particular regulator's format) becomes one click instead of a rebuild.

Genuinely valuable. Repeatability is what turns a demo into something used
weekly. Three design problems to solve first, and the form is not one of them.

### The hard part is persistence, not the form

The architecture's central property is **no durable local state — Graph is the
source of truth**. That is the defect this project exists to fix. A
user-built template must live somewhere, and every obvious option costs
something:

| Where | Cost |
|---|---|
| Local file | Recreates the original sin. A template built on the laptop is invisible on the Mac, which is exactly the failure that killed the predecessor |
| SharePoint list / OneDrive file | Needs `Files.ReadWrite` or `Sites.ReadWrite.All` — a large consent expansion for a tool whose pitch is a minimal permission set. Hard to justify to the reviewer who approved two scopes |
| Entra extension property on the app | Awkward, size-limited, and puts config in an identity object |
| Azure Table or blob | Works hosted, not on the desktop — so the feature would exist in one mode only |
| **Export / import JSON** | **No new permissions, travels as a file, and can be reviewed before it is trusted** |

**Recommended: export/import JSON first.** The operator builds a template,
exports it, and it travels the way any other artefact does — attached to a
ticket, committed to a repo, sent to a colleague. A tenant-side store can come
later if the file version proves too clumsy, and by then there will be evidence
about which store is worth the consent.

It also answers "patch it back to the app" directly: an exported template is a
JSON object in the same shape as `query_templates.json`, so a good one can be
raised as a pull request and become a built-in.

### The second problem is that templates generate queries

A user-built template is user-supplied query construction. Not a code injection
risk — `compose()` parenthesises both sides and `quote_phrase` refuses anything
that cannot be expressed — but a **correctness and scope** risk, which for a
DSAR is worse:

- A template that widens the search returns material outside the request.
- A template that narrows it **under-discloses**, and under-disclosure is a
  compliance failure rather than a cosmetic one.

We have already met this exact trap: the `workload` narrowing sets `kind:email`,
which drops the site count to zero. A built-in template carries a caution about
it. A user-built one would not, unless the builder makes them write one.

**So the builder must compose from the vetted primitives, not accept raw KQL.**
The five existing builders — `date_range`, `choice`, `phrase_or`, `people_or`,
`filetypes` — are the vocabulary. A user picks one, supplies terms, names the
template and writes its guidance. Raw KQL stays in the editable query box where
it already is, in front of the operator, per-request.

If raw KQL is ever allowed in a saved template, it needs a visible marker on
every query built from it, because a saved query is one nobody reads again.

### The third problem is trust

An imported template is a file from somewhere. It must be shown before it is
used — name, builder, terms, and the exact fragment it will contribute — and
imported explicitly rather than applied on load. Structural validation on
import: known builder, known input kinds, bounded lengths, no unexpected keys.

### Sketch

```
GET  /api/templates              built-in + imported, marked by origin
POST /api/templates/preview      build it, return the fragment, save nothing
POST /api/templates/import       validate and add to the session
POST /api/templates/export       the JSON, for a file or a pull request
```

Session-scoped first. A template that survives sign-out is durable local state
by another name, and that decision deserves its own review rather than arriving
as a side effect.

**Recommendation: after B-01.** A half-built template builder is worse than
none for the demo, and B-01 closes a gap that is already written down in two
security reviews.

---

## B-03 · Phase 5 — hosted mode

**Size:** 2–3 days + the FIC spike · **Blocks:** team use

Confidential client, federated credential, multi-operator sessions, Bicep,
Container Apps. Unreviewed and unbuilt.

The offline half of the FIC unknown is answered — MSAL does send
`client_assertion` on an `authorization_code` grant, lazily, with no secret.
What remains is whether Entra *accepts* a managed-identity-minted assertion for
that grant, which needs a real Container App. Expect `AADSTS700213` or
`AADSTS70021` on refusal rather than a silent fallback.

Requires its own WS10 pass. The Entra/MSAL check area in the Phase 1–4 review
is marked design-only for exactly this reason.

---

## B-04 · Prove CAE is negotiated

**Size:** 1 hour

`cp1` is declared and the authorize request carries it, confirmed in the live
redirect. Whether the STS **agreed** is only readable from `xms_cc` on the
issued token, and it has not been observed.

Until it is: do not claim near-real-time revocation. Declaring a capability and
having it honoured are different things, and the eDiscovery namespace's CAE
behaviour is undocumented either way.

---

## B-05 · Conditional Access, enforced

**Size:** decision, then minutes

CA01 (phishing-resistant MFA), CA04 (session lifetime), CA06 (block device
code) and CA07 (block legacy auth) are designed and not applied.

**CA03 needs a decision from Ben**: requiring a compliant device on the desktop
app will hard-block a container on an unmanaged Linux box, including this
workstation. Recommendation stands — enforce for hosted, leave report-only for
desktop, because the desktop path's value is running wherever the operator is.

---

## B-06 · Session eviction on a shared instance

**Size:** small · **Raised by:** OWASP A04 pass

`SessionStore` evicts LRU at 64. Reaching it needs authentication, so it is not
an unauthenticated denial of service — but on a shared hosted instance an
authenticated operator can evict colleagues. Belongs to the B-03 review, where
the multi-operator model is in scope.

---

## B-07 · Supply chain — SBOM and signing

**Size:** half a day · **Raised by:** OWASP A08

`--sbom` and `--provenance` are documented in the Dockerfile and not produced
by CI; images are unsigned. Deferred deliberately, recorded so the deferral
stays a decision.

---

## B-08 · Distroless evaluation

**Size:** half a day

`python:3.13-slim` was chosen because the diagnostic story is
`docker run --entrypoint dsar <image> doctor` and the hosted operational story
includes console exec — distroless has no shell. The report-only Trivy scan
lists 23 unfixed findings, 4 Critical, all base-image packages with no
available patch. Distroless would remove most of that surface. Re-evaluate
against the cost to diagnosis.

---

## B-09 · Server-side query floor for `/api/case` ✅ DONE 2026-08-14

The floor was on `/api/statistics`, which the UI never calls — it polls
`/api/case`. A limit on an endpoint nobody calls is not a limit. Both are now
covered.

---

## Closed

- Portability — one image plus a `uv` path, verified on three operating systems
- The empty queue — Graph is the source of truth, nothing to copy between machines
- Identity plane — both open questions answered live; `roles` is emitted to a
  public client, and the loopback port is ignored
- Statistics — `partiallySucceeded` handled, locations summed, and the case view
  now actually fetches them
- Path traversal out of the operations table (WS10 SEC-H-02)
- Rate limiting, flow-store eviction, refused-authorisation logging (OWASP A04, A09)
