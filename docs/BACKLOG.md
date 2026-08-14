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

**Built, except the one thing that needs a deployment.** 2026-08-14

| Piece | State |
|---|---|
| `auth/managed_identity.py` — mints the client assertion and the storage token | ✅ 10 tests |
| `msal_client.build_client` — the one place the mode is consulted | ✅ hosted refuses to start without a UAMI |
| `audit/blob.py` — append-blob sink | ✅ 10 tests, same chain and verifier as the file sink |
| `infra/main.bicep` + modules | ✅ compiles; 8 structural tests, each proven by tampering |
| `infra/entra/add-fic.sh` | ✅ idempotent, warns about the case-sensitive subject |
| `dsar doctor` hosted checks | ✅ assertion aud/iss/sub, and the `invalid_client` vs `invalid_grant` probe |
| B-06 session eviction | ✅ see below |
| **The live FIC exchange** | ✅ **proven 2026-08-14** — `invalid_grant`, see `verification/2026-08-14-fic-exchange-live.md` |

### Answered 2026-08-14 — it works

Deployed to `rg-dsar-prod-uks-01` and probed from the container:
`client authentication succeeded`. `invalid_grant`, not `invalid_client`.

Deploying it found two defects that 277 tests, a compiling template and a
clean type check could not: `MSI_SECRET` made hosted mode fail its own health
check on every Container Apps deployment it could ever have had, and the `aud`
guidance pointed at a mismatch that is not one. Both fixed.

The original question, kept for the record:

**Does Entra accept a managed-identity-minted assertion on an
`authorization_code` grant?** The offline half is answered — MSAL does send
`client_assertion` on that grant, lazily, with no secret
(`verification/2026-08-14-fic-assertion-offline.md`). Every Microsoft sample
for federated-credential-by-managed-identity uses `AcquireTokenForClient`,
which is app-only, so this remains unproven by anyone's documentation.

`dsar doctor` answers it in one request that creates nothing: redeem a
deliberately invalid authorization code, and read the refusal.
`invalid_grant` means client authentication succeeded and Entra objected only
to the bogus code. `invalid_client` means it did not.

~~It needs a real Container App and a real UAMI.~~ Done.

Expect `AADSTS70021` for a few minutes after creating the credential — that is
replication, not misconfiguration.

### Still to do

* **Admin consent**, in the portal — `provision.sh` could not grant it
  automatically. Nobody can sign in until it is granted and an app role is
  assigned, which is the design working rather than a fault
* **The append-blob sink has never written a record.** The blob is created on
  first append and there are no records yet, because nobody has signed in
* Two operators signing in concurrently, each as themselves — the
  `prompt=select_account` property, run by hand as well as in CI
* The immutability policy locked, which is irreversible and therefore a human's
  decision rather than a template default
* CA02 and CA11
* A WS10 pass over the hosted attack surface, which is unreviewed

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

## B-06 · Session eviction on a shared instance ✅ DONE 2026-08-14

The store evicted the globally-oldest session to make room. On a desktop that
is one operator and harmless. On a shared instance it means a signed-in
operator opening tabs silently signs out a colleague, mid-case, with no message
either of them can see — a bystander paying for someone else's traffic, which
is the same defect the flow store had.

Two bounds instead of one. **Per principal**, evicting their own oldest, so one
person's habits cost that person. Then a **global cap that refuses**: with
everyone inside their own budget, a full store means genuinely too many people
rather than one person misbehaving, and refusing is visible while leaving every
established session working.

The refusal is a 503 and is written to the trail. A trail holding only
successes describes a system where nobody is ever turned away.

---

## B-07 · Supply chain — SBOM and signing ✅ DONE 2026-08-14

`.github/workflows/publish.yml`: multi-arch build pushed to ghcr.io with an
SBOM and provenance attached to the image, a build-provenance attestation, and
keyless cosign signing — then a verify step, because a signing step nobody
verifies is one nobody would notice breaking.

Signs the **digest**, not the tag. A tag can be repointed; signing `:latest`
would sign whatever `latest` means at verification time, which is not a
signature.

**Correction, 2026-08-14.** This was recorded as done before the workflow had
ever succeeded. It failed all three times it ran, at *Attest provenance*:
GitHub's attestation store refuses user-owned **private** repositories, and
this repository is private by policy. The image was built and pushed, but the
steps after it — cosign signing and the verification of that signature — never
ran, so the published `:latest` was unsigned while the workflow claimed
otherwise.

The attestation step is now skipped on a private repository rather than marked
`continue-on-error`, because a security step permitted to fail quietly is
precisely how a Trivy scan came to be recorded as passed without running. The
SBOM and SLSA provenance are still attached to the image by buildx, and the
signature is still cosign's over the digest.

Same lesson as the WS10 verdict in `HANDOVER.md` §7: block a claim on every
check having *executed*, not on the summary line being green.

Fixed alongside it, and the more important half: the launcher's default image
`ghcr.io/azurebeard/dsar-assist:latest` **had never been published**, so
`./dsar up` — the primary documented path — failed for anyone not running from
source. Worse, the launcher preferred Docker on `command -v docker` alone, so
having Docker installed was a *reason the tool did not start*. It now checks
the image is actually pullable and falls back to `uv` with an explanation.
Both runtimes exist so neither is a single point of failure; that had quietly
stopped being true.

---

## B-11 · Six Dependabot pull requests, now honestly evaluable

**Size:** a review each · **Unblocked:** 2026-08-14 · **Four merged**

They were red for a reason unrelated to the bumps. With the secret scan fixed
they are green and can be judged on their merits. `actions/checkout` 4.2.2 →
7.0.1 was confirmed green end to end including the container smoke test.

Two want more than a glance: **mypy 1.20.2 → 2.3.0** is a major bump on a
`--strict` codebase, and **python 3.13-slim → 3.14-slim** needs the runtime
base image digest re-pinned by hand, since the pin is by digest and not by tag
on purpose.

---

## B-12 · WS10 hosted — what is left, and it is all yours

`docs/WS10-review-hosted-2026-08-14.md` · **APPROVED WITH CONDITIONS**.
Everything in code, IaC and provisioning is closed. Four items remain and none
of them can be fixed in this repository.

| # | Item | Why it is yours |
|---|---|---|
| **SEC-M-02** | Conditional Access: phishing-resistant MFA and a sign-in frequency, scoped to both DSAR apps | B-05 arriving. Until then the app's 8h TTL **is** the session lifetime, and the threat model now says so |
| **SEC-M-06** | Three standing `#EXT#` guest **Owners at tenant root** | Any of them can attach the managed identity to compute they control, or replace the image on a process holding live operator tokens. Tenant governance |
| **SEC-M-03a** | Lock the immutability policy | Irreversible — retention can then only be extended, for the life of the account. A go-live gate, and worth recording the date |
| **SEC-M-03b** | Log Analytics retention 90 → 2555 days | A real cost. The second copy currently expires 2465 days before the first |
| **B-04** | Prove CAE is negotiated | One sign-in. Still the only evidence for `cp1` |

---

## Not doing · A combined Auditor + Operator role

**Asked 2026-08-14. Recommendation: no.**

App roles in Entra are **additive**. A user assigned both carries
`["DSAR.Auditor", "DSAR.Operator"]` in the token and nothing "wins" — it only
looked that way because the page showed the effect and not the roles.

`can_write` is `DSAR.Operator in roles`, and reading is unconditional. So
**Operator is already a strict superset of Auditor**: holding both is redundant
rather than contradictory, and a third value would add drift surface across the
registration, `KNOWN_ROLES`, the code and provisioning for no new capability.

The two-role split also encodes a real separation of duties — an auditor who
**cannot** create cases or initiate exports. Collapsing it is the opposite of
what a DSAR tool wants.

⚠️ **One consequence worth knowing.** Assigning `DSAR.Auditor` to someone who
already holds `DSAR.Operator` restricts nothing. Roles add; they do not
subtract. Removing Operator is the only way to make someone read-only.

---

## B-10 · Comparability warning — the two residuals

**Size:** small · **Raised by:** `WS10-review-comparability-2026-08-14`

The banner that says when the delta has stopped meaning what it looks like is
**advice, not a control** — it never refuses a run. Deliberate: narrowing one
side is a legitimate thing to want, and a tool that refuses it teaches the
operator to route around it. But an operator who ignores it can still start two
searches that are not comparable.

And the mail-item list is **a list, not a parser**. `kind:`, `filetype:` and
`hasattachment:` are the three measured on 2026-08-02. A fourth would not be
detected, and this tool does not parse KQL. A false negative leaves the
operator exactly where they were before the warning existed, so there is no
state in which it makes things worse — but it is not the guarantee the banner's
confident tone might suggest.

Revisit if a fourth mail-item property is measured, or if the delta is ever
presented anywhere the queries are not visible beside it.

---

## B-08 · Distroless ✅ DONE 2026-08-14

Adopted. **179 findings → 19; 4 Critical and 19 High → zero**, measured either
side with the same Trivy version and database. The full measurement, the costs
and the two things it broke are in `B-08-distroless-2026-08-14.md`.

The original entry's objection — distroless has no shell, and the diagnostic
story is `docker run --entrypoint dsar <image> doctor` — turned out to be about
the fallback rather than the plan. `doctor`, `--version` and `python -m dsar`
all run in the distroless image, verified. What is genuinely gone is
`docker exec` and the Container Apps console.

Two surprises worth carrying forward. **Size went up**, 215 MB to 226 MB, since
a python-build-standalone interpreter is heavier than Debian's minimal one —
the opposite of the usual claim. And **pip came back**, shipped inside that
interpreter, while the CI check that should have caught it kept passing because
it asked the import system and pip was never in the venv. Trivy found it.

**arm64 remains unproven locally** — this workstation has no binfmt
registration for it, and neither Dockerfile builds arm64 here. CI's multi-arch
job is the check that matters on this change.

---

## B-09 · Server-side query floor for `/api/case` ✅ DONE 2026-08-14

The floor was on `/api/statistics`, which the UI never calls — it polls
`/api/case`. A limit on an endpoint nobody calls is not a limit. Both are now
covered.

---

## Closed

- **Every pull request failed the secret scan** with "Resource not accessible
  by integration". On a `pull_request` event gitleaks asks the API which
  commits the PR contains; the workflow granted `contents: read` and nothing
  else. All six Dependabot bumps were red for a reason unrelated to the bump,
  which is worse than noise — a bump that genuinely breaks something looked
  identical to one that did not. Fixed with `pull-requests: read` (read, never
  write: the job runs pull request content) and confirmed on a rebased PR
- **Publish had never once succeeded** — see B-07 below
- **SEC-H-01 — a rolling deployment ran two audit writers.** `maxReplicas: 1`
  bounds a *revision*; a rolling update runs two, measured at 46s and 37s here.
  Two writers produced duplicate sequence numbers and the verifier read that as
  *"a record was removed or inserted here"* — not two valid chains as the Bicep
  claimed, but one trail reading as tampered, permanently, under a 2555-day
  policy. Closed with a conditional append and a rebuild-on-refusal
- **SEC-M-01 — the no-credentials claim covered one registration and blocked
  neither.** Both are now asserted and both carry an app management policy,
  proven by trying to add a secret to each and being refused
- **SEC-M-04, M-05, L-01, L-05** — account selection bound to the principal,
  logout cookie deletable in hosted mode, a redirect URI for a route that does
  not exist, and a blob listing that ignored its continuation marker
- **The delta reading backwards** — a narrowing applied to one query and not
  the other measured the narrowing rather than the expansion. Measured on
  DSAR-2026-0418a: naive 40 items and one site, expanded 4 and none. Closed two
  ways, because they catch different mistakes: a narrowing now applies to both
  queries by default, and the text of both boxes is scanned for a mail-item
  clause — which is what catches a query pasted in from the Purview query
  builder, the path the click tracking is blind to and the one that actually
  happened
- **`innerHTML` was a rule in a comment with nothing enforcing it** — the same
  shape as SEC-H-02. Now a structural test, proven by tampering
- **No request body cap anywhere in the stack** — found while fact-checking a
  sentence in the review that claimed one existed
- Portability — one image plus a `uv` path, verified on three operating systems
- The empty queue — Graph is the source of truth, nothing to copy between machines
- Identity plane — both open questions answered live; `roles` is emitted to a
  public client, and the loopback port is ignored
- Statistics — `partiallySucceeded` handled, locations summed, and the case view
  now actually fetches them
- Path traversal out of the operations table (WS10 SEC-H-02)
- Rate limiting, flow-store eviction, refused-authorisation logging (OWASP A04, A09)
