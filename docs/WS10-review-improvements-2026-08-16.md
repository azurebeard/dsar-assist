# WS10 Security Review — the improvements delta

**Scope** `main` at `40bdf59`, delta since `6597a28` (five commits: B-02 templates
doc, the statutory clock, the claims register, the audit `case_id` field, the
evidence pack).
**Date** 2026-08-16
**Mode** Read-only. No source, infrastructure, Azure resource or role assignment
was changed. The only file written is this one.

**Baseline** All 350 tests pass (`uv run pytest -q`). `uv run mypy` (the CI
invocation, `src` only) reports *Success: no issues found in 46 source files*.
Numbering continues from the earlier reviews; the highest previously used ids
were `SEC-H-02`, `SEC-M-07`, `SEC-L-05`.

---

## Answering the question that was asked first: is `ADDED_AFTER_V1` sound?

**Yes, for the field it currently holds.** I tried to break it four ways and the
chain caught all four. This is a positive finding and it is evidenced.

```
$ uv run python probe_hash.py
ADDED_AFTER_V1 = ('case_id',)
1 baseline intact: True                                      # v1-era line, key absent entirely
2 add case_id to old record      -> intact: False ['altered'] # false attribution
3 clear case_id on new record    -> intact: False ['altered'] # de-attribution
4 change case_id on new record   -> intact: False ['altered'] # re-attribution
5 delete case_id KEY on new rec  -> intact: False ['altered'] # not just blanking
```

The asymmetry is real and it is the right way round: *absence* is free, *presence*
is bound. There is no key/value confusion between two late-added fields either —
`canonical_json` includes the key name, so moving a value from `case_id` to a
hypothetical second field changes the digest:

```
   body with case_id=X : {"case_id":"X","seq":1}
   body with note=X    : {"note":"X","seq":1}
   collide: False
```

The measurement that motivated the design is confirmed: without the rule, adding
the field would have made every pre-existing record verify as `altered`. The fix
does not weaken the chain. Two narrower concerns are recorded as `SEC-L-06` and
`SEC-L-07` below.

---

## Findings

### SEC-H-03 — `dsar audit evidence --json` does not honour the tampered-trail refusal

**Location** `src/dsar/audit/report.py:run_evidence` / `_evidence_json`;
claimed by `src/dsar/audit/evidence.py` module docstring and by `docs/CLAIMS.md`
INV-68; supposedly enforced by `tests/test_evidence.py::test_a_tampered_trail_yields_no_trustworthy_extract`.

**Finding** `evidence.py` states: *"If the whole chain does not verify, the pack
refuses to present a clean extract."* The human renderer implements this — it
prints `REFUSED` and returns before any content. The `--json` renderer does not.
`_evidence_json` serialises `events`, `searches`, `actors` and `subject_refs`
unconditionally, and `run_evidence` prints it whole and then sets the exit code.
A caller who runs the machine-readable form on a tampered trail receives the full
extract with `"trustworthy": false` buried in it.

The registered enforcement does not test this. It asserts `pack.trustworthy is
False` and that breaks exist — properties of the dataclass, not of either output
path. `test_the_exit_code_follows_the_chain` asserts only `run_evidence("c") == 1`.
Neither test invokes `as_json=True`, and no test asserts that any renderer
withholds anything.

**This is the seventh instance of the project's recurring defect**, and it is the
one the register itself was created to prevent: INV-68 is a stated guarantee
whose named check does not check it.

**Evidence** Built a ten-record trail, edited `detail` on the export record in
the JSONL, then ran both renderers:

```
--- human rendering ---
REFUSED. The audit trail does not verify: 10 record(s), 1 break(s). First at seq 7 ...
No extract is presented. A trail that has been altered cannot
produce trustworthy evidence about part of itself.
exit: 1

--- --json rendering ---
exit: 1 trustworthy: False
events emitted despite refusal: 9
actors emitted: ['op@x.test']
searches emitted: 1
```

**Recommendation** Make the refusal a property of the pack, not of one renderer.
Either return early in `run_evidence` before the `as_json` branch, or have
`_evidence_json` emit only `case_id`, `source`, `trustworthy` and `chain` when
`not pack.trustworthy`. Then add the test INV-68 is supposed to have: assert that
**both** renderings of a tampered trail contain no event, actor or search. Until
that test exists, INV-68 should read `open — B-nn`.

---

### SEC-H-04 — the evidence pack merges same-named searches and emits a fabricated row

**Location** `src/dsar/audit/evidence.py:_searches`; reachable from
`src/dsar/web/api.py:_create_search` (`name = ctx.text("name") or default_name`).

**Finding** `_searches` keys on the search *name*. Its docstring justifies this:
*"Two searches with the same name in one case would merge; the tool names them
'Naive' and 'Expanded', so that is a documented limit rather than an unnoticed
one."* Neither half of that justification holds.

1. The name is **not** always the tool's. `/api/search/create` accepts a caller-
   supplied `name` and uses it verbatim, unvalidated. The UI does not send one,
   but the endpoint is the control — `api.py`'s own words: *"A button that is not
   rendered is not a control; the endpoint is still there."*
2. Even when the tool does name them, `NAIVE_SEARCH_NAME` and
   `EXPANDED_SEARCH_NAME` are **constants**. Nothing prevents running the
   workflow twice against one case, and nothing makes `_create_search`
   idempotent. Two legitimate expanded searches on one case therefore collide on
   the ordinary path, with no adversary involved.

The consequence is worse than "merged". `entry["search_id"]` and
`entry["created_at"]` are overwritten by the later record while
`entry["export"]` is retained from the earlier one, so the pack emits a single
row that attributes the first search's export to the second search's id — at a
timestamp *before* that search was created. The first search's id disappears
from the artefact entirely.

**Evidence** Trail with two searches both named `Expanded` (`search-A` created,
estimated and exported; `search-B` created and estimated):

```
searches in pack: [('Expanded', 'search-B', created 2026-08-16T10:00:09, export 2026-08-16T10:00:07)]
search ids actually in the trail: ['search-A', 'search-B']
```

An export recorded two seconds before the search it is attached to was created.

**Recommendation** Key on the search id where one exists and fall back to the
name only for the `attempted` record that precedes it — i.e. resolve
`attempted -> ok` by nearest-preceding-unmatched rather than by name, and emit
one `SearchRecord` per distinct `target_id`. If the name key is kept for now,
never overwrite a populated `search_id`, and mark the entry `ambiguous` so the
pack says so. Also add a register row for it: a DPO-facing artefact that under-
reports the number of searches is a disclosure defect.

---

### SEC-H-05 — an accepted received date can make `/api/requests` return 500 for every operator, permanently

**Location** `src/dsar/web/api.py:_received_date` and `_deadline_json`;
`src/dsar/cases/deadline.py:due_date`; `src/dsar/web/app.py:176`.

**Finding** `_received_date` applies no range bound. `date.fromisoformat` happily
returns `9999-12-31`. `due_date` then computes `year = 9999 + 1` and calls
`date(10000, 1, 31)`, which raises `ValueError`. `handle()` catches
`InvalidReference` (a `ValueError` subclass) but not bare `ValueError`, and
`app.py` wraps the `handle(...)` call in no try/except — so the exception escapes
to Starlette as a 500.

`_deadline_json` is called from `_requests` for **every case in scope**. One case
created with a far-future received date therefore breaks the request list for
every operator who can see it. There is deliberately no `update_case`, so the
only remediation is editing the description in the Purview portal — the tool
cannot fix what the tool accepted.

**Evidence**

```
due_date(9999-12-31)   -> ValueError year 10000 is out of range
parsed received: 9999-12-31
_deadline_json         -> ValueError year 10000 is out of range
```

`grep -nE "except" src/dsar/web/app.py` shows no handler around line 176.

**Recommendation** Bound the accepted range in `_received_date` — a DSAR cannot
have been received in year 1 or year 9999. Something like *not before 2018-05-25
and not after today* is defensible and is itself a correctness control (a receipt
date in the future is always an error). Independently, make `due_date` total:
either clamp or raise a typed error that `handle()` maps to 400, and give
`_deadline_json` the same "degrades to not recorded" behaviour that
`decode_received` already has, so a bad stored value cannot take the list down.

---

### SEC-M-08 — `_MARKER_LINE` is quadratic over an unbounded, persistently stored input

**Location** `src/dsar/cases/received.py:_MARKER_LINE`, called from
`cases/model.py:parse_case` for every case in every `/api/requests` response.
`description` reaches Graph unvalidated from `web/api.py:258`.

**Finding** No ReDoS in the exponential sense — there is no nested quantifier and
no ambiguous alternation. But `re.MULTILINE` gives one start position per line,
and at each one `^\s*` greedily consumes the remaining whitespace before failing
on the literal. That is O(n) per line over O(n) lines. Measured, it is exactly
quadratic:

```
n=  1000 newlines =    3.215 ms
n=  2000 newlines =   12.830 ms   (4x)
n=  4000 newlines =   50.718 ms   (4x)
n=  8000 newlines =  206.432 ms   (4x)
n= 16000 newlines =  824.269 ms   (4x)
n= 32000 newlines =     3.28 s
n= 65000 newlines =    13.46 s
```

Nothing caps `description`. `_create_case` passes `ctx.text("description")`
straight through `encode_received` to Graph; the only ceiling is
`MAX_BODY_BYTES = 64 * 1024`, which buys 13.5 seconds of single-threaded CPU per
decode. The case is then read back on **every** list call by **every** operator,
and with one replica per revision (INV-45) that is the whole service. A tenant
user with Purview portal access can achieve the same by editing a description
directly, without touching this tool at all.

**Evidence** Timings above, produced by calling `decode_received` directly. The
first attempt at this probe with n=200000 exceeded a 120-second timeout, which
is how the behaviour was noticed.

**Recommendation** Cap `description` at `_create_case` (the field is boilerplate
plus operator notes — 4 KiB is generous) and, independently, make
`decode_received` defensive about what comes *back*: it is reading a field a
third party controls. Slice the first ~256 bytes and match the marker there, or
match against `description.split("\n", 8)` rather than the whole blob. The
docstring already says the field is "free text a person can edit in the portal" —
that makes it untrusted input, and it should be bounded before it is parsed.

---

### SEC-M-09 — a received date can be recorded through `description`, bypassing `_received_date`

**Location** `src/dsar/cases/received.py:encode_received` /
`decode_received`; `src/dsar/web/api.py:_create_case`.

**Finding** `encode_received(None, description)` returns the operator's
description unmodified. `decode_received` then searches the whole string for the
first marker line. So an operator who leaves the `received` field blank and puts
`DSAR-Received: 2020-01-01` on the first line of `description` gets a recorded
received date that never passed `_received_date` — and the create response tells
them the opposite.

This is the "parses to a date but is not the one written" case. The marker
placement is correct when a real date is supplied (the tool's line is prepended,
and `.search()` returns the first match, so ours wins). The gap is only in the
`received=None` path, where there is no line of ours to win.

Two consequences. First, the validation in `_received_date` — the thing the
docstring calls a refusal rather than a guess — is optional. Second, the API
response and the list disagree: `_create_case` returns `"received": null` because
`received` is `None`, while `/api/requests` will report a deadline for the same
case.

**Evidence**

```
received=None, operator description -> 'DSAR-Received: 2020-01-01\nreal notes'
   decode_received -> 2020-01-01
parse_case.received = 2020-01-01 | deadline = Deadline(received=2020-01-01, due=2020-02-01, days_remaining=-2388)
lowercase marker in free text -> 1999-12-31        # the IGNORECASE flag widens this
```

**Recommendation** `encode_received` should neutralise any marker-shaped line in
the caller-supplied body — strip it, or refuse the description with a message
naming why. Whichever, the case's `received` must be a function of the `received`
argument alone. Add a test: *a description containing a marker line does not
produce a received date when none was supplied.*

---

### SEC-M-10 — `_received_date` accepts formats its own error message rules out

**Location** `src/dsar/web/api.py:_received_date`.

**Finding** The error text promises `YYYY-MM-DD`. Python 3.11+ `date.fromisoformat`
accepts considerably more, and nothing narrows it:

```
'2026-08-14'                   -> 2026-08-14
'20260814'                     -> 2026-08-14
'2026-W33-1'                   -> 2026-08-10     <-- ISO week date
'0001-01-01'                   -> 0001-01-01
'9999-12-31'                   -> 9999-12-31     <-- see SEC-H-05
'2026-08-14T23:59:59'          -> REFUSED
'2026-08-14x'                  -> REFUSED
```

`2026-W33-1` silently resolving to a date four days from anything the operator
typed is a statutory-date defect, and it is the exact failure mode `deadline.py`
opens by warning about. The UI's `<input type="date">` makes this unreachable
from the browser; the endpoint is still there.

**Evidence** Output above, from `dsar.web.api._received_date` directly.

**Recommendation** Match `^\d{4}-\d{2}-\d{2}$` before calling
`date.fromisoformat`, then range-bound as in SEC-H-05. The message becomes true
rather than aspirational, which is the whole point of the register.

---

### SEC-M-11 — a caller-supplied search name reaches the immutable trail and the DPO pack, and the "no subject data" claim is a schema check

**Location** `src/dsar/web/api.py:_create_search` / `_export`;
`src/dsar/audit/record.py` module docstring; `docs/CLAIMS.md` INV-22, INV-69;
`src/dsar/audit/report.py:_print_evidence`.

**Finding** Three claims stack here and the bottom one does not carry the weight:

* `record.py` says *"What must never be in here. Subject identifiers … The
  subject appears as a case-scoped pseudonym and nowhere else."*
* `evidence.py` and the pack's own "What this does not contain" paragraph say
  *"no subject identifiers … asserted by a structural test."*
* The structural test is `test_the_audit_record_cannot_carry_subject_data`,
  whose docstring is explicit: *"The field names are the control."* It asserts
  over `AuditRecord.__dataclass_fields__`. It says nothing about contents.

`detail` is free text. `_create_search` takes `name` from the request body with
no validation beyond `.strip()`, and `_export` does the same (the UI populates it
from the search's Graph `displayName`, which a Purview portal user can rename).
That value is written to `detail`, hashed into the chain, and — in hosted mode —
lands in an append blob under a 2555-day immutability policy. It is then printed
verbatim in the evidence pack's "Searches", "Refused" and "Every recorded action"
sections.

An operator naming a search `j.smith@corp.com grievance` therefore writes a
subject identifier into the one artefact the design says can never hold one, and
into the one store from which it cannot be deleted for seven years. INV-69's test
(`test_the_pack_never_carries_subject_data`) checks `repr(pack)` for four literal
strings from a fixture; it cannot see this.

**Evidence** `grep -n "ctx.text(\"name\")" src/dsar/web/api.py` returns the
unvalidated assignments in both handlers. `scrub()` in `logging_setup.py` matches
only token shapes — five patterns, all credential-shaped — so nothing filters a
name. `MAX_DETAIL_BYTES = 512` truncates but does not sanitise.

**Recommendation** Constrain `name` the way `reference` is constrained: it is an
operator-supplied label, and `_REFERENCE`'s "permissive about shape, strict about
characters" reasoning applies identically. At minimum bound the length and reject
`@`. Separately, split the claim: INV-22 is a *schema* invariant and should say
so; the *contents* invariant needs its own row and its own enforcement, or an
honest `open — B-nn`.

---

### SEC-M-12 — hostile or careless `detail` can forge sections of the evidence pack

**Location** `src/dsar/audit/report.py:_print_evidence`.

**Finding** Related to SEC-M-11 but a distinct consequence. `detail` is
interpolated into the rendered pack with no control-character handling:

```python
print(f"  {record.ts[:19]}  {who}  {record.detail}")      # Refused
line += f"  {record.detail}"                              # Every recorded action
print(f"  {search.name}")                                 # Searches
```

Newlines and ANSI escapes both survive `build()` — `scrub` passes them through
and the truncation is byte-count only. 512 bytes is ample to forge a section
heading, and the pack is a Markdown-shaped document a DPO is expected to attach.

**Evidence**

```
detail survived scrub()? 'Benign\n\n## Integrity\n\nThe whole audit trail verifies: 999 record(s), chain intact.\n\n## Searches\n\n  Nothing to s ...
newline present in stored detail: True
ANSI escape survives: True
```

The `--json` renderer is safe here — `json.dumps` escapes both.

**Recommendation** Strip or replace control characters in `build()` before the
value is hashed, so the trail never stores them, and defensively in
`_print_evidence` for records already written. `detail` is documented as *"a
human-readable note, not a payload"*; a note has no newlines in it.

---

### SEC-M-13 — the claims register cannot detect four of its own failure modes

**Location** `tests/test_claims_register.py`, `docs/CLAIMS.md`.

**Finding** The register is the project's meta-control, so its blind spots matter
more than most. I mutated `docs/CLAIMS.md` four ways and ran all six register
tests against each. All four passed.

```
0. unmodified                                          rows parsed: 66   failures: NONE
1. INV-68 row de-shaped, names a nonexistent test      rows parsed: 65   failures: NONE
2. INV-68 points at an unrelated real test             rows parsed: 66   failures: NONE
3. INV-68 row deleted outright                         rows parsed: 65   failures: NONE
4. fictional claim INV-99 backed by a real unrelated test  rows parsed: 67   failures: NONE
```

* **(1) is the dangerous one.** `_ROW` requires an exact five-cell pipe shape. A
  row that loses a pipe — a plausible hand edit — silently stops being a row.
  `_rows()` asserts only that the list is non-empty, so 66 quietly becomes 65 and
  the claim it carried is no longer checked by anything, including
  `test_every_named_test_exists`.
* **(3)** A row can be deleted outright. The reverse guard
  (`test_every_structural_test_is_registered`) covers only
  `tests/test_structural.py`; INV-68's test lives in `test_evidence.py`, so its
  row is unprotected.
* **(2) and (4)** are inherent — no test can know whether a test proves a claim —
  but they are worth stating in `CLAIMS.md` rather than leaving a reader to infer
  the register is stronger than it is.

SEC-H-03 is (2) occurring for real, today, unaided.

**Evidence** The run above, executed against a temporary copy of `CLAIMS.md` with
`test_claims_register.CLAIMS` repointed. `docs/CLAIMS.md` was not modified.

**Recommendation** Two cheap additions close (1) and (3):

* assert that the number of parsed rows equals the number of lines matching
  `^\|\s*INV-\d+`, so a de-shaped row fails loudly;
* assert that every `INV-\d+` token appearing anywhere in the file appears in a
  parsed row, and that the set of invariant numbers is append-only against a
  checked-in count or a `git show HEAD~1` comparison.

And extend `test_every_structural_test_is_registered` beyond
`test_structural.py`, or say plainly in `CLAIMS.md` §"How it is enforced" that
the reverse guard covers structural tests only.

---

### SEC-L-06 — `ADDED_AFTER_V1` skips on truthiness, not on presence

**Location** `src/dsar/audit/record.py:_hashed_body`.

**Finding** The predicate is `not value`. For `case_id: str` that is only `""`
and the rule is sound. For any future field it is not:

```
   skipped for '':      True
   skipped for 0:       True
   skipped for False:   True
   skipped for None:    True
   skipped for []:      True
   skipped for {}:      True
   skipped for '0':     False
   skipped for ' ':     False
```

A later `attempt_count: int = 0` or `step_up: bool = False` would be excluded
from the hash whenever it carried its meaningful zero value, and `0`, `False`,
`None` and `[]` would all be indistinguishable to the verifier. The docstring
addresses "what if a value is legitimately empty" for strings and not for types
where falsy is a real answer.

**Evidence** Output above, from `_hashed_body`'s predicate evaluated directly.

**Recommendation** Constrain the rule to strings — assert at import that every
name in `ADDED_AFTER_V1` has annotation `str` and default `""` — or change the
predicate to `value == ""` so a falsy non-string field fails loudly rather than
silently leaving the hash.

---

### SEC-L-07 — unknown JSON keys are dropped before verification, so the verifier attests to bytes it did not read

**Location** `src/dsar/audit/record.py:AuditRecord.from_json`.

**Finding** `from_json` filters the parsed object down to known dataclass fields.
Arbitrary added keys are therefore invisible to `recompute()`, and the record
verifies as intact.

```
8 future field dropped by from_json, self-hash still ok: True
```

Nothing downstream in this codebase reads those keys, so there is no exploit
today. But the trail is explicitly designed to travel ("any sink, any host, one
verifier"), and a consumer reading the raw NDJSON out of the append blob — a
SIEM, a DPO opening the file — sees injected fields that `dsar audit verify`
called intact. The chain's promise is "these bytes are unaltered"; what it
actually checks is "the fields I recognise are unaltered".

**Evidence** Probe result above: an extra key `new_field_v2` added to a record's
JSON line, then reloaded and self-hashed.

**Recommendation** Either reject unknown keys in `from_json` as `malformed` — the
verifier already has that break kind and it is the right answer — or state the
scope precisely in `record.py` and add a register row for it. Rejecting is
cheaper and matches `verify.py`'s existing vocabulary.

---

### SEC-L-08 — the pack's "unattributable" wording is wrong for a present-day refusal

**Location** `src/dsar/audit/evidence.py:_unattributable`;
`src/dsar/audit/report.py:_print_evidence`.

**Finding** `_unattributable` excludes `CASE_CREATED + ATTEMPTED` because a case
has no id before it exists. It does not exclude `CASE_CREATED + DENIED`, which
`workflow._require_write("Creating a case", Action.CASE_CREATED)` writes with no
`case_id` for the same reason — the case never existed.

Such a record is counted as unattributable, and the pack then tells the reader
*"Records written before case attribution existed cannot be attributed to any
case."* That is a factual statement about a record written this morning, and a
DPO reading it will draw the wrong conclusion about when the trail changed.

**Evidence** `src/dsar/cases/workflow.py:143` passes no `case_id` to
`_require_write` for case creation; `_unattributable`'s exclusion list in
`evidence.py` names only `(CASE_CREATED, ATTEMPTED)`.

**Recommendation** Exclude `CASE_CREATED` with *any* outcome that precedes the
case existing (`ATTEMPTED` and `DENIED`), and soften the sentence to *"cannot be
attributed to a case"* without asserting when they were written.

---

### SEC-L-09 — the new inputs and the new artefact are absent from the threat model

**Location** `docs/THREAT-MODEL.md`.

**Finding** `git diff 6597a28..HEAD -- docs/THREAT-MODEL.md docs/DESIGN.md` is
empty, and `grep -Ei "description|received|deadline|statutory" docs/THREAT-MODEL.md`
returns nothing. This delta adds a parsed input from Graph that any Purview
portal user in the tenant can control (`description`), a new operator-supplied
field on a mutating endpoint (`received`), and a new output artefact intended to
leave the organisation (the evidence pack). None is represented.

SEC-M-08, SEC-M-09 and SEC-M-11 all follow from the first of those — reading a
third-party-editable field back as structured data is a trust-boundary crossing
the model does not currently describe.

**Recommendation** Add `description` to the threat model as untrusted input with
the two controls that will exist after SEC-M-08 and SEC-M-09 (bounded before
parse; marker neutralised on write), and add the evidence pack as an egress
surface with its own "what may appear in it" statement.

---

### SEC-L-10 — README's "six query templates" is a count with nothing checking it

**Location** `README.md` (new "Narrowing a search" section);
`tests/test_templates.py::test_the_shipped_definitions_load` asserts `>= 6`.

**Finding** The delta's own new prose asserts a number no test pins. A seventh
template would leave the README wrong. Trivially, but this is the defect shape
the same commit introduces `docs/CLAIMS.md` to eliminate, and it appears three
paragraphs above the link to it.

**Evidence** `assert len(templates) >= 6` in `test_the_shipped_definitions_load`;
README: *"Six query templates ship with the tool"*.

**Recommendation** Either write "several" / "the shipped set", or tighten the
assertion to `== 6` and add a register row. The bidirectional builder tests
(`test_every_builder_is_documented` / `test_every_documented_builder_exists`) are
a good model and are the strongest new tests in this delta — the count claim is
the one thing they do not cover.

---

## What I checked and found clean

* **The `ADDED_AFTER_V1` hashing rule** — sound for `str` fields; all four tamper
  directions detected; no key/value confusion with a hypothetical second field.
  See the section above. `SEC-L-06` and `SEC-L-07` are about future-proofing and
  scope-of-claim, not about a present break.
* **`_MARKER_LINE` is not exponentially backtrackable.** No nested quantifier, no
  ambiguous alternation. The problem is quadratic and input-size-driven
  (`SEC-M-08`), which is a different fix.
* **The marker cannot lose to a later forgery when a real date was supplied.**
  `encode_received` prepends and `decode_received` takes the first match, so
  `encode_received(date(2026,8,14), "DSAR-Received: 2020-01-01\nnotes")` correctly
  decodes to `2026-08-14`. Verified.
* **No unescaped rendering anywhere in the new front end.** `dueCell` and the
  received column both go through `el()`, which uses `textContent`; INV-53's test
  enforces this repo-wide. The `{raw!r}` echo in `_received_date`'s error message
  reaches the DOM as text only, and is bounded by `MAX_BODY_BYTES`.
* **`_requests` reads `today` once per response**, so a list cannot straddle
  midnight. The `CaseService` cache holds `received` as a `date` and the deadline
  is recomputed per request — no staleness.
* **The evidence pack emits no subject data of its own.** `subject_ref` is the
  HMAC pseudonym; `uti` is a token identifier, not a token; no query text, no
  identifiers, no content. The leak path is `detail` (`SEC-M-11`), not the pack's
  own projection.
* **`_searches` correctly excludes refusals** from the search list — the fix its
  docstring describes is present and `test_a_refusal_is_not_listed_as_a_search`
  genuinely tests it.
* **The template drift tests are the right shape.** Bidirectional, specific, and
  they would fail on the drift they describe.
* **`verification/probe_case_description.py`** binds `127.0.0.1` only, holds no
  token on disk, and is excluded from the image by `.dockerignore` (`*` with an
  allowlist of `pyproject.toml`, `uv.lock`, `README.md`, `src/`). It imports
  `httpx` and `msal` outside the INV-12/INV-13 choke points, which is correct
  because those tests scan `src/` — worth knowing, not worth a finding.
* **No regression against the earlier reviews.** The delta does not touch
  `graph/operations.py` path construction (SEC-H-02), `audit/blob.py` or the
  replica configuration (SEC-H-01), the registrations (SEC-M-01), session
  handling (SEC-M-04, SEC-M-05, B-06), or the distroless image. `uv run mypy`
  passes on `src` and all 350 tests pass.

---

## Claims in the new documentation I could not verify

* **`docs/CLAIMS.md` INV-68** — *"A tampered trail yields no trustworthy
  extract."* False for `--json`. See SEC-H-03.
* **`docs/CLAIMS.md` INV-69 / `evidence.py`** — *"no subject identifiers …
  asserted by a structural test."* The structural test asserts field names. See
  SEC-M-11.
* **`evidence.py:_searches`** — *"the tool names them 'Naive' and 'Expanded', so
  that is a documented limit."* The endpoint accepts any name, and the tool's own
  names collide on a re-run. See SEC-H-04.
* **`received.py`** — *"Every failure to parse returns `None`."* True of
  `decode_received`. Not true of the consumer: a successfully parsed far-future
  date raises out of `_deadline_json`. See SEC-H-05.
* **`api.py:_received_date`** — *"the received date must be YYYY-MM-DD."* Four
  other ISO 8601 forms are accepted. See SEC-M-10.
* **`README.md`** — *"Six query templates ship."* Asserted as `>= 6`. See
  SEC-L-10.
* **Not verifiable from here (no live tenant call made, per the read-only
  constraint):** that Graph returns `description` in the `list_cases` projection
  byte-identical, and what length limit `ediscoveryCase.description` enforces.
  `verification/probe_case_description.py` exists to settle exactly this and its
  result is not recorded in the repo. SEC-M-08's bound should not depend on the
  answer, but the storage decision does.

---

## Residual risk accepted

* **Write-once received date.** Correcting it requires the Purview portal. Stated
  in `received.py`, stated in the UI, and consistent with the no-`update_case`
  rule. Accepted — but note it is what makes SEC-H-05 and SEC-M-09 persistent
  rather than transient.
* **No two-month extension, no clock-stop, no working-day roll.** All three named
  in `deadline.py` and surfaced rather than silently modelled. Correct treatment.
* **The register cannot know whether a test proves its claim.** Inherent.
  SEC-M-13 addresses only the mechanical failure modes.
* **An operator with `DSAR.Operator` can already do everything the SEC-M findings
  describe through legitimate use.** These are integrity-of-evidence and
  availability findings, not privilege boundaries. Nothing in this delta weakens
  authentication, authorisation, or the data-plane exclusion.

---

## Verdict

**APPROVED WITH CONDITIONS.**

Nothing in this delta leaks subject data, weakens the token boundary, or breaks
the no-data-plane guarantee. The `ADDED_AFTER_V1` design — the change I was most
concerned about going in — holds under direct attack, and the templates
documentation tests are the best new enforcement in the repo.

The conditions are on the two things this delta newly claims to be evidence:

1. **SEC-H-03 must be fixed before `dsar audit evidence` is described to anyone
   as a defensibility artefact.** A refusal implemented in one of two renderers
   is not a refusal, and `docs/CLAIMS.md` INV-68 currently asserts it is. If the
   fix does not land in this change, INV-68 must be demoted to `open — B-nn`
   before merge; a false row in the register is worse than a missing one.
2. **SEC-H-04 must be fixed or disclosed in the pack itself.** As it stands the
   pack can under-report the number of searches run against a case and emit an
   export timestamped before its search existed, on the ordinary path.
3. **SEC-H-05 must be fixed before the next hosted deploy.** It is a persistent,
   authenticated denial of the primary endpoint with no in-product remediation.

SEC-M-08 through SEC-M-13 should be scheduled, with SEC-M-11 (subject data
reaching a seven-year immutable store through an unvalidated field) the highest
of them on data-protection grounds rather than security grounds.

**The seventh instance of "a stated guarantee with no check behind it" is
SEC-H-03**, and its location is the commit that introduced the register designed
to catch it. That is not an argument against the register — it is the register
working exactly one iteration too late. Adding the assertions in SEC-M-13 would
have caught neither; adding the test named in SEC-H-03's recommendation would
have caught it immediately.
