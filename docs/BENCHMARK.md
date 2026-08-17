# Measuring the productivity claim

The claim this tool exists on is that a small privacy team establishes a
defensible Purview DSAR search with materially less operator effort than
through the native portal. That claim must be measured or it must not be
made, and this document is the method. It contains no results until a
measured baseline exists; an invented savings figure would be worse than
none.

## The two clocks, kept apart

**Active operator time** is what the practitioner spends navigating, typing,
reviewing and retrying. It is the only number this tool claims to reduce.

**Backend elapsed time** is what Microsoft spends creating the case, running
the estimate and preparing results. It belongs to Purview, it is the same
work whichever surface asked for it, and no reduction in it is claimed. Any
comparison that blends the two flatters the tool with time it did not save.

Every captured field is one or the other, never a mixture:

| Field | Clock | Meaning |
|---|---|---|
| `active_ms` | operator | Time on the form minus time spent inside requests |
| `interactions` | operator | Buttons pressed and fields used, counted per workflow |
| `templates_applied` | operator | Distinct reviewed narrowings applied |
| `case_create_ms` | backend | Case creation round trip |
| `expand_ms` | backend | Identity resolution round trip |
| `searches_submit_ms` | backend | Creating and starting both searches |
| `first_estimate_ms` | backend | Submission to the first complete estimate |
| `both_estimates_ms` | backend | Submission to both estimates complete |
| `naive_estimate_s` | backend | Purview's own naive-estimate duration, from the operation's timestamps |
| `expanded_estimate_s` | backend | The same for the expanded estimate |
| `total_ms` | both | Form entry to both estimates complete |

Two of those deserve a note. `first_estimate_ms` and `both_estimates_ms` are
the browser's view and are quantised by its sixty-second poll;
`naive_estimate_s` and `expanded_estimate_s` are read from the Purview
operation's own `createdDateTime` and `completedDateTime`, so they are exact.
Where the two disagree, the seconds figures are the estimate's truth and the
milliseconds figures are the operator's experience of waiting for it —
both are real, and they answer different questions. One provenance caveat:
the two seconds fields are read from Graph server-side but travel to the
store via the browser's one-shot post, so unlike the per-operation events
below they pass through the client on the way. Bounded integers either way;
a benchmark quoting them as evidence should say "client-echoed" rather than
"server-observed".

The server also records one event per Graph mutation it performs — operation
name from a fixed set (`case_create`, `search_create`, `estimate_start`),
duration and outcome, nothing else. Unlike the workflow summary these cover
every attempt, including failures and abandoned flows, so the failure rate
and the retry cost are measurable rather than remembered.

## What is captured, and what cannot be

Capture is off by default. With `DSAR_METRICS=1` set, the browser posts one
summary per completed workflow to the local instance, which appends it to
`~/.dsar/metrics/metrics.jsonl`, owner-only. The server holds every event to
an allowlist of bounded integers: no reference, no subject value, no query
text, no free text of any kind survives, and one stray field refuses the
whole event. The register rows INV-81 to INV-83 in [CLAIMS.md](CLAIMS.md)
name the tests that keep this true. The store is deliberately separate from
the audit trail: the trail is evidence, timings are telemetry, and one file
doing both jobs would weaken the claim the trail makes.

Only a flow that reaches both complete estimates posts an event, so the store
measures finished work; an abandoned form simply never reports. That is
client behaviour, not a server guarantee — the server's guarantees are the
allowlist and the opt-in gate, and those are the ones held by tests.

## The scenarios

Each run establishes one case with both searches estimated, for a fictional
subject in a non-production tenant. Four scenarios, covering the shapes
routine DSAR work actually takes:

1. **Plain** — primary address only.
2. **Aliases** — primary address plus two supplied aliases and one other
   address.
3. **Former name** — as (2), plus a former name.
4. **Narrowed** — as (2), plus one reviewed template applied to both queries.

## The portal arm

The same scenarios, driven through the Microsoft Purview portal by a human
with a stopwatch, recording per run: active operator time (pause the watch
while Purview processes), a count of clicks and fields, and the backend
waits separately. The operator should be practised in both surfaces before
measurement starts; the comparison is between tools, not between a rehearsed
flow and a first attempt.

## Sample size and reporting

At least twenty runs per arm across the scenarios before any figure is
quoted. Report median and p90 active operator time, median interaction
count, and the backend waits separately and clearly labelled as Microsoft's
time. Report the environment: tenant type, tool version, portal date —
the portal changes without notice, so a portal baseline carries its date or
it carries nothing.

Export the tool arm's aggregate:

```bash
uv run dsar metrics export
uv run dsar metrics export --json
```

## Reproducing

Anyone with a test tenant can reproduce both arms: install a pinned release,
set `DSAR_METRICS=1`, run the scenarios, export; then run the same scenarios
through the portal with a stopwatch. No production DSAR data is required,
and no subject data leaves the machine either way.

## Results

No baseline has been published yet. When one exists it will state sample
size, medians, p90s, interaction counts, environment and tool version, and
it will not attribute Microsoft's processing time to this tool.
