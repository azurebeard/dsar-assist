# Query templates

A template is a **narrowing**. It never replaces the query the identity
expansion produced; it is joined onto it with `AND`, wrapped in parentheses so
it cannot change what the query already meant.

Templates are **compiled in at build time** — they live in
`src/dsar/identity/query_templates.json`, ship inside the wheel and the
container image, and are validated when the module is imported. Adding one is a
pull request against that file.

That is the whole mechanism, and it was chosen over a runtime builder
deliberately.

## Why a file and not a form

**A template decides the scope of somebody's subject access response.** One
that narrows too far **under-discloses**, and under-disclosure is a compliance
failure rather than a cosmetic one. A template arriving as a pull request gets
read by a person before it can shape a search. One built at runtime does not.

It also removes a problem rather than solving it: a template built on a laptop
would have to live somewhere, and every option costs something — a local file
recreates the defect this project exists to fix, a SharePoint list needs a
consent expansion that is hard to justify against a two-scope permission set,
and a blob works hosted but not on the desktop. A file in the repository is
present on every machine running that image, because it *is* the image.

---

## The shape

```json
{
  "version": "1.0.0",
  "verified": "2026-08-02",
  "templates": [
    {
      "id": "employment_file",
      "name": "Employment file",
      "purpose": "The vocabulary an employment-dispute DSAR usually turns on.",
      "builder": "phrase_or",
      "verified": "2026-08-02",
      "fixed_terms": ["grievance", "disciplinary"],
      "mailbox_only": false,
      "guidance": "Why an operator would reach for this.",
      "caution": "What it costs them if they do.",
      "inputs": [
        {
          "name": "terms",
          "label": "Additional terms",
          "kind": "terms",
          "required": false,
          "placeholder": "restructure, whistleblowing",
          "help": "Comma or newline separated."
        }
      ]
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable key. The interface tracks which narrowings were applied by it |
| `name` | yes | Shown on the card and in the comparability warning |
| `purpose` | yes | One line: what this is for |
| `builder` | yes | One of the six below. An unknown value fails at import |
| `inputs` | — | What the operator supplies. Omit for a template that takes nothing |
| `fixed_terms` | — | Vocabulary the template always contributes, or — for `choice` and `flag` — the KQL property itself in `fixed_terms[0]` |
| `guidance` | yes in practice | Why reach for it. A test requires `purpose` and `guidance` on every shipped template |
| `caution` | — | What it costs. Required in spirit for anything that narrows sharply |
| `mailbox_only` | — | See below. Drives a warning, so it is a field and not prose |
| `verified` | — | The date this template's KQL was last run against a real tenant |

`inputs[].kind` is one of `date`, `text`, `terms`, `choice`, `filetypes`.

---

## The six builders

Every fragment below is the **real output**, produced by running the builder.

### `date_range`

Two `date` inputs, `start` and `end`; at least one required. Scopes on mail
*and* file timestamps together, because scoping on `sent` alone silently drops
every document in range.

```
((sent>=2026-01-01 AND sent<=2026-06-30) OR (lastmodifiedtime>=2026-01-01 AND lastmodifiedtime<=2026-06-30))
```

### `choice`

The KQL property in `fixed_terms[0]`, the value chosen from the input's own
`options`. A value outside those options is refused — the operator never types
one.

```
kind:email
```

### `phrase_or`

`fixed_terms` plus anything the operator adds, de-duplicated case-insensitively
and quoted. Free-text, so it catches a document *discussing* the subject even
where they were never a participant.

```
("grievance" OR "appraisal")
```

### `people_or`

Splits by shape rather than by asking: an address becomes a `participants:`
clause, anything else a free-text mention. An operator naming the other party
in a grievance should not have to know which KQL property that becomes.

```
(participants:"alex@x.com" OR "Alex Taylor")
```

### `flag`

A literal clause in `fixed_terms[0]` with no operator input at all.

```
hasattachment:true
```

### `filetypes`

```
(filetype:pdf OR filetype:docx)
```

⚠️ **`filetype:` takes a bare token**, so a file extension is the one value
that reaches a query **unquoted** — it cannot be made safe by quoting. It is
allowlisted (`^[A-Za-z0-9]{1,10}$`) rather than escaped, and anything else is
refused. Everything else in a template goes through `quote_phrase`.

---

## `mailbox_only`

`kind:` and `filetype:` are **mail-item properties**: measured against a live
tenant, adding either reduces the SharePoint/OneDrive site count to **zero**,
including on a query that touches multiple sites.

Set `mailbox_only: true` and the interface will:

- mark the template card `· mailbox only`, before the operator clicks it, and
- explain the zero afterwards, so a site count of nothing reads as *the clause
  working* rather than as an empty estate.

It is a field rather than prose because **the interface has to act on it**, and
a caution inside a collapsed panel is not a control.

---

## Refusals are deliberate

A value that cannot be expressed is **refused, not escaped**. KQL has no
portable escape for a quote inside a phrase, so escaping would silently change
what was searched for — and a search that quietly means something else is worse
than one that fails.

Validation happens at import, so a malformed template breaks the build rather
than producing a template that returns nothing. A template that produces
nothing looks exactly like a search with no results.

---

## Adding one

1. Add the object to `src/dsar/identity/query_templates.json`.
2. `uv run pytest tests/test_templates.py` — 18 tests cover the shipped file,
   including that every template declares a `purpose` and `guidance`, and that
   `mailbox_only` marks exactly the templates measured to zero the site count.
3. Raise it as a pull request. **That review is the control** — see the top of
   this page.

If you need a seventh builder, add it to `_BUILDERS` in
`src/dsar/identity/templates.py` **and document it here**; a test asserts every
builder name appears in this file, so the two cannot drift.

---

## What is deliberately not here

**Raw KQL in a saved template.** The builders are the vocabulary. Raw KQL stays
in the editable query box, in front of the operator, per request — because a
saved query is one nobody reads again. If raw KQL is ever allowed in a
template, every query built from it needs a visible marker.
