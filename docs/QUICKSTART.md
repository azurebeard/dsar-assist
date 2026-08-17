# Quick start, for the person answering the DSAR

Written for the privacy practitioner, not the administrator. It assumes you
know what a DSAR is and what a defensible search looks like; it does not
assume you know Purview's portal or a terminal beyond pasting two commands.

## The problem this solves

Your organisation already owns Purview eDiscovery, and it can do the search.
What it costs you is the repetitive part: creating the case, building the
query, remembering the aliases, checking you did not search the primary
address alone. This tool does the setup; Purview stays authoritative for the
search itself, the review and the export. Nothing responsive ever passes
through this tool, and it holds no way to read a document even if asked.

## What you need before you start

- A Microsoft work account in the tenant the requests concern.
- **A DSAR role on this application**, assigned in Microsoft Entra ID by
  whoever administers it. `DSAR.Operator` creates and runs; `DSAR.Auditor`
  reads the record.
- **An eDiscovery role in Microsoft Purview** (typically eDiscovery Manager),
  granted by a compliance administrator. The tool cannot grant this and
  cannot work without it.
- The two IDs for your tenant's registration, from your administrator.
  Neither is a secret. If no registration exists yet, an administrator runs
  `infra/entra/provision.sh` once per tenant.

## Install and sign in

macOS or Linux:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uvx --from git+https://github.com/azurebeard/dsar-assist@v0.1.1 dsar init
uvx --from git+https://github.com/azurebeard/dsar-assist@v0.1.1 dsar up
```

Windows (PowerShell):

```powershell
winget install astral-sh.uv
uvx --from git+https://github.com/azurebeard/dsar-assist@v0.1.1 dsar init
uvx --from git+https://github.com/azurebeard/dsar-assist@v0.1.1 dsar up
```

`init` asks for the two IDs and runs once. `up` opens your browser; sign in
with your normal Microsoft account. The footer then tells you whether you
are ready: it checks your role and asks Purview a real question, and if
either fails it names the person to ask, not an error code.

## The first case

1. **New request.** Type the DSAR reference from your register, and the date
   the request arrived. The date drives the one-calendar-month clock shown on
   every case; it is recorded once, at creation. Extensions and clock pauses
   are not modelled; the date shown is the baseline.
2. **The data subject.** Their primary email, plus everything the directory
   cannot know: nicknames, a former surname, a personal address they wrote
   in from. This is where responses are won; in measurement, one nickname
   was worth an entire location the plain search never looked at.
3. **Resolve identity.** The tool shows what it found, grouped by where it
   came from, and builds two searches: the naive one (primary address only)
   and the expanded one (everything known). Both are shown before anything
   runs, and both are editable.
4. **Narrow if the request calls for it** with a reviewed template: a date
   window, employment-file vocabulary, attachments. Apply narrowings to both
   searches so they stay comparable; the page warns you if they stop being.
5. **Run both searches.** Estimates take minutes; the page updates itself
   and you can leave it.

## Reading the result

The case shows both estimates side by side and states the difference
plainly: what the naive search would have missed, in items and in places it
never looked. That sentence is the reason both searches exist. Item counts
are estimates of matching items, not a promise every item is disclosable;
judgement stays with you.

If a search reports "partial", some locations could not be searched. Treat
that as unfinished business, not a smaller total.

## Continuing in Purview

Export starts from the case view but delivers in the Microsoft Purview
portal, under your own sign-in, where review and redaction live. The case
link is on the page. This is a boundary, not a missing feature: the tool
never touches responsive content, which is what makes it safe to run on any
machine.

Every action along the way, including anything refused, lands in a
tamper-evident record. When the response goes out:

```bash
uvx --from git+https://github.com/azurebeard/dsar-assist@v0.1.1 dsar audit evidence <case-id>
```

produces the per-case evidence pack, suitable for the file.

## When something is wrong

```bash
uvx --from git+https://github.com/azurebeard/dsar-assist@v0.1.1 dsar doctor
```

names the problem and the fix for anything that does not need a sign-in.
The two things that do need one, your role and Purview answering, are
checked every time you sign in, in the footer.

## The deeper end

How the guarantees are held: [CLAIMS.md](CLAIMS.md). What was considered
and defended against: [THREAT-MODEL.md](THREAT-MODEL.md). The reviewed
narrowings: [TEMPLATES.md](TEMPLATES.md). Measuring the time this saves:
[BENCHMARK.md](BENCHMARK.md).
