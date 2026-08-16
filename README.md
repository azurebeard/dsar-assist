# DSAR Assist

A tool for answering **Data Subject Access Requests** against Microsoft 365.
When someone exercises their right of access, the person handling it has to
find everything the organisation holds about them — mail, files, chat — inside
a statutory deadline. This tool runs that search through Microsoft Purview
eDiscovery, tracks the deadline, and keeps a tamper-evident record of who
searched for what.

**It has no data plane.** It cannot show you a document and it cannot copy one
anywhere. The app registration requests Microsoft Graph and nothing else — the
separate resource that carries the eDiscovery download permission is never
named in this codebase — no download or preview call exists in the permitted
operations table, and the operator collects exports from the Purview portal
under their own identity. All three facts are asserted structurally at every
commit, and `doctor` re-proves the first at runtime by inspecting the scopes on
the issued token.

## What it does

- **Creates the eDiscovery case** and stamps it with your DSAR reference, so
  the same case list appears on any machine you sign in from — Microsoft Graph
  is the source of truth and nothing is stored locally.
- **Tracks the statutory clock.** One calendar month from the day the request
  was *received* — not thirty days, and not from when someone opened the case.
  The deadline and days remaining sit on the request list; a case with no
  recorded receipt date says so rather than showing a guessed date.
- **Shows what a naive search would miss.** The directory is asked who the
  subject actually is — aliases, former names, employee ID — and both queries
  are shown side by side, editable, before anything runs. The difference
  between them is the demonstration.
- **Narrows with reviewed templates** — an employment-file sweep, privilege
  triage, third-party co-occurrence and more, each shipped in the image and
  changed only by pull request, because a template decides the scope of
  somebody's subject access response ([docs/TEMPLATES.md](docs/TEMPLATES.md)).
- **Keeps a hash-chained audit trail** — who searched, when, refusals
  included, with the subject appearing only as a case-scoped pseudonym. Any
  edit or deletion is detectable and named by record.
- **Produces a per-case evidence pack** a data protection officer can attach
  to the response, refusing outright if the trail does not verify.

The operator signs in as themselves; the tool can see nothing their own
Purview permissions do not already allow, and holds no credential of its own.

---

## Install

`uv` is the only prerequisite — one static binary, no admin rights, no Python
needed on the host, nothing cloned.

**Windows** (PowerShell):

```powershell
winget install astral-sh.uv
uvx --from git+https://github.com/azurebeard/dsar-assist dsar init
uvx --from git+https://github.com/azurebeard/dsar-assist dsar up
```

**macOS / Linux:**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uvx --from git+https://github.com/azurebeard/dsar-assist dsar init
uvx --from git+https://github.com/azurebeard/dsar-assist dsar up
```

`init` runs once: it asks for the two GUIDs that identify your app
registration (neither is a secret), validates them, and writes
`~/.dsar/config.json` owner-only. Every run after that is just `up` — it
starts the local server and opens the browser to sign in.

**Container** — the second supported path, because relying on only one is how
this tool's predecessor died on stage. Multi-arch (amd64 and arm64), signed,
with SBOM and provenance attached:

```bash
docker run --rm -p 127.0.0.1:8765:8765 \
  -v ~/.dsar:/home/dsar/.dsar \
  ghcr.io/azurebeard/dsar-assist:latest
```

From a clone, `./dsar up` (macOS/Linux) or `.\dsar.ps1 up` (Windows) picks
whichever runtime is available, preferring the container and falling back to
`uv`.

If anything is wrong, ask:

```bash
uvx --from git+https://github.com/azurebeard/dsar-assist dsar doctor
```

`doctor` names the problem and the fix. It prints the exact redirect URI to
register, refuses to run if a secret-shaped environment variable is set, and
states plainly that tokens live in memory only.

### One-time tenant setup (an admin, once per tenant)

The tool authenticates against an Entra app registration your tenant owns.
`infra/entra/provision.sh` creates it idempotently: single-tenant, public
client with PKCE, **zero credentials of any kind**, app roles
(`DSAR.Operator`, `DSAR.Auditor`) with assignment required, and an app
management policy that blocks anyone adding a secret later. Assign operators
to a role, grant admin consent, and hand the two GUIDs to whoever runs
`init`. Operators also need an eDiscovery role in Purview — the tool grants
nothing and cannot elevate.

---

## Configuration

`init` writes everything a desktop install needs. The full set, for scripting
or for hosted mode — environment wins over the file:

| Variable | Required | Meaning |
|---|---|---|
| `DSAR_CLIENT_ID` | yes | Application ID of the app registration |
| `DSAR_TENANT_ID` | yes | Tenant GUID. Pins the authority — not `/common` |
| `DSAR_MODE` | no | `desktop` or `hosted`. Inferred when unset |
| `DSAR_PORT` | no | Default `8765` |
| `DSAR_AUDIT_DIR` | no | Default `~/.dsar/audit` |
| `DSAR_IDENTITY_EXPANSION` | no | Enables the directory-read scope |
| `DSAR_BASE_URL` | hosted | External origin, used to build the redirect URI |
| `DSAR_UAMI_CLIENT_ID` | hosted | User-assigned managed identity for the client assertion |
| `DSAR_AUDIT_BLOB_URL` | hosted | Append-blob container for the audit trail |

Neither required value is a secret. There is no setting for a client secret,
because there is no code path that could consume one.

The config file must not be writable by group or other — `tenant_id` selects
the Entra tenant the operator signs in to, so whoever can write it chooses the
identity provider. `init` sets this correctly; if you write the file by hand
on macOS or Linux, `chmod 600 ~/.dsar/config.json`. On Windows, NTFS
inheritance applies and the check is not enforced.

---

## How it is built

| Property | How it is held |
|---|---|
| No data plane | Download resource never named; structural tests; runtime scope check |
| No secrets | Desktop is a public client with PKCE; hosted uses a federated credential minted by a managed identity. `doctor` fails if a secret-shaped variable exists |
| Tokens in memory only | `msal.SerializableTokenCache` is banned by a structural test. No keyring, no file cache, no `msal-extensions` |
| State travels | Microsoft Graph is the source of truth. There is no local database — a structural test bans `sqlite3` outright |
| One HTTP choke point | Exactly three modules may import an HTTP client, asserted by test |
| Reproducible | `uv.lock` locks across all platform markers; CI fails on a stale lock |
| Entry points work | The container's `ENTRYPOINT` *is* the console script, both entry points are asserted to agree, and a test greps these docs for commands that would not run on a fresh machine |
| Container hardened | Distroless runtime — no shell, no package installer — non-root uid 10001, read-only root filesystem, all capabilities dropped, base images digest-pinned. Zero fixable findings, zero High or Critical |
| Audit trail protected | Hash-chained, append-only by construction, directory forced to `0700`; two concurrent writers cannot fork it |
| Requests observable | Logged by route template, never by concrete path — so 401s and 403s are visible without copying case identifiers into a second, ungoverned store |

Each row exists because the predecessor lost it. The full reasoning is in
[`docs/DESIGN.md`](docs/DESIGN.md), and
**[`docs/CLAIMS.md`](docs/CLAIMS.md) names the test that fails when any of it
stops being true** — because a guarantee with nothing checking it has been this
project's most common defect, seven times over.

---

## Narrowing a search

Six query templates ship with the tool — a time window, a workload split, an
employment-file sweep, privilege triage, third-party co-occurrence, and
attachments. Each **narrows** the generated query; none replaces it.

They are compiled in at build time from
`src/dsar/identity/query_templates.json`, so adding one is a pull request
against that file — and **that review is the control**. A template decides the
scope of somebody's subject access response, and one that narrows too far
under-discloses, which is a compliance failure rather than a cosmetic one.

[`docs/TEMPLATES.md`](docs/TEMPLATES.md) documents the JSON shape and all six
builders, with the real fragment each one produces.

---

## Develop

```bash
uv sync --frozen
uv run pytest
uv run mypy
uv run dsar doctor --offline
```

Structural invariants run first and alone, so a breach is unambiguous:

```bash
uv run pytest tests/test_structural.py -v
```

Build the image the way CI does — `linux/arm64` is not optional, because Apple
Silicon is where the predecessor failed:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  --sbom=true --provenance=true -t dsar-assist:dev .
```

CI runs the full suite on Ubuntu, macOS and Windows on every push, plus a
container smoke test under the real hardening flags and a blocking
vulnerability scan.

---

## Status

**Desktop mode is the product, and it is complete**: case creation, the
statutory clock, identity expansion and the query delta, templates, searches
and estimates, export handoff, the audit trail and the evidence pack — 370
tests, `mypy --strict`, three operating systems.

**Hosted mode is proven, then retired by choice.** It was deployed to Azure
Container Apps with zero secrets — client authentication by federated
credential from a managed identity, verified live — then torn down because
desktop mode serves the current need at zero running cost. Every answer is
recorded in [`verification/`](verification/), the archived audit trail
verifies in-repo, and [`docs/DEPLOY-hosted.md`](docs/DEPLOY-hosted.md)
rebuilds it in about thirty minutes when there is a team to serve.

Security reviews, the threat model, and the software bill of materials are in
[`docs/`](docs/). Working notes for contributors are in
[`HANDOVER.md`](HANDOVER.md).
