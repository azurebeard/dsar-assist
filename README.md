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
under their own identity. All three facts are asserted by tests at every
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
  between them is what the expansion found.
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
`~/.dsar/config.json` owner-only. Every run after that is just `up`.

**Container** — the second supported path. Multi-arch (amd64 and arm64),
signed, with SBOM and provenance attached:

```bash
docker run --rm -p 127.0.0.1:8765:8765 \
  -v ~/.dsar:/home/dsar/.dsar \
  ghcr.io/azurebeard/dsar-assist:latest
```

From a clone, `./dsar up` (macOS/Linux) or `.\dsar.ps1 up` (Windows) picks
whichever runtime is available.

If anything is wrong, ask:

```bash
uvx --from git+https://github.com/azurebeard/dsar-assist dsar doctor
```

`doctor` names the problem and the fix — including the exact redirect URI to
register.

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

## Use

`up` starts a local server on `http://localhost:8765` and opens the browser.
Sign in with your Microsoft account; the roles you hold are shown next to
your name.

**Handle a request:**

1. **New request** — enter the DSAR reference from your ticketing system and
   the date the request was **received**. The received date drives the
   statutory deadline and is written once, at creation; leave it blank and the
   deadline shows as *not recorded* rather than being guessed.
2. **Resolve the subject** — primary email, plus anything the directory cannot
   know: nicknames, former names, a personal address from the request itself.
   Two queries come back: *naive* (primary address only) and *expanded*
   (everything the directory and you supplied). Both are editable, and nothing
   runs until you say so.
3. **Narrow if needed** — the template panel stacks reviewed narrowings onto
   the queries. Apply to *both* unless you mean otherwise; the tool warns when
   the two queries stop being comparable, and when a narrowing counts only
   mailbox content.
4. **Run both searches** and leave the page — it polls on its own. Estimates
   land with item and location counts, and the difference between the two
   searches is what the naive query would have missed.
5. **Export** — starts in Purview; you collect the results from the Purview
   portal under your own identity. This tool never touches item content.

**Requests list** shows every case this tool created, from any machine, with
status, received date, and the deadline — overdue and due-soon highlighted.

**The audit trail** records every action, including refusals, with the
subject as a case-scoped pseudonym — never their name or the query text:

```bash
uvx --from git+https://github.com/azurebeard/dsar-assist dsar audit verify
uvx --from git+https://github.com/azurebeard/dsar-assist dsar audit tail
uvx --from git+https://github.com/azurebeard/dsar-assist dsar audit evidence <case-id>
```

`verify` recomputes the hash chain and names the first break if anything was
altered. `evidence` produces the per-case pack — who searched, what was
searched, when, with the chain verification attached — and refuses to produce
one from a trail that does not verify. Both work offline: the record survives
even when the case list (which *is* Microsoft Graph) is unreachable.

**Roles:** `DSAR.Operator` can do everything above. `DSAR.Auditor` can see
cases and read the trail, and is refused anything that creates or exports —
and the refusal itself is recorded.

---

## Configuration

`init` writes everything a desktop install needs. The full set — environment
wins over the file:

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

Hosted mode — the same image on Azure Container Apps, with no secret anywhere
and the audit trail in an append blob — is documented in
[`docs/DEPLOY-hosted.md`](docs/DEPLOY-hosted.md).

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

[`docs/CLAIMS.md`](docs/CLAIMS.md) maps every guarantee to the test that fails
when it stops being true. The design reasoning is in
[`docs/DESIGN.md`](docs/DESIGN.md), the threat model in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md), and the software bill of
materials in [`docs/SBOM.md`](docs/SBOM.md).

---

## Develop

```bash
uv sync --frozen
uv run pytest
uv run mypy
uv run dsar doctor --offline
```

The invariant tests run first and alone, so a breach is unambiguous:

```bash
uv run pytest tests/test_structural.py -v
```

Build the image the way CI does:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  --sbom=true --provenance=true -t dsar-assist:dev .
```

CI runs the full suite on Ubuntu, macOS and Windows on every push, plus a
container smoke test under the real hardening flags and a blocking
vulnerability scan.

---

## Licence

[MIT](LICENSE).
