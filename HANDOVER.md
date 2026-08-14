# HANDOVER — DSAR Assist

Written 2026-08-14, at the end of the build session. **Read this first.**
Everything below is checked against the tenant or the code; where something is
assumed rather than verified, it says so.

---

## 1 · What and where

| | |
|---|---|
| Mission | `1b1d65d1` — DSAR Assist, successor to `dsar-orchestrator` (`8652e638`) |
| Working copy | `/media/ben/data/projects/1b1d65d1/dsar-assist` |
| Remote | **github.com/azurebeard/dsar-assist** (private), CI green |
| Predecessor | `/media/ben/data/projects/8652e638/` — **read-only reference**, do not modify |
| Status | **Phases 0–4 built and working end to end. Demo next week, blocker cleared.** |

A control plane for Purview eDiscovery DSAR cases. **No data plane** — it never
requests the resource carrying the download permission, no download or preview
call exists in the eleven-operation table, and exports are collected by a human
from the Purview portal.

### Why it exists

The predecessor worked and **could not be moved to another machine**. Four
causes, all now structurally fixed:

1. `msal-extensions` OS-keyring cache needing a hand-made symlink pip cannot create
2. A local SQLite queue that *was* the source of truth, so work did not travel
3. No lockfile, no container, no IaC
4. A console script never installed, while every doc assumed it was

---

## 2 · Run it

```bash
cd /media/ben/data/projects/1b1d65d1/dsar-assist
DSAR_CLIENT_ID=<DESKTOP_APP_ID> \
DSAR_TENANT_ID=<TENANT_ID> \
DSAR_IDENTITY_EXPANSION=1 \
uv run dsar up
```

Then <http://localhost:8765> → **Sign in with Microsoft**.

`./dsar up` also works (Docker, falling back to uv). `dsar doctor` diagnoses
anything that will not start.

### Tenant

| | |
|---|---|
| Tenant | `<TENANT_ID>` · the demo tenant |
| App registration | `DSAR Assist (Desktop)` · `<DESKTOP_APP_ID>` |
| Shape | public client, single tenant, **zero credentials**, `appRoleAssignmentRequired` |
| Roles | `DSAR.Operator`, `DSAR.Auditor` — `<operator>` holds Operator |
| Provision | `./infra/entra/provision.sh desktop` — idempotent |

---

## 3 · What is built

| Phase | State |
|---|---|
| 0 · Portable skeleton | ✅ one image + `uv` path, three OSes, no Python on host |
| 1 · Identity plane | ✅ PKCE, `tid` pinned, app roles, CAE declared, in-memory tokens |
| 2 · Graph as source of truth | ✅ case list rebuilt from Graph — **nothing travels between machines** |
| 3 · Audit trail | ✅ hash-chained, tamper-evident, no subject data |
| 4 · Write path | ✅ create case → expand → review KQL → search → delta → export handoff |
| 5 · Hosted | ✅ **deployed and proven** on `rg-dsar-prod-uks-01`. FIC exchange verified live. Needs admin consent + a role assignment before anyone can sign in; WS10 not yet run |

**239 tests, `mypy --strict` clean, CI green.** Multi-arch image (amd64 +
arm64, built in CI), **distroless runtime** — no shell, no package manager, no
coreutils — non-root uid 10001, read-only root. **Zero High, zero Critical**:
B-08 took it from 179 findings to 19, none fixable, none above Medium.

### Documents worth reading, in order

`docs/DESIGN.md` (why each decision) · `docs/THREAT-MODEL.md` ·
`docs/BACKLOG.md` (what is left) · `docs/SBOM.md` ·
`docs/WS10-review-phases1-4-2026-08-14.md` · `docs/OWASP-top10-2026-08-14.md` ·
`docs/ROADMAP.md` · `verification/` (dated live probes)

---

## 4 · The demo

**The blocker is fixed** (2026-08-14). It was this, measured on `DSAR-2026-0418a`:

```
             items   mailboxes   sites
naive           40          12       1
expanded         4           3       0
```

`AND kind:email` was on the expanded query only. `kind:` is a mail-item
property, it **zeroes the site count**, and the expanded query was therefore
the narrower of the two — so the delta read backwards.

The tool now says so, two ways, because they catch different mistakes:

* A narrowing applies to **both queries** by default. *Expanded only* is still
  there, quieter, because narrowing one side is a legitimate thing to want.
* The **text of both boxes is scanned** for `kind:`, `filetype:` and
  `hasattachment:` on every keystroke. This is the one that matters — your
  query came from the Purview query builder and was pasted in, which the click
  tracking cannot see.

Either way a warning appears above the run button naming what the delta will
actually measure. Nothing is refused; the queries stay visible and editable.

If you see the banner on stage, hit **Reset to generated queries**.

### Subject to use — Megan Bowen

| Field | Value |
|---|---|
| Primary email | `MeganB@<tenant>.onmicrosoft.com` |
| Full name | `Megan Bowen` |
| Nicknames | `Meg` |
| Employee ID | `E-4411` |
| Other addresses | **leave empty** |

**Do not claim the alias beat.** Exchange normalises proxy addresses to the
primary SMTP in the eDiscovery index, so `megan.hartley@` returns exactly what
the primary returns. **Do not use** `…@example.test` — a reserved domain that
cannot route, so it returns 0.

The delta is carried by the **free-text mention clauses**. `"Meg"` was worth
+2 items and a third site in a controlled comparison, and a nickname is
knowledge a directory cannot supply — which is the argument for the operator
being in the loop.

**Numbers drift.** the demo tenant is live; the same query returned 49 one morning
and 50 that afternoon. Re-run the pre-run on the day and quote what you get.

---

## 5 · Gotchas that cost time

1. **Restart after any code change, and sign in again.** The session caches its
   Graph reader, so a reload is not enough. This cost an hour twice.
2. **A stale `dsar up` holds port 8765** and serves new files from disk with old
   code in memory. Kill by port: `ss -lptn 'sport = :8765'`.
3. **`az` cannot reach the eDiscovery API** — directory scopes only. Fine for
   apps, users and roles; useless for cases. The probes do their own sign-in.
4. **Admin consent leaves a "Default Access" assignment** with the all-zero role
   GUID. It satisfies `appRoleAssignmentRequired` but no DSAR role reaches the
   token. Delete it and assign a real role.
5. **Estimation timing is unpredictable.** Run searches ahead of a demo and
   present completed numbers. No figure is quoted in the UI on purpose.

---

## 6 · Open — needs you

| # | Item | Effort |
|---|---|---|
| **B-04** | **Prove CAE is negotiated** — `cp1` is declared, but whether the STS agreed is only readable from `xms_cc` on an issued token. **Until observed, do not claim near-real-time revocation** | 1 hour, one sign-in |
| **B-05** | **CA03 decision.** Requiring a compliant device on the *desktop* app hard-blocks a container on an unmanaged Linux box, including this workstation. Recommendation: enforce for hosted, report-only for desktop | a decision |
| **Admin consent** | Hosted mode is live but nobody can sign in until consent is granted in the portal and an operator holds a DSAR role. `provision.sh` could not grant it automatically | minutes |
| **WS10 on hosted** | The hosted attack surface is deployed and unreviewed — an internet-facing endpoint and server-side sessions holding delegated tokens. The threat model names it as reopening the review | half a day |

Branch protection is deliberately open (admin bypass) for development speed.

---

## 7 · Things I got wrong, so you can distrust the right parts

Recorded because a handover listing only successes is not a handover.

- **CI was red for four commits** and I did not notice. A `style.css` assertion
  in the CI shell duplicated a pytest assertion I had updated and it did not.
- **I pinned four GitHub Actions to SHAs I invented.** None existed. Caught by
  checking each against the API before pushing.
- **The launcher's image had never been published**, and it *preferred* Docker —
  so having Docker installed was a reason the tool did not start. Fixed.
- **I shipped auth routes with nothing linking to them.** Every test called
  `/auth/login` directly, so the suite was green while the flow was unreachable.
- **I guessed the templates API instead of reading it.** `mypy` caught it.
- **Three frontend tests pinned literals** that then legitimately improved.
  Assert properties, not expressions.
- **`WS10 Approved` was recorded before the image had ever been scanned.** The
  container job had failed earlier, so the blocking Trivy step never ran. Block
  a verdict on every check having *executed*.
- **I blamed the wrong thing for the secret scan failing every pull request,**
  confidently, from reading the code. The fix shipped, the job failed
  identically, and the actual cause — a missing `pull-requests: read` — was in
  the run log the whole time. Read the failure before theorising about it.
- **I recorded B-07 as done without watching the Publish workflow finish.** It
  failed all three times it ever ran: GitHub's attestation store refuses
  user-owned private repositories. The image was pushed; cosign signing and its
  verification come after and never ran, so `:latest` was unsigned while the
  workflow said it signed it. The same mistake as the line above, made again in
  the same session — a green CI badge is not every workflow.

The one that generalises: **SEC-H-02**, a path-traversal escape from the
operations allowlist, existed because a *comment* claimed a guarantee the regex
did not provide. It survived two readings and a passed WS10 review in the
predecessor. Every finding in this project was found by **running something**,
never by re-reading code.
