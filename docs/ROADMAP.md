# Roadmap

Value lands early and in the right order: Phase 0 fixes portability, Phase 1
lands the identity plane, Phase 2 fixes the empty queue. All three precede any
hosted work, so if Phase 5 slips or is cancelled the result is still a strictly
better version of the tool that exists today.

| Phase | Contents | Done means |
|---|---|---|
| **0 — Skeleton that ships** ✅ | uv project, both entry points, Dockerfile, `./dsar` + `uvx`, `doctor --offline`, `/healthz`, structural tests, CI incl. container smoke and multi-arch | `doctor` passes on a Mac, a Windows box and a Linux box, with no Python installed on any host, via both `docker run` and `uvx` |
| **1 — Identity plane** | Two app registrations + app roles + app management policies via `provision.sh`; CA01/CA04/CA06/CA07 report-only then enforce; desktop auth-code flow, `cp1`, `tid` pinning, roles validation, in-memory session; identity doctor checks | Sign-in works on all three OSes from the same artefact; `doctor` shows `xms_cc` contains `cp1`, the expected `roles`, and no download scope. **Both open questions resolved live** (below) |
| **2 — Graph read + state** | Port `graph/*`, add `list_cases`/`list_searches`, request list from `externalId`, scope toggle, claims-challenge retry, `$filter` and `createdBy` probes recorded in `verification/` | The request list is reconstructed on a second machine, from Graph, with zero local state copied |
| **3 — Audit** | Sink protocol, JSONL sink, hash chain, `audit verify`/`tail`, tee to stderr, Entra + Graph Activity diagnostic settings | Kill the container mid-flow → chain verifies. Tamper a record → `verify` names its `seq`. A sign-in joins to its audit records by `uti` |
| **4 — Write path** | `create_case` with `externalId`, ported identity expansion + templates + KQL editor, `create_search`, `run_search`, stats ladder, `initiate_export`, portal deep link, auth-context `C1` step-up on create and export | Full DSAR flow end to end against the demo tenant, from the container, on two machines each seeing the same cases |
| **5 — Hosted** | FIC spike first, then Bicep, dedicated UAMI, confidential client, `prompt=select_account`, session cookies, append-blob sink, ingress, CA02/CA11 | Same image tag in `ca-dsar-prod-uks-01`; `secrets` returns `[]`; two operators sign in concurrently **as themselves** |
| **6 — Governance + hardening** | Access reviews, CA03 enforcement decision, immutability policy, IP restrictions, cosign + SBOM, distroless evaluation, CAE step-up drill, WS10 review | The CAE drill run live and recorded in `verification/`. WS10 PASS |

---

## Open questions, to be resolved live in Phase 1

Both are load-bearing. Neither can be settled from documentation.

1. **Is the `roles` claim emitted in the ID token of a *public* client?**
   Documented for apps that sign users in, but not stated explicitly for public
   clients. Verify with one test app-role assignment before building the
   desktop authorization on it. Fallback if absent: rely on
   `appRoleAssignmentRequired` at the IdP alone and drop the in-process check,
   which was advisory anyway.

2. **Loopback redirect behaviour.** RFC 8252 §7.3 has the authorization server
   ignore the port when matching a localhost redirect. Confirm live, and
   confirm that registering `http://127.0.0.1/...` requires a Graph PATCH
   because the portal refuses it.

Record both in `verification/`, dated, with what was actually observed.

---

## Deferred deliberately

| Item | Why |
|---|---|
| Incremental / dynamic consent | Mechanically dead: `requireAssignment` disallows user consent, and both scopes are admin-restricted. Replaced by CA authentication context |
| Per-token scope narrowing | `.default` returns all scopes granted for the resource. Not a control that exists |
| PIM for eDiscovery roles | eDiscovery Manager accepts only a mail-enabled security group; Administrator accepts no group at all; Purview's auto-expiring permissions exclude both |
| Token protection, DPoP, mTLS-bound tokens | None are available for a custom app on Graph from a Linux container. Compensating controls documented in `docs/DESIGN.md` |
| Access packages / entitlement management | Disproportionate for a handful of operators. Revisit above ~20 |
| Device code flow | Blocked tenant-wide by CA06. It is the highest-yield phishing vector against exactly these operators |
| Distroless base image | The diagnostic story depends on a shell. Re-evaluate in Phase 6 |
