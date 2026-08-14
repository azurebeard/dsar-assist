# DSAR Assist

A control plane for Microsoft Purview eDiscovery cases raised in response to
Data Subject Access Requests.

**It has no data plane.** It cannot show you a document and it cannot copy one
anywhere. The app registration requests Microsoft Graph and nothing else — the
separate resource that carries the eDiscovery download permission is never
named in this codebase — no download or preview call exists in the permitted
operations table, and the operator collects exports from the Purview portal
under their own identity. All three facts are asserted structurally at every
commit, and `doctor` re-proves the first at runtime by inspecting the scopes on
the issued token.

Successor to `dsar-orchestrator` (mission `8652e638`). That version worked and
failed to move to a second machine; this one is built around not doing that.

---

## Run it

Two supported ways, because relying on only one is how the predecessor's demo
died. Docker Desktop is frequently blocked or unlicensed on a locked-down
client laptop; `uv` is a single static binary that installs without admin
rights. Neither needs Python on the host.

```bash
export DSAR_CLIENT_ID=<the desktop app registration's application ID>
export DSAR_TENANT_ID=<your tenant ID>

./dsar up            # prefers Docker, falls back to uv
```

Force one or the other:

```bash
DSAR_RUNTIME=uv ./dsar up
DSAR_RUNTIME=docker ./dsar up
```

On Windows, `.\dsar.ps1 up`.

If anything is wrong, ask:

```bash
./dsar doctor
```

`doctor` names the problem and the fix. It prints the exact redirect URI to
register, refuses to run if a secret-shaped environment variable is set, and
states plainly that tokens live in memory only.

---

## Configuration

Neither of the two required values is a secret. They identify a registration;
they do not authorise anything. There is no setting for a client secret,
because there is no code path that could consume one.

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

Values may also be written to `$DSAR_HOME/config.json`. Environment wins.

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

Each row exists because the predecessor lost it. The full reasoning is in
[`docs/DESIGN.md`](docs/DESIGN.md).

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

---

## Status

**Phase 0 complete** — the skeleton that ships. Portable, containerised,
diagnosable, tested on three operating systems.

Next: Phase 1, the identity plane. See [`docs/ROADMAP.md`](docs/ROADMAP.md).
