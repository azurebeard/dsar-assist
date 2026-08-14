# The FIC exchange, live — the design's last open question

**Date:** 2026-08-14 · **Tenant:** `<TENANT_ID>` · **Mode:** hosted
**Result: it works.** A managed-identity-minted assertion is accepted on an
`authorization_code` grant.

This was recorded as the largest technical unknown in the original plan, and
it has been open since. It is now answered by observation.

---

## What was deployed

| | |
|---|---|
| Resource group | `rg-dsar-prod-uks-01`, UK South |
| Container app | `ca-dsar-prod-uks-01`, single replica, distroless image |
| Identity | `id-dsar-prod-uks-01`, user-assigned, dedicated |
| Storage | `stdsarproduks01`, `allowSharedKeyAccess: false` |
| App registration | `DSAR Assist (Hosted, UK South)` |
| Ingress | locked to one `/32`; `allowInsecure: false` |

Asserted against the deployed resource, not the template:

```
secrets:        (empty)
registries:     []
allowInsecure:  false
identity:       UserAssigned
replicas:       min=1 max=1
```

## The result

```
[  ok  ] client assertion
          aud=fb60f99c-7a34-4190-8149-302f77469936
          iss=https://login.microsoftonline.com/<TENANT_ID>/v2.0
          sub=0fb44ef4-c45f-416d-87e9-a6a7aed2ba96

[  ok  ] FIC exchange
          client authentication succeeded — Entra rejected only the
          deliberately invalid code, which is the expected result

All checks passed.
```

`invalid_grant`, not `invalid_client`. Entra authenticated the client against
a credential it has never been given, using a token minted seconds earlier by
a managed identity — then declined the deliberately bogus authorization code,
which is the only thing left to decline. One request, nothing created.

**No secret exists anywhere in this deployment.** Both credential collections
on the app registration are empty; the container holds no registry credential;
the storage account has no shared key.

---

## Two defects that only exist on real infrastructure

Both were invisible to 277 tests, a compiling template and a clean type check.

### `MSI_SECRET` — hosted mode failed its own health check

```
[ FAIL ] no secrets
          set: MSI_SECRET
```

Container Apps injects `MSI_SECRET`: the legacy name for the value that
authenticates a caller to the **local** managed identity endpoint, identical to
`IDENTITY_HEADER`. It authorises nothing against Entra and nothing against
Graph — and it is the thing that makes the secretless design *work*, because it
is how the container proves it may mint the assertion.

`doctor` rejected it as a credential because the check reasons about variable
**names**, and this one is named like the thing it is not. Hosted mode would
have failed its own health check on **every Container Apps deployment it could
ever have had**.

Allowlisted by exact name. Never by relaxing the suffix rule — a test asserts
`AZURE_CLIENT_SECRET` is still caught while `MSI_SECRET` is present.

### The `aud` guidance sent the reader the wrong way

`doctor` printed *"The federated credential must match all three EXACTLY"*
beside `aud=fb60f99c-…`. The credential registers the literal
`api://AzureADTokenExchange`; Entra puts that resource's **GUID** in the issued
token. Both are correct and they do not look alike.

Someone comparing them would have gone hunting a mismatch that is not one —
against Microsoft's own warning that a wrong `aud` fails exactly here. Reworded
to say `sub` is the one to compare, and why the `aud` GUID is expected.

---

## Also confirmed live

- **The distroless multi-arch image runs on Container Apps.** Revision
  `Healthy`, `RunningAtMaxScale`, pulled anonymously from a public package with
  `registries: []`.
- **HSTS is present** — hosted only, absent on desktop.
- **`/healthz` withholds the version** in hosted mode (WS10 SEC-L-01), and
  discloses no tenant.
- **An unauthenticated API call returns 401**, with a correct `Origin`.
- **Provenance attestation works again.** It had failed on every previous
  publish because GitHub's attestation store refuses user-owned *private*
  repositories. With the repository public, `Attest provenance`, `Sign the
  image` and `Verify what we just signed` all pass — the first fully attested
  and signed build.

---

## Still unproven

- **The append-blob audit sink has never written a record.** The blob is
  created lazily on first append, and no record exists because nobody has
  signed in yet. Needs admin consent plus an app-role assignment.
- **Admin consent could not be granted automatically** by `provision.sh`; it
  needs a Global Administrator in the portal. Until then nobody can sign in,
  which is `appRoleAssignmentRequired` and consent working, not a fault.
- **Two operators concurrently**, each as themselves — the
  `prompt=select_account` property.
- **The hosted attack surface is unreviewed.** WS10 has not run against it.
