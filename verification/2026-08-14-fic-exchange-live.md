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

## The append-blob trail — proven the same day

An operator ran a case through the hosted instance. Read back from
`audit-2026-08-14.jsonl`:

```
blobType     AppendBlob
blocks       13 committed   (one per record, as designed)
records      13
verify       13 record(s), chain intact.
```

**Append-only is the storage primitive, not a convention.** Thirteen records
produced thirteen committed append blocks; `comp=appendblock` has no offset and
cannot overwrite.

### What the real records confirm

| Claim | Evidence |
|---|---|
| The subject appears only as a case-scoped pseudonym | `subject_ref: 7e4ba3ab68401b36`. Greps for `megan`, `bowen`, `E-4411`, `participants`, `kind:` all return **0** |
| No KQL is recorded | 0 |
| `uti` is captured for the cross-log join | `U86Knr3SDEmIAemfb3tcAA` |
| Refusals are recorded, not only successes | `seq 1  sign_in_refused  denied  no DSAR app role` |
| Writes are bracketed | `case_created attempted` → `case_created ok` |

The only address in the trail is the **operator's own** UPN, which is by design
— display alongside `oid`, never the key.

### The roles question, answered by the trail

```
seq  2  sign_in  ok  DSAR.Auditor, DSAR.Operator
seq 12  sign_in  ok  DSAR.Auditor, DSAR.Operator
```

Both roles are in the token. Nothing "won" — app roles are additive, and the
interface was showing the effect rather than the roles.

### One interrupted write, and it is the documented one

```
seq 13  case_created  attempted     (no matching `ok`)
```

That is the shape `Outcome.ATTEMPTED` exists to make visible. It coincides with
a revision update — *"a revision update signs everyone out"*, recorded as a
property of the single-replica design rather than discovered. The trail showing
it is the mechanism working, not a fault.

## Still unproven

- **Admin consent could not be granted automatically** by `provision.sh`; it
  needs a Global Administrator in the portal.
- **Two operators concurrently**, each as themselves.
- **The hosted attack surface is unreviewed.** WS10 has not run against it.

## Found by reading the real trail

`dsar audit verify` constructed a `JsonlFileSink` unconditionally, so in the
hosted container it read an empty directory and reported *"no audit trail"*
while thirteen records sat in the blob. The verifier could not verify the only
trail there was, and this chain had to be checked by hand.

The claim was that the verifier is the same code either side. It is —
`verify_chain` never changed. What was missing is that the *command* could not
reach the hosted trail, which makes the claim true and useless. Fixed.
