# Deploying hosted mode

Hosted mode runs the same image on Azure Container Apps with no secret
anywhere. This is the order to run the deployment in, and the places it will
bite.

---

## 0 · Make the container image pullable

`ghcr.io/azurebeard/dsar-assist` inherits the repository's private visibility.
A private image needs registry credentials, and a registry credential in
Container Apps is a **secret** — which contradicts `secrets: []`, the central
claim of the hosted design and the thing `test_the_hosted_deployment_declares_
no_secrets` asserts.

**There is no REST API for this.** GitHub's packages API supports list, get,
delete and restore — there is no PATCH for visibility, and attempting one
returns 404 on a URL where GET succeeds. It is a web UI action only.

**A package's visibility is independent of its repository's.** Making the
repository public does not make the package public; they are two settings in
two places, and both pages have a "Danger Zone → Change visibility". That
ambiguity is easy to fall into.

Start from the package page, which the API gives you authoritatively:

```bash
gh api user/packages/container/dsar-assist -q .html_url
# https://github.com/users/azurebeard/packages/container/package/dsar-assist
```

On that page — it shows the pull command and the version list, which is how you
know it is the package and not the repository — use **Package settings** in the
right-hand sidebar, then **Danger Zone → Change visibility → Public**.

Verify with the only test that matters, which is what Container Apps does:

```bash
docker logout ghcr.io
docker manifest inspect ghcr.io/azurebeard/dsar-assist:latest >/dev/null \
  && echo "pullable" || echo "still private"
```

### What that publishes, and what it does not

The image carries the application and its four dependencies. It carries **no
configuration**: `docker inspect` shows only `PATH`, `SSL_CERT_FILE`, two
`PYTHON*` flags, `DSAR_IN_CONTAINER` and `DSAR_AUDIT_DIR`. No tenant id, no
client id, no token, no endpoint.

Verified rather than assumed, on the built image:

```
trivy image --scanners secret dsar-assist:ci   →  0 secrets
gitleaks (CI, full history)                    →  clean
```

It does make the Python source readable to anyone who pulls it. That is the
same source that is going public with the repository.

---

## 1 · The hosted app registration

Needs no infrastructure, so it goes first — the Bicep takes its `appId` as a
parameter.

```bash
export DSAR_HOSTED_REDIRECT="https://placeholder.invalid/auth/callback"
./infra/entra/provision.sh hosted
```

The redirect is a placeholder because the real one is the Container App's
FQDN, which does not exist yet. Step 4 corrects it.

`provision.sh` creates **no credential of any kind** — that is the point, and
it is asserted at the end of the script.

---

## 2 · Deploy the infrastructure

`allowedIpRanges` has **no default**, deliberately: the deployment fails until
a human decides whether this endpoint is internet-facing.

```bash
MY_IP="$(curl -s https://api.ipify.org)/32"

az deployment sub create \
  --name dsar-hosted \
  --location uksouth \
  --template-file infra/main.bicep \
  --parameters environment=prod \
               appClientId="<appId from step 1>" \
               allowedIpRanges="[\"${MY_IP}\"]" \
               containerImage="ghcr.io/azurebeard/dsar-assist@sha256:<digest>"
```

Get the digest from the Publish workflow summary, or:

```bash
docker buildx imagetools inspect ghcr.io/azurebeard/dsar-assist:latest \
  --format '{{.Manifest.Digest}}'
```

**Pin by digest, not `:latest`.** The structural test enforces it in the
template, and a tag can be repointed with no change here.

Creates: `rg-dsar-prod-uks-01`, `log-`, `id-`, `cae-`, `ca-`, `stdsarproduks01`.
Roughly £30–50/month at a single replica.

---

## 3 · The federated identity credential

```bash
PRINCIPAL_ID="$(az deployment sub show --name dsar-hosted \
  --query properties.outputs.identityPrincipalId.value -o tsv)"

./infra/entra/add-fic.sh "<appId>" "${PRINCIPAL_ID}"
```

⚠️ The subject is the identity's **principal** id, and it is **case-sensitive**.
It is *not* `DSAR_UAMI_CLIENT_ID`, which is a different GUID for the same
identity. Microsoft's documentation is explicit that a wrong value here creates
the credential *successfully, without error* and fails only at token exchange.

---

## 4 · Point the registration at the real URL

```bash
APP_URL="$(az deployment sub show --name dsar-hosted \
  --query properties.outputs.appUrl.value -o tsv)"

az ad app update --id "<appId>" --web-redirect-uris \
  "${APP_URL}/auth/callback" "${APP_URL}/auth/post-logout"
```

`DSAR_BASE_URL` is already set to this by the template. It is configured and
never derived from the `Host` header — a redirect URI taken from a forwarded
header is an attacker-controlled redirect URI.

---

## 5 · Prove the federated credential actually works

This is the last open question in the design. `doctor` answers it in one
request that creates nothing.

```bash
az containerapp logs show -n ca-dsar-prod-uks-01 -g rg-dsar-prod-uks-01 --tail 50
```

There is **no shell in the image** (B-08), so `az containerapp exec` will not
give you one. Run `doctor` as the container's command instead:

```bash
az containerapp update -n ca-dsar-prod-uks-01 -g rg-dsar-prod-uks-01 \
  --args doctor
# read the logs, then put it back
az containerapp update -n ca-dsar-prod-uks-01 -g rg-dsar-prod-uks-01 \
  --args up
```

Read the two hosted checks:

| Check | What it tells you |
|---|---|
| **client assertion** | `aud`, `iss`, `sub` off the token the managed identity actually issued. Compare `sub` with what step 3 registered |
| **FIC exchange** | `invalid_grant` → client authentication **succeeded**, the credential is right. `invalid_client` → it is wrong. `AADSTS70021` → replication lag, wait and re-run |

⚠️ A newly created credential can return `AADSTS70021` for several minutes.
That is propagation, not misconfiguration. **Retry before changing anything** —
changing a correct credential because it had not propagated yet is how an
afternoon disappears.

---

## 6 · Then, and only then

- **Assign an operator** an app role on the enterprise app. Nobody can sign in
  until you do — that is `appRoleAssignmentRequired` working. Watch for the
  all-zero "Default Access" assignment that admin consent leaves behind; it
  satisfies the requirement without putting a DSAR role in the token.
- **Two operators signing in concurrently**, each as themselves. This is the
  `prompt=select_account` property, and it is worth running by hand.
- **Lock the immutability policy.** It ships `Unlocked`, because locking is
  irreversible — the retention period can afterwards only be extended, never
  reduced, for the life of the account. That is a decision for a person, not a
  default in a template.
- **CA02** (compliant device, hosted) and **CA11** (egress location) if wanted.
- **A security review of the deployed surface.** The threat model names a
  hosted deployment as a change that warrants one: it adds an internet-facing
  endpoint and server-side sessions holding delegated tokens.

---

## Things that will bite

1. **A revision update signs everyone out.** Sessions are in-process and the
   replica count is pinned to one — not for cost, but because two writers would
   fork the audit chain into two chains that both verify and neither of which
   is the record. The UI detects the lost session and re-runs sign-in, usually
   invisibly against a live Entra session. Documented rather than discovered.
2. **No shell in the container.** See step 5. `doctor` is the diagnostic path
   and it is intact; `exec` is not.
3. **The IP allowlist is a front door, not a firewall.** The ingress FQDN is
   still public DNS. The controls that matter are Entra sign-in, the app-role
   assignment and Conditional Access.
4. **Tearing down.** `az group delete -n rg-dsar-prod-uks-01` will refuse while
   the immutability policy holds blobs, if you have locked it. Unlocked
   policies can be removed first; locked ones cannot, for their full term.
