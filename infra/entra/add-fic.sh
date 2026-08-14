#!/usr/bin/env bash
#
# Add the federated identity credential that lets the hosted app authenticate
# to Entra with no secret.
#
# Separate from provision.sh because it needs something provision.sh cannot
# know: the principal ID of the user-assigned managed identity, which only
# exists after infra/main.bicep has been deployed.
#
#   ./infra/entra/add-fic.sh <hosted-app-id> <uami-principal-id>
#
# Or let it read both from the deployment:
#
#   ./infra/entra/add-fic.sh --from-deployment <deployment-name>
#
# ⚠️ Microsoft's own documentation warns that a federated credential with the
# wrong subject is **created successfully, without error**, and fails only at
# token exchange — hours later, as AADSTS700213, in a log nobody is watching.
# So this script prints the three values back and offers to probe them, rather
# than reporting success on the strength of a 201.

set -euo pipefail

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[33m    %s\033[0m\n' "$*"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# Exactly this, and nothing else is accepted. Not a URL that resolves.
AUDIENCE="api://AzureADTokenExchange"
FIC_NAME="dsar-hosted-uami"

command -v az >/dev/null || die "az CLI is not installed"
TENANT_ID="$(az account show --query tenantId -o tsv)" || die "az is not signed in"
ISSUER="https://login.microsoftonline.com/${TENANT_ID}/v2.0"

if [ "${1:-}" = "--from-deployment" ]; then
  deployment="${2:-}"
  [ -n "${deployment}" ] || die "--from-deployment needs a deployment name"
  APP_ID="${DSAR_HOSTED_APP_ID:-}"
  [ -n "${APP_ID}" ] || die "set DSAR_HOSTED_APP_ID, or pass both arguments"
  SUBJECT="$(az deployment sub show --name "${deployment}" \
    --query properties.outputs.identityPrincipalId.value -o tsv)"
else
  APP_ID="${1:-}"
  SUBJECT="${2:-}"
fi

[ -n "${APP_ID:-}" ]  || die "usage: add-fic.sh <hosted-app-id> <uami-principal-id>"
[ -n "${SUBJECT:-}" ] || die "usage: add-fic.sh <hosted-app-id> <uami-principal-id>"

OBJECT_ID="$(az ad app show --id "${APP_ID}" --query id -o tsv)" \
  || die "no application with appId ${APP_ID}"

say "Federated identity credential"
info "application  ${APP_ID}"
info "issuer       ${ISSUER}"
info "subject      ${SUBJECT}"
info "audience     ${AUDIENCE}"

# The subject is CASE-SENSITIVE and is the managed identity's *principal* ID —
# not its client ID, and not its resource ID. Those two mistakes account for
# most of the "created fine, fails at exchange" reports, and neither produces
# an error here.
warn "subject is case-sensitive and must be the identity's PRINCIPAL id"
warn "(not its client id — DSAR_UAMI_CLIENT_ID is a different GUID)"

existing="$(az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/applications/${OBJECT_ID}/federatedIdentityCredentials" \
  --query "value[?name=='${FIC_NAME}'].id" -o tsv 2>/dev/null || true)"

body="$(python3 - <<PY
import json
print(json.dumps({
    "name": "${FIC_NAME}",
    "issuer": "${ISSUER}",
    "subject": "${SUBJECT}",
    "audiences": ["${AUDIENCE}"],
    "description": "DSAR Assist hosted mode. The user-assigned managed identity mints the client assertion; no secret exists.",
}))
PY
)"

if [ -n "${existing}" ]; then
  info "exists — updating in place"
  # An app may hold at most 20 federated credentials. Updating rather than
  # adding keeps repeated runs idempotent instead of walking towards that cap.
  az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications/${OBJECT_ID}/federatedIdentityCredentials/${existing}" \
    --headers "Content-Type=application/json" \
    --body "${body}" >/dev/null
else
  info "creating"
  az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/applications/${OBJECT_ID}/federatedIdentityCredentials" \
    --headers "Content-Type=application/json" \
    --body "${body}" >/dev/null
fi

say "Created — which is not the same as correct"

cat <<EOF
Entra accepted the credential. That tells you the request was well-formed and
nothing more: a credential whose subject does not match the identity is created
without error and fails only when a token is exchanged.

Two things to do before trusting it.

1. Confirm no credential of any other kind exists on this application. The
   design's claim is that none does:

     az ad app show --id ${APP_ID} \\
       --query "{passwords: passwordCredentials, certs: keyCredentials}"

   Both must be empty. An app management policy should also be blocking
   passwordAddition — see provision.sh.

2. Prove the exchange, from inside the container, with no side effects:

     dsar doctor

   In hosted mode `doctor` runs two extra checks: it mints a client assertion
   and prints its aud/iss/sub for comparison with what was registered above,
   then redeems a deliberately invalid authorization code. The two outcomes of
   that second check are unambiguous, which is the whole point of doing it
   that way:

     invalid_grant   client authentication SUCCEEDED — the FIC is right, and
                     Entra is only objecting to the bogus code
     invalid_client  client authentication FAILED — the FIC is wrong; compare
                     the subject above against the identity's principal id

   Nothing is created either way.

⚠️ Allow for replication. A newly created credential can return
   AADSTS70021 "No matching federated identity record found" for a few minutes.
   That is propagation, not misconfiguration — retry before changing anything.
EOF
