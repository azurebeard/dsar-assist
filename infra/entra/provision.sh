#!/usr/bin/env bash
# Provision the DSAR Assist identity plane in Microsoft Entra ID.
#
# Idempotent: safe to re-run. Every object is looked up before it is created,
# and every property is re-applied, so this script is the definition of what
# the registrations should look like rather than a one-time bootstrap.
#
#   ./infra/entra/provision.sh              # both registrations
#   ./infra/entra/provision.sh desktop      # desktop only
#
# Requires: az CLI, signed in with rights to create applications and grant
# admin consent (Application Administrator + Privileged Role Administrator, or
# Global Administrator).
#
# Entra objects are NOT in Bicep. The Microsoft.Graph Bicep extension is still
# preview, including in Microsoft's own federated-credential samples, so the
# app registrations and their policies live here and the Azure resources live
# in ../main.bicep. Revisit when the extension reaches GA.
set -euo pipefail

GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"

# Delegated permission IDs on Microsoft Graph. Looked up rather than hardcoded
# would be more portable, but these are stable well-known GUIDs and pinning
# them means the script cannot silently request a different permission if a
# lookup returns something unexpected.
SCOPE_EDISCOVERY_RW="acb8f680-0834-4146-b69e-4ab1b39745ad"  # eDiscovery.ReadWrite.All
SCOPE_USER_READ_ALL="a154be20-db9c-4678-8ab7-66f6cc099a59"  # User.Read.All
SCOPE_USER_READ="e1fe6dd8-ba31-4d61-89e7-88639da4683d"      # User.Read

DESKTOP_NAME="${DSAR_DESKTOP_APP_NAME:-DSAR Assist (Desktop)}"
HOSTED_NAME="${DSAR_HOSTED_APP_NAME:-DSAR Assist (Hosted, UK South)}"
DESKTOP_REDIRECT="${DSAR_DESKTOP_REDIRECT:-http://localhost:8765/auth/callback}"
HOSTED_REDIRECT="${DSAR_HOSTED_REDIRECT:-}"

# App role IDs are fixed so that re-running never orphans an assignment. A
# regenerated GUID would silently unassign every operator.
ROLE_OPERATOR_ID="6f1cd1a4-2b7e-4c3d-9a15-8e2f0b7c4d11"
ROLE_AUDITOR_ID="c3b8e07a-9d41-4f62-8a03-1e5c9d2f6b88"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

command -v az >/dev/null || die "az CLI not found"
command -v python3 >/dev/null || die "python3 not found (used to build manifests)"

TENANT_ID="$(az account show --query tenantId -o tsv)"
say "Tenant ${TENANT_ID}"
info "signed in as $(az ad signed-in-user show --query userPrincipalName -o tsv)"

# ---------------------------------------------------------------- app roles

app_roles_json() {
  cat <<JSON
[
  {
    "id": "${ROLE_OPERATOR_ID}",
    "value": "DSAR.Operator",
    "displayName": "DSAR Operator",
    "description": "Create cases and searches, run estimates, initiate exports.",
    "allowedMemberTypes": ["User"],
    "isEnabled": true
  },
  {
    "id": "${ROLE_AUDITOR_ID}",
    "value": "DSAR.Auditor",
    "displayName": "DSAR Auditor",
    "description": "Read-only: list cases and searches, view estimates.",
    "allowedMemberTypes": ["User"],
    "isEnabled": true
  }
]
JSON
}

# Optional claims. `roles` is not requested here — it is emitted by virtue of an
# app-role assignment, not by an optional-claims entry. The rest are:
#   login_hint  feeds logout_hint and silent re-auth
#   acrs        the satisfied Conditional Access authentication context
#   xms_cc      proves the STS agreed to the CAE capability we declared
#   amr         what authentication actually happened, for the audit record
#   auth_time   supports max_age freshness checks
optional_claims_json() {
  cat <<'JSON'
{
  "idToken": [
    {"name": "login_hint", "essential": false},
    {"name": "acrs",       "essential": false},
    {"name": "xms_cc",     "essential": false},
    {"name": "amr",        "essential": false},
    {"name": "auth_time",  "essential": false}
  ],
  "accessToken": [],
  "saml2Token": []
}
JSON
}

required_resource_access_json() {
  local with_user_read_all="$1"
  local extra=""
  if [ "$with_user_read_all" = "yes" ]; then
    extra=",{\"id\": \"${SCOPE_USER_READ_ALL}\", \"type\": \"Scope\"}"
  fi
  cat <<JSON
[{
  "resourceAppId": "${GRAPH_APP_ID}",
  "resourceAccess": [
    {"id": "${SCOPE_EDISCOVERY_RW}", "type": "Scope"},
    {"id": "${SCOPE_USER_READ}", "type": "Scope"}
    ${extra}
  ]
}]
JSON
}

find_app_id() {
  az ad app list --filter "displayName eq '$1'" --query "[0].appId" -o tsv 2>/dev/null || true
}

# ------------------------------------------------------------------ desktop

provision_desktop() {
  say "Desktop registration — ${DESKTOP_NAME}"

  local app_id
  app_id="$(find_app_id "${DESKTOP_NAME}")"
  if [ -z "${app_id}" ]; then
    info "creating"
    app_id="$(az ad app create --display-name "${DESKTOP_NAME}" \
      --sign-in-audience AzureADMyOrg --query appId -o tsv)"
  else
    info "exists — reapplying properties"
  fi

  local object_id
  object_id="$(az ad app show --id "${app_id}" --query id -o tsv)"

  # A public client. `isFallbackPublicClient` is what makes Entra treat it as
  # one; the redirect URI goes under publicClient, not web. Implicit and hybrid
  # flows are explicitly disabled — RFC 9700 (BCP 240) removes implicit, and a
  # registration that can issue tokens on the front channel is a registration
  # someone can misuse.
  #
  # Exactly ONE loopback URI is registered. RFC 8252 §7.3 has the server ignore
  # the port when matching localhost, but two localhost URIs differing only by
  # port are chosen between arbitrarily, so registering a second is a bug not a
  # belt-and-braces.
  az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications/${object_id}" \
    --headers "Content-Type=application/json" \
    --body "$(python3 - <<PY
import json
print(json.dumps({
    "isFallbackPublicClient": True,
    "signInAudience": "AzureADMyOrg",
    "groupMembershipClaims": None,
    "publicClient": {"redirectUris": ["${DESKTOP_REDIRECT}"]},
    "web": {
        "redirectUris": [],
        "implicitGrantSettings": {
            "enableIdTokenIssuance": False,
            "enableAccessTokenIssuance": False,
        },
    },
    "spa": {"redirectUris": []},
    "appRoles": json.loads('''$(app_roles_json)'''),
    "optionalClaims": json.loads('''$(optional_claims_json)'''),
    "requiredResourceAccess": json.loads('''$(required_resource_access_json yes)'''),
    "tags": ["DSAR", "Production", "PublicClient", "NoCredentials"],
}))
PY
)" >/dev/null
  info "appId ${app_id}"
  info "redirect ${DESKTOP_REDIRECT}"

  ensure_sp "${app_id}" "${DESKTOP_NAME}"
  assert_no_credentials "${object_id}" "${DESKTOP_NAME}"

  DESKTOP_APP_ID="${app_id}"
}

# ------------------------------------------------------------------- hosted

provision_hosted() {
  if [ -z "${HOSTED_REDIRECT}" ]; then
    say "Hosted registration — skipped"
    info "Set DSAR_HOSTED_REDIRECT to the https callback URL to provision it."
    info "It is not needed until Phase 5; the demo runs desktop mode."
    return 0
  fi

  say "Hosted registration — ${HOSTED_NAME}"
  local app_id
  app_id="$(find_app_id "${HOSTED_NAME}")"
  if [ -z "${app_id}" ]; then
    info "creating"
    app_id="$(az ad app create --display-name "${HOSTED_NAME}" \
      --sign-in-audience AzureADMyOrg --query appId -o tsv)"
  else
    info "exists — reapplying properties"
  fi

  local object_id
  object_id="$(az ad app show --id "${app_id}" --query id -o tsv)"
  local base="${HOSTED_REDIRECT%/auth/callback}"

  az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications/${object_id}" \
    --headers "Content-Type=application/json" \
    --body "$(python3 - <<PY
import json
print(json.dumps({
    "isFallbackPublicClient": False,
    "signInAudience": "AzureADMyOrg",
    "groupMembershipClaims": None,
    "publicClient": {"redirectUris": []},
    "spa": {"redirectUris": []},
    "web": {
        "redirectUris": ["${HOSTED_REDIRECT}", "${base}/auth/post-logout"],
        "logoutUrl": "${base}/auth/signed-out",
        "implicitGrantSettings": {
            "enableIdTokenIssuance": False,
            "enableAccessTokenIssuance": False,
        },
    },
    "appRoles": json.loads('''$(app_roles_json)'''),
    "optionalClaims": json.loads('''$(optional_claims_json)'''),
    "requiredResourceAccess": json.loads('''$(required_resource_access_json yes)'''),
    "tags": ["DSAR", "Production", "ConfidentialClient", "FIC-ManagedIdentity"],
}))
PY
)" >/dev/null
  info "appId ${app_id}"
  info "redirect ${HOSTED_REDIRECT}"

  ensure_sp "${app_id}" "${HOSTED_NAME}"

  # No secret, no certificate. The client assertion is minted at runtime by a
  # user-assigned managed identity through a federated identity credential,
  # added separately once the Container App exists (it needs the UAMI principal
  # ID as the FIC subject). Deliberately not created here so this script never
  # produces a credential of any kind.
  info "no credential created — the FIC is added by infra/entra/add-fic.sh"

  HOSTED_APP_ID="${app_id}"
}

# ------------------------------------------------------------------ helpers

ensure_sp() {
  local app_id="$1" name="$2"
  local sp_id
  sp_id="$(az ad sp list --filter "appId eq '${app_id}'" --query "[0].id" -o tsv 2>/dev/null || true)"
  if [ -z "${sp_id}" ]; then
    sp_id="$(az ad sp create --id "${app_id}" --query id -o tsv)"
    info "service principal created"
  fi

  # Assignment required. This is what gates access at the identity provider, so
  # it holds even in desktop mode where the operator controls the process and
  # the in-process role check is only advisory.
  #
  # Known limit, stated rather than overclaimed: Global Administrators bypass
  # appRoleAssignmentRequired.
  az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${sp_id}" \
    --headers "Content-Type=application/json" \
    --body '{"appRoleAssignmentRequired": true}' >/dev/null
  info "assignment required = true (sp ${sp_id})"
}

assert_no_credentials() {
  local object_id="$1" name="$2"
  # Queried one at a time. A single array query returns newline-separated
  # values under `-o tsv`, which reads as "0\n0" and compares unequal to
  # anything sensible — the first version of this check failed on a
  # registration that was in fact clean. A security assertion that cries wolf
  # gets disabled, so it is worth the three extra calls to be unambiguous.
  local passwords keys fic
  passwords="$(az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/applications/${object_id}" \
    --query "length(passwordCredentials)" -o tsv)"
  keys="$(az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/applications/${object_id}" \
    --query "length(keyCredentials)" -o tsv)"
  fic="$(az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/applications/${object_id}/federatedIdentityCredentials" \
    --query "length(value)" -o tsv)"
  if [ "${passwords}" != "0" ] || [ "${keys}" != "0" ] || [ "${fic}" != "0" ]; then
    die "${name} holds credentials (passwords: ${passwords}, keys: ${keys}, \
federated: ${fic}). The desktop registration must hold none of any kind — that \
is what makes 'this application cannot authenticate as itself' mechanically \
checkable."
  fi
  info "credentials: none (verified)"
}

# ------------------------------------------------------------------ consent

grant_consent() {
  local app_id="$1"
  say "Admin consent — ${app_id}"
  # Both scopes are admin-restricted, and `appRoleAssignmentRequired` disallows
  # user consent entirely, so consent must be granted by an administrator.
  # There is no configuration in which a runtime consent prompt does anything
  # useful here — which is why incremental consent was ruled out of the design
  # in favour of Conditional Access authentication context.
  if az ad app permission admin-consent --id "${app_id}" 2>/dev/null; then
    info "granted"
  else
    info "could not grant automatically — grant it in the portal:"
    info "  Entra ID > App registrations > API permissions > Grant admin consent"
  fi
}

# --------------------------------------------------------------------- main

TARGET="${1:-all}"
DESKTOP_APP_ID=""
HOSTED_APP_ID=""

case "${TARGET}" in
  desktop) provision_desktop ;;
  hosted)  provision_hosted ;;
  all)     provision_desktop; provision_hosted ;;
  *)       die "usage: $0 [desktop|hosted|all]" ;;
esac

[ -n "${DESKTOP_APP_ID}" ] && grant_consent "${DESKTOP_APP_ID}"
[ -n "${HOSTED_APP_ID}" ] && grant_consent "${HOSTED_APP_ID}"

say "Done"
if [ -n "${DESKTOP_APP_ID}" ]; then
  cat <<EOF

Desktop mode — export these and run the tool. Neither is a secret.

  export DSAR_CLIENT_ID=${DESKTOP_APP_ID}
  export DSAR_TENANT_ID=${TENANT_ID}

Still to do by hand, because each is a decision rather than a step:

  1. Assign operators to an app role. Nobody can sign in until you do —
     that is appRoleAssignmentRequired working.
       Entra ID > Enterprise applications > ${DESKTOP_NAME} > Users and groups

     WATCH FOR THIS: granting admin consent can leave a "Default Access"
     assignment whose appRoleId is the all-zero GUID. It satisfies
     appRoleAssignmentRequired, so the user signs in fine — but no DSAR role
     reaches the token, and an in-process role check refuses them for reasons
     the portal does not make obvious. Check with:

       az rest --method GET --uri \\
         "https://graph.microsoft.com/v1.0/servicePrincipals/<spId>/appRoleAssignedTo" \\
         --query "value[].{who:principalDisplayName, role:appRoleId}" -o table

     Any 00000000-... row is default access. Delete it and assign a real role.

  2. Conditional Access. Start CA01 (phishing-resistant MFA) and CA04
     (4h sign-in frequency, never-persistent browser) in REPORT-ONLY against
     this enterprise app. See docs/DESIGN.md for the full policy set.

  3. Purview. The operator needs an eDiscovery role; this application grants
     nothing on its own and cannot elevate.
EOF
fi
