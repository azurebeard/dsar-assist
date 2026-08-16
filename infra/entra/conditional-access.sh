#!/usr/bin/env bash
#
# The Conditional Access policy set, created in REPORT-ONLY.
#
#   ./infra/entra/conditional-access.sh            # create/update, report-only
#   ./infra/entra/conditional-access.sh --list     # show what exists
#
# Report-only is not a half measure here. These policies gate the tool that
# handles other people's personal data, and the two that will hurt — compliant
# device on the desktop app, and blocking high sign-in risk tenant-wide — hurt
# in ways you want to see in a log before you see them in a support call.
# Microsoft's own guidance for the device policy is report-only for at least
# two weeks. Everything below reports until a human moves it.
#
# ⚠️ EVERY policy excludes the break-glass account. That exclusion is the
# difference between "switch this to enforce" being reversible and being a
# lockout, and this script REFUSES TO RUN if it cannot find one — because a
# policy set built without it is a trap laid for whoever enables it later.
#
# Idempotent: matches on displayName and PATCHes rather than creating twice.

set -euo pipefail

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[33m    %s\033[0m\n' "$*"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

GRAPH="https://graph.microsoft.com/v1.0"
POLICIES="${GRAPH}/identity/conditionalAccess/policies"

# Report-only. The Graph value is deliberately verbose; that is the point.
STATE="enabledForReportingButNotEnforced"

# The two DSAR registrations, by application id. No defaults: this repository
# is public, and a structural test refuses a committed tenant identifier —
# which is how the first version of this file was caught. Take them from the
# tenant, or set them in the environment.
HOSTED_APP="${DSAR_HOSTED_APP_ID:-}"
if [ -z "${HOSTED_APP}" ]; then
  HOSTED_APP="$(az ad app list --filter "displayName eq 'DSAR Assist (Hosted, UK South)'" \
    --query "[0].appId" -o tsv 2>/dev/null || true)"
fi

# Built-in authentication strength policies. These GUIDs are fixed by
# Microsoft and identical in every tenant:
#   ...0002 multifactor authentication
#   ...0003 passwordless MFA
#   ...0004 phishing-resistant MFA
PHISHING_RESISTANT="00000000-0000-0000-0000-000000000004"

command -v az >/dev/null || die "az CLI is not installed"
az account show >/dev/null 2>&1 || die "az is not signed in"

if [ "${1:-}" = "--list" ]; then
  say "Conditional Access policies in this tenant"
  az rest --method GET --uri "${POLICIES}" \
    --query "value[].{name:displayName, state:state}" -o table
  exit 0
fi

# ------------------------------------------------------------- break-glass

say "Break-glass account"
BREAK_GLASS="${DSAR_BREAK_GLASS_ID:-}"
if [ -z "${BREAK_GLASS}" ]; then
  # Reuse whatever the tenant's existing policies already exclude, rather than
  # inventing a second convention. If policies disagree, that is a finding in
  # itself and the script stops rather than guessing which is right.
  BREAK_GLASS="$(az rest --method GET --uri "${POLICIES}" \
    --query "value[].conditions.users.excludeUsers[]" -o tsv 2>/dev/null \
    | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')"
fi

[ -n "${HOSTED_APP}" ] || die "the hosted app registration was not found. Run \
./infra/entra/provision.sh hosted first, or set DSAR_HOSTED_APP_ID."

[ -n "${BREAK_GLASS}" ] || die "no break-glass account found, and none given in \
DSAR_BREAK_GLASS_ID. Refusing to create policies that nobody is excluded from \
— switching one of these to enforce could then lock every administrator out."

BG_NAME="$(az rest --method GET --uri "${GRAPH}/users/${BREAK_GLASS}" \
  --query "userPrincipalName" -o tsv 2>/dev/null || echo "")"
[ -n "${BG_NAME}" ] || die "break-glass id ${BREAK_GLASS} does not resolve to a user"
info "excluding ${BG_NAME}"
info "id ${BREAK_GLASS}"

# ------------------------------------------------------------------ helper

upsert() {
  # upsert <display-name> <json-body>
  local name="$1" body="$2" existing
  existing="$(az rest --method GET --uri "${POLICIES}" \
    --query "value[?displayName=='${name}'].id | [0]" -o tsv 2>/dev/null || true)"

  if [ -n "${existing}" ] && [ "${existing}" != "None" ]; then
    az rest --method PATCH --uri "${POLICIES}/${existing}" \
      --headers "Content-Type=application/json" --body "${body}" >/dev/null
    info "updated   ${name}"
  else
    az rest --method POST --uri "${POLICIES}" \
      --headers "Content-Type=application/json" --body "${body}" >/dev/null
    info "created   ${name}"
  fi
}

policy_json() {
  # policy_json <name> <apps-json> <grant-or-session-json> [risk-json]
  python3 - "$1" "$2" "$3" "${4:-{\}}" "${STATE}" "${BREAK_GLASS}" <<'PY'
import json, sys
name, apps, controls, extra, state, break_glass = sys.argv[1:7]
body = {
    "displayName": name,
    "state": state,
    "conditions": {
        "applications": json.loads(apps),
        "users": {
            "includeUsers": ["All"],
            # The one exclusion that makes any of this reversible.
            "excludeUsers": [break_glass],
        },
        "clientAppTypes": ["all"],
        **json.loads(extra),
    },
    **json.loads(controls),
}
print(json.dumps(body))
PY
}

# ⚠️ THE DESKTOP APP CANNOT BE TARGETED BY CONDITIONAL ACCESS.
#
# Entra refuses it outright: `1034: Policy contains invalid applications:
# {"<desktop-app-id>": "PublicClientsAreUnsupported"}`. Verified both ways —
# the hosted registration (isFallbackPublicClient: false) is accepted, the
# desktop one (true) is refused.
#
# The design assumed CA01, CA03 and CA04 could target "both DSAR SPs". They
# cannot. CA targets the RESOURCE being reached, and a public client is not a
# resource. So policy scoped to the desktop CLIENT does not exist as an
# option, and the desktop path's controls are:
#
#   appRoleAssignmentRequired    who may get a token at all
#   tenant-wide CA on the user   whatever applies to them everywhere
#   Purview RBAC                 what they can actually do with it
#
# CA03 is therefore not "report-only pending a decision". There is no decision
# to make: it cannot be built. That is a correction to DESIGN.md, not a
# deferral.
DSAR_APPS="{\"includeApplications\": [\"${HOSTED_APP}\"]}"
ALL_APPS='{"includeApplications": ["All"]}'

# --------------------------------------------------------------- the set

say "DSAR application policies — report-only"

# CA01 · Phishing-resistant MFA. The threat model's compensating control for a
# stolen refresh token: it cannot be re-minted on a device without the key.
# Hosted only — see the note above.
upsert "DSAR — CA01 phishing-resistant MFA" "$(policy_json \
  "DSAR — CA01 phishing-resistant MFA" "${DSAR_APPS}" \
  "{\"grantControls\": {\"operator\": \"OR\", \"builtInControls\": [], \
     \"authenticationStrength\": {\"id\": \"${PHISHING_RESISTANT}\"}}}")"

# CA04 · Session lifetime. Time-based, NOT "every time": re-authenticating on
# every request produces MFA fatigue and sign-in looping, and the app's own 8h
# session sits outside this deliberately.
#
# ⚠️ `persistentBrowser` is NOT set here, and cannot be. Entra refuses it on an
# app-scoped policy — `1032: InvalidConditionsForPersistentBrowserSessionMode`
# — because "never persistent" is only meaningful across every app a browser
# session spans. Setting it would mean a tenant-wide policy changing sign-in
# behaviour for everything, which is a much larger decision than this one and
# is not made here.
#
# The consequence, stated rather than assumed: a browser session on the hosted
# app may persist across restarts. The 4-hour sign-in frequency below is what
# bounds it, along with the app's own 8h absolute and 60m idle session.
upsert "DSAR — CA04 sign-in frequency" "$(policy_json \
  "DSAR — CA04 sign-in frequency" "${DSAR_APPS}" \
  '{"sessionControls": {"signInFrequency": {"value": 4, "type": "hours",
      "authenticationType": "primaryAndSecondaryAuthentication", "isEnabled": true}}}')"

# CA02 · Compliant device, HOSTED only. The hosted endpoint is reachable from
# the internet, so the device posture is worth more there.
upsert "DSAR — CA02 compliant device (hosted)" "$(policy_json \
  "DSAR — CA02 compliant device (hosted)" \
  "{\"includeApplications\": [\"${HOSTED_APP}\"]}" \
  '{"grantControls": {"operator": "OR",
      "builtInControls": ["compliantDevice", "domainJoinedDevice"]}}')"

# CA03 is NOT created. It targeted the desktop app, which Conditional Access
# cannot target at all. See the note above the app list — this is a design
# correction, not something waiting on a decision.

say "Tenant-wide policies — report-only"

# CA06 · Device code flow and authentication transfer. DSAR Assist never uses
# either; both are phishing vectors aimed squarely at the kind of privileged
# operator this tool has. Microsoft's guidance is to get as close to a
# unilateral block as the tenant allows.
upsert "DSAR — CA06 block device code and auth transfer" "$(policy_json \
  "DSAR — CA06 block device code and auth transfer" "${ALL_APPS}" \
  '{"grantControls": {"operator": "OR", "builtInControls": ["block"]}}' \
  '{"authenticationFlows": {"transferMethods": "deviceCodeFlow,authenticationTransfer"}}')"

# CA08 · High sign-in risk. The tenant already requires MFA on sign-in risk;
# this blocks instead, which is stronger. Report-only shows the difference
# before anyone commits to it.
upsert "DSAR — CA08 block high sign-in risk" "$(policy_json \
  "DSAR — CA08 block high sign-in risk" "${ALL_APPS}" \
  '{"grantControls": {"operator": "OR", "builtInControls": ["block"]}}' \
  '{"signInRiskLevels": ["high"]}')"

# CA09 · High user risk. Password change plus MFA, which is the remediation
# path rather than a block — a compromised account should be recoverable.
upsert "DSAR — CA09 high user risk remediation" "$(policy_json \
  "DSAR — CA09 high user risk remediation" "${ALL_APPS}" \
  '{"grantControls": {"operator": "AND",
      "builtInControls": ["mfa", "passwordChange"]}}' \
  '{"userRiskLevels": ["high"]}')"

say "Done — everything above is REPORT-ONLY and enforces nothing"

cat <<EOF
Not created, and why:

  CA05  step-up on create-case and export. It targets an authentication
        CONTEXT rather than an application, and this token cannot read or
        create one — the az CLI's Graph scopes do not include
        Policy.ReadWrite.ConditionalAccess. Create the context in the portal
        (Entra ID > Protection > Conditional Access > Authentication context),
        then the app already knows how to demand it: the claims challenge and
        the acrs check are built and tested.

  CA07  block legacy authentication. ALREADY EXISTS in this tenant and is
        ENABLED. Not duplicated.

  CA10  Purview portal controls. That is where the data plane actually lives,
        and it is a decision about the portal rather than about this tool.

  CA11  egress named location for the hosted app. Only worth it if Container
        Apps egress is a fixed NAT address, and it must be IP-range based —
        country and MFA trusted IPs are invisible to CAE.

Overlap worth knowing: the tenant already has "[XDR Demo] Require MFA for all
users" ENABLED, granting plain MFA. CA01 above asks for phishing-resistant on
the DSAR apps specifically. Until CA01 is enforced, the threat model's
"phishing-resistant MFA" compensating control is NOT in place — plain MFA is.

Next:
  1. Leave these for a fortnight and read Insights and Reporting > Report-only.
  2. CA03 is the decision. If it catches the operators you expect to catch,
     enforce hosted and leave desktop reporting.
  3. Re-run this script to update; it matches on name and will not duplicate.
EOF
