# WS10 Security Review — hosted mode (B-03)

**Date:** 2026-08-14 · **Reviewer:** WS10 Security Reviewer
**Scope:** the hosted delta only — the internet-facing endpoint, server-side
sessions holding delegated tokens for multiple operators, the federated
identity credential, the append-blob audit sink, and `infra/`. Desktop mode is
not re-reviewed; `THREAT-MODEL.md` item 6 is the trigger for this pass.

**Verdict: APPROVED WITH CONDITIONS.** Two conditions, both listed at the end.
One High, six Medium, five Low. The identity design is sound and the storage
posture is better than most things I review. The High is not in the auth
path — it is in the audit trail, and it fires on a routine deployment.

**Instance reviewed:** `rg-dsar-prod-uks-01` /
`ca-dsar-prod-uks-01` / `stdsarproduks01` / `id-dsar-prod-uks-01`, subscription
`58ffe548-…`. The revision changed under me during the review
(`--0000004` → `--0000005`, image `9c31f82a…` → `b4554476…` at 22:05Z); every
configuration claim below was re-checked against `--0000005`.

**Baseline established:** `284 passed`, `mypy --strict` clean on 43 source
files, both run at review time.

---

## Deployed configuration versus the template's claims

Every property the Bicep calls out as load-bearing was read back off the live
resource. All match.

| Claim | Template | Deployed | |
|---|---|---|---|
| No secret in the deployment | `secrets: []` | `secrets: null` (empty) | ✅ |
| No registry credential | `registries: []` | `[]` | ✅ |
| No plaintext listener | `allowInsecure: false` | `false` | ✅ |
| One replica | `min/maxReplicas: 1` | `1` / `1` | ✅ **but see SEC-H-01** |
| User-assigned identity only | `type: 'UserAssigned'` | `UserAssigned`, one identity | ✅ |
| Image by digest | digest parameter | `ghcr.io/…@sha256:b4554476…` | ✅ |
| No shared key | `allowSharedKeyAccess: false` | `false` | ✅ |
| No public blob | `allowBlobPublicAccess: false` | `false` | ✅ |
| TLS floor | `TLS1_2` | `TLS1_2`, `enableHttpsTrafficOnly: true` | ✅ |
| WORM on the audit container | `allowProtectedAppendWrites: true`, 2555 days | same, **`state: Unlocked`** | ⚠️ SEC-M-03 |
| Ingress restricted | `ipSecurityRestrictions` | `86.28.200.50/32` | ⚠️ SEC-L-03 |
| Identity is dedicated | comment | **exactly one role assignment**, Storage Blob Data Contributor at *container* scope | ✅ |

Entra side, read live:

* Hosted app `6864d88d-…` holds `passwordCredentials: []`, `keyCredentials: []`,
  one federated credential (`issuer` = the tenant v2.0 endpoint, `subject` =
  `0fb44ef4-…` which is the UAMI's principal id, `audiences` =
  `["api://AzureADTokenExchange"]`). `signInAudience: AzureADMyOrg`,
  `isFallbackPublicClient: false`, implicit grant off for both token types.
* Service principal: `appRoleAssignmentRequired: true`.
* Application permissions granted to the app: **none** (`appRoleAssignments` on
  the SP is `[]`). This matters — see SEC-M-06.
* Delegated consent present: `eDiscovery.ReadWrite.All offline_access openid
  profile`, `consentType: Principal` for one user. `User.Read.All` is requested
  and not granted, so identity expansion will 403 and degrade as designed.

Live response probe (from inside the allowed /32):

```
GET /healthz  -> 200 {"status":"ok"}            # no version, no tenant
GET /.env     -> 404, logged as "GET <unmatched>"
GET /api/whoami (anon) -> 401 {"signed_in":false}
POST /auth/logout (no Origin) -> 403 {"error":"bad_origin"}
GET /auth/login -> 302, Set-Cookie: __Host-dsar_flow=…; HttpOnly; Max-Age=300; Path=/; SameSite=lax; Secure
```
Full header set present including HSTS and `default-src 'none'`. No `Server`
header. Authorize URL carries `code_challenge_method=S256`,
`prompt=select_account`, `claims={"access_token":{"xms_cc":{"values":["cp1"]}}}`,
and the exact registered `redirect_uri`.

---

## SEC-H-01 · A revision rollout runs two writers against one audit blob, and the assertion cited as the guard cannot detect it

**Severity:** High
**Location:** `infra/modules/containerapp.bicep:91-105` · `src/dsar/audit/blob.py:173-188`
(`head()`) · `src/dsar/audit/trail.py:26` · `tests/test_structural.py:898`
(`test_the_container_app_is_pinned_to_one_replica`)

**Finding.** The Bicep pins `minReplicas: 1` / `maxReplicas: 1` and says why:
*"two writers would each believe they held it, and the trail would fork into
two chains that both verify and neither of which is the record."* The reasoning
is right. The bound is not. `maxReplicas` is a **per-revision** limit. During a
single-revision rolling transition Container Apps starts the new revision's
replica and only stops the old one once the new one is healthy — so every
deployment produces a window in which two `dsar` processes are running, each
having read `head()` once at start and each trusting it for the rest of its
life.

The structural test asserts the literal strings `minReplicas: 1` and
`maxReplicas: 1` are present in the Bicep. Both are present. Both are true. The
test passes and cannot fail while the property it is cited for is violated on
every deploy. This is HANDOVER §7's pattern again.

**Evidence — the window is real, measured on this instance.** From
`ContainerAppSystemLogs_CL` in `log-dsar-prod-uks-01`:

```
ContainerStarted    ca-dsar-prod-uks-01--0000004   2026-08-14T21:39:40.75Z
StoppingContainer   ca-dsar-prod-uks-01--0000003   2026-08-14T21:40:26.79Z   → 46s overlap
ContainerStarted    ca-dsar-prod-uks-01--0000005   2026-08-14T22:05:24.77Z
StoppingContainer   ca-dsar-prod-uks-01--0000004   2026-08-14T22:06:01.82Z   → 37s overlap
ContainerStarted    ca-dsar-prod-uks-01--4pfsqhn   2026-08-14T21:06:20.69Z
ContainerStarted    ca-dsar-prod-uks-01--0000001   2026-08-14T21:07:52.70Z
ContainerStarted    ca-dsar-prod-uks-01--0000002   2026-08-14T21:13:54.73Z
ContainerStarted    ca-dsar-prod-uks-01--0000003   2026-08-14T21:14:55.92Z
StoppingContainer   ca-dsar-prod-uks-01--4pfsqhn   2026-08-14T21:15:47.88Z   → four revisions' containers alive at 21:15
```

A KQL bin of console logs to one minute, `where dcount(RevisionName_s) > 1`,
returns **nine distinct minutes** across the instance's short life.

**Evidence — the consequence, run rather than reasoned.** Two `AuditTrail`
objects over one shared sink, the second constructed after the first has
written, exactly as a rollout produces:

```
records in the blob: 5
seqs: [1, 2, 2, 3, 3]
5 record(s), 5 break(s). First at seq 2: broken link — prev_hash does not match
the previous record; a record was removed or inserted here
  seq 2: out of order - expected seq 3
  seq 3: broken link  (×2)
  seq 3: out of order - expected seq 4
```

So the Bicep comment is wrong in the reader's favour and wrong in the operator's:
the forked trail does **not** produce "two chains that both verify". It produces
one trail that `dsar audit verify` reports as **tampered**, naming a record
removal that never happened. For a DSAR evidence artefact that is the worse
outcome. And because the container carries a 2555-day immutability policy with
`allowProtectedAppendWrites`, the offending records can never be removed — the
trail is permanently unverifiable from that seq onwards.

**Not yet realised.** I reconstructed the live trail independently from the
Log Analytics copy (22 records, seq 1–22) and ran `verify_chain` over it:
`22 record(s), chain intact.` Records 1–11 were written by `--0000003` and
12–22 by `--0000004`, with a clean handover — the overlap windows happened to
contain no audit-generating activity. This is latent, not live.

**Recommendation.** Stop relying on replica pinning for the single-writer
property; it is not a property Container Apps offers. Use the primitive the
service provides: send `x-ms-blob-condition-appendpos` on every
`comp=appendblock`, set to the writer's believed blob length. A second writer
then gets `412 AppendPositionConditionNotMet` instead of forking, and
`AppendBlobSink.append` can re-read `head()` and retry — which turns the fork
into a correctness mechanism rather than a deployment hazard. Failing that,
teach `verify_chain` to name a fork as a fork (duplicate `seq` with divergent
`prev_hash`) rather than as a removal, and gate deployments on zero active
sessions. Either way, delete the claim from the Bicep comment or make it true.

---

## SEC-M-01 · "Both registrations hold zero credentials, asserted mechanically" is asserted for one registration, and blocked for neither

**Severity:** Medium
**Location:** `infra/entra/provision.sh:179`, `:274-299` · `docs/THREAT-MODEL.md:153-155`
· `infra/entra/add-fic.sh` (closing text)

**Finding.** The threat model's §4 elevation control reads: *"No secret exists
anywhere … Both registrations hold zero credentials, asserted mechanically."*
`assert_no_credentials()` is a good check — it queries `passwordCredentials`,
`keyCredentials` and `federatedIdentityCredentials` separately, with a comment
explaining why the combined query gave a wrong answer. It is called exactly
once, at `provision.sh:179`, inside the **desktop** branch. `provision_hosted()`
never calls it. So the mechanical assertion covers one of the two registrations,
and it is not the internet-facing one.

`add-fic.sh` tells the operator *"An app management policy should also be
blocking passwordAddition — see provision.sh."* There is no app management
policy anywhere in the repository — `rg appManagementPolicy infra/` returns
nothing — and none exists in the tenant.

**Evidence.**

```
$ rg -n "assert_no_credentials" infra/entra/provision.sh
179:  assert_no_credentials "${object_id}" "${DESKTOP_NAME}"
274:assert_no_credentials() {

$ az rest --uri ".../applications(appId='6864d88d-…')/appManagementPolicies"
  "value": []

$ az rest --uri "https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy"
  "applicationRestrictions": { "keyCredentials": [], "passwordCredentials": [] }
  "servicePrincipalRestrictions": { "keyCredentials": [], "passwordCredentials": [] }
```

The registration is clean today (`passwords: []`, `certs: []`, verified). Nothing
keeps it that way and nothing would notice.

**Why Medium and not High.** The actor who can add a secret already holds
Application Administrator or better, and could do considerably worse elsewhere
in the tenant. The marginal privilege is small. What is not small is that the
design's central claim — *the FIC is the only path to client authentication,
which is why "who can run code as the UAMI" is the whole blast radius* — stops
being true the moment a secret is added, and unlike the UAMI path a secret is
portable and usable from anywhere.

**Recommendation.** Call `assert_no_credentials` in the hosted branch too.
Create an `appManagementPolicy` on both applications denying
`passwordAddition` (and `keyAddition`, or `asymmetricKeyLifetime` if
certificates are ever wanted), applied from `provision.sh` so it is part of the
deployment rather than a note. Add a `doctor` hosted check that reads
`passwordCredentials` off its own registration and FAILs on non-empty — the
existing secret-shaped-environment check answers a different question.

---

## SEC-M-02 · Three compensating controls the documents name as real are not configured in this tenant

**Severity:** Medium
**Location:** `docs/THREAT-MODEL.md:163` (the token-theft row) · `docs/DESIGN.md:135`
· `docs/DESIGN.md:180-183` · `src/dsar/auth/session.py:60-62`

**Finding.** Three controls are cited as present and compensating. None exists.

1. **Phishing-resistant MFA.** THREAT-MODEL's "Not mitigated" table compensates
   token theft with *"phishing-resistant MFA so a stolen refresh token cannot be
   re-minted on a new device."* DESIGN §4 repeats it in the list headed
   *"Compensating controls, which are real."*
2. **CA04, a 4-hour sign-in frequency.** `session.py:60-62` sets
   `ABSOLUTE_TTL_SECONDS = 8h` with the comment *"Inside CA04's 4-hour sign-in
   frequency plus slack, so Conditional Access rather than this constant is what
   governs session lifetime."*
3. **Conditional Access on the hosted ingress.** DESIGN §3's control table lists
   the hosted row as *"ingress with `allowInsecure: false`,
   `ipSecurityRestrictions`, Conditional Access."*

**Evidence.** `GET /identity/conditionalAccess/policies` returns 7 policies.
None names the DSAR application in `includeApplications`; none excludes it. The
enabled ones that reach it via `includeApplications: ["All"]` are:

```
Block legacy authentication            enabled     grants=['block']
[XDR Demo] Require MFA for all users   enabled     grants=['mfa']          authenticationStrength: none
[XDR Demo] User risk - require MFA     enabled     grants=['mfa']          authenticationStrength: none
[XDR Demo] Sign-in risk - require MFA  enabled     grants=['mfa']          authenticationStrength: none
Allow Trusted Location                 enabledForReportingButNotEnforced
```

No policy in the tenant sets `sessionControls.signInFrequency` at all. The MFA
grant is the built-in control, not an authentication strength — it is satisfied
by Authenticator push, SMS and voice, all phishable. The only named-location
policy is report-only.

The consequence for (2) is the sharper one: the code's 8-hour absolute and
1-hour idle TTLs are not "inside" anything. They **are** the session lifetime,
and the comment says the opposite, which is how a constant gets loosened later
by someone who believes something else is holding the line.

**Recommendation.** Either configure them — an authentication strength of
`Phishing-resistant MFA` and a `signInFrequency` of 4 hours, both scoped to the
two DSAR applications, which is B-05's decision arriving anyway — or strike all
three claims from the documents in the same commit. Until one of those happens,
the token-theft residual in THREAT-MODEL has exactly two compensating controls:
in-memory-only tokens, and `cp1` — and `cp1` is itself unproven (B-04, open).

---

## SEC-M-03 · The audit trail's second copy shares the first copy's blast radius, expires first, and nothing logs access to either

**Severity:** Medium
**Location:** `infra/modules/platform.bicep:12-26`, `:102-119` · `docs/THREAT-MODEL.md:135-138`
· `src/dsar/audit/sink.py:79-95`

**Finding, in four parts.** The question asked was what the UNLOCKED policy
buys. Plainly:

**What it does buy, and this is the important half.** With
`state: Unlocked`, `immutabilityPeriodSinceCreationInDays: 2555` and
`allowProtectedAppendWrites: true`, a principal holding only the *data-plane*
role cannot overwrite or delete a blob already in the container; only appends to
append blobs are permitted. The internet-facing process holds exactly that role
and nothing else — verified: `id-dsar-prod-uks-01` has **one** role assignment
in the whole subscription, Storage Blob Data Contributor scoped to the `audit`
container. So the component most likely to be compromised is the component that
cannot destroy the evidence. That is a real and well-chosen property.

**What it does not buy.** Nothing against the management plane. Deleting an
unlocked immutability policy is one `DELETE` on
`.../containers/audit/immutabilityPolicies/default`, available to Owner,
Contributor and Storage Account Contributor. After that the blobs, the
container and the account are all deletable. There is no resource lock:
`az lock list -g rg-dsar-prod-uks-01` returns empty. Locking is irreversible
and is correctly left as a human decision — but it is currently recorded as a
note rather than a go-live gate, and this instance is already carrying real
records.

**The second copy is not in a different trust domain.** THREAT-MODEL §3's
residual leans on *"the stderr sink, which on Container Apps lands in Log
Analytics, a different trust domain."* The sink works — I verified it end to end
and it is the reason SEC-H-01 above could be assessed at all:

```
$ # reconstruct the trail from ContainerAppConsoleLogs_CL and verify it
records recovered from Log Analytics: 22   seq range: 1 - 22
verify_chain over the LA copy: 22 record(s), chain intact.
```

But `log-dsar-prod-uks-01` is in the **same resource group**, the same
subscription, under the same RBAC. One Owner deletes both copies. It is a
different *data plane*, not a different trust domain, and the document should
say the smaller thing. It also holds 90 days against the blob's 2555 — so the
"second copy" covers 3.5% of the retention period the design claims.

**No data-plane audit of the audit trail.** `az monitor diagnostic-settings
list` on `stdsarproduks01/blobServices/default` returns `[]`. There is no
`StorageRead` / `StorageWrite` / `StorageDelete` logging, and Defender for
Storage is on the Free tier (`az security pricing show -n StorageAccounts` →
`Free`). If someone granted themselves the container role and tampered, the
role assignment would appear in the Azure Activity Log and the tampering itself
would appear nowhere.

**Recommendation.** Make locking the policy a go-live gate rather than a note,
and record the date it was locked. Add `CanNotDelete` locks to the storage
account and the workspace. Enable blob diagnostic settings for read/write/delete
to a workspace **outside** this resource group. Raise LA retention to match the
immutability period, or export the audit table to an immutable store. Add an
Activity Log alert on writes and deletes to `immutabilityPolicies` and on
role assignments at the container scope. And amend THREAT-MODEL §3 to say
"a different data plane in the same subscription" rather than "a different
trust domain".

---

## SEC-M-04 · The token provider selects `accounts[0]`, so the audited actor and the token's identity are not the same fact

**Severity:** Medium
**Location:** `src/dsar/auth/desktop.py:50-51`, `:93-95` · `src/dsar/web/app.py:225-251`

**Finding.** This was the multi-operator isolation question, and the answer is
*not today, but not because anything checks*.

The isolation itself holds. Each session carries its own `msal.TokenCache`,
created empty inside `build_confidential_client` and populated by exactly one
`acquire_token_by_auth_code_flow` in `callback`. `_session_services` rebuilds a
client per session and assigns `app_client.token_cache = session.cache`, and the
resulting services are cached on the `Session` object. There is no
process-global cache, no shared `CaseService`, and no shared MSAL application.
Verified: two concurrently created sessions hold distinct cache objects.

What does not hold is the stated reason. Both `desktop.py`'s class docstring
and `app.py:230-232` claim the provider is *"bound to one identity at
construction, so nothing downstream can name another account even by mistake."*
It is bound to a `Principal`, which is used for auditing and for the role check.
Token acquisition is not bound to it at all: `get_token` calls
`self._account or self._first_account()`, `_session_services` passes no
`account=`, and `_first_account` returns `accounts[0]` — positional, unfiltered,
never compared to `principal.oid`.

**Evidence.** Driving `_first_account` against a cache holding two accounts:

```
principal.oid:    aaaa-oid-1
account chosen:   {'home_account_id': 'someone-else.tid', 'username': 'victim@example.test'}
matches the principal: False
```

Today no cache can hold two accounts, so this is unreachable. The failure mode
if it ever becomes reachable is not "a wrong token" — it is a Graph call made as
operator A while every audit record for that call names operator B, with the
hash chain attesting to the wrong name. That is the one failure this audit trail
exists to make impossible.

**Recommendation.** Pass `account=` explicitly, selected by matching the
account's `home_account_id` prefix (or `local_account_id`) against
`session.principal.oid`, and raise `ReauthRequired` when no account matches
rather than falling back to position. Add a test that puts two accounts in one
cache and asserts the provider refuses rather than picks. Then the docstring is
true and something can fail if it stops being.

---

## SEC-M-05 · Logout's `Set-Cookie` is rejected by the browser in hosted mode, and the test that covers it runs only in desktop mode

**Severity:** Medium
**Location:** `src/dsar/web/auth_routes.py:276` (logout), `:240` (callback) ·
`tests/test_auth.py:338`

**Finding.** `response.delete_cookie(state.session_cookie, path="/")` uses
Starlette's default `secure=False`. In hosted mode the cookie is named
`__Host-dsar_session`, and RFC 6265bis §4.1.3.2 requires a user agent to
**reject** a `__Host-`-prefixed cookie that does not carry `Secure`. The
deletion is therefore discarded by the browser and the cookie survives sign-out
for its full 8-hour `Max-Age`. The same applies to the flow cookie deletion in
`callback`.

**Evidence.** Hosted app, in-process, real response:

```
[2] logout status: 302
    Set-Cookie: __Host-dsar_session=""; expires=Fri, 14 Aug 2026 22:01:59 GMT;
                Max-Age=0; Path=/; SameSite=lax
    __Host- prefix requirements satisfied on this Set-Cookie: False
    session still in store after logout: False

[3] inspect.signature(starlette.responses.Response.delete_cookie)
    (self, key, path='/', domain=None, secure=False, httponly=False, samesite='lax')
```

**Impact is bounded and I will not inflate it.** `state.sessions.remove()` does
destroy the server-side session — the probe confirms it — so the retained
cookie is an inert 256-bit string that resolves to nothing and yields a 401.
There is no session-continuation risk. What is lost is the stated property
("logout clears the session cookie") and any hygiene value on a shared
workstation.

**The reason it survived review is the recurring one.**
`test_logout_clears_the_session_cookie` asserts `"dsar_session=" in c and
"Max-Age=0" in c` — against the **desktop** fixture, where the cookie has no
prefix and the browser would accept the deletion. The one hosted cookie test,
`test_hosted_cookies_are_secure_and_host_prefixed`, inspects the `/auth/login`
response only. Between them they cannot fail on this.

**Recommendation.** `response.delete_cookie(name, path="/",
secure=config.mode.is_hosted, httponly=True, samesite="lax")` in both places —
ideally via a `_clear_cookie` helper mirroring `_set_cookie`, so the two cannot
drift. Add a hosted-mode test asserting the deletion `Set-Cookie` carries
`Secure`.

---

## SEC-M-06 · The FIC's blast radius is not the identity's permissions — it is who may attach it, and that set includes standing external guests

**Severity:** Medium
**Location:** `infra/modules/platform.bicep:28-36` · `docs/THREAT-MODEL.md` (no
hosted trust boundary section)

**Finding.** The design's own framing is correct as far as it goes: *"anyone who
can run code as this identity can mint the assertion — so it is exactly as
sensitive as a client secret would have been, and it is not shared with anything
else."* The dedication claim checks out — the UAMI has exactly one role
assignment in the subscription. What is missing is the second half: what the
assertion is worth, and who can get one.

**What the assertion buys its holder.** Client authentication as
`DSAR Assist (Hosted, UK South)` — and no more than that, which is the good
news. The app holds **zero application permissions** (`appRoleAssignments` on
the service principal is `[]`, verified), so a client-credentials grant returns
nothing useful against Graph. Delegated access still requires an operator's
authorization code or refresh token. So the assertion alone does not reach
Purview.

**Who can get one.** Anyone holding
`Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action`, which is
inside Contributor's `*`. From `az role assignment list -g rg-dsar-prod-uks-01
--include-inherited`: four principals hold Owner at subscription scope (one a
group, one an `#EXT#` guest), four hold Owner at the tenant-root management
group — **three of them `#EXT#` guests from two external domains** — plus two
service principals with Contributor and one with Role Based Access Control
Administrator. Any of them can attach `id-dsar-prod-uks-01` to a resource they
control.

**And the same privilege buys something much worse than the assertion.** A
Contributor on this resource group can replace the container image or add a
`secrets` entry to the container app. That process holds live delegated
operator tokens in memory. Contributor on `rg-dsar-prod-uks-01` is equivalent to
compromise of every operator session in flight, and no part of the design
addresses it because it is not the design's job. It should still be written
down.

**Recommendation.** Add a hosted trust-boundary section to THREAT-MODEL stating
plainly that Azure Contributor over this resource group is equivalent to
operator-session compromise, and that the FIC's blast radius is bounded by the
app holding no application permissions — which is a property worth asserting
mechanically, because it is currently true by omission rather than by check.
Separately: standing `#EXT#` guest Owner at the tenant root is a tenant problem
larger than this project, but this project now stores personal-data-adjacent
audit records under it. Raise it, PIM it, or accept it in writing.

---

## SEC-L-01 · A redirect URI is registered for a route that does not exist

**Severity:** Low
**Location:** `infra/entra/provision.sh:221`

**Finding.** The hosted registration's `web.redirectUris` is patched to
`[<base>/auth/callback, <base>/auth/post-logout]`, while `logoutUrl` is set
separately to `<base>/auth/signed-out`. Verified live — both URIs are on the
registration. `/auth/post-logout` is not in `build_app`'s route table
(`/healthz`, `/auth/login`, `/auth/callback`, `/auth/logout`, `/api/whoami`, the
ten API endpoints, four static paths). A post-logout destination belongs in
`postLogoutRedirectUris`, not `redirectUris`; as registered it is an additional
URI at which Entra will deliver an authorization code, serving a route that
404s.

**Recommendation.** Drop it from `web.redirectUris`. If a post-logout landing
page is wanted, add it to `web.postLogoutRedirectUris` and build the route.

---

## SEC-L-02 · The authorization code travels in the query string

**Severity:** Low
**Location:** `src/dsar/auth/msal_client.py:177-189` (`flow_extras`)

**Finding.** No `response_mode` is set, so Entra uses the default, `query`. RFC
9700 §4.3.1 recommends `form_post`; MSAL emits a `UserWarning` saying exactly
that on every `initiate_auth_code_flow` — it is visible in the test run output.
Hosted mode is where this matters, because the redirect now traverses the
public internet and a real ingress.

**Evidence.** The live authorize URL carries `response_type=code` and no
`response_mode`. Mitigations are genuinely in place and I checked each: PKCE
`code_challenge_method=S256` with the verifier held server-side and single-use;
`Referrer-Policy: no-referrer` on every response; and `RequestLogMiddleware`
logging route templates only — I searched `ContainerAppConsoleLogs_CL` for the
review window and the application logs `GET /auth/callback -> …` with no query
string, and unmatched paths as `GET <unmatched>`. The code does not reach any
log I can find in this deployment.

**Recommendation.** Set `response_mode: "form_post"` in `flow_extras` for hosted
and add `POST` to the `/auth/callback` route, or record the decision to keep
`query` with the mitigations above as the reasoning. Either is defensible; the
current state is the default rather than a decision.

---

## SEC-L-03 · The ingress allowlist is one dynamic residential /32, and it is not an authentication control

**Severity:** Low
**Location:** `infra/modules/containerapp.bicep:21-30`, `:52-62`

**Finding.** `ipSecurityRestrictions` is `["86.28.200.50/32"]`. That is the
egress address of the workstation this review ran from — I reached
`/healthz`, `/auth/login` and `/auth/logout` directly, so this machine is inside
the perimeter. The FQDN resolves publicly (`74.177.145.108`), the certificate is
public, and the hostname is derivable from the resource name.

What actually protects the endpoint is Entra, and it is doing the work:
`appRoleAssignmentRequired: true` on the service principal, an authority pinned
to one tenant, `tid` pinned again at claim validation, PKCE S256, a server-side
single-use flow store, and `require_app_role` defaulting to `True` so the
in-process role check is `REQUIRED` rather than advisory. The IP rule buys
reduced exposure to untargeted scanning and nothing else.

The specific fragility: a single residential /32 will change. If the lease moves
and the rule is not updated, operators are locked out (visible, fine). If the
ISP reassigns that address to another customer, a stranger reaches the sign-in
page — which is a fresh audience for the sign-in surface rather than a breach,
but it is the opposite of what an allowlist is understood to promise.

**Recommendation.** Treat the /32 as availability hygiene, not a control, and
say so where it is currently listed as one (DESIGN §3's control table). If the
instance outlives one operator, put it behind a stable egress or a private
ingress. The `allowedIpRanges` parameter having no default is a good design and
should stay exactly as it is.

---

## SEC-L-04 · `/auth/login` rate limiting is global behind the ingress, and the consequence is not carried into the threat model

**Severity:** Low
**Location:** `src/dsar/web/auth_routes.py:105-113` · `src/dsar/web/limits.py:32-34`

**Finding.** The limiter keys on `request.client.host`. Behind Container Apps
ingress that is the ingress, not the caller — the code comment says so, to its
credit. The consequence is not carried anywhere: the 10-per-minute bound is a
bound on *everyone*, so a single caller who reaches the endpoint can deny
sign-in to every operator for up to a minute.

**Evidence.** Fourteen sequential `/auth/login` requests from one peer:
`[302 ×9, 429 ×5]`. The `FlowStore` refusal behaves correctly as the backstop
(`FlowStoreFull` raised after 64 pending, existing flows untouched) and the
session store likewise — 63 admissions then `SessionStoreFull`, with the
pre-existing victim session confirmed alive afterwards. Those two controls are
exactly as advertised.

Today the exposure is one /32. But `allowedIpRanges: []` is documented in the
template as *"a legitimate answer"* meaning internet-facing — and in that
configuration this becomes an unauthenticated, internet-reachable sign-in
denial of service costing ten requests a minute.

**Recommendation.** When hosted, key the login limiter on the first hop of
`X-Forwarded-For` (the app is not directly reachable, so the header is
ingress-set) and keep the peer key for desktop. Or raise the limit and lean on
`FlowStore`'s refusal, and state the trade. Either way add the "empty
allowlist" consequence to `DEPLOY-hosted.md` where that choice is presented.

---

## SEC-L-05 · The blob listing does not follow the continuation marker

**Severity:** Low
**Location:** `src/dsar/audit/blob.py:215-239`

**Finding.** `_list_blobs` parses `<Name>` elements out of a single
`comp=list` response. Azure returns at most 5,000 blobs per page plus a
`NextMarker`, and the marker is not read. `read_all` is what both `head()` and
`dsar audit verify` consume, so a truncated listing yields a chain that appears
to start mid-stream. At one blob per UTC day that is ~13.7 years, past the
2,555-day retention, so it is unreachable — but the module's own docstring is
built on the argument that hand-written REST is safe *because the contract is
written down*, and this is the one place it is not fully honoured.

**Recommendation.** Follow `NextMarker`, or assert the response contains an
empty `<NextMarker />` and raise `BlobSinkError` if not. Three lines, and it
removes a silent-truncation path from the only code that reads the evidence.

---

## Nothing found at these

No finding in **session isolation between operators** beyond SEC-M-04's
defence-in-depth gap: no process-global token cache, no shared MSAL application,
no shared `CaseService`, per-session caches confirmed distinct at runtime.

No finding in **CSRF or session fixation**. Every hypothesis I tested was
already closed: a fresh 256-bit session id is minted at every callback so a
pre-set cookie cannot be adopted; the flow is server-side, single-use
(`FlowStore.take` pops) and 5-minute TTL, with the client holding only an opaque
key; `__Host-` on both cookies with `Secure`, `HttpOnly`, `SameSite=lax`,
`Path=/` and no `Domain` — verified on the live `Set-Cookie`; and the origin
check rejects on absence. All five bypass shapes I threw at it were refused:

```
no Origin -> 403   suffix (…co.uk.evil.test) -> 403   prefix (evil.test + origin) -> 403
scheme downgrade (http://) -> 403   Origin: null -> 403   correct origin -> 200
```

Body cap behaves as documented: 413 for an authenticated 64 KiB + 1 body, and
401 for the same body anonymously — refused before buffering, as claimed.

No finding in **audit write ordering**. `AuditTrail.write` advances the sequence
only after the sink accepts, so a failed append refuses the action rather than
leaving a gap, and the write-ahead `ATTEMPTED` / `OK` pattern in `workflow.py`
means an interrupted operation is a visible shape rather than a silent absence.
Fail-closed, correctly.

No finding in **`prompt=select_account`**. Present on the live authorize URL,
hosted-only, and the reasoning in `flow_extras` is right.

---

## Claims I could not verify

* **CAE (`cp1`) is negotiated.** The `claims` parameter requesting `xms_cc` is
  present on the live authorize URL, but whether the STS agreed is only readable
  from `xms_cc` on an issued token, and I hold no operator session. This is
  B-04, already open. Until observed, near-real-time revocation should not be
  claimed — and it is currently claimed in THREAT-MODEL:163 and DESIGN §4
  without qualification.
* **The append blob's contents.** I hold no data-plane role on
  `stdsarproduks01` and did not grant myself one. Everything I say about the
  hosted trail is derived from the Log Analytics copy, which verified intact at
  22 records. The blob itself is unread by this review — someone with the
  container role should run `dsar audit verify` against it and record the
  result alongside this document.
* **That an unlocked policy blocks data-plane deletion.** Asserted from
  Microsoft's documented semantics plus the observed
  `allowProtectedAppendWrites: true` / `state: Unlocked` / 2555 days, not from a
  deletion attempt — testing it would have required granting myself the
  container role. Worth proving once, deliberately, before go-live.

---

## Residuals — accepted, and named

* **Purview owns authorisation.** Unchanged from the desktop review and still
  the right call. Hosted does not alter it.
* **Token theft from process memory.** Sender-constrained tokens remain
  unavailable. Hosted makes the residual worse in one specific way that should
  be stated: on the desktop the tokens in memory are the operator's own, on
  their own machine; hosted, one process holds up to 64 operators' delegated
  tokens and its host is administered by whoever holds Azure Contributor
  (SEC-M-06). The compensating controls named for this residual are the ones
  SEC-M-02 shows do not exist.
* **A revision update signs everyone out.** Documented, accepted, correct.
* **`allowedIpRanges: []` is a legitimate deployment answer.** Accepted, with
  SEC-L-04's consequence to be written down.
* **The `audit` container's data plane is reachable from the whole internet**
  (`publicNetworkAccess: Enabled`, `networkAcls.defaultAction: Allow`), guarded
  by Entra RBAC alone. The Bicep argues this correctly — Container Apps egress
  has no fixed address without a NAT gateway — and shared key is off, so there
  is no key or SAS to steal. Accepted as written.
* **Global Administrators bypass `appRoleAssignmentRequired`.** Already stated
  in DESIGN §6. Still true, still accepted.

---

## Verdict

**APPROVED WITH CONDITIONS.**

The hosted delta is well built. The FIC is genuinely secretless and the
deployment proves it — `secrets: []` read back off the live resource, no
account key, no SAS, one federated credential with a correct subject, and a
managed identity holding exactly one narrowly scoped role assignment. Session
isolation is real. The origin, body-cap, flow-store and session-store controls
all behave exactly as their comments claim, and I could not bend any of them.
The audit sink's second copy works, and it is the reason the most serious
finding here could be assessed at all.

Two conditions before this carries real DSAR cases:

1. **Close SEC-H-01.** The single-writer property the audit chain depends on is
   not one Container Apps provides, and the test cited as its guard cannot
   fail. Fix the mechanism (`x-ms-blob-condition-appendpos` is the right
   primitive), or gate deployments on an empty session store — but not the
   comment alone.
2. **Close SEC-M-02 one way or the other.** Either configure phishing-resistant
   MFA and a sign-in frequency scoped to the two DSAR applications, or delete
   those three claims from THREAT-MODEL and DESIGN in the same commit. A
   compensating control that does not exist is worse than an acknowledged gap,
   because it stops anyone looking.

Everything else is a should-fix. SEC-M-01, SEC-M-04 and SEC-M-05 are all the
same defect wearing three costumes and the one HANDOVER §7 warns about: a stated
guarantee whose check cannot detect its violation. That the project keeps
finding these by running things rather than reading them is why this review
found them too — every finding above except SEC-L-01 and SEC-L-05 came out of a
command, not a paragraph.
