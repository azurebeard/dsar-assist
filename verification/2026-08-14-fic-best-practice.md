# Is the federated identity credential current best practice?

**Date:** 2026-08-14 · **Question raised by:** Ben — *"the federated credential
feels outside of best practice, verify this is a modern approach"*
**Answer: it is the recommended approach, not a workaround.** Sources below.

A fair challenge, and the design documents had been describing this as an
unusual path — which overstated the risk. Corrected here.

---

## What was checked

Three separate claims, because the design rests on all three and only one of
them was actually uncertain.

### 1 · Is workload identity federation Microsoft's recommendation? Yes

*"Federated identity credentials allow you to access Microsoft Entra and
Microsoft Graph resources without having to manage secrets. You eliminate the
maintenance burden of manually managing credentials and eliminate the risk of
leaking secrets or having certificates expire."*

It is GA, not preview.

### 2 · Is a managed identity a supported federation source? Yes, first-class

*Entra admin center → App registrations → Certificates & secrets → Federated
credentials → **Federated credential scenario: Managed Identity***.

It is a dropdown option in the portal. Microsoft ships samples for it in .NET,
Go, Java, Node.js and **Python**, plus a dedicated `Microsoft.Identity.Web`
configuration source type — `SignedAssertionFromManagedIdentity`. A pattern
with its own config enum in Microsoft's own framework is not a niche path.

The prerequisites page also settles a question the design had left implicit:

> *"The app registration must have access granted to Microsoft Entra protected
> resources… This access can be granted through API permissions or **delegated
> permissions**."*

Delegated permissions are named explicitly as a supported case. That is
exactly what DSAR Assist uses.

### 3 · Can a client assertion authenticate an authorization-code redemption?

**This was the real open question, and it is answered — in the documentation,
not merely by experiment.**

> *"The Microsoft identity platform allows an application to use its own
> credentials for authentication **anywhere a client secret could be used**."*

and, unambiguously:

> *"**Client assertions can be used anywhere a client secret would be used. For
> example, in the authorization code flow**, you can pass in a `client_secret`
> to prove that the request is coming from your app. You can replace this with
> `client_assertion` and `client_assertion_type` parameters."*

The authorization code flow is named as the example. Client authentication is
orthogonal to grant type — which is what OAuth 2.0 says, and Entra implements
it that way.

The same page then points at workload identity federation as the route for
*"using a JWT issued by another identity provider as a credential for your
application"*. So the chain is complete and each link is documented:

```
managed identity token  →  client assertion  →  authorization_code redemption
   (workload id fed)        (private_key_jwt)      (delegated Graph token)
```

---

## Correction to earlier framing

`2026-08-14-fic-assertion-offline.md` and `DESIGN.md` describe this as the
design's *largest unknown*, on the grounds that **every Microsoft sample for
FIC-by-managed-identity uses `AcquireTokenForClient`** — app-only.

That observation is still true, and it is why the offline probe was worth
running. But *"no sample does it"* is not *"it is unsupported"*, and the two
were being treated as the same thing. The documentation sanctions it directly.

**Risk downgraded from "largest technical unknown" to "unproven in this
tenant".** What remains is a deployment check, not a design question.

---

## Why not the obvious alternatives

| Alternative | Why not |
|---|---|
| **Managed identity alone, no app registration** | Managed identities are app-only. DSAR Assist acts *as the signed-in operator* against Purview — delegated, or the no-data-plane claim collapses into an application permission that can read everything. An app registration is unavoidable; the only question is how it authenticates |
| **Client secret** | The thing workload identity federation exists to remove. Stored, rotated, leakable |
| **Certificate** | Better than a secret and still a credential to store, rotate and eventually let expire. Microsoft's own guidance points at federation instead |
| **Container Apps Easy Auth** | Rejected earlier for separate reasons and still correct: it requires a client secret *and* a blob SAS for its token store, and has no claims-challenge mechanism, so a mid-session Conditional Access step-up cannot be satisfied |

---

## What the implementation must get right, from the same sources

All four were already in the code; confirmed rather than discovered.

| Requirement | Where |
|---|---|
| `audiences` exactly `api://AzureADTokenExchange` | `TOKEN_EXCHANGE_AUDIENCE` |
| `issuer` = `https://login.microsoftonline.com/{tenant}/v2.0`, no whitespace | `add-fic.sh` |
| `subject` = the identity's **Object (Principal) ID**, **case-sensitive** | `add-fic.sh`, warned twice |
| User-assigned only; same tenant as the app registration | `platform.bicep` |
| RS256 only; max 20 credentials per app | `add-fic.sh` updates in place |
| *"If you accidentally add incorrect information in the issuer, subject or audience setting the federated identity credential is created successfully without error. The error does not become apparent until the token exchange fails."* | why `dsar doctor` probes rather than trusting the 201 |
| Propagation delay after creation | `AADSTS70021` reported as lag, not misconfiguration |

---

## Sources

- [Workload identity federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [Configure an application to trust a managed identity](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-config-app-trust-managed-identity) — updated 2026-06-15
- [Microsoft identity platform certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) — the "anywhere a client secret would be used" statement
- [Federated identity credentials overview (Graph v1.0)](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview?view=graph-rest-1.0)
