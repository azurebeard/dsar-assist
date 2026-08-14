# FIC client assertion on an authorization-code grant — offline half

**Date:** 2026-08-14 · **Probe:** `verification/probe_fic_assertion_offline.py`
**msal:** 1.37.0 · **Network:** none — MSAL's HTTP client replaced with a recorder

## Question

The hosted mode authenticates with a federated identity credential: a
user-assigned managed identity mints a token, that token is presented as the
client assertion, and the app redeems an authorization code for a **delegated**
Graph token. Every Microsoft sample for federated-credential-by-managed-identity
uses `AcquireTokenForClient` — app-only. None does it with an authorization
code. This was recorded as the largest unknown in the design.

It decomposes, and only the second half needs infrastructure:

- **A.** Does MSAL send `client_assertion` when redeeming an authorization
  code, or only on a client-credentials grant?
- **B.** Does Entra *accept* a managed-identity-minted assertion for that grant?

**A** was the more likely hard blocker: if MSAL simply does not send a client
assertion on this grant, no Entra configuration helps and the hosted design
needs rethinking. It is also free to answer.

## Result — A: yes

```
grant_type             authorization_code
client_assertion       PRESENT
client_assertion_type  urn:ietf:params:oauth:client-assertion-type:jwt-bearer
assertion is ours      True
callable invoked       1 time(s) — lazily, not at construction
client_secret sent     no
```

Client authentication is orthogonal to grant type in OAuth, and MSAL implements
it that way. Passing `client_credential={"client_assertion": <callable>}`
produces a correctly-formed private-key-JWT client authentication on an
authorization-code redemption.

Two details worth keeping:

- **The callable is invoked lazily**, once, at redemption — not at construction.
  This is why it must be a callable and not a pre-computed string: a managed
  identity token expires, and a long-lived process would start failing token
  refreshes some time after startup for reasons that look nothing like an
  expiry.
- **No `client_secret` appears in the request body.** The assertion is the only
  client credential sent.

## Still unknown — B

Whether Entra accepts an assertion minted by a managed identity for this grant.
Needs a real Container App and UAMI, so it is deferred to Phase 5 where that
infrastructure exists anyway. Expect `AADSTS700213` or `AADSTS70021` on refusal
rather than a silent fallback — and note Microsoft's own warning that a
misconfigured FIC is *created successfully without error* and fails only at
exchange, which is what the `invalid_client` vs `invalid_grant` doctor probe
exists to disambiguate.

Risk after this probe: materially lower. The remaining question is one of Entra
policy rather than of whether the client library can express the request at all.

## Incidental finding — `response_mode` is a live decision, not a settled one

MSAL emitted this while building the authorize request:

```
UserWarning: response_mode='form_post' is recommended for better security.
See https://www.rfc-editor.org/rfc/rfc9700.html#section-4.3.1
```

RFC 9700 (BCP 240) §4.3.1 recommends `form_post` because it keeps the
authorization code out of the URL, and therefore out of browser history, the
`Referer` header, and any proxy or server log along the way.

The plan chose `response_mode=query` with a `SameSite=Lax` flow cookie, on the
grounds that `form_post` makes the callback a **cross-site POST**, and a Lax
cookie is not sent on one — which would silently break the server-side flow
lookup. Both halves of that are true, so this is a genuine trade rather than an
oversight, but the plan recorded only one side of it.

Resolve in Phase 1, deliberately, and write down which was chosen:

| Option | Code exposure | Cookie |
|---|---|---|
| `query` + `SameSite=Lax` | code in URL, history, `Referer`, logs | works as-is |
| `form_post` + `SameSite=None; Secure` | code in a POST body | needs `Secure`, awkward over `http://localhost` on desktop |
| `form_post` hosted, `query` desktop | best of both | two paths to test, and the mode abstraction exists to avoid exactly that |

Leaning: `form_post` for hosted, where `Secure` is available and the endpoint is
internet-facing, and `query` for desktop, where the whole exchange stays on
loopback and `Secure` cookies over `http://localhost` are already flagged as
browser-dependent. That is a third path to test, so it needs a test, not a
comment.
