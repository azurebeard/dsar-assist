"""The sole outbound HTTP choke point for Microsoft Graph.

One of exactly three modules permitted to import `httpx`, enforced by a
structural test. Everything that reaches Microsoft goes through
`GraphClient.request`, which means there is one place that:

* injects the token, and only ever the one bound to this provider's identity,
* handles the CAE / Conditional Access claims challenge and retries **once**,
* maps an HTTP response onto the domain error taxonomy,
* holds the response-handling rule that keeps the no-content property true.

On that last point. This client returns parsed JSON, and for the eleven
permitted operations that JSON is metadata: identifiers, states, counts,
location names. It is never item content, because none of the permitted
operations return item content — search *preview* does, and it is not in the
table and never will be. The client's own contribution is narrower and
checkable: it never writes a response body to disk and never logs one.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Mapping

import httpx

from dsar.auth.errors import ClaimsChallenge, ReauthRequired, parse_claims_challenge
from dsar.auth.provider import TokenProvider
from dsar.graph.errors import (
    BillingNotConfigured,
    PermanentGraphError,
    PurviewRoleMissing,
    Throttled,
    TransientGraphError,
)

__all__ = ["GraphClient", "GraphResponse", "DEFAULT_TIMEOUT"]

log = logging.getLogger(__name__)

#: A read timeout matters more than it looks: without one, a hung connection
#: holds a slot until the process is killed.
DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=30.0, pool=10.0)

_USER_AGENT = "dsar-assist/0.1 (control-plane; no data path)"

#: 403 codes that mean something other than a missing Purview role, and so must
#: not be reported as one.
_NON_ROLE_403_CODES = frozenset(
    {"Request_ResourceNotFound", "ResourceNotFound", "invalidRequest"}
)

#: A refusal for commercial rather than permissions reasons. Deliberately
#: narrow: "subscription" alone appears in plenty of unrelated Graph messages,
#: and wrongly telling an operator their billing is broken wastes as much time
#: as the generic error it replaces.
_BILLING_HINT = re.compile(
    r"pay[-\s]?as[-\s]?you[-\s]?go|\bpayg\b|billing|not\s+billable|consumptive",
    re.IGNORECASE,
)

_CASE_PATH = re.compile(r"/ediscoveryCases/[^/]+")


class GraphResponse:
    """A parsed Graph response. Metadata only, by construction."""

    def __init__(self, status: int, body: dict[str, Any], headers: Mapping[str, str]):
        self.status = status
        self.body = body
        self.headers = dict(headers)

    def get(self, key: str, default: Any = None) -> Any:
        return self.body.get(key, default)

    @property
    def correlation_id(self) -> str:
        """The id Graph echoes back for this exact request.

        We send `client-request-id` and ask for the echo; Graph answers with
        `request-id` (its own) and `client-request-id` (ours, returned). That
        pair is what joins an audit record to a Graph activity log entry at
        investigation time — and the audit field for it sat empty on every
        record of the first live trail (B-25), because the id lived in these
        headers and nothing read it out.
        """
        return str(
            self.headers.get("request-id")
            or self.headers.get("client-request-id")
            or ""
        )


class GraphClient:
    """Issues authenticated Graph requests on behalf of one identity."""

    def __init__(
        self,
        tokens: TokenProvider,
        *,
        base_url: str = "https://graph.microsoft.com/v1.0",
        client: httpx.Client | None = None,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
    ) -> None:
        self.tokens = tokens
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=False)

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        json_body: dict[str, Any] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> GraphResponse:
        """One Graph call, with at most one claims-challenge retry."""
        claims: str | None = None
        retried = False

        while True:
            token = self.tokens.get_token(claims_challenge=claims)
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": _USER_AGENT,
                # We generate it; Graph echoes it back as `request-id`. That
                # pair is what lets an audit record be joined to a Graph
                # activity log entry at investigation time.
                "client-request-id": _new_correlation_id(),
                "return-client-request-id": "true",
            }
            if json_body is not None:
                headers["Content-Type"] = "application/json"

            try:
                response = self._client.request(
                    method,
                    f"{self.base_url}{path}",
                    headers=headers,
                    json=json_body,
                    params=dict(params) if params else None,
                )
            except (httpx.HTTPError, OSError) as exc:
                raise TransientGraphError(
                    f"{operation}: {type(exc).__name__}"
                ) from exc

            if response.status_code != 401:
                return self._handle(response, operation=operation, path=path)

            # ---- 401. Three different things wear this status code. ----
            challenge_header = response.headers.get("WWW-Authenticate")
            new_claims = parse_claims_challenge(challenge_header)

            if challenge_header is None:
                # Not an authentication problem. Purview refuses an
                # authenticated caller holding no eDiscovery role with a 401
                # and no challenge header. RFC 7235 requires the header on a
                # genuine authentication failure, so its absence is the
                # authorisation layer answering.
                #
                # Measured against the demo tenant 2026-07-31, then re-measured
                # 2026-08-02, which showed the first measurement was
                # under-determined: a deleted case, a case id that never
                # existed, and a role-less account return byte-identical
                # responses. Purview will not distinguish forbidden from
                # not-found, because that would leak whether a case exists.
                # So the error names both causes rather than guessing.
                code, _ = _error_fields(_parse_body(response))
                raise PurviewRoleMissing(
                    status=401,
                    code=code,
                    operation=operation,
                    inferred_from_401=True,
                    case_scoped=bool(_CASE_PATH.search(path)),
                )

            if new_claims is None:
                code, _ = _error_fields(_parse_body(response))
                raise ReauthRequired(f"{operation}: 401 {code}")

            if retried:
                # Exactly once, tracked per request rather than as a loop. A
                # loop against a policy the token can never satisfy hammers the
                # STS forever.
                raise ClaimsChallenge(
                    new_claims,
                    reason=f"{operation}: policy still unsatisfied after step-up",
                )

            log.info("%s: claims challenge received; retrying once", operation)
            claims, retried = new_claims, True

    def _handle(
        self, response: httpx.Response, *, operation: str, path: str
    ) -> GraphResponse:
        status = response.status_code
        body = _parse_body(response)

        if 200 <= status < 300:
            return GraphResponse(status, body, response.headers)

        code, message = _error_fields(body)

        # 402 is unambiguous, and a billing hint in any 4xx outranks the role
        # reading below — a role group cannot fix an unconfigured subscription.
        if status == 402 or (
            400 <= status < 500 and _BILLING_HINT.search(f"{code} {message}")
        ):
            raise BillingNotConfigured(
                status=status, code=code, operation=operation, detail=message[:120]
            )

        if status == 403:
            if code in _NON_ROLE_403_CODES:
                raise PermanentGraphError(
                    f"{operation}: 403 {code}: {message}", status=status, code=code
                )
            # A delegated token carrying eDiscovery.ReadWrite.All that still
            # gets a 403 is almost always a role-group problem, not a scope
            # problem. Reporting it as an authentication failure sends the
            # operator to re-authenticate against something sign-in cannot fix.
            raise PurviewRoleMissing(status=status, code=code, operation=operation)

        if status in (429, 503):
            raise Throttled(
                _retry_after(response.headers.get("Retry-After")),
                status=status,
                code=code,
            )

        if status >= 500:
            raise TransientGraphError(
                f"{operation}: {status} {code}", status=status, code=code
            )

        raise PermanentGraphError(
            f"{operation}: {status} {code}: {message}", status=status, code=code
        )


def _parse_body(response: httpx.Response) -> dict[str, Any]:
    if not response.content:
        return {}
    try:
        parsed = response.json()
    except ValueError:
        # Never log the body. A non-JSON response from Graph is a proxy or a
        # captive portal far more often than it is Graph, and either way the
        # content is not ours to record.
        return {}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _error_fields(body: Mapping[str, Any]) -> tuple[str, str]:
    error = body.get("error")
    if not isinstance(error, dict):
        return "", ""
    return str(error.get("code", "")), str(error.get("message", ""))


def _retry_after(value: str | None) -> int:
    """Honoured exactly — no jitter, no multiplier.

    Graph is telling us when it will serve us again. Adding a multiplier makes
    the tool slower for no benefit; subtracting one makes it a bad citizen.
    """
    if not value:
        return 30
    try:
        return max(0, int(float(value.strip())))
    except (TypeError, ValueError):
        return 30


def _new_correlation_id() -> str:
    import uuid

    return str(uuid.uuid4())
