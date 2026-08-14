"""Phase 1 identity probes. One sign-in answers both open questions.

    uv run python verification/probe_phase1_identity.py

Both questions are load-bearing for the desktop mode and neither can be settled
from documentation.

  Q1. Is the `roles` claim emitted in the ID token of a PUBLIC client?
      Microsoft documents app roles for apps that sign users in and for APIs,
      but does not state the behaviour for public clients specifically. The
      desktop authorization check depends on it. If the claim is absent, the
      in-process check is dropped and `appRoleAssignmentRequired` at the
      identity provider carries the whole control — which it was always doing
      anyway, since an operator controls their own process.

  Q2. Does Entra ignore the PORT when matching a loopback redirect URI?
      RFC 8252 §7.3 says it should. The launcher's `--port` depends on it, and
      exactly one loopback URI is registered.

The design of the probe answers Q2 for free: it listens on a port that is
DELIBERATELY NOT the registered one. If the flow completes, the port was
ignored. If Entra returns AADSTS50011, it was not, and the launcher's port
override has to go.

An earlier version of this probe tried to answer Q2 with an unauthenticated GET
to the authorize endpoint, on the theory that Entra validates `redirect_uri`
before authenticating. It does not — a mismatched host returned the ordinary
sign-in page, byte-for-byte indistinguishable from a good one. That method is
recorded here because it looked convincing and was wrong, which is the same
trap the predecessor documented: a comparison that varies one input proves the
input sufficient, never necessary.

Nothing is written to disk. The token lives in memory for the length of the
process, which is also how the application itself behaves.
"""

from __future__ import annotations

import base64
import http.server
import json
import os
import socket
import sys
import threading
import urllib.parse
import webbrowser

import msal

REGISTERED_PORT = 8765
#: Deliberately not the registered port. This IS the Q2 experiment.
PROBE_PORT = 9876

CLIENT_ID = os.environ.get("DSAR_CLIENT_ID", "")
TENANT_ID = os.environ.get("DSAR_TENANT_ID", "")
SCOPES = ["https://graph.microsoft.com/eDiscovery.ReadWrite.All"]

_result: dict[str, str] = {}
_done = threading.Event()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        query = urllib.parse.urlparse(self.path).query
        _result.update({k: v[0] for k, v in urllib.parse.parse_qs(query).items()})
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            b"<h1>Probe complete</h1><p>Return to the terminal.</p>"
        )
        _done.set()

    def log_message(self, *args: object) -> None:
        pass  # the probe prints its own narrative


def decode_segment(token: str, index: int) -> dict:
    """Decode a JWT segment without verifying it.

    Legitimate here and nowhere else: this is a diagnostic reading a token the
    process just obtained for itself, not an application trusting a token it
    was handed. The application never parses an access token at all, and reads
    ID-token claims only through MSAL, which validates signature, issuer,
    audience and nonce.
    """
    part = token.split(".")[index]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def main() -> int:
    if not CLIENT_ID or not TENANT_ID:
        print("Set DSAR_CLIENT_ID and DSAR_TENANT_ID first.", file=sys.stderr)
        print("  ./infra/entra/provision.sh desktop  prints both.", file=sys.stderr)
        return 2

    redirect_uri = f"http://localhost:{PROBE_PORT}/auth/callback"

    print(f"Tenant   {TENANT_ID}")
    print(f"Client   {CLIENT_ID}")
    print(f"Registered redirect  http://localhost:{REGISTERED_PORT}/auth/callback")
    print(f"Probe redirect       {redirect_uri}   <- deliberately a different port")
    print()

    app = msal.PublicClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        # Declares CAE readiness. Whether the STS agreed is reported below as
        # `xms_cc`, which is the difference between a CAE claim and CAE.
        client_capabilities=["cp1"],
        # In memory. There is no serialisable cache and no file, here or in the
        # application.
        token_cache=msal.TokenCache(),
    )

    flow = app.initiate_auth_code_flow(SCOPES, redirect_uri=redirect_uri)
    if "auth_uri" not in flow:
        print(f"Could not start the flow: {flow}", file=sys.stderr)
        return 1

    try:
        server = http.server.HTTPServer(("127.0.0.1", PROBE_PORT), Handler)
    except OSError as exc:
        print(f"Cannot listen on {PROBE_PORT}: {exc}", file=sys.stderr)
        return 1

    threading.Thread(target=server.serve_forever, daemon=True).start()

    print("Open this and sign in as an operator holding a DSAR app role:\n")
    print(f"  {flow['auth_uri']}\n")
    try:
        webbrowser.open(flow["auth_uri"])
    except Exception:
        pass

    print("Waiting for the callback (Ctrl-C to abandon)...")
    if not _done.wait(timeout=300):
        print("\nTimed out after 5 minutes.", file=sys.stderr)
        return 1
    server.shutdown()

    print()
    if "error" in _result:
        code = _result.get("error", "")
        desc = urllib.parse.unquote(_result.get("error_description", ""))
        print("=" * 72)
        print(f"Q2 — loopback port: REJECTED ({code})")
        print("=" * 72)
        print(desc[:400])
        if "AADSTS50011" in desc:
            print()
            print("The port is NOT ignored. Consequences:")
            print("  - the launcher's --port override cannot work")
            print("  - every port an operator might use must be registered")
            print("  - pin the port in the launcher and document it")
        return 1

    result = app.acquire_token_by_auth_code_flow(flow, _result)
    if "access_token" not in result:
        print(f"Token acquisition failed: {result.get('error')}", file=sys.stderr)
        print(result.get("error_description", "")[:400], file=sys.stderr)
        return 1

    print("=" * 72)
    print(f"Q2 — loopback port: IGNORED. Flow completed on {PROBE_PORT} while "
          f"{REGISTERED_PORT} is registered.")
    print("=" * 72)

    id_claims = result.get("id_token_claims", {})
    access = decode_segment(result["access_token"], 1)

    roles = id_claims.get("roles")
    print()
    print("=" * 72)
    if roles:
        print(f"Q1 — roles claim in a public client ID token: PRESENT  {roles}")
        print("The in-process app-role check is viable. Build it.")
    else:
        print("Q1 — roles claim in a public client ID token: ABSENT")
        print("Drop the in-process check. `appRoleAssignmentRequired` at the")
        print("identity provider is the control, and it already holds — a token")
        print("was only issued because the operator is assigned.")
    print("=" * 72)

    print()
    print("Supporting claims:")
    print(f"  tid        {id_claims.get('tid')}")
    print(f"  oid        {id_claims.get('oid')}")
    print(f"  amr        {id_claims.get('amr')}")
    print(f"  auth_time  {id_claims.get('auth_time')}")
    print(f"  acrs       {id_claims.get('acrs', '(none — no auth context yet)')}")
    xms_cc = id_claims.get("xms_cc") or access.get("xms_cc")
    if xms_cc and "cp1" in xms_cc:
        print(f"  xms_cc     {xms_cc}   <- the STS agreed to CAE, not just us")
    else:
        print(f"  xms_cc     {xms_cc or '(absent)'}   <- CAE NOT negotiated")

    scopes = access.get("scp", "").split()
    print()
    print("Access token scopes:")
    for scope in sorted(scopes):
        print(f"  {scope}")
    download = [s for s in scopes if "download" in s.lower()]
    print()
    print(f"  no download scope: {'YES' if not download else 'NO — ' + str(download)}")
    print("  (proven at runtime on an issued token, not from the portal blade)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
