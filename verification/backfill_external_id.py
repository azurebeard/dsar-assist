"""One-off: adopt pre-existing Purview cases into the request list.

    uv run python verification/backfill_external_id.py            # dry run
    uv run python verification/backfill_external_id.py --apply    # writes

The request list shows cases whose `externalId` starts with `dsar:v1:`. Cases
created before this tool existed — the demo pre-runs `DSAR-DELTA3` and
`DSAR-DELTA` — carry no marker, so they are correctly absent. This stamps one
onto named cases so they appear.

## Why this is a script and not a feature

`update_case` is deliberately **not** in the permitted-operations table. Adding
it would widen the table for a one-off, and the rule that keeps the table
meaningful is that a case without our marker simply is not ours.

The predecessor set the same precedent for the same reason: case deletion was
done *outside* the repository with a one-off Graph call, deliberately, so that
nothing in the codebase taught the tool an operation it should not have. This
follows that. It lives in `verification/`, it is not imported by anything, and
it names every case it will touch before it touches it.

## Why it does its own sign-in

The Azure CLI cannot reach the eDiscovery API — its token carries directory
scopes only, which is fine for licences, apps, users and roles, and useless
here. So this performs the same authorization-code flow the application does.

Nothing is written to disk. The token lives in memory for the length of the
process.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import sys
import threading
import urllib.parse
import webbrowser

import httpx
import msal

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPES = ["https://graph.microsoft.com/eDiscovery.ReadWrite.All"]
PORT = 8766
PREFIX = "dsar:v1:"

CLIENT_ID = os.environ.get("DSAR_CLIENT_ID", "")
TENANT_ID = os.environ.get("DSAR_TENANT_ID", "")

_result: dict[str, str] = {}
_done = threading.Event()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        query = urllib.parse.urlparse(self.path).query
        _result.update({k: v[0] for k, v in urllib.parse.parse_qs(query).items()})
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<h1>Signed in</h1><p>Return to the terminal.</p>")
        _done.set()

    def log_message(self, *args: object) -> None:
        pass


def sign_in() -> str:
    app = msal.PublicClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_capabilities=["cp1"],
        token_cache=msal.TokenCache(),
    )
    redirect = f"http://localhost:{PORT}/auth/callback"
    flow = app.initiate_auth_code_flow(SCOPES, redirect_uri=redirect)
    server = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print("Sign in as an operator with an eDiscovery role:\n")
    print(f"  {flow['auth_uri']}\n")
    try:
        webbrowser.open(flow["auth_uri"])
    except Exception:
        pass
    if not _done.wait(timeout=300):
        raise SystemExit("timed out waiting for sign-in")
    server.shutdown()

    result = app.acquire_token_by_auth_code_flow(flow, _result)
    if "access_token" not in result:
        raise SystemExit(f"sign-in failed: {result.get('error_description', '')[:200]}")
    return str(result["access_token"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply", action="store_true", help="actually write (default is a dry run)"
    )
    parser.add_argument(
        "--match",
        default="DSAR-",
        help="only cases whose displayName starts with this (default: DSAR-)",
    )
    args = parser.parse_args()

    if not CLIENT_ID or not TENANT_ID:
        print("Set DSAR_CLIENT_ID and DSAR_TENANT_ID.", file=sys.stderr)
        return 2

    token = sign_in()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    with httpx.Client(timeout=30.0) as client:
        response = client.get(
            f"{GRAPH}/security/cases/ediscoveryCases",
            headers=headers,
            params={"$top": "100"},
        )
        if response.status_code != 200:
            print(f"list failed: {response.status_code} {response.text[:300]}", file=sys.stderr)
            return 1
        cases = response.json().get("value", [])

    print(f"\n{len(cases)} case(s) visible to this account:\n")
    planned: list[tuple[str, str, str]] = []
    for case in cases:
        name = case.get("displayName", "")
        external = case.get("externalId") or ""
        if external.startswith(PREFIX):
            print(f"  [already ours] {name}  ({external})")
            continue
        if not name.startswith(args.match):
            print(f"  [skip]         {name}")
            continue
        if external:
            # Refuse to overwrite. An externalId set by something else is that
            # thing's, and clobbering it to make a demo tidier is not a trade
            # worth making.
            print(f"  [has other id] {name}  ({external}) — not touching it")
            continue
        planned.append((case["id"], name, f"{PREFIX}{name}"))
        print(f"  [will stamp]   {name}  ->  {PREFIX}{name}")

    if not planned:
        print("\nNothing to do.")
        return 0

    if not args.apply:
        print(f"\nDry run. Re-run with --apply to write {len(planned)} change(s).")
        return 0

    print()
    with httpx.Client(timeout=30.0) as client:
        for case_id, name, external_id in planned:
            patch = client.patch(
                f"{GRAPH}/security/cases/ediscoveryCases/{case_id}",
                headers={**headers, "Content-Type": "application/json"},
                content=json.dumps({"externalId": external_id}),
            )
            ok = 200 <= patch.status_code < 300
            print(
                f"  {'ok  ' if ok else 'FAIL'} {name}"
                + ("" if ok else f"  {patch.status_code} {patch.text[:160]}")
            )
    print("\nRefresh the request list.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
