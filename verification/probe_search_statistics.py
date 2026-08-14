"""Dump the RAW Graph JSON for a case's searches and their estimates.

    uv run python verification/probe_search_statistics.py                 # list cases
    uv run python verification/probe_search_statistics.py <case-id>       # dump searches

Written because the UI reported "running" for a search that had plainly
returned results. That is either a status value this code does not recognise,
or a count in a field it does not read — and both are questions only the actual
bytes can settle.

The predecessor's hardest bug was of exactly this shape: statistics were read
off the case-level operations collection, which carries no reference back to
the search that produced each one, so every search in a case reported the same
numbers. It survived a full offline test suite because the fixtures were written
from the same assumption as the code. Measure, do not predict.

Nothing is written to disk. The token lives in memory for the length of the
process.
"""

from __future__ import annotations

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
PORT = 8767

CLIENT_ID = os.environ.get("DSAR_CLIENT_ID", "")
TENANT_ID = os.environ.get("DSAR_TENANT_ID", "")

_result: dict[str, str] = {}
_done = threading.Event()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        _result.update(
            {k: v[0] for k, v in urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query).items()}
        )
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
    print(f"Sign in:\n\n  {flow['auth_uri']}\n")
    try:
        webbrowser.open(flow["auth_uri"])
    except Exception:
        pass
    if not _done.wait(timeout=300):
        raise SystemExit("timed out")
    server.shutdown()
    result = app.acquire_token_by_auth_code_flow(flow, _result)
    if "access_token" not in result:
        raise SystemExit(f"sign-in failed: {result.get('error_description','')[:200]}")
    return str(result["access_token"])


def main() -> int:
    if not CLIENT_ID or not TENANT_ID:
        print("Set DSAR_CLIENT_ID and DSAR_TENANT_ID.", file=sys.stderr)
        return 2

    case_id = sys.argv[1] if len(sys.argv) > 1 else ""
    token = sign_in()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    with httpx.Client(timeout=60.0, headers=headers) as client:
        if not case_id:
            cases = client.get(
                f"{GRAPH}/security/cases/ediscoveryCases", params={"$top": "50"}
            ).json().get("value", [])
            print(f"\n{len(cases)} case(s):\n")
            for case in cases:
                print(f"  {case.get('id')}  {case.get('displayName')}"
                      f"  externalId={case.get('externalId') or '—'}")
            print("\nRe-run with a case id to dump its searches.")
            return 0

        searches = client.get(
            f"{GRAPH}/security/cases/ediscoveryCases/{case_id}/searches"
        ).json().get("value", [])
        print(f"\n{len(searches)} search(es) in {case_id}\n")

        for search in searches:
            sid = search.get("id")
            print("=" * 74)
            print(f"{search.get('displayName')}   id={sid}")
            print("=" * 74)
            print("  contentQuery:")
            print(f"    {search.get('contentQuery')}")

            # The $expand is what makes the answer THIS search's.
            expanded = client.get(
                f"{GRAPH}/security/cases/ediscoveryCases/{case_id}/searches/{sid}",
                params={"$expand": "lastEstimateStatisticsOperation"},
            )
            print(f"\n  GET ...?$expand=lastEstimateStatisticsOperation -> {expanded.status_code}")
            body = expanded.json()
            operation = body.get("lastEstimateStatisticsOperation")
            if operation is None:
                print("  lastEstimateStatisticsOperation: ABSENT")
                print("  full search body keys:", sorted(body.keys()))
            else:
                print("  lastEstimateStatisticsOperation:")
                print(json.dumps(operation, indent=4)[:2000])
            print()

    print("What matters: the exact `status` value, and which field carries the")
    print("item count. The code treats status in {succeeded, completed} as done")
    print("and reads indexedItemCount / indexedItemsSize / mailboxCount / siteCount.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
