"""Does `description` survive a round trip through `list_cases`?

    uv run python verification/probe_case_description.py            # read only
    uv run python verification/probe_case_description.py --write    # + create one

The statutory deadline needs a **received date**, and a DSAR arrives by email
days before anyone opens a case — so `createdDateTime` is the wrong answer and
always later than the truth. Being wrong about a statutory date is precisely
the failure a DSAR tool must not have.

`description` is the only writable field on an `ediscoveryCase` that is not
already carrying something: it is set at creation (`workflow.py`), accepted by
`/api/case/create`, and **never read back anywhere in this codebase**. That
makes it the natural home — and it also means nothing has ever confirmed it
comes back.

That is the whole question here. Microsoft documents `description` on the
resource; documentation and the bytes on the wire are different things, and
this project has been caught by that difference before — statistics were read
from a collection that carried no reference back to the search that produced
them, and every offline test agreed with the code because the fixtures were
written from the same assumption.

Three things to settle, and only the first is blocking:

  1. Is `description` present in the **list** projection, or only on a
     single-case GET? The request list is built from `list_cases`, so if it is
     absent there the storage decision changes.
  2. Does it come back byte-identical, or does the service trim, normalise
     newlines, or strip anything?
  3. Is there a length limit worth knowing before a marker line is prepended
     to the existing boilerplate?

Read-only unless `--write` is passed. Nothing is written to disk; the token
lives in memory for the length of the process.
"""

from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import urllib.parse
import webbrowser
from datetime import datetime, timezone

import httpx
import msal

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPES = ["https://graph.microsoft.com/eDiscovery.ReadWrite.All"]
PORT = 8768

CLIENT_ID = os.environ.get("DSAR_CLIENT_ID", "")
TENANT_ID = os.environ.get("DSAR_TENANT_ID", "")

#: The shape the feature would write: a machine-readable first line, then the
#: existing human boilerplate. Probed verbatim so the answer is about the real
#: value rather than a simplified one.
MARKER = "DSAR-Received: 2026-08-14"
PROBE_DESCRIPTION = (
    f"{MARKER}\n"
    "Raised via DSAR Assist. Control plane only; no item content is "
    "downloaded by this tool."
)

_result: dict[str, str] = {}
_done = threading.Event()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        _result.update(
            {
                k: v[0]
                for k, v in urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query
                ).items()
            }
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

    write = "--write" in sys.argv
    token = sign_in()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    with httpx.Client(timeout=60.0, headers=headers) as client:
        created_id = ""
        if write:
            reference = f"PROBE-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
            print(f"\nCreating {reference} with a description carrying a marker line")
            response = client.post(
                f"{GRAPH}/security/cases/ediscoveryCases",
                headers={**headers, "Content-Type": "application/json"},
                content=json.dumps(
                    {
                        "displayName": reference,
                        "externalId": f"dsar:v1:{reference}",
                        "description": PROBE_DESCRIPTION,
                    }
                ),
            )
            print(f"  POST -> {response.status_code}")
            if response.status_code not in (200, 201):
                print(f"  {response.text[:400]}")
                return 1
            created_id = str(response.json().get("id", ""))
            print(f"  id={created_id}")

        # -------------------------------------------------- question 1
        print("\n" + "=" * 74)
        print("1 · Is `description` in the LIST projection?")
        print("=" * 74)
        listing = client.get(
            f"{GRAPH}/security/cases/ediscoveryCases", params={"$top": "50"}
        )
        print(f"  GET /security/cases/ediscoveryCases -> {listing.status_code}")
        cases = listing.json().get("value", [])
        print(f"  {len(cases)} case(s)")

        if cases:
            keys = sorted(cases[0].keys())
            print(f"\n  keys on the first case:\n    {keys}")
            print(
                f"\n  'description' present in list projection: "
                f"{'description' in cases[0]}"
            )

        with_description = [c for c in cases if c.get("description")]
        print(
            f"  cases whose description is non-empty in the list: "
            f"{len(with_description)}/{len(cases)}"
        )
        for case in with_description[:3]:
            first_line = str(case.get("description", "")).splitlines()[:1]
            print(f"    {case.get('displayName')}: {first_line}")

        # -------------------------------------------------- question 2
        print("\n" + "=" * 74)
        print("2 · Byte-identical round trip?")
        print("=" * 74)
        target = created_id or (cases[0].get("id") if cases else "")
        if not target:
            print("  no case to inspect")
            return 0

        single = client.get(f"{GRAPH}/security/cases/ediscoveryCases/{target}")
        print(f"  GET .../{target} -> {single.status_code}")
        body = single.json()
        got = body.get("description")
        print(f"  description present on single GET: {got is not None}")

        if created_id and got is not None:
            print(f"\n  sent  ({len(PROBE_DESCRIPTION)} chars): {PROBE_DESCRIPTION!r}")
            print(f"  got   ({len(str(got))} chars): {str(got)!r}")
            print(f"  identical: {got == PROBE_DESCRIPTION}")
            print(f"  marker line survives: {str(got).startswith(MARKER)}")
            # Newlines are the thing most likely to be normalised, and the
            # marker design depends on the first line being separable.
            print(f"  contains a newline: {chr(10) in str(got)}")

            from_list = next((c for c in cases if c.get("id") == created_id), None)
            if from_list is not None:
                print(
                    f"  list value == single-GET value: "
                    f"{from_list.get('description') == got}"
                )
            else:
                print("  (the new case was not in the first page of the listing)")

        # -------------------------------------------------- question 3
        print("\n" + "=" * 74)
        print("3 · Length")
        print("=" * 74)
        lengths = [len(str(c.get("description") or "")) for c in cases]
        if lengths:
            print(f"  longest description seen: {max(lengths)} chars")
        print("  (no documented limit; a marker line adds ~26 chars)")

        if created_id:
            print(
                f"\nProbe case {created_id} was CREATED and is not cleaned up — "
                f"delete it in the Purview portal."
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
