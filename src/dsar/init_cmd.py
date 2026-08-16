"""`dsar init` — the last piece of install friction, removed.

The install path is already one command with nothing cloned:

    uvx --from git+https://github.com/azurebeard/dsar-assist dsar up

What remained was the two identifiers, which had to be exported every run or
written to `~/.dsar/config.json` by hand. This writes that file once, with the
permissions the loader insists on, and every later `dsar up` needs nothing.

Neither value is a secret — they identify a registration, they authorise
nothing — but the file's permissions still matter: `tenant_id` selects which
Entra tenant the operator signs in to, so whoever can write the file chooses
the identity provider. `0600`, same as the loader enforces.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from dsar.config import DEFAULT_HOME, ensure_private_dir

__all__ = ["run_init"]

_GUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _ask(prompt: str, given: str) -> str:
    """A flag wins; otherwise ask. Refuses to prompt with no terminal, so a
    script that forgot a flag fails loudly instead of hanging on stdin."""
    if given:
        return given.strip()
    if not sys.stdin.isatty():
        raise SystemExit(
            f"{prompt} is required. Non-interactively, pass --client-id and "
            f"--tenant-id."
        )
    return input(f"{prompt}: ").strip()


def run_init(client_id: str = "", tenant_id: str = "", force: bool = False) -> int:
    home = Path(os.environ.get("DSAR_HOME", str(DEFAULT_HOME))).expanduser()
    target = home / "config.json"

    if target.exists() and not force:
        print(f"{target} already exists. Re-run with --force to overwrite it.")
        print("Current contents are preserved; nothing was changed.")
        return 1

    client_id = _ask("Application (client) ID", client_id)
    tenant_id = _ask("Tenant ID", tenant_id)

    problems = [
        f"  {name} does not look like a GUID: {value!r}"
        for name, value in (("client id", client_id), ("tenant id", tenant_id))
        if not _GUID.match(value)
    ]
    if problems:
        print("Refusing to write a config that cannot work:", file=sys.stderr)
        for problem in problems:
            print(problem, file=sys.stderr)
        print(
            "Both values are GUIDs from the app registration — ask whoever ran "
            "provision.sh, or read them off the registration's overview page.",
            file=sys.stderr,
        )
        return 2

    ensure_private_dir(home)
    target.write_text(
        json.dumps({"client_id": client_id, "tenant_id": tenant_id}, indent=2) + "\n",
        encoding="utf-8",
    )
    # The loader refuses a group- or other-writable file, because whoever can
    # write it chooses the identity provider. Set correctly at creation rather
    # than diagnosed afterwards.
    if os.name == "posix":
        target.chmod(0o600)

    print(f"Wrote {target}")
    print()
    print("Neither value is a secret; they identify a registration and")
    print("authorise nothing. The file is owner-only because tenant_id")
    print("chooses which Entra tenant sign-in goes to.")
    print()
    print("Next:  dsar up      (or: uvx --from git+https://github.com/azurebeard/dsar-assist dsar up)")
    return 0
