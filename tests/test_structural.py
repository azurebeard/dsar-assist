"""Structural invariants. These MUST pass at every commit.

Mechanical enforcement of the properties that make the security claim true —
the ones checkable without running the application. CI runs this file first and
alone, so an invariant breach is unambiguous in the log rather than buried in a
hundred unit-test lines.

A note on how the forbidden strings are written, inherited from the predecessor
and worth keeping. Every banned pattern below is assembled from fragments at
runtime. Written out whole, this file would trip the scan it performs, and the
honest fix — excluding this file from the sweep — would create a blind spot
exactly where a violation is easiest to hide. Assembling them keeps the scan
total.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

from conftest import REPO_ROOT

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
    "htmlcov",
}

# Markdown is excluded on purpose: the docs necessarily name the strings they
# forbid, and prose is not an execution path.
SOURCE_EXTS = {
    ".py",
    ".js",
    ".html",
    ".css",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".cfg",
    ".ini",
    ".sh",
    ".ps1",
    ".bicep",
    ".txt",
}


def _source_files() -> list[Path]:
    out: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.relative_to(REPO_ROOT).parts):
            continue
        if path.suffix.lower() in SOURCE_EXTS:
            out.append(path)
    return sorted(out)


def _python_files(subdir: str) -> list[Path]:
    root = REPO_ROOT / subdir
    if not root.exists():
        return []
    return sorted(
        p
        for p in root.rglob("*.py")
        if not any(part in EXCLUDED_DIRS for part in p.relative_to(REPO_ROOT).parts)
    )


def _rel(path: Path) -> str:
    """Repo-relative path, always with forward slashes.

    `str(Path.relative_to())` yields backslashes on Windows, so every allowlist
    below silently stopped matching there — six structural tests failed on
    `windows-latest` and passed everywhere else. That is precisely the class of
    failure the cross-platform CI matrix exists to catch, and precisely how the
    predecessor died.
    """
    return path.relative_to(REPO_ROOT).as_posix()


def _scan(pattern: str, *, flags: int = 0, files: list[Path] | None = None) -> list[str]:
    """Return 'relpath:lineno' for every line matching `pattern`."""
    rx = re.compile(pattern, flags)
    hits: list[str] = []
    for path in files if files is not None else _source_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if rx.search(line):
                hits.append(f"{_rel(path)}:{lineno}")
    return hits


# --------------------------------------------------------------- no data plane


def test_no_download_permission_named() -> None:
    """The download scope is never named in source.

    Stronger than it looks. The scope this scans for is not a Microsoft Graph
    permission at all — it is an application permission on a separate resource
    (see the next test), and downloads additionally require a distinct token
    and header. So this is not "we forgot to request it"; it is "no code path
    in this repository has ever contemplated it".

    The pattern is assembled rather than written out, so this file does not
    trip its own scan and no file needs excluding.
    """
    pattern = "eDiscovery" + r"\.Download\.Read"
    assert _scan(pattern) == []


def test_purview_download_resource_never_named() -> None:
    """The eDiscovery download resource is never named, by name or by app ID.

    This is where the download permission actually lives — a resource distinct
    from Microsoft Graph, whose service principal usually does not even exist
    in a tenant until someone creates it. Never naming it is what makes the
    no-data-plane claim structural, rather than a matter of which scopes happen
    to be requested today.
    """
    resource = "Microsoft" + "Purview" + "EDiscovery"
    app_id = "b26e684c-5068" + "-4120-a679-" + "64a5d2c909d9"
    assert _scan(resource) == []
    assert _scan(re.escape(app_id)) == []


def test_no_download_or_preview_verbs_in_graph_layer() -> None:
    """No Graph operation may be named for downloading or previewing."""
    forbidden = ("download", "preview", "exportResult" + "/content")
    hits: list[str] = []
    for word in forbidden:
        hits += _scan(rf"\b{re.escape(word)}\b", flags=re.I, files=_python_files("src/dsar/graph"))
    assert hits == []


# ------------------------------------------------------------------ no secrets


def test_no_client_secret_anywhere() -> None:
    """No source file may carry a client-secret configuration path.

    Desktop is a public client with PKCE. Hosted authenticates with a federated
    credential minted at runtime by a managed identity. There is no third
    option, and a secret appearing in source means one was invented.
    """
    patterns = [
        "client" + "_secret",
        "clientSecret",
        "password" + "Credentials",
    ]
    allowed = {
        # `config.py` names the variables it refuses to let you set, and
        # `checks.py` reports on them. Naming a thing in order to ban it is the
        # opposite of using it.
        "src/dsar/config.py",
        "src/dsar/doctor/checks.py",
        # The suite strips these from the environment and asserts doctor fails
        # on them. Naming a thing in order to prove it is refused is the
        # opposite of using it.
        "tests/conftest.py",
        "tests/test_doctor.py",
        "tests/test_hardening.py",
        "tests/test_structural.py",
    }
    hits = [
        hit
        for pattern in patterns
        for hit in _scan(pattern, flags=re.I)
        if hit.rsplit(":", 1)[0] not in allowed
    ]
    assert hits == []


def test_no_serializable_token_cache() -> None:
    """`msal.SerializableTokenCache` must not appear.

    This is what makes "tokens live in memory only" an invariant rather than a
    convention. The serialisable cache is the first step towards writing one to
    disk, and a token on disk is a local re-implementation of session lifetime
    that Conditional Access cannot see, cannot shorten and cannot revoke.
    """
    pattern = "Serializable" + "TokenCache"
    allowed = {"tests/test_structural.py"}
    hits = [h for h in _scan(pattern) if h.rsplit(":", 1)[0] not in allowed]
    assert hits == []


def test_msal_extensions_never_imported() -> None:
    """The dependency that caused every observed portability failure.

    Its libsecret backend needs PyGObject, a system package pip cannot install,
    so inside a venv the encrypted backend silently disappears and the tool
    degrades to interactive sign-in on every launch — on a host that has a
    perfectly good keyring.
    """
    pattern = "msal" + "_extensions"
    allowed = {
        # Each of these names the package in order to prove it is absent:
        # doctor at runtime, CI inside the built image, this file statically.
        "src/dsar/doctor/checks.py",
        ".github/workflows/ci.yml",
        "tests/test_structural.py",
    }
    hits = [h for h in _scan(pattern) if h.rsplit(":", 1)[0] not in allowed]
    assert hits == []


# ------------------------------------------------------------- choke points


def test_http_client_choke_point() -> None:
    """Only named files may speak HTTP.

    The predecessor allowed exactly one. This design allows three, and each
    addition is argued rather than assumed: the hosted audit sink talks to
    Azure Blob Storage, and the hosted client assertion comes from the
    Container Apps identity endpoint. Taking the Azure SDK for four REST calls
    between them would be the worse trade. The invariant is widened explicitly,
    not quietly — a fourth importer fails.
    """
    permitted = {
        "src/dsar/graph/client.py",
        "src/dsar/audit/blob.py",
        # Mints the client assertion from the Container Apps identity endpoint.
        # A documented REST contract, ~30 lines, no SDK.
        "src/dsar/auth/managed_identity.py",
    }
    banned = ["httpx", "requests", "aiohttp", "urllib" + ".request", "http" + ".client"]
    hits: list[str] = []
    for module in banned:
        pattern = rf"^\s*(?:import|from)\s+{re.escape(module)}\b"
        hits += [
            h
            for h in _scan(pattern, flags=re.M, files=_python_files("src/dsar"))
            if h.rsplit(":", 1)[0] not in permitted
        ]
    assert hits == []


def test_msal_confined_to_auth_package() -> None:
    """Only `dsar/auth/` may import MSAL.

    Everything downstream takes a `TokenProvider` and cannot discover which
    mode it is in, let alone which client class produced its token.
    """
    pattern = r"^\s*(?:import|from)\s+msal\b"
    hits = [
        h
        for h in _scan(pattern, flags=re.M, files=_python_files("src/dsar"))
        if not h.startswith("src/dsar/auth/")
    ]
    assert hits == []


def test_no_sqlite_anywhere() -> None:
    """The database is gone. Make it stay gone.

    A local SQLite store as the source of truth is why the predecessor's work
    did not travel: a correctly-installed second machine, signed into the right
    tenant, showed an empty queue. Microsoft Graph is now the source of truth,
    and reintroducing a durable local store would reintroduce the failure.
    """
    pattern = r"\bsqlite3?\b"
    allowed = {"tests/test_structural.py"}
    hits = [h for h in _scan(pattern, flags=re.I) if h.rsplit(":", 1)[0] not in allowed]
    assert hits == []


# -------------------------------------------------------------- dependencies


def test_declared_dependencies_are_the_budget() -> None:
    """The dependency budget is asserted over what we declare, not what resolves.

    `msal` pulls `requests` transitively; that is visible in `uv.lock` and is
    not hidden. The predecessor maintained a hand-written allowlist of resolved
    transitives and it did not survive dependency churn — a Dependabot bump was
    closed because the audit tripped on two new indirect packages. Asserting on
    the declared set is the version of this invariant that stays true.
    """
    manifest = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {
        re.split(r"[<>=!~\[]", spec, maxsplit=1)[0].strip()
        for spec in manifest["project"]["dependencies"]
    }
    assert declared == {"msal", "httpx", "starlette", "uvicorn"}


# ------------------------------------------------------------------ exposure


def test_launchers_publish_to_loopback_only() -> None:
    """The desktop network boundary, now that it is a flag and not a literal.

    The predecessor asserted a `127.0.0.1` bind address in the source. Docker
    publishes to the container's interface, so that guarantee cannot survive
    containerisation. It moved to the launcher, and this is the test that moved
    with it — without which the change would be a quiet loss rather than a
    relocation.
    """
    for name in ("dsar", "dsar.ps1"):
        path = REPO_ROOT / name
        assert path.is_file(), f"{name} is missing"
        text = path.read_text(encoding="utf-8")
        assert "127.0.0.1:8765:8765" in text, (
            f"{name} must publish to host loopback only — without the address "
            f"prefix, `-p 8765:8765` binds every interface on the host"
        )


def test_launchers_harden_the_container() -> None:
    """Runtime hardening flags live in the launcher, so assert them there.

    The application writes only to the audit mount, so a read-only root costs
    nothing. Without these the container can be written to, can gain privileges
    through a setuid binary, and holds every default capability.
    """
    required = (
        "--read-only",
        "--tmpfs /tmp",
        "--security-opt no-new-privileges",
        "--cap-drop ALL",
    )
    for name in ("dsar", "dsar.ps1"):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        missing = [flag for flag in required if flag not in text]
        assert missing == [], f"{name} is missing {missing}"


def test_base_images_are_digest_pinned() -> None:
    """A tag can be repointed upstream without any change here.

    Reproducibility is this project's reason for existing, so a build that can
    silently change underneath it is not a defensible base.
    """
    lines = [
        line
        for line in (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
        if line.startswith("FROM ")
    ]
    assert lines, "no FROM lines found"
    unpinned = [line for line in lines if "@sha256:" not in line]
    assert unpinned == [], f"not digest-pinned: {unpinned}"


def test_bind_address_is_not_configurable() -> None:
    """There is no option that changes what the process binds.

    An environment variable or a CLI flag that moved the bind address would
    make the launcher's `-p 127.0.0.1:8765:8765` guarantee unverifiable from
    the outside — the operator could no longer tell, from the command they
    typed, what the container is reachable on.

    The wildcard address is named in exactly two modules: `web/app.py`, which
    binds it, and `doctor/checks.py`, which explains the resulting exposure to
    the operator. A third would mean the decision had spread.
    """
    assert _scan(r"DSAR_(?:BIND|HOST|BIND_HOST)\b") == []

    literal = "0.0.0." + "0"
    naming_it = {
        h.rsplit(":", 1)[0]
        for h in _scan(re.escape(literal), files=_python_files("src/dsar"))
    }
    assert naming_it == {"src/dsar/web/app.py", "src/dsar/doctor/checks.py"}


# ---------------------------------------------------------------- entry points


def test_both_entry_points_resolve() -> None:
    """`dsar` and `python -m dsar` must be the same code.

    The predecessor's docs assumed a console script nobody had installed, and
    nothing caught it. Here the console script target and `__main__` are
    asserted to be the same object.
    """
    manifest = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert manifest["project"]["scripts"] == {"dsar": "dsar.__main__:main"}

    import dsar.__main__ as entry
    from dsar.cli import main

    assert entry.main is main


def test_docs_never_show_a_bare_dsar_command() -> None:
    """Every documented invocation must be one that works on a fresh machine.

    This targets the observed failure directly: the documentation lied, said
    `dsar auth login`, and the console script was not on PATH. Prefixes that
    are true on a machine with nothing installed are the only ones allowed.
    """
    prefixes = ("uv run ", "uvx ", "docker run", "docker ", "./dsar", ".\\dsar")
    offenders: list[str] = []
    for path in sorted(REPO_ROOT.rglob("*.md")):
        if any(part in EXCLUDED_DIRS for part in path.relative_to(REPO_ROOT).parts):
            continue
        in_block = False
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("```"):
                in_block = stripped.startswith(("```bash", "```sh", "```console"))
                continue
            if not in_block:
                continue
            if stripped.startswith("dsar ") and not stripped.startswith(prefixes):
                offenders.append(f"{_rel(path)}:{lineno}: {stripped}")
    assert offenders == []


def test_every_source_package_is_tracked_by_git() -> None:
    """No package may be excluded by an ignore rule.

    `.gitignore` carried a bare `audit/` to keep audit output out of the repo.
    A bare directory pattern matches at *any* depth, so it silently excluded
    `src/dsar/audit/` — the package Phase 3 lives in. Nothing failed; the files
    would simply never have been committed. An ignore rule that hides your own
    source is worse than the accident it was written to prevent.
    """
    import subprocess

    packages = {
        p.parent.relative_to(REPO_ROOT).as_posix()
        for p in (REPO_ROOT / "src").rglob("__init__.py")
    }
    assert packages, "no packages found under src/"

    ignored = subprocess.run(
        ["git", "check-ignore", "--stdin"],
        cwd=REPO_ROOT,
        input="\n".join(sorted(packages)),
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split()
    assert ignored == [], f"ignored by .gitignore: {ignored}"


def test_static_allowlist_files_exist_in_the_package() -> None:
    """Every allowlisted asset must exist where the installed package looks.

    This is the class of bug that only appears in the container: the source
    tree has the file, the wheel does not, and the first symptom is a 500 on
    the front page during a demo.
    """
    from dsar.web.app import STATIC_DIR
    from dsar.web.security import ALLOWED_STATIC

    missing = [name for name in set(ALLOWED_STATIC.values()) if not (STATIC_DIR / name).is_file()]
    assert missing == []


def test_no_print_outside_the_cli_surface() -> None:
    """Output is a user-facing concern and belongs where a user is expected.

    Ported from the predecessor. A stray `print` in a library module is how a
    token ends up on stdout, bypassing the redaction filter attached to the
    logging handlers.
    """
    permitted = {"src/dsar/doctor/report.py"}
    offenders: list[str] = []
    for path in _python_files("src/dsar"):
        rel = _rel(path)
        if rel in permitted:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                offenders.append(f"{rel}:{node.lineno}")
    assert offenders == []
