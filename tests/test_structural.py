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


def test_no_download_or_preview_operation_exists() -> None:
    """No permitted operation may download or preview item content.

    Checked against the operations table and the callable surface rather than
    against free text. An earlier version scanned the whole Graph package for
    the words, which failed on prose explaining that the tool does *not*
    download — a test that forbids describing the guarantee is a test that
    pressures you into deleting the explanation.

    What matters is that no operation exists, so that is what is asserted: no
    table key, no URL template, and no public method name contains either verb.
    """
    from dsar.graph.operations import OPERATIONS, GraphOperations

    forbidden = ("download", "preview", "content")
    offenders: list[str] = []

    for key, operation in OPERATIONS.items():
        haystack = f"{key} {operation.template}".lower()
        offenders += [f"OPERATIONS[{key!r}]" for word in forbidden if word in haystack]

    for name in dir(GraphOperations):
        if name.startswith("_"):
            continue
        offenders += [
            f"GraphOperations.{name}" for word in forbidden if word in name.lower()
        ]

    assert offenders == []


def test_operations_table_is_the_documented_set() -> None:
    """Eleven operations, named. Adding one is a visible diff — the point of
    the table."""
    from dsar.graph.operations import OPERATIONS

    assert set(OPERATIONS) == {
        "list_cases",
        "create_case",
        "get_case",
        "list_searches",
        "create_search",
        "run_search",
        "get_statistics",
        "list_operations",
        "get_operation",
        "initiate_export",
        "find_users",
    }
    # Every entry's key must match its own name, or the table lies about itself.
    assert all(key == op.name for key, op in OPERATIONS.items())


def test_no_graph_path_is_caller_supplied() -> None:
    """Every request path comes from the table, never from an argument.

    This is what makes the allowlist an allowlist. A method that accepted a
    path would turn the table into documentation.
    """
    import ast

    source = (REPO_ROOT / "src/dsar/graph/operations.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            args = {a.arg for a in node.args.args} | {
                a.arg for a in node.args.kwonlyargs
            }
            if {"path", "url", "template", "endpoint"} & args:
                offenders.append(f"{node.name}:{node.lineno}")
    assert offenders == []


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
        # Probes and provisioning assert the *absence* of a secret: the FIC
        # probe checks no client_secret is sent alongside the assertion, and
        # provision.sh refuses a registration holding password credentials.
        # Naming a thing in order to prove it is not there is the opposite of
        # using it.
        "verification/probe_fic_assertion_offline.py",
        "infra/entra/provision.sh",
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
    allowed = {
        # Both name the class in a comment explaining why the in-memory
        # `msal.TokenCache` is used instead. Naming a thing in order to rule it
        # out is the opposite of using it — and the comment is the reason the
        # next person does not "helpfully" swap it in.
        "src/dsar/auth/msal_client.py",
        "src/dsar/auth/session.py",
        "tests/test_structural.py",
    }
    hits = [h for h in _scan(pattern) if h.rsplit(":", 1)[0] not in allowed]
    assert hits == []

    # The ban is only meaningful if the class is genuinely never instantiated.
    # A comment cannot be checked by reading comments, so check the AST too.
    import ast

    offenders: list[str] = []
    for path in _python_files("src/dsar"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                if name == "Serializable" + "TokenCache":
                    offenders.append(f"{_rel(path)}:{node.lineno}")
    assert offenders == []


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


def test_no_local_database() -> None:
    """The database is gone. Make it stay gone.

    A local SQLite store as the source of truth is why the predecessor's work
    did not travel: a correctly-installed second machine, signed into the right
    tenant, showed an empty queue, and the documented remedy was to copy the
    file. Microsoft Graph is the source of truth now, and reintroducing a
    durable local store would reintroduce the failure.

    Checked by import and by usage rather than by scanning for the word. The
    text-scanning version failed on a comment explaining *why* there is no
    database — the fourth time a structural test in this file had objected to
    prose describing the guarantee it enforces. A test that penalises writing
    down the reason quietly pressures the next person into deleting it, which
    costs more than the test protects.
    """
    import ast

    banned_modules = {"sqlite" + "3", "aiosqlite", "sqlalchemy", "psycopg", "pymongo"}
    offenders: list[str] = []

    for path in _python_files("src/dsar"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in banned_modules:
                        offenders.append(f"{_rel(path)}:{node.lineno} import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in banned_modules:
                    offenders.append(f"{_rel(path)}:{node.lineno} from {node.module}")

    assert offenders == []

    # And no code path that names a database file. A `.db` under the audit
    # directory would be a durable local store by another name.
    assert _scan(r"\.db\b", files=_python_files("src/dsar")) == []


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
    permitted = {
        # The two modules whose whole job is speaking to a person at a
        # terminal. Everything else logs, so the redaction filter applies.
        "src/dsar/doctor/report.py",
        "src/dsar/audit/report.py",
    }
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


def test_path_segments_cannot_escape_the_operations_table() -> None:
    """A crafted identifier must not reach an endpoint outside the table.

    The predecessor's pattern permitted `..`, and its comment claimed a
    dot-segment guarantee it did not provide. HTTP clients normalise dot
    segments before the request leaves, so `caseId=".."` against the
    `{caseId}/searches` template resolved to `/security/cases/searches` —
    outside the allowlist, reached through the check meant to prevent it.

    This is the allowlist's load-bearing assumption, so it is asserted with
    the vectors rather than trusted to a regex reading.
    """
    from dsar.graph.operations import GraphOperations, UnsafePathArgument

    class Spy:
        def __init__(self) -> None:
            self.paths: list[str] = []

        def request(self, method: str, path: str, **kwargs: object) -> object:
            self.paths.append(path)
            return object()

    spy = Spy()
    operations = GraphOperations(spy)  # type: ignore[arg-type]

    attacks = [
        "..", ".", "...", "%2e%2e", "..%2f..", "../../users",
        "a/b", "a?x=1", "a#f", "", " ", "a b", "%2f", "..;/",
    ]
    accepted = []
    for value in attacks:
        try:
            operations.get_case(case_id=value)
            accepted.append(value)
        except UnsafePathArgument:
            pass
    assert accepted == [], f"path check accepted: {accepted}"
    assert spy.paths == [], f"a crafted identifier reached the client: {spy.paths}"

    # And a real Graph identifier is still usable, or the fix is a denial of
    # service on the product.
    operations.get_case(case_id="01f85886-7bef-4a22-a27d-18bf9733bbc8")
    assert spy.paths == [
        "/security/cases/ediscoveryCases/01f85886-7bef-4a22-a27d-18bf9733bbc8"
    ]


def test_the_audit_sink_has_no_mutating_method() -> None:
    """Append-only because there is no other verb, not because one is guarded.

    The predecessor enforced this with SQLite triggers — correct, and a
    guarantee that cannot travel, because it lives inside the engine. A
    Protocol with no update, delete or truncate travels with the record.
    """
    from dsar.audit.sink import AuditSink

    surface = {name for name in dir(AuditSink) if not name.startswith("_")}
    assert surface == {"append", "head"}, f"AuditSink grew a method: {surface}"


def test_nothing_in_the_audit_package_can_rewrite_a_file() -> None:
    """A sink that can open for writing, truncate or unlink is a sink that can
    edit history. Checked by AST, so a new file cannot quietly acquire it."""
    import ast

    banned_calls = {"remove", "unlink", "truncate", "rmtree", "replace", "rename"}
    offenders: list[str] = []

    for path in _python_files("src/dsar/audit"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name in banned_calls:
                offenders.append(f"{_rel(path)}:{node.lineno} {name}()")
            # `open(..., "w")` and friends truncate. Append and read do not.
            if name == "open":
                for arg in list(node.args[1:2]) + [
                    kw.value for kw in node.keywords if kw.arg == "mode"
                ]:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if any(c in arg.value for c in ("w", "x", "+")):
                            offenders.append(
                                f"{_rel(path)}:{node.lineno} open(mode={arg.value!r})"
                            )
    assert offenders == []


def test_the_audit_record_cannot_carry_subject_data() -> None:
    """The field names are the control.

    There is no field for a name, an address, an employee id or a query — so a
    caller cannot record one without changing the record shape, which is a
    visible diff. Writing those to a durable local file would create a second,
    ungoverned copy of exactly the third-party personal data this tool exists
    to handle carefully.
    """
    from dsar.audit.record import AuditRecord

    fields = set(AuditRecord.__dataclass_fields__)
    forbidden = {
        "subject_email", "subject_name", "primary_email", "display_name",
        "query", "content_query", "kql", "employee_id", "proxy_addresses",
        "other_mails", "aliases", "mentions",
    }
    assert not (fields & forbidden), f"audit record grew: {fields & forbidden}"
    # The subject appears as a pseudonym and in no other form.
    assert "subject_ref" in fields


def test_every_action_is_pinned_to_a_commit_sha() -> None:
    """A tag can be repointed at different code without any change here.

    Not new — CI already did this — but the publish workflow signs and pushes
    an artefact, so an unpinned action there has a longer reach than one that
    merely runs tests.
    """
    unpinned: list[str] = []
    for path in sorted((REPO_ROOT / ".github/workflows").glob("*.yml")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith(("- uses:", "uses:")):
                continue
            ref = stripped.split("uses:", 1)[1].strip()
            if ref.startswith("./"):
                continue
            if "@" not in ref:
                unpinned.append(f"{_rel(path)}:{lineno} {ref}")
                continue
            sha = ref.split("@", 1)[1].split()[0]
            if len(sha) != 40 or not all(c in "0123456789abcdef" for c in sha):
                unpinned.append(f"{_rel(path)}:{lineno} {ref}")
    assert unpinned == []


def test_the_launcher_does_not_treat_docker_as_available_by_default() -> None:
    """Docker being installed is not the same as the image being pullable.

    The launcher preferred Docker on `command -v docker` alone, and the default
    image had never been published — so having Docker installed was a reason
    the tool did not start. Both runtimes exist so that neither is a single
    point of failure; this restores that.
    """
    for name in ("dsar", "dsar.ps1"):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        assert "docker image inspect" in text, f"{name} does not check for the image"
        assert "docker pull" in text, f"{name} does not try to pull it"


def test_the_front_end_never_assigns_html() -> None:
    """`app.js` opens by declaring "textContent, never innerHTML" as a rule of
    its own. Until now nothing enforced it.

    That is precisely the shape of SEC-H-02, where a comment claimed a
    guarantee the code did not provide and survived two readings and a passed
    review. The values rendered here are a data subject's name, their aliases
    and the free-text terms an operator typed — the CSP blocks a remote script
    but not markup injected into the page from a directory lookup.

    Literals assembled at runtime so the scanner does not match itself. Same
    trick as the rest of this module, and for the same reason.
    """
    from dsar.web.app import STATIC_DIR

    forbidden = (
        "inner" + "HTML",
        "outer" + "HTML",
        "insertAdjacent" + "HTML",
        "document." + "write",
    )
    offenders: list[str] = []
    for path in sorted(STATIC_DIR.glob("*.js")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue  # the rule is allowed to name what it forbids
            offenders += [
                f"{path.name}:{number} {word}" for word in forbidden if word in line
            ]
    assert offenders == []


def test_the_interpreter_version_is_decided_in_one_place() -> None:
    """Two stages that must agree on a Python minor version, and nothing
    checking, is a silent failure waiting for a dependency bump.

    It arrived on schedule. Dependabot's `python:3.13-slim` -> `3.14-slim`
    (PR #1) changed the runtime base and not the builder, so the venv was built
    at 3.13 into `lib/python3.13/site-packages` and a 3.14 interpreter did not
    look there. The whole failure was one line: `No module named 'dsar'`.

    The runtime image now carries an interpreter copied from the builder, so
    there is one version and it is named once, in `PYTHON_VERSION`. This
    asserts that stays true — that no `FROM` reintroduces a second interpreter
    whose version has to be kept in step by hand.
    """
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")

    versions = set(re.findall(r"^ARG PYTHON_VERSION=(.+)$", dockerfile, re.M))
    assert len(versions) == 1, f"expected exactly one PYTHON_VERSION, got {versions}"

    # A base image whose tag names a Python version is a second, independent
    # decision about which interpreter runs.
    froms = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    versioned = [line for line in froms if re.search(r"python[:/]?3\.\d+", line)]
    assert versioned == [], (
        "a base image tag names a Python version, so two places now decide "
        f"which interpreter runs: {versioned}"
    )


def test_the_runtime_image_has_no_shell() -> None:
    """The base is distroless and that is load-bearing: it is what removed all
    23 unfixable HIGH and CRITICAL findings (B-08).

    Asserted against the Dockerfile because the suite must not require Docker.
    CI checks the built image directly, which is the stronger form of the same
    check — see "No shell in the runtime image".
    """
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile.split("# ------")[-1]
    final_from = [line for line in dockerfile.splitlines() if line.startswith("FROM ")][-1]
    assert "distroless" in final_from, f"runtime base is not distroless: {final_from}"

    # `RUN` in the runtime stage cannot work without a shell, and a `SHELL`
    # directive or a copied-in busybox would put one back.
    for forbidden in ("RUN ", "SHELL ", "busybox"):
        assert forbidden not in runtime, (
            f"{forbidden.strip()!r} in the runtime stage — there is no shell "
            f"for it, and adding one undoes B-08"
        )
