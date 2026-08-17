"""Preflight checks.

Every check returns a verdict, a one-line finding, and — when it fails — the
thing to do about it. That last field is the point of the module. The
predecessor's failure mode was not that it broke loudly; it was that it
degraded silently and correctly reported "no encrypted backend" on a host that
had one, and nobody could tell whether that was expected.

This file covers everything a session is not needed for: packaging, mode,
configuration, credential hygiene and the audit sink. The two checks that DO
need a session — whether the operator holds a DSAR app role, and whether
Purview eDiscovery answers them — cannot run here, because `doctor` has no
token and never will. They run at sign-in instead (`/api/readiness`, B-18)
and surface in the interface, so a first-run operator gets a named diagnosis
before real work starts rather than a surprise on the first attempt.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator

from dsar import __version__
from dsar.config import (
    SECRET_SHAPED_SUFFIXES,
    ConfigError,
    dir_mode,
    ensure_private_dir,
    load_config,
    secret_shaped_env,
)
from dsar.mode import Mode, ModeError, detect_mode

__all__ = ["Verdict", "Finding", "Check", "CHECKS", "run_checks"]


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass(frozen=True)
class Finding:
    check: str
    verdict: Verdict
    detail: str
    #: What to do about it. Empty when there is nothing to do.
    fix: str = ""


@dataclass(frozen=True)
class Check:
    name: str
    #: True when the check reaches the network, so `--offline` can skip it.
    needs_network: bool
    run: Callable[[], Finding]


# --------------------------------------------------------------- packaging


def _check_entry_point() -> Finding:
    """Are we running from an installed console script, or from a source tree?

    This is the predecessor's failure #4, made visible. `pip install -e .` was
    never run there, so `dsar` was not on PATH, yet every line of documentation
    assumed it was. In the container this is guaranteed by construction — the
    ENTRYPOINT *is* the console script — so a FAIL here means a contributor
    environment, not a shipped artefact.
    """
    argv0 = Path(sys.argv[0]).name
    if argv0 in {"dsar", "dsar.exe"}:
        return Finding(
            "entry point",
            Verdict.PASS,
            f"running as the installed console script ({sys.argv[0]})",
        )
    if argv0 in {"__main__.py", "-c"} or "-m" in sys.argv:
        return Finding(
            "entry point",
            Verdict.PASS,
            "running via `python -m dsar`, which is a supported entry point",
        )
    return Finding(
        "entry point",
        Verdict.WARN,
        f"invoked as {sys.argv[0]!r}, which is neither entry point",
        "Use `uv run dsar`, `uvx dsar`, `python -m dsar` or the container. "
        "A bare `dsar` only works once the package is installed, which is the "
        "exact failure this project exists to prevent.",
    )


def _check_version_agreement() -> Finding:
    """`dsar --version` and `python -m dsar --version` must agree.

    Both resolve through `dsar.__main__:main`, so they cannot disagree without
    something being very wrong with the install — which is precisely when you
    want to be told.
    """
    from dsar.cli import build_parser

    parser = build_parser()
    action = next(
        (a for a in parser._actions if "--version" in a.option_strings), None
    )
    declared = getattr(action, "version", None)
    expected = f"dsar {__version__}"
    if declared == expected:
        return Finding("version", Verdict.PASS, expected)
    return Finding(
        "version",
        Verdict.FAIL,
        f"parser reports {declared!r}, package reports {expected!r}",
        "The console script and the package metadata have diverged. Reinstall.",
    )


def _check_no_msal_extensions() -> Finding:
    """`msal-extensions` must not be importable.

    Not a style preference. Its libsecret backend needs PyGObject, a system
    package pip cannot install, so inside a venv the encrypted backend silently
    disappears and the tool degrades to interactive sign-in on every launch.
    That is the single cause of every observed portability failure in the
    predecessor. Tokens here live in memory and nowhere else, so if this
    package is present something has reintroduced the dependency.
    """
    import importlib.util

    if importlib.util.find_spec("msal_extensions") is None:
        return Finding(
            "no keyring dependency",
            Verdict.PASS,
            "msal-extensions is absent; tokens are held in memory only",
        )
    return Finding(
        "no keyring dependency",
        Verdict.FAIL,
        "msal-extensions is installed",
        "Remove it. Persisting tokens to an OS keyring is what made the "
        "predecessor unportable; this design signs in once per process instead.",
    )


# -------------------------------------------------------------------- mode


def _check_mode() -> Finding:
    try:
        mode, reason = detect_mode()
    except ModeError as exc:
        return Finding("mode", Verdict.FAIL, str(exc), "Set DSAR_MODE=desktop|hosted.")
    return Finding("mode", Verdict.PASS, f"{mode.value} — {reason}")


def _check_exposure() -> Finding:
    """Report the effective network exposure, as far as it can be observed.

    The predecessor asserted `127.0.0.1` as a literal in the source and tested
    for it. That guarantee cannot survive containerisation — Docker publishes
    to the container's interface, so the process must bind `0.0.0.0` inside its
    own network namespace even on a desktop. The control moved to the launcher
    (`-p 127.0.0.1:8765:8765`) and to the ingress configuration, and both are
    asserted elsewhere. What this check can honestly do is say where the
    boundary now lives, rather than imply one that no longer exists.
    """
    mode, _ = detect_mode()
    if mode.is_hosted:
        return Finding(
            "exposure",
            Verdict.PASS,
            "hosted: reachable via Container Apps ingress. The boundary is "
            "allowInsecure=false, ipSecurityRestrictions and Conditional Access "
            "— not the bind address",
        )
    in_container = Path("/.dockerenv").exists() or os.environ.get("DSAR_IN_CONTAINER")
    if in_container:
        return Finding(
            "exposure",
            Verdict.PASS,
            "desktop in a container: binds 0.0.0.0 inside its own network "
            "namespace. Reachability is decided by the launcher's "
            "-p 127.0.0.1:8765:8765, which publishes to host loopback only",
        )
    return Finding(
        "exposure",
        Verdict.PASS,
        "desktop on the host: binds loopback directly",
    )


# ----------------------------------------------------------- configuration


def _check_no_secrets() -> Finding:
    """No secret-shaped variable may be set.

    The design has no secret: desktop is a public client with PKCE, hosted
    authenticates with a federated credential minted at runtime by a managed
    identity. So a secret in the environment is not a risk to be weighed — it
    means someone has misunderstood the deployment, and is about to be
    surprised by which credential is actually in use. FAIL, not WARN.
    """
    present = secret_shaped_env()
    if not present:
        return Finding(
            "no secrets",
            Verdict.PASS,
            "no variable ending "
            + ", ".join(SECRET_SHAPED_SUFFIXES)
            + " is set",
        )
    return Finding(
        "no secrets",
        Verdict.FAIL,
        f"set: {', '.join(present)}",
        "Unset it. This application has no code path that consumes a client "
        "secret, certificate or assertion from the environment; its presence "
        "means the deployment is not what you think.",
    )


def _check_config() -> Finding:
    try:
        config = load_config()
    except ConfigError as exc:
        return Finding(
            "configuration",
            Verdict.FAIL,
            str(exc),
            "Set DSAR_CLIENT_ID and DSAR_TENANT_ID. Neither is a secret — they "
            "identify a registration, they do not authorise anything.",
        )

    bad = [
        f"{label}={value!r}"
        for label, value in (
            ("DSAR_CLIENT_ID", config.client_id),
            ("DSAR_TENANT_ID", config.tenant_id),
        )
        if not _looks_like_guid(value)
    ]
    if bad:
        return Finding(
            "configuration",
            Verdict.FAIL,
            f"not a well-formed GUID: {', '.join(bad)}",
            "Both are GUIDs. A tenant domain name is not a tenant ID here — the "
            "authority is pinned to the GUID so a token from another tenant "
            "cannot be silently accepted.",
        )

    return Finding(
        "configuration",
        Verdict.PASS,
        f"client {config.client_id}, tenant {config.tenant_id} (from {config._source})",
    )


def _check_redirect_uri() -> Finding:
    """Print the exact redirect URI, ready to paste into the registration.

    A mismatch here is the most common cause of auth grief and the error Entra
    returns names the value it expected, not the value to register. Printing it
    turns a twenty-minute round trip into a copy and paste.
    """
    try:
        config = load_config()
        uri = config.redirect_uri
    except ConfigError as exc:
        return Finding(
            "redirect URI",
            Verdict.SKIP,
            f"cannot compute: {exc}",
        )

    note = ""
    if config.mode is Mode.DESKTOP:
        note = (
            " — RFC 8252 §7.3 has the authorization server ignore the port when "
            "matching a localhost redirect, but never register two localhost "
            "URIs differing only by port: the login server picks between them "
            "arbitrarily. [::1] is not supported."
        )
    return Finding(
        "redirect URI",
        Verdict.PASS,
        f"register exactly this: {uri}{note}",
    )


def _check_audit_dir() -> Finding:
    try:
        config = load_config()
    except ConfigError:
        return Finding("audit sink", Verdict.SKIP, "configuration unresolved")

    if config.mode.is_hosted:
        if config.audit_blob_url:
            return Finding(
                "audit sink",
                Verdict.PASS,
                f"append blob at {config.audit_blob_url}",
            )
        return Finding(
            "audit sink",
            Verdict.FAIL,
            "hosted mode with no DSAR_AUDIT_BLOB_URL",
            "Set it to the append-blob container URL. Hosted mode without a "
            "durable audit sink keeps only the stderr copy.",
        )

    target = config.audit_dir
    try:
        ensure_private_dir(target)
        probe = target / ".dsar-write-probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return Finding(
            "audit sink",
            Verdict.FAIL,
            f"{target} is not writable: {exc}",
            "Point DSAR_AUDIT_DIR somewhere writable, or mount a volume there. "
            "In the container this path must be a mount or the trail dies with "
            "the container.",
        )

    mode = dir_mode(target)
    # `ensure_private_dir` tightens what it can. A mode that survives it is a
    # filesystem that does not honour chmod — a Windows path, or a mount with
    # a fixed uid/gid and permission set. Report it rather than claim a
    # protection the operator does not have.
    if mode.startswith("0o") and int(mode, 8) & 0o077:
        return Finding(
            "audit sink",
            Verdict.FAIL,
            f"{target} is mode {mode} — readable or writable by other local accounts",
            "The audit trail carries operator identity, case identifiers and a "
            f"subject pseudonym. Run: chmod 700 {target}. If this is a bind "
            "mount, set the ownership on the host side.",
        )

    return Finding(
        "audit sink",
        Verdict.PASS,
        f"append-only JSONL under {target} (mode {mode}, owner only)",
    )


def _looks_like_guid(value: str) -> bool:
    # Shared with `serve`, which refuses to start on the same answer this
    # check diagnoses — one shape rule, not two drifting copies.
    from dsar.config import looks_like_guid

    return looks_like_guid(value)


# --------------------------------------------------------------------- hosted


def _check_client_assertion() -> Finding:
    """Mint a client assertion and print the three values the FIC must match.

    Microsoft's own documentation warns that a federated credential with the
    wrong subject is *created successfully, without error* and fails only at
    token exchange. So this reads `aud`, `iss` and `sub` off the assertion the
    managed identity actually issues, and prints them for comparison against
    what `add-fic.sh` registered.

    The assertion is decoded, not validated — it is our own token, obtained
    over the container's loopback identity endpoint, and its signature is
    Entra's business. This is a diagnostic, not an authentication decision.
    """
    config = load_config()
    if not config.mode.is_hosted:
        return Finding("client assertion", Verdict.SKIP, "desktop mode")
    if not config.uami_client_id:
        return Finding(
            "client assertion",
            Verdict.FAIL,
            "DSAR_UAMI_CLIENT_ID is not set",
            "Hosted mode mints its client assertion from a user-assigned "
            "managed identity. There is no secret to fall back to.",
        )

    from dsar.auth.managed_identity import AssertionError_, client_assertion_for

    try:
        token = client_assertion_for(config.uami_client_id)()
    except AssertionError_ as exc:
        return Finding(
            "client assertion",
            Verdict.FAIL,
            str(exc),
            "Check the Container App has identity: UserAssigned and that "
            "DSAR_UAMI_CLIENT_ID names that identity's CLIENT id.",
        )

    claims = _unverified_claims(token)
    if claims is None:
        return Finding(
            "client assertion",
            Verdict.WARN,
            "an assertion was minted but could not be decoded",
            "The token is still usable; only this diagnostic is affected.",
        )
    return Finding(
        "client assertion",
        Verdict.PASS,
        f"aud={claims.get('aud')} iss={claims.get('iss')} sub={claims.get('sub')}",
        "`sub` must match the federated credential EXACTLY — it is the "
        "identity's principal id, case-sensitive, and is not the client id in "
        "DSAR_UAMI_CLIENT_ID. `aud` is shown as the resource's GUID because "
        "that is what Entra puts in the token; the credential still registers "
        "the literal `api://AzureADTokenExchange`, so a GUID here is correct "
        "and not a mismatch.",
    )


def _check_fic_exchange() -> Finding:
    """Prove Entra accepts the assertion, without creating anything.

    Redeems a deliberately invalid authorization code. The two failures are
    completely different things and Entra distinguishes them, which is what
    makes this a usable probe rather than a deployment:

      invalid_grant   client authentication SUCCEEDED. Entra is objecting only
                      to the bogus code, which means the FIC is right.
      invalid_client  client authentication FAILED. The FIC is wrong — compare
                      the three values from the check above.

    One request, nothing created, unambiguous either way. This is the live half
    of the question recorded as the design's largest unknown; the offline half
    (does MSAL send a client assertion on an authorization_code grant at all)
    was answered in verification/2026-08-14-fic-assertion-offline.md.
    """
    config = load_config()
    if not config.mode.is_hosted:
        return Finding("FIC exchange", Verdict.SKIP, "desktop mode")

    from dsar.auth.msal_client import build_client, scopes_for

    try:
        app = build_client(config)
        result = app.acquire_token_by_authorization_code(
            "invalid-code-this-probe-creates-nothing",
            scopes=scopes_for(config),
            redirect_uri=config.redirect_uri,
        )
    except ConfigError as exc:
        return Finding("FIC exchange", Verdict.FAIL, str(exc))
    except Exception as exc:  # a diagnostic must not take down the caller
        return Finding(
            "FIC exchange", Verdict.WARN, f"{type(exc).__name__}: {exc}"
        )

    error = str(result.get("error", ""))
    description = str(result.get("error_description", ""))[:200]

    if error == "invalid_grant":
        return Finding(
            "FIC exchange",
            Verdict.PASS,
            "client authentication succeeded — Entra rejected only the "
            "deliberately invalid code, which is the expected result",
        )
    if error == "invalid_client":
        return Finding(
            "FIC exchange",
            Verdict.FAIL,
            f"client authentication FAILED: {description}",
            "The federated credential does not match the assertion. Compare "
            "aud/iss/sub above with what add-fic.sh registered, and remember "
            "`sub` is the principal id, case-sensitive.",
        )
    if "AADSTS70021" in description:
        return Finding(
            "FIC exchange",
            Verdict.WARN,
            "no matching federated identity record found (AADSTS70021)",
            "This is usually replication lag on a newly created credential. "
            "Wait a few minutes and re-run before changing anything.",
        )
    return Finding(
        "FIC exchange",
        Verdict.WARN,
        f"unexpected response: {error or 'no error'} {description}",
        "Neither invalid_grant nor invalid_client, so this probe cannot say "
        "whether client authentication worked. Read the description.",
    )


def _unverified_claims(token: str) -> dict[str, object] | None:
    """Decode a JWT payload without validating it.

    Ours, from the loopback identity endpoint, for display only. Validation is
    Entra's job and doing it here would be a second implementation of an
    authority we do not own.
    """
    import base64
    import json as _json

    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        decoded = _json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None
    return decoded if isinstance(decoded, dict) else None


# ------------------------------------------------------------------ registry

CHECKS: tuple[Check, ...] = (
    Check("entry point", False, _check_entry_point),
    Check("version", False, _check_version_agreement),
    Check("no keyring dependency", False, _check_no_msal_extensions),
    Check("mode", False, _check_mode),
    Check("exposure", False, _check_exposure),
    Check("no secrets", False, _check_no_secrets),
    Check("configuration", False, _check_config),
    Check("redirect URI", False, _check_redirect_uri),
    Check("audit sink", False, _check_audit_dir),
    # Hosted only, and both reach the network. `--offline` skips them; so does
    # desktop mode, which is why they report SKIP rather than PASS there — a
    # check that passes without running is the mistake this project keeps
    # finding.
    Check("client assertion", True, _check_client_assertion),
    Check("FIC exchange", True, _check_fic_exchange),
)


def run_checks(offline: bool = False) -> Iterator[Finding]:
    for check in CHECKS:
        if offline and check.needs_network:
            yield Finding(check.name, Verdict.SKIP, "skipped: --offline")
            continue
        try:
            yield check.run()
        except Exception as exc:  # a broken check must not hide the others
            yield Finding(
                check.name,
                Verdict.FAIL,
                f"the check itself raised {type(exc).__name__}: {exc}",
                "This is a bug in doctor, not necessarily in your environment.",
            )
