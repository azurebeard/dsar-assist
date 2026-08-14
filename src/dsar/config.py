"""Runtime configuration.

Nothing here is credential material. A client ID and a tenant ID are published
values — they identify a registration, they do not authorise anything. There is
no setting for a secret because there is no code path that could use one, and
`doctor` fails if a secret-shaped variable is present in the environment at all.

Resolution order, first hit wins:
  1. environment variable
  2. `$DSAR_HOME/config.json`
  3. the default below, where one exists

Ported from the predecessor at 8652e638. Removed: `db_path`, `accounts_path`,
`token_cache_path` and the three worker concurrency caps — there is no database,
no account registry, no persisted token cache and no worker. Kept verbatim:
`PURVIEW_CASE_URL_TEMPLATE` and its reasoning, which was measured against a real
portal URL and is easy to get subtly wrong.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from dsar.mode import Mode, detect_mode

__all__ = [
    "Config",
    "ConfigError",
    "load_config",
    "DEFAULT_HOME",
    "SCOPES_V1",
    "SCOPE_USER_READ_ALL",
    "purview_case_url",
    "secret_shaped_env",
    "SECRET_SHAPED_SUFFIXES",
    "ensure_private_dir",
]

DEFAULT_HOME = Path.home() / ".dsar"
DEFAULT_PORT = 8765

# Reserved OIDC scopes. MSAL injects these itself and rejects them if passed in
# explicitly, so the scope list is expressed without them.
RESERVED_SCOPES: tuple[str, ...] = ("openid", "profile", "offline_access")

GRAPH_RESOURCE = "https://graph.microsoft.com"

# Where the operator goes to do the collection this tool deliberately cannot do.
# One constant, because the handoff link appears in the UI, the CLI and the
# audit trail, and they must agree.
#
# Ported verbatim, including this reasoning. Both halves of the original guess
# were wrong: the path segment is `casespage`, not `cases`, and the tenant id is
# a required query parameter — without `tid` the link resolves against whichever
# tenant the browser last used, which for anyone signed into more than one is a
# link that silently opens the wrong place. `viewid=Searches` lands the operator
# on the searches tab, which is where the work is.
#
# The portal also emits `&casename=...`. It is deliberately NOT reproduced: it
# is cosmetic, and the case name derives from the DSAR reference, so including
# it would push a request identifier into a URL that gets copied into tickets
# and chat messages.
PURVIEW_PORTAL_URL = "https://purview.microsoft.com"
PURVIEW_CASE_URL_TEMPLATE = (
    "https://purview.microsoft.com/ediscovery/casespage/{case_id}"
    "?tid={tenant_id}&viewid=Searches"
)


def purview_case_url(case_id: str, tenant_id: str) -> str:
    """Deep-link to a case in the Purview portal, scoped to its tenant."""
    return PURVIEW_CASE_URL_TEMPLATE.format(
        case_id=quote(case_id, safe=""), tenant_id=quote(tenant_id, safe="")
    )


#: The only Graph scope v1 requests. `eDiscovery.Read.All` is deliberately not
#: also requested: `.default` returns every scope granted for the resource, so a
#: read-only token is not something this design can actually obtain, and
#: pretending otherwise would be a control that does not exist.
SCOPES_V1: tuple[str, ...] = (f"{GRAPH_RESOURCE}/eDiscovery.ReadWrite.All",)

#: Identity expansion only. Registered but optional: a tenant may decline to
#: consent, and the expansion path degrades to UPN/mail-only search on 403.
#: `User.ReadBasic.All` cannot substitute — it returns neither `proxyAddresses`,
#: `otherMails` nor `employeeId`, which are the three fields expansion exists to
#: read. There is no narrower scope.
SCOPE_USER_READ_ALL = f"{GRAPH_RESOURCE}/User.Read.All"

#: Suffixes that must never appear on a set environment variable. The design
#: has no secret — desktop is a public client with PKCE, hosted authenticates
#: with a federated credential minted at runtime — so one of these being
#: present means someone has misunderstood the deployment and is about to be
#: surprised by which credential is actually in use. `doctor` fails on a match
#: rather than warning.
#:
#: Suffix matching rather than an explicit list: the list version covered three
#: names and missed `DSAR_CLIENT_ASSERTION` and `AZURE_CLIENT_CERTIFICATE_PATH`
#: entirely, which is a check narrower than its own claim (WS10 SEC-L-02).
SECRET_SHAPED_SUFFIXES: tuple[str, ...] = (
    "_SECRET",
    "_PASSWORD",
    "_ASSERTION",
    "_CERTIFICATE_PATH",
    "_PRIVATE_KEY",
)


def secret_shaped_env(env: dict[str, str] | None = None) -> list[str]:
    """Names of set variables that look like credential material."""
    environ = os.environ if env is None else env
    return sorted(
        name
        for name, value in environ.items()
        if value and name.upper().endswith(SECRET_SHAPED_SUFFIXES)
    )


class ConfigError(RuntimeError):
    """Configuration is absent or unusable."""


#: Group- and other-write bits. Windows does not model POSIX permissions, so
#: the checks below no-op there rather than reporting a false result.
_GROUP_OTHER_WRITE = 0o022
_GROUP_OTHER_ANY = 0o077
_POSIX = os.name == "posix"


def _assert_not_writable_by_others(path: Path) -> None:
    """Refuse a config file others can write.

    `tenant_id` from this file builds the authority, so whoever can write it
    chooses which Entra tenant the operator is sent to. The sign-in page stays
    a genuine `login.microsoftonline.com` URL, so there is no visual cue, and a
    multi-tenant attacker application requesting eDiscovery permissions becomes
    a credible consent-phishing surface.

    Stated honestly: an attacker with this access could also replace the
    launcher script. This is defence in depth, not a boundary — but it is one
    line, and a config file that selects an identity provider should not be
    writable by anyone but its owner.
    """
    if not _POSIX:
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & _GROUP_OTHER_WRITE:
        raise ConfigError(
            f"{path} is writable by group or other (mode {oct(mode)}) and will "
            f"not be trusted — it selects the Entra tenant this tool signs in "
            f"to. Run: chmod 600 {path}"
        )


def ensure_private_dir(path: Path) -> Path:
    """Create (or tighten) a directory only its owner may read.

    `mkdir(exist_ok=True)` does not change the mode of a directory that already
    exists, and the `mode=` argument is masked by the process umask, so both
    the create and the pre-existing paths need handling. The audit trail holds
    operator identity, case identifiers and a subject pseudonym; on a shared
    host the default `0o775` makes all of it readable by every local account
    (WS10 SEC-M-01).
    """
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if _POSIX and stat.S_IMODE(path.stat().st_mode) & _GROUP_OTHER_ANY:
        path.chmod(0o700)
    return path


def dir_mode(path: Path) -> str:
    """Octal permissions, for reporting. `n/a` where POSIX modes do not apply."""
    if not _POSIX:
        return "n/a (non-POSIX)"
    return oct(stat.S_IMODE(path.stat().st_mode))


@dataclass(frozen=True)
class Config:
    """Resolved configuration for one running instance."""

    client_id: str
    tenant_id: str
    mode: Mode
    mode_reason: str
    home: Path
    audit_dir: Path
    port: int = DEFAULT_PORT
    #: Optional. Off by default so the consent surface stays minimal.
    identity_expansion: bool = False
    #: Hosted only. The user-assigned managed identity whose token is exchanged
    #: for the client assertion. Dedicated to this app — with a federated
    #: credential there is no secret, but anyone who can run code as this
    #: identity can mint the assertion, so it must not be reused.
    uami_client_id: str | None = None
    #: Hosted only. Absolute https URL of the append-blob audit container.
    audit_blob_url: str | None = None
    #: Hosted only. The externally reachable origin, used to build `redirect_uri`.
    #: Never derived from the Host header — a forwarded header is attacker
    #: input unless the ingress is the only thing that can set it.
    base_url: str | None = None
    _source: str = field(default="defaults", compare=False)

    @property
    def authority(self) -> str:
        """Single-tenant authority.

        Pinned to one tenant rather than `/organizations` or `/common`, so a
        token issued for a different tenant cannot be silently accepted. The
        `tid` claim is additionally pinned at validation time.
        """
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @property
    def scopes(self) -> tuple[str, ...]:
        if self.identity_expansion:
            return SCOPES_V1 + (SCOPE_USER_READ_ALL,)
        return SCOPES_V1

    @property
    def redirect_uri(self) -> str:
        """The exact value that must be registered on the app registration.

        Desktop uses a loopback URI. RFC 8252 §7.3 has the authorization server
        ignore the port when matching a localhost redirect, but `[::1]` is not
        supported and two localhost URIs differing only by port must never both
        be registered — the login server picks between them arbitrarily. So one
        URI is registered, and this is it.
        """
        if self.mode.is_hosted:
            if not self.base_url:
                raise ConfigError(
                    "hosted mode needs DSAR_BASE_URL — the redirect URI must be "
                    "configured, never derived from the Host header"
                )
            return f"{self.base_url.rstrip('/')}/auth/callback"
        return f"http://localhost:{self.port}/auth/callback"


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_config(
    home: Path | None = None, env: dict[str, str] | None = None
) -> Config:
    """Resolve configuration, raising `ConfigError` if the registration is unknown."""
    environ = dict(os.environ) if env is None else env
    mode, mode_reason = detect_mode(environ)

    resolved_home = home or Path(
        environ.get("DSAR_HOME", str(DEFAULT_HOME))
    ).expanduser()

    file_values: dict[str, object] = {}
    config_file = resolved_home / "config.json"
    if config_file.is_file():
        _assert_not_writable_by_others(config_file)
        try:
            loaded = json.loads(config_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{config_file} is not valid JSON: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigError(f"{config_file} must contain a JSON object")
        file_values = loaded

    def pick(env_key: str, file_key: str) -> str | None:
        value_env = environ.get(env_key)
        if value_env:
            return value_env
        value = file_values.get(file_key)
        return str(value) if value is not None else None

    client_id = pick("DSAR_CLIENT_ID", "client_id")
    tenant_id = pick("DSAR_TENANT_ID", "tenant_id")

    missing = [
        name
        for name, value in (("client_id", client_id), ("tenant_id", tenant_id))
        if not value
    ]
    if missing:
        raise ConfigError(
            f"missing configuration: {', '.join(missing)}. Set DSAR_CLIENT_ID and "
            f"DSAR_TENANT_ID, or write them to {config_file}. Neither is a secret."
        )
    assert client_id is not None and tenant_id is not None  # narrowed by `missing`

    port_raw = pick("DSAR_PORT", "port")
    try:
        port = int(port_raw) if port_raw else DEFAULT_PORT
    except ValueError as exc:
        raise ConfigError(f"port must be an integer, got {port_raw!r}") from exc
    if not 1 <= port <= 65535:
        raise ConfigError(f"port must be in 1..65535, got {port}")

    audit_raw = pick("DSAR_AUDIT_DIR", "audit_dir")
    audit_dir = (
        Path(audit_raw).expanduser() if audit_raw else resolved_home / "audit"
    )

    expansion_raw = pick("DSAR_IDENTITY_EXPANSION", "identity_expansion")

    return Config(
        client_id=client_id,
        tenant_id=tenant_id,
        mode=mode,
        mode_reason=mode_reason,
        home=resolved_home,
        audit_dir=audit_dir,
        port=port,
        identity_expansion=_bool(expansion_raw) if expansion_raw else False,
        uami_client_id=pick("DSAR_UAMI_CLIENT_ID", "uami_client_id"),
        audit_blob_url=pick("DSAR_AUDIT_BLOB_URL", "audit_blob_url"),
        base_url=pick("DSAR_BASE_URL", "base_url"),
        _source=str(config_file) if file_values else "environment",
    )
