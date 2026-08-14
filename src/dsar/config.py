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
    "SECRET_SHAPED_ENV",
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

#: Names that must never be set. The design has no secret, so one of these
#: being present means someone has misunderstood the deployment and is about to
#: be surprised. `doctor` fails on any match rather than warning.
SECRET_SHAPED_ENV: tuple[str, ...] = (
    "DSAR_CLIENT_SECRET",
    "AZURE_CLIENT_SECRET",
    "CLIENT_SECRET",
)


class ConfigError(RuntimeError):
    """Configuration is absent or unusable."""


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
