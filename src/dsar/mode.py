"""Which mode this process is running in — the single source of truth.

One image runs two ways: an operator's own machine, or Azure Container Apps.
Everything downstream that needs to differ (client class, redirect origin,
cookie attributes, audit sink) asks here rather than sniffing the environment
for itself, so there is exactly one place where the answer can be wrong.

Detection is explicit-first on purpose. `DSAR_MODE` is honoured before any
inference, because a wrong guess here selects a whole different auth path, and
an operator who has to override it should not have to know what we sniff for.
"""

from __future__ import annotations

import os
from enum import Enum

__all__ = ["Mode", "detect_mode", "ModeError", "CONTAINER_APPS_MARKERS"]

#: Environment variables Azure Container Apps injects into every container. The
#: identity pair is what the hosted auth path actually consumes, so detecting on
#: them means "hosted" and "able to mint a client assertion" cannot disagree.
CONTAINER_APPS_MARKERS: tuple[str, ...] = (
    "CONTAINER_APP_NAME",
    "CONTAINER_APP_REVISION",
)


class ModeError(RuntimeError):
    """`DSAR_MODE` was set to something that is not a mode."""


class Mode(str, Enum):
    DESKTOP = "desktop"
    HOSTED = "hosted"

    @property
    def is_hosted(self) -> bool:
        return self is Mode.HOSTED


def detect_mode(env: dict[str, str] | None = None) -> tuple[Mode, str]:
    """Return the mode and a one-line account of how it was decided.

    The reason string is not decoration: `doctor` prints it, and "why does it
    think it is hosted" is the first question when auth behaves unexpectedly.
    """
    environ = os.environ if env is None else env

    explicit = environ.get("DSAR_MODE", "").strip().lower()
    if explicit:
        try:
            return Mode(explicit), f"DSAR_MODE={explicit}"
        except ValueError as exc:
            valid = ", ".join(m.value for m in Mode)
            raise ModeError(
                f"DSAR_MODE={explicit!r} is not a mode. Valid values: {valid}"
            ) from exc

    present = [name for name in CONTAINER_APPS_MARKERS if environ.get(name)]
    if present:
        return Mode.HOSTED, f"Azure Container Apps detected via {', '.join(present)}"

    return Mode.DESKTOP, "no DSAR_MODE and no Container Apps markers present"
