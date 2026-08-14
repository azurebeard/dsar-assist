"""Logging configuration and the redaction filter.

Logs MUST NOT contain tokens, KQL free-text values, or subject identifiers
beyond an opaque reference.

Discipline gets you most of the way — no call site logs a token. The filter is
here for the rest: a stack trace, a third-party library's debug output, or a
future call site that forgets. It is a backstop, not the primary control.

Ported from 8652e638 with one addition: `_scrub` is also used by the audit
writer, so a record that somehow acquires token-shaped material is scrubbed
before it is hashed into the chain rather than after.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

__all__ = ["configure_logging", "RedactingFilter", "REDACTED", "scrub"]

REDACTED = "[redacted]"

_PATTERNS: tuple[re.Pattern[str], ...] = (
    # JWTs — three base64url segments. Covers access, ID and refresh tokens.
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    # Bearer headers, whatever the token shape.
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{20,}"),
    # MSAL response fields, should one ever be rendered into a message.
    re.compile(
        r"(?i)\"?(access_token|refresh_token|id_token)\"?\s*[:=]\s*\"?[^\s\",}]+"
    ),
    # The authorization code and the PKCE verifier. Neither is a token, and
    # neither is caught by the patterns above, but a code in a log is a
    # replayable credential for its (short) lifetime and the verifier defeats
    # PKCE if it leaks alongside one.
    re.compile(r"(?i)\"?(code|code_verifier)\"?\s*[:=]\s*\"?[A-Za-z0-9._~-]{20,}"),
)


def scrub(value: Any) -> Any:
    """Replace token-shaped substrings. Non-strings pass through unchanged."""
    if not isinstance(value, str):
        return value
    scrubbed = value
    for pattern in _PATTERNS:
        scrubbed = pattern.sub(
            lambda m: (f"{m.group(1)} {REDACTED}" if m.lastindex else REDACTED),
            scrubbed,
        )
    return scrubbed


class RedactingFilter(logging.Filter):
    """Scrub token-shaped material from every record before a handler sees it.

    Applied to the record's message and args rather than the formatted output,
    so it holds regardless of which handler or formatter is attached.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = scrub(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: scrub(v) for k, v in record.args.items()}
            else:
                record.args = tuple(scrub(a) for a in record.args)
        return True


def configure_logging(verbose: bool = False) -> None:
    """Install the root handler. Called once, from `cli.py`."""
    root = logging.getLogger()
    if any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        return

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s %(name)-22s %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    handler.addFilter(RedactingFilter())
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)

    # MSAL is chatty at DEBUG and its records can carry response fragments.
    # The filter would catch them, but not emitting them is better.
    logging.getLogger("msal").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
