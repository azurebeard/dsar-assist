"""Opt-in workflow timings (DSA-A02). Telemetry, and deliberately not audit.

The productivity claim — "this saves operator time against the Purview
portal" — must be measured or it must not be made. This module is the
measured half: one summary event per completed workflow, milestone durations
and counts only, appended to a local JSONL store.

Three decisions shape it:

  * **Separate from the audit trail.** The trail is evidence with a hash
    chain and an immutability story; timings are telemetry with neither. One
    store serving both jobs would weaken the claim the trail makes.
  * **Off by default.** Measurement is a choice (`DSAR_METRICS=1`), not a
    side effect of using the tool.
  * **Allowlist, refused not trimmed.** The browser posts the event, and a
    browser is an untrusted client. Every field must be named below and every
    value must be a bounded non-negative integer; anything else refuses the
    whole event. Trimming instead of refusing would mean a client quietly
    learning which of its fields survive, which is how an allowlist rots.

No field can hold a reference, a subject identifier or a query, because no
allowed field holds a string at all — and a structural test keeps this
package unable to import the modules those live in.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Mapping

from dsar import __version__
from dsar.config import Config, ensure_private_dir

__all__ = [
    "ALLOWED_FIELDS",
    "MetricsError",
    "validate",
    "record",
    "read_events",
    "aggregate",
    "metrics_path",
]

#: Nothing in a workflow legitimately runs for a day.
_DAY_MS = 24 * 60 * 60 * 1000

#: Every field a client may send: (lower bound, upper bound), integers only.
#: `*_ms` values are durations. `active_ms` approximates operator attention —
#: time on the form minus time spent waiting on requests — which is the number
#: the productivity thesis is actually about; the estimate waits are
#: Microsoft's time, reported separately and never claimed as savings.
ALLOWED_FIELDS: Mapping[str, tuple[int, int]] = {
    "active_ms": (0, _DAY_MS),
    "case_create_ms": (0, _DAY_MS),
    "expand_ms": (0, _DAY_MS),
    "searches_submit_ms": (0, _DAY_MS),
    "first_estimate_ms": (0, _DAY_MS),
    "both_estimates_ms": (0, _DAY_MS),
    "total_ms": (0, _DAY_MS),
    "interactions": (0, 10_000),
    "templates_applied": (0, 100),
}


class MetricsError(Exception):
    """The event is not one the allowlist describes, or the store is unusable."""


def metrics_path(config: Config) -> Path:
    return config.home / "metrics" / "metrics.jsonl"


def validate(body: Mapping[str, Any]) -> dict[str, int]:
    """Hold a client-supplied event to the allowlist, strictly.

    Unknown key, string value, negative, out of bounds, or nothing usable at
    all — each refuses the whole event rather than keeping the acceptable
    part. A client that can find out which fields survive has been handed a
    channel; a client that is refused has been handed an error message.
    """
    out: dict[str, int] = {}
    for key, value in body.items():
        bounds = ALLOWED_FIELDS.get(str(key))
        if bounds is None:
            raise MetricsError(f"field {key!r} is not an allowed metric")
        # bool is an int subclass; True would otherwise pass as 1.
        if isinstance(value, bool) or not isinstance(value, int):
            raise MetricsError(f"field {key!r} must be an integer")
        low, high = bounds
        if not low <= value <= high:
            raise MetricsError(f"field {key!r} is out of range")
        out[str(key)] = value
    if not out:
        raise MetricsError("the event carries no metric fields")
    return out


def record(config: Config, fields: Mapping[str, int]) -> None:
    """Append one validated event. The caller has already run `validate`."""
    path = metrics_path(config)
    try:
        ensure_private_dir(path.parent)
        event = {
            "ts": round(time.time(), 3),
            "mode": config.mode.value,
            "version": __version__,
            **fields,
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    except OSError as exc:
        raise MetricsError(f"the metrics store is not writable: {exc}") from exc


def read_events(path: Path) -> list[dict[str, Any]]:
    """Every recorded event. A malformed line is skipped and counted, not fatal —
    telemetry is not evidence, and a torn write must not block the export."""
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


def _percentile(ordered: list[int], fraction: float) -> int:
    """Nearest-rank percentile over a sorted list."""
    index = max(0, min(len(ordered) - 1, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def aggregate(events: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Per-field count, median and p90 across every event carrying the field."""
    out: dict[str, dict[str, int]] = {}
    for field in ALLOWED_FIELDS:
        values = sorted(
            v for e in events if isinstance(v := e.get(field), int) and not isinstance(v, bool)
        )
        if not values:
            continue
        out[field] = {
            "n": len(values),
            "median": _percentile(values, 0.5),
            "p90": _percentile(values, 0.9),
        }
    return out
