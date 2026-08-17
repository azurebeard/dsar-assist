"""`dsar metrics export` — the aggregate, spoken at a terminal.

One of the few modules permitted to `print`; the allowlist in the structural
test names it, and widening that list was this deliberate, visible diff.
Nothing printed here can carry a token, a reference or a subject: the store
holds integers under allowlisted names, and nothing else survives `validate`.
"""

from __future__ import annotations

import json

from dsar.config import ConfigError, load_config
from dsar.metrics.store import (
    aggregate,
    aggregate_operations,
    metrics_path,
    read_events,
)

__all__ = ["run_metrics"]


def run_metrics(command: str | None, *, as_json: bool = False) -> int:
    if command != "export":
        print("usage: dsar metrics export [--json]")
        return 2

    try:
        config = load_config()
    except ConfigError as exc:
        print(f"configuration: {exc}")
        return 1

    path = metrics_path(config)
    events = read_events(path)
    summary = aggregate(events)
    operations = aggregate_operations(events)

    if as_json:
        print(
            json.dumps(
                {
                    "events": len(events),
                    "fields": summary,
                    "operations": operations,
                },
                indent=2,
            )
        )
        return 0

    if not events:
        print("No metrics recorded.")
        print(
            "Capture is opt-in: set DSAR_METRICS=1, run workflows, then export. "
            f"The store would be {path}."
        )
        return 0

    print(f"{len(events)} event(s) in {path}")

    if summary:
        print()
        print("Per completed workflow (browser-observed):")
        print(f"  {'field':<22} {'n':>5} {'median':>9} {'p90':>9}")
        for field, stats in summary.items():
            print(
                f"  {field:<22} {stats['n']:>5} {stats['median']:>9} {stats['p90']:>9}"
            )

    if operations:
        print()
        print("Per Graph operation (server-observed, every attempt):")
        print(f"  {'operation':<22} {'n':>5} {'failed':>7} {'median':>9} {'p90':>9}")
        for op, stats in operations.items():
            print(
                f"  {op:<22} {stats['n']:>5} {stats['failed']:>7} "
                f"{stats['median']:>9} {stats['p90']:>9}"
            )

    print()
    print(
        "Durations are milliseconds, except *_estimate_s (seconds, from "
        "Purview's own operation timestamps). active_ms approximates operator "
        "attention; everything else is Microsoft's processing time and is not "
        "claimed as savings. Method: docs/BENCHMARK.md."
    )
    return 0
