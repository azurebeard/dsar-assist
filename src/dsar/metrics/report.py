"""`dsar metrics export` — the aggregate, spoken at a terminal.

One of the few modules permitted to `print`; the allowlist in the structural
test names it, and widening that list was this deliberate, visible diff.
Nothing printed here can carry a token, a reference or a subject: the store
holds integers under allowlisted names, and nothing else survives `validate`.
"""

from __future__ import annotations

import json

from dsar.config import ConfigError, load_config
from dsar.metrics.store import aggregate, metrics_path, read_events

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

    if as_json:
        print(json.dumps({"events": len(events), "fields": summary}, indent=2))
        return 0

    if not events:
        print("No metrics recorded.")
        print(
            "Capture is opt-in: set DSAR_METRICS=1, run workflows, then export. "
            f"The store would be {path}."
        )
        return 0

    print(f"{len(events)} workflow event(s) in {path}")
    print()
    print(f"  {'field':<22} {'n':>5} {'median':>9} {'p90':>9}")
    for field, stats in summary.items():
        print(
            f"  {field:<22} {stats['n']:>5} {stats['median']:>9} {stats['p90']:>9}"
        )
    print()
    print(
        "Durations are milliseconds. active_ms approximates operator attention; "
        "the estimate waits are Microsoft's processing time and are not claimed "
        "as savings. Method: docs/BENCHMARK.md."
    )
    return 0
