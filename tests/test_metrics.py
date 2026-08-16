"""Opt-in workflow timings (DSA-A02): allowlisted, refused-not-trimmed, local.

The productivity claim must be measured or not made, and the measurement must
not become a second data store. These tests hold both halves: capture is off
by default and refused when off, and nothing survives validation except
bounded integers under allowlisted names.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dsar.config import load_config
from dsar.metrics.store import (
    ALLOWED_FIELDS,
    MetricsError,
    aggregate,
    metrics_path,
    read_events,
    record,
    validate,
)
from dsar.web.api import handle

TENANT = "66666666-7777-8888-9999-aaaaaaaaaaaa"
CLIENT = "11111111-2222-3333-4444-555555555555"


def _config(tmp_path: Path, **extra: str):
    env = {
        "DSAR_CLIENT_ID": CLIENT,
        "DSAR_TENANT_ID": TENANT,
        "DSAR_MODE": "desktop",
        **extra,
    }
    return load_config(home=tmp_path, env=env)


def _principal():
    from dsar.auth.provider import Principal

    return Principal(oid="oid-1", tenant_id=TENANT, roles=frozenset({"DSAR.Operator"}))


# ------------------------------------------------------------- validation


def test_an_unknown_field_refuses_the_whole_event() -> None:
    """Refused, not trimmed. A client that can learn which of its fields
    survive has been handed a channel."""
    with pytest.raises(MetricsError, match="not an allowed metric"):
        validate({"active_ms": 1200, "reference": "DSAR-2026-0001"})


def test_a_string_value_is_refused_even_under_an_allowed_name() -> None:
    """The allowlist is names AND types. An integer field that accepted a
    string would be a field that can carry a subject."""
    with pytest.raises(MetricsError, match="must be an integer"):
        validate({"active_ms": "fast"})
    with pytest.raises(MetricsError, match="must be an integer"):
        validate({"interactions": True})  # bool is an int subclass; still refused


def test_bounds_are_enforced_both_ways() -> None:
    with pytest.raises(MetricsError, match="out of range"):
        validate({"active_ms": -1})
    with pytest.raises(MetricsError, match="out of range"):
        validate({"active_ms": 10**12})


def test_an_empty_event_is_refused() -> None:
    with pytest.raises(MetricsError, match="no metric fields"):
        validate({})


def test_a_fully_allowed_event_passes_unchanged() -> None:
    event = {name: low for name, (low, _high) in ALLOWED_FIELDS.items()}
    assert validate(event) == event


# ------------------------------------------------------------ opt-in gate


def test_capture_is_off_by_default_and_the_endpoint_refuses(tmp_path: Path) -> None:
    """Measurement is a choice. Unset, the endpoint refuses and writes
    nothing — not even a directory."""
    config = _config(tmp_path)
    assert config.metrics is False

    status, payload = handle(
        "/api/metrics",
        {"active_ms": 1200},
        principal=_principal(),
        cases=None,  # type: ignore[arg-type]
        config=config,
        workflow=None,  # type: ignore[arg-type]
    )
    assert status == 403
    assert payload["error"] == "metrics_disabled"
    assert not metrics_path(config).parent.exists()


def test_an_enabled_endpoint_records_and_a_bad_field_still_refuses(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, DSAR_METRICS="1")
    assert config.metrics is True

    status, payload = handle(
        "/api/metrics",
        {"active_ms": 1200, "interactions": 9},
        principal=_principal(),
        cases=None,  # type: ignore[arg-type]
        config=config,
        workflow=None,  # type: ignore[arg-type]
    )
    assert (status, payload) == (200, {"recorded": True})

    status, payload = handle(
        "/api/metrics",
        {"active_ms": 1200, "query": "participants:x"},
        principal=_principal(),
        cases=None,  # type: ignore[arg-type]
        config=config,
        workflow=None,  # type: ignore[arg-type]
    )
    assert status == 400
    assert payload["error"] == "invalid_metrics"

    events = read_events(metrics_path(config))
    assert len(events) == 1
    assert events[0]["active_ms"] == 1200
    assert events[0]["mode"] == "desktop"
    # The refused event left no partial trace.
    assert "query" not in json.dumps(events)


def test_the_store_directory_is_owner_only(tmp_path: Path) -> None:
    """Same posture as the audit directory: timings reveal working patterns,
    and a world-readable telemetry file on a shared host is a leak with no
    compensating value."""
    import os
    import stat

    config = _config(tmp_path, DSAR_METRICS="1")
    record(config, validate({"active_ms": 5}))
    if os.name == "posix":
        mode = stat.S_IMODE(metrics_path(config).parent.stat().st_mode)
        assert mode == 0o700


# ------------------------------------------------------------- aggregation


def test_aggregate_reports_count_median_and_p90() -> None:
    events = [{"active_ms": v} for v in [100, 200, 300, 400, 1000]]
    summary = aggregate(events)
    assert summary["active_ms"]["n"] == 5
    assert summary["active_ms"]["median"] == 300
    assert summary["active_ms"]["p90"] == 1000


def test_a_torn_line_is_skipped_not_fatal(tmp_path: Path) -> None:
    """Telemetry is not evidence. A torn write must not block the export the
    way a torn audit record must block the evidence pack."""
    path = tmp_path / "metrics.jsonl"
    path.write_text('{"active_ms": 100}\n{"active_ms": 2\n', encoding="utf-8")
    events = read_events(path)
    assert events == [{"active_ms": 100}]
