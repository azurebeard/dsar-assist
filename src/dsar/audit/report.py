"""`dsar audit verify` and `dsar audit tail`.

The trail is readable offline, on purpose. When Graph is unreachable the case
list shows nothing — it *is* Graph — but the record of what was done survives
locally and can be read with no network and no sign-in. That split is
deliberate: live status needs the tenant, evidence does not.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

from dsar.audit.sink import JsonlFileSink
from dsar.audit.verify import verify_chain
from dsar.config import ConfigError, load_config

__all__ = ["run_audit"]


def run_audit(verb: str | None, *, as_json: bool = False, count: int = 20) -> int:
    try:
        config = load_config()
    except ConfigError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    sink = JsonlFileSink(config.audit_dir)
    if not config.audit_dir.exists():
        print(f"No audit trail at {config.audit_dir}.", file=sys.stderr)
        return 1

    if verb == "tail":
        records = list(sink.read_all())[-max(1, count) :]
        for record in records:
            print(
                f"{record.ts}  seq={record.seq:<5} {record.action:<18} "
                f"{record.outcome:<9} {record.actor_upn or record.actor_oid or '—'}"
                + (f"  target={record.target_id}" if record.target_id else "")
                + (f"  subject={record.subject_ref}" if record.subject_ref else "")
            )
        if not records:
            print("No audit records yet.")
        return 0

    # `verify` is the default, because it is the question worth asking.
    result = verify_chain(sink.read_all())
    if as_json:
        print(json.dumps({
            "records": result.records,
            "intact": result.intact,
            "breaks": [asdict(b) for b in result.breaks],
        }, indent=2))
        return 0 if result.intact else 1

    print(f"Audit trail: {config.audit_dir}")
    print(result.summary())
    for brk in result.breaks:
        print(f"  seq {brk.seq} ({brk.ts}): {brk.kind} — {brk.detail}")
    return 0 if result.intact else 1
