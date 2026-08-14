"""`dsar audit verify` and `dsar audit tail`.

On the desktop the trail is readable offline, on purpose. When Graph is
unreachable the case list shows nothing — it *is* Graph — but the record of
what was done survives locally and can be read with no network and no sign-in.
That split is deliberate: live status needs the tenant, evidence does not.

Hosted, the trail is an append blob, so reading it necessarily needs the
network and the managed identity. The offline property is a desktop property
and is stated as one rather than implied for both.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

from dsar.audit.sink import JsonlFileSink
from dsar.audit.verify import verify_chain
from dsar.config import Config, ConfigError, load_config

__all__ = ["run_audit"]


def _reader(config: Config) -> tuple[object, str]:
    """The trail this deployment actually writes, and where to say it is.

    `run_audit` used to construct a `JsonlFileSink` unconditionally. In hosted
    mode the trail is an append blob and that directory is empty, so
    `dsar audit verify` reported "no audit trail" while thirteen records sat in
    the blob — the verifier unable to verify the only trail there was.

    The claim was that the verifier is the same code either side. It is:
    `verify_chain` never changed. What was missing is that the *command* could
    not reach the hosted trail, which makes the claim true and useless.
    """
    if config.audit_blob_url:
        if not config.uami_client_id:
            raise ConfigError(
                "DSAR_AUDIT_BLOB_URL is set but DSAR_UAMI_CLIENT_ID is not, so "
                "there is no identity to read the trail with. The storage "
                "account allows no shared key, by design."
            )
        from dsar.audit.blob import AppendBlobSink
        from dsar.auth.managed_identity import storage_token_for

        return (
            AppendBlobSink(config.audit_blob_url, storage_token_for(config.uami_client_id)),
            config.audit_blob_url,
        )
    return JsonlFileSink(config.audit_dir), str(config.audit_dir)


def run_audit(verb: str | None, *, as_json: bool = False, count: int = 20) -> int:
    try:
        config = load_config()
    except ConfigError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    try:
        sink, location = _reader(config)
    except ConfigError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    # Only the local trail can be missing as a *directory*. A blob container
    # that is unreachable raises, and that is a different failure worth
    # distinguishing from an empty trail.
    if not config.audit_blob_url and not config.audit_dir.exists():
        print(f"No audit trail at {location}.", file=sys.stderr)
        return 1

    if verb == "tail":
        records = list(sink.read_all())[-max(1, count) :]  # type: ignore[attr-defined]
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
    result = verify_chain(sink.read_all())  # type: ignore[attr-defined]
    if as_json:
        print(json.dumps({
            "records": result.records,
            "intact": result.intact,
            "breaks": [asdict(b) for b in result.breaks],
        }, indent=2))
        return 0 if result.intact else 1

    print(f"Audit trail: {location}")
    print(result.summary())
    for brk in result.breaks:
        print(f"  seq {brk.seq} ({brk.ts}): {brk.kind} — {brk.detail}")
    return 0 if result.intact else 1
