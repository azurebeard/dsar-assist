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

from typing import Any

from dsar.audit.evidence import EvidencePack, build_evidence
from dsar.audit.sink import JsonlFileSink
from dsar.audit.verify import verify_chain
from dsar.config import Config, ConfigError, load_config
from dsar.doctor.report import _wrap


def _para(text: str, width: int = 76) -> str:
    """`_wrap` returns lines. Printing the list prints its repr, which is what
    the first run of the evidence pack did."""
    return "\n".join(_wrap(text, width))

__all__ = ["run_audit", "run_evidence"]


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


def run_evidence(case_id: str, *, as_json: bool = False) -> int:
    """`dsar audit evidence <case-id>` — the pack a DPO attaches.

    Offline. Filtering on `case_id` needs no Graph call, so this works with no
    network and no sign-in — the same property the trail itself has, and the
    reason the record of what was done survives when the case list does not.

    Exit code follows the integrity of the trail, matching `verify`: a pack
    built over a broken chain is not evidence, and a script that pipes this
    somewhere should be able to tell without parsing prose.
    """
    if not case_id:
        print("A case id is required: dsar audit evidence <case-id>", file=sys.stderr)
        return 2
    try:
        config = load_config()
        sink, location = _reader(config)
    except ConfigError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    if not config.audit_blob_url and not config.audit_dir.exists():
        print(f"No audit trail at {location}.", file=sys.stderr)
        return 1

    records = list(sink.read_all())  # type: ignore[attr-defined]
    # The WHOLE trail, deliberately. The extract's integrity derives from this
    # and from nothing narrower — see `audit/evidence.py`.
    chain = verify_chain(records)
    pack = build_evidence(records, case_id, chain)

    if as_json:
        print(json.dumps(_evidence_json(pack, location), indent=2))
        return 0 if pack.trustworthy else 1

    _print_evidence(pack, location)
    return 0 if pack.trustworthy else 1


def _evidence_json(pack: EvidencePack, location: str) -> dict[str, Any]:
    return {
        "case_id": pack.case_id,
        "reference": pack.reference,
        "source": location,
        "trustworthy": pack.trustworthy,
        "chain": {
            "records": pack.chain.records,
            "intact": pack.chain.intact,
            "breaks": [asdict(b) for b in pack.chain.breaks],
        },
        "actors": list(pack.actors),
        "subject_refs": list(pack.subject_refs),
        "searches": [asdict(s) for s in pack.searches],
        "events": [asdict(r) for r in pack.events],
        "refusals": len(pack.refusals),
        "unattributable_records": pack.unattributable,
    }


def _print_evidence(pack: EvidencePack, location: str) -> None:
    print(f"# DSAR evidence — {pack.reference or pack.case_id}")
    print()
    print(f"Case id   {pack.case_id}")
    print(f"Source    {location}")
    if pack.first_seen:
        print(f"Activity  {pack.first_seen[:19]} to {pack.last_seen[:19]} UTC")
    print()

    # The integrity statement first, and stated for what it actually covers.
    # A reader who takes only the first paragraph should take the right one.
    print("## Integrity")
    print()
    if pack.trustworthy:
        print(f"The whole audit trail verifies: {pack.chain.summary()}")
        print("These records are an extract from it. Their integrity derives")
        print("from the chain above verifying end to end, not from the extract.")
    else:
        print(f"REFUSED. The audit trail does not verify: {pack.chain.summary()}")
        for brk in pack.chain.breaks[:5]:
            print(f"  seq {brk.seq} ({brk.ts}): {brk.kind} — {brk.detail}")
        print()
        print("No extract is presented. A trail that has been altered cannot")
        print("produce trustworthy evidence about part of itself.")
        return

    if not pack.events:
        print()
        print(f"No records for case {pack.case_id}.")
        if pack.unattributable:
            print(
                f"{pack.unattributable} record(s) in the trail carry no case and "
                f"may predate case attribution."
            )
        return

    print()
    print("## Who")
    print()
    for actor in pack.actors:
        print(f"  {actor}")

    if pack.subject_refs:
        print()
        print("## Data subject")
        print()
        for ref in pack.subject_refs:
            print(f"  {ref}   (case-scoped pseudonym)")
        print()
        print(_para(
            "The subject appears only as this pseudonym. It is an HMAC keyed on "
            "the case, so the same person in another case has a different one "
            "and the trail cannot be used to index who has been searched for."
        ))

    if pack.searches:
        print()
        print("## Searches")
        print()
        for search in pack.searches:
            print(f"  {search.name}")
            if search.incomplete:
                print("    ATTEMPTED, no completion recorded — an interrupted write")
                continue
            print(f"    created   {search.created_at[:19]}")
            if search.estimate_started_at:
                print(f"    estimated {search.estimate_started_at[:19]}")
            if search.export_initiated_at:
                print(f"    exported  {search.export_initiated_at[:19]}")

    if pack.refusals:
        print()
        print("## Refused")
        print()
        for record in pack.refusals:
            who = record.actor_upn or record.actor_oid or "unknown"
            print(f"  {record.ts[:19]}  {who}  {record.detail}")

    print()
    print("## Every recorded action")
    print()
    for record in pack.events:
        line = f"  {record.ts[:19]}  seq={record.seq:<4} {record.action:<18} {record.outcome:<9}"
        if record.detail:
            line += f"  {record.detail}"
        print(line)
        if record.uti:
            print(f"{'':22}  token={record.uti}")

    print()
    print("## What this does not contain")
    print()
    print(_para(
        "No item content, no query terms and no subject identifiers. Those are "
        "absent from the audit trail by construction — the record has no field "
        "that could hold them, which is asserted by a structural test — so "
        "their absence here is the design rather than a redaction. The token "
        "identifiers above join each action to the Microsoft Entra sign-in log "
        "for the same event."
    ))
    if pack.unattributable:
        print()
        print(_para(
            f"{pack.unattributable} record(s) elsewhere in the trail carry no "
            f"case identifier. Records written before case attribution existed "
            f"cannot be attributed to any case, including this one."
        ))
