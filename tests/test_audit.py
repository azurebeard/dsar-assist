"""Phase 3: the audit trail.

The chain is only worth having if a break is genuinely detected, so these
tamper with real records rather than asserting the hash function was called.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from dsar.audit.record import (
    GENESIS_HASH,
    Action,
    AuditRecord,
    Outcome,
    build,
    canonical_json,
    case_pseudonym,
)
from dsar.audit.sink import JsonlFileSink, MemorySink, StderrSink, TeeSink
from dsar.audit.trail import AuditTrail
from dsar.audit.verify import verify_chain

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX modes only")


def _trail(sink=None) -> tuple[AuditTrail, MemorySink]:
    memory = sink or MemorySink()
    return AuditTrail(memory), memory


# ------------------------------------------------------------------ chain


def test_the_first_record_chains_from_genesis() -> None:
    trail, sink = _trail()
    record = trail.write(Action.SIGN_IN, Outcome.OK, actor_oid="o")
    assert record.seq == 1
    assert record.prev_hash == GENESIS_HASH
    assert record.hash == record.recompute()


def test_each_record_chains_onto_the_last() -> None:
    trail, sink = _trail()
    first = trail.write(Action.SIGN_IN, Outcome.OK)
    second = trail.write(Action.CASE_CREATED, Outcome.OK)
    assert second.prev_hash == first.hash
    assert second.seq == 2
    assert verify_chain(sink.records).intact


def test_a_clean_chain_verifies() -> None:
    trail, sink = _trail()
    for _ in range(10):
        trail.write(Action.SEARCH_CREATED, Outcome.OK)
    result = verify_chain(sink.records)
    assert result.intact and result.records == 10


# -------------------------------------------------------------- tampering


def test_editing_a_record_is_detected_and_named() -> None:
    """"The trail has been altered" is not actionable. "Record 3" is."""
    trail, sink = _trail()
    for _ in range(5):
        trail.write(Action.CASE_CREATED, Outcome.OK, detail="original")

    tampered = list(sink.records)
    victim = tampered[2]
    tampered[2] = AuditRecord(**{**victim.__dict__, "detail": "edited"})

    result = verify_chain(tampered)
    assert not result.intact
    assert result.breaks[0].seq == victim.seq
    assert result.breaks[0].kind == "altered"


def test_removing_a_record_is_detected() -> None:
    """A deletion breaks the link and the sequence — two different signals for
    the same act, which is what makes it hard to remove one cleanly."""
    trail, sink = _trail()
    for _ in range(5):
        trail.write(Action.SEARCH_CREATED, Outcome.OK)

    without_third = [r for r in sink.records if r.seq != 3]
    result = verify_chain(without_third)
    assert not result.intact
    kinds = {b.kind for b in result.breaks}
    assert "broken link" in kinds and "out of order" in kinds


def test_inserting_a_forged_record_is_detected() -> None:
    """A forger can compute a valid hash for their own record. They cannot make
    the NEXT record's prev_hash point at it without rewriting everything after."""
    trail, sink = _trail()
    for _ in range(3):
        trail.write(Action.CASE_CREATED, Outcome.OK)

    forged = build(seq=2, action=Action.EXPORT_INITIATED, outcome=Outcome.OK)
    forged = forged.with_hash(sink.records[0].hash)
    spliced = [sink.records[0], forged, *sink.records[1:]]

    assert not verify_chain(spliced).intact


def test_reordering_is_detected() -> None:
    trail, sink = _trail()
    for _ in range(4):
        trail.write(Action.SIGN_IN, Outcome.OK)
    swapped = [sink.records[1], sink.records[0], *sink.records[2:]]
    assert not verify_chain(swapped).intact


def test_an_empty_trail_is_intact_not_broken() -> None:
    result = verify_chain([])
    assert result.intact and result.records == 0


# ----------------------------------------------------------- no leakage


def test_the_subject_appears_only_as_a_case_scoped_pseudonym() -> None:
    trail, sink = _trail()
    ref = trail.subject_ref("case-1", "MeganB@<tenant>.onmicrosoft.com")
    trail.write(Action.IDENTITY_EXPANDED, Outcome.OK, subject_ref=ref, target_id="case-1")

    serialised = sink.records[0].to_json()
    assert "meganb" not in serialised.lower()
    # The domain, not a tenant name. Asserting on a tenant name made this test
    # depend on which tenant it was written against — and it silently stopped
    # meaning anything the moment that name was scrubbed for publication.
    assert "onmicrosoft.com" not in serialised.lower()
    assert ref in serialised


def test_the_same_subject_in_two_cases_gets_two_pseudonyms() -> None:
    """Otherwise the trail becomes a cross-case index of who has been searched
    for — a register nobody asked this tool to keep."""
    identifier = "meganb@example.test"
    assert case_pseudonym("case-a", identifier) != case_pseudonym("case-b", identifier)
    assert case_pseudonym("case-a", identifier) == case_pseudonym("case-a", identifier)


def test_the_pseudonym_is_case_insensitive_on_the_identifier() -> None:
    assert case_pseudonym("c", "Megan@X.com") == case_pseudonym("c", "megan@x.com  ")


def test_a_token_in_detail_is_scrubbed() -> None:
    record = build(
        seq=1, action=Action.SIGN_IN, outcome=Outcome.OK,
        detail="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def",
    )
    assert "eyJ" not in record.detail


def test_detail_is_truncated() -> None:
    record = build(seq=1, action=Action.SIGN_IN, outcome=Outcome.OK, detail="x" * 5000)
    assert len(record.detail.encode("utf-8")) <= 512


# ------------------------------------------------------------ file sink


@POSIX_ONLY
def test_the_trail_file_is_owner_only(tmp_path: Path) -> None:
    sink = JsonlFileSink(tmp_path)
    sink.append(build(seq=1, action=Action.SIGN_IN, outcome=Outcome.OK).with_hash(GENESIS_HASH))
    written = next(tmp_path.glob("audit-*.jsonl"))
    assert stat.S_IMODE(written.stat().st_mode) == 0o600


def test_the_chain_resumes_across_processes(tmp_path: Path) -> None:
    """The head is read back from the file, so a restart continues the chain
    rather than starting a second one that also looks valid."""
    first = AuditTrail(JsonlFileSink(tmp_path))
    first.write(Action.SIGN_IN, Outcome.OK)
    first.write(Action.CASE_CREATED, Outcome.OK)

    resumed = AuditTrail(JsonlFileSink(tmp_path))
    third = resumed.write(Action.SEARCH_CREATED, Outcome.OK)

    assert third.seq == 3
    assert verify_chain(JsonlFileSink(tmp_path).read_all()).intact


def test_one_json_object_per_line(tmp_path: Path) -> None:
    trail = AuditTrail(JsonlFileSink(tmp_path))
    for _ in range(3):
        trail.write(Action.SIGN_IN, Outcome.OK)
    lines = next(tmp_path.glob("audit-*.jsonl")).read_text().strip().splitlines()
    assert len(lines) == 3
    for line in lines:
        json.loads(line)


def test_a_malformed_tail_does_not_stop_new_writes(tmp_path: Path) -> None:
    """A partial write must not wedge the trail. `verify` reports it; `head`
    only needs somewhere to chain from."""
    trail = AuditTrail(JsonlFileSink(tmp_path))
    trail.write(Action.SIGN_IN, Outcome.OK)
    path = next(tmp_path.glob("audit-*.jsonl"))
    with path.open("a") as handle:
        handle.write('{"seq": 2, "truncated\n')

    resumed = AuditTrail(JsonlFileSink(tmp_path))
    assert resumed.write(Action.CASE_CREATED, Outcome.OK).seq == 2


def test_canonical_json_is_stable_across_key_order() -> None:
    """A hash over a dict with arbitrary ordering verifies on the machine that
    wrote it and nowhere else."""
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


# ---------------------------------------------------------------- tee


def test_a_failing_secondary_does_not_lose_the_primary_write() -> None:
    class Broken:
        def append(self, record):  # noqa: ANN001, ANN201
            raise OSError("disk gone")

        def head(self):  # noqa: ANN201
            return 0, GENESIS_HASH

    primary = MemorySink()
    trail = AuditTrail(TeeSink(primary, Broken()))
    trail.write(Action.SIGN_IN, Outcome.OK)
    assert len(primary.records) == 1


def test_tee_head_comes_from_the_primary_alone() -> None:
    """A chain with two heads is not a chain."""
    primary = MemorySink()
    tee = TeeSink(primary, StderrSink())
    AuditTrail(tee).write(Action.SIGN_IN, Outcome.OK)
    assert tee.head() == primary.head()


# ------------------------------------------------- which trail gets verified


def test_audit_verify_reads_the_blob_when_hosted(monkeypatch, tmp_path) -> None:
    """`dsar audit verify` must read the trail the deployment actually writes.

    It constructed a `JsonlFileSink` unconditionally. In hosted mode the trail
    is an append blob and that directory is empty, so the command reported "no
    audit trail" while thirteen real records sat in the blob — the verifier
    unable to verify the only trail there was.

    The claim was that the verifier is the same code either side. It is;
    `verify_chain` never changed. What was missing is that the *command* could
    not reach the hosted trail, which makes the claim true and useless. Found
    by reading a deployed instance's trail by hand.
    """
    from dsar.audit.blob import AppendBlobSink
    from dsar.audit.report import _reader
    from dsar.audit.sink import JsonlFileSink
    from dsar.config import load_config

    monkeypatch.setenv("DSAR_CLIENT_ID", "11111111-2222-3333-4444-555555555555")
    monkeypatch.setenv("DSAR_TENANT_ID", "66666666-7777-8888-9999-aaaaaaaaaaaa")
    monkeypatch.setenv("DSAR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("DSAR_AUDIT_DIR", str(tmp_path / "audit"))

    reader, location = _reader(load_config())
    assert isinstance(reader, JsonlFileSink)

    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    monkeypatch.setenv("DSAR_UAMI_CLIENT_ID", "99999999-8888-7777-6666-555555555555")
    monkeypatch.setenv(
        "DSAR_AUDIT_BLOB_URL", "https://st.blob.core.windows.net/audit"
    )

    reader, location = _reader(load_config())
    assert isinstance(reader, AppendBlobSink)
    assert location == "https://st.blob.core.windows.net/audit"


def test_a_hosted_trail_with_no_identity_refuses_rather_than_reading_nothing(
    monkeypatch, tmp_path
) -> None:
    """Reporting an empty trail when one exists and cannot be read is the
    worst answer available: it looks like nothing happened."""
    from dsar.audit.report import _reader
    from dsar.config import ConfigError, load_config

    monkeypatch.setenv("DSAR_CLIENT_ID", "11111111-2222-3333-4444-555555555555")
    monkeypatch.setenv("DSAR_TENANT_ID", "66666666-7777-8888-9999-aaaaaaaaaaaa")
    monkeypatch.setenv("DSAR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("DSAR_MODE", "hosted")
    monkeypatch.setenv("DSAR_BASE_URL", "https://dsar.example.co.uk")
    monkeypatch.setenv("DSAR_AUDIT_BLOB_URL", "https://st.blob.core.windows.net/audit")
    monkeypatch.delenv("DSAR_UAMI_CLIENT_ID", raising=False)

    with pytest.raises(ConfigError, match="DSAR_UAMI_CLIENT_ID"):
        _reader(load_config())
