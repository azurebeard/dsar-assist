"""Phase 3: the audit trail.

The chain is only worth having if a break is genuinely detected, so these
tamper with real records rather than asserting the hash function was called.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict
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


# ------------------------------------------------ two writers, one trail


class _ContendedSink:
    """A sink that refuses an append whose predecessor has moved.

    Models what `AppendBlobSink` does with `x-ms-blob-condition-appendpos`:
    the service appends only if the blob is exactly the expected length, so a
    second writer is refused rather than silently landing beside the first.
    """

    def __init__(self) -> None:
        self.records: list = []
        self.refusals = 0

    def append(self, record) -> None:
        from dsar.audit.sink import StaleHead

        expected = self.records[-1].hash if self.records else GENESIS_HASH
        if record.prev_hash != expected:
            self.refusals += 1
            raise StaleHead("the head moved")
        self.records.append(record)

    def head(self):
        if not self.records:
            return 0, GENESIS_HASH
        return self.records[-1].seq, self.records[-1].hash


def test_two_writers_during_a_rollout_do_not_corrupt_the_trail() -> None:
    """WS10 SEC-H-01. `maxReplicas: 1` bounds a *revision*, not the app.

    A Container Apps rolling deployment starts the new replica and stops the
    old one only once the new one is healthy — measured at 46s and 37s on the
    live instance — so every deploy runs two `dsar` processes, each holding a
    head it read at start.

    Before the conditional append, that produced duplicate sequence numbers and
    `verify_chain` reported five breaks as "a record was removed or inserted
    here": not two valid chains as the Bicep claimed, but one trail reading as
    tampered, permanently, under a 2555-day immutability policy.
    """
    from dsar.audit.trail import AuditTrail

    sink = _ContendedSink()
    old_revision, new_revision = AuditTrail(sink), AuditTrail(sink)

    old_revision.write(Action.SIGN_IN, Outcome.OK, actor_oid="a")
    new_revision.write(Action.SIGN_IN, Outcome.OK, actor_oid="b")
    old_revision.write(Action.CASE_CREATED, Outcome.OK, target_id="case-a")
    new_revision.write(Action.CASE_CREATED, Outcome.OK, target_id="case-b")

    assert sink.refusals >= 1, "the contention was never exercised"
    assert [r.seq for r in sink.records] == [1, 2, 3, 4], "sequence forked"

    result = verify_chain(sink.records)
    assert result.intact, result.summary()
    # Every record survives. The refusal rebuilds; it never drops.
    assert result.records == 4


def test_a_refused_append_is_rebuilt_not_lost() -> None:
    """The refused write did not land, which is what makes the retry safe —
    sequence and hash advance only after the sink accepts."""
    from dsar.audit.trail import AuditTrail

    sink = _ContendedSink()
    a, b = AuditTrail(sink), AuditTrail(sink)

    a.write(Action.SIGN_IN, Outcome.OK, actor_oid="a")
    record = b.write(Action.CASE_CREATED, Outcome.OK, target_id="rebuilt")

    assert record.seq == 2
    assert record.prev_hash == sink.records[0].hash
    assert record.target_id == "rebuilt"
    assert verify_chain(sink.records).intact


def test_a_head_that_never_settles_fails_loudly() -> None:
    """Bounded, not unbounded. A trail that blocks forever is an outage, and
    losing one record loudly beats hanging the request that produced it."""
    from dsar.audit.trail import AuditTrail
    from dsar.audit.sink import StaleHead

    class _AlwaysStale(_ContendedSink):
        def append(self, record) -> None:
            self.refusals += 1
            raise StaleHead("never settles")

    trail = AuditTrail(_AlwaysStale())
    with pytest.raises(RuntimeError, match="head kept moving"):
        trail.write(Action.SIGN_IN, Outcome.OK, actor_oid="a")


# ------------------------------------- adding a field to an existing trail


def test_a_record_written_before_case_id_existed_still_verifies() -> None:
    """The hash covers whatever `asdict()` returns, so adding a field would
    change the hash of every record ever written — including the ones already
    in an append blob under a 2555-day immutability policy, which would then
    all verify as `altered` with no way to fix them.

    Measured before the field was added, not assumed. This is the regression
    test for it: a record whose stored hash was computed WITHOUT `case_id`
    must still verify.
    """
    import hashlib

    from dsar.audit.record import canonical_json

    record = AuditRecord(
        seq=1,
        ts="2026-08-14T10:00:00.000+00:00",
        action=Action.SIGN_IN.value,
        outcome=Outcome.OK.value,
        actor_oid="oid-1",
    )
    # The hash exactly as the previous version of this dataclass computed it —
    # every field except `hash`, with no `case_id` in sight.
    legacy_body = {
        k: v
        for k, v in asdict(record).items()
        if k not in ("hash", "case_id")
    }
    legacy_hash = hashlib.sha256(
        GENESIS_HASH.encode("ascii") + canonical_json(legacy_body).encode("utf-8")
    ).hexdigest()

    from dataclasses import replace

    as_stored = replace(record, hash=legacy_hash)
    assert as_stored.recompute() == legacy_hash, "an existing record stopped verifying"
    assert verify_chain([as_stored]).intact


def test_a_populated_case_id_is_covered_by_the_hash() -> None:
    """An added field that is not hashed is an unprotected field, which in an
    audit trail is worse than not having it."""
    from dataclasses import replace

    record = AuditRecord(
        seq=1,
        ts="2026-08-14T10:00:00.000+00:00",
        action=Action.CASE_CREATED.value,
        outcome=Outcome.OK.value,
        case_id="case-1",
    ).with_hash(GENESIS_HASH)
    assert record.recompute() == record.hash

    moved = replace(record, case_id="case-2")
    assert moved.recompute() != moved.hash, "case_id can be changed undetected"

    cleared = replace(record, case_id="")
    assert cleared.recompute() != cleared.hash, "case_id can be removed undetected"


def test_the_chain_still_verifies_across_records_with_and_without_it() -> None:
    """A trail spans the change: sign-in has no case, the records after it do."""
    sink = MemorySink()
    trail = AuditTrail(sink)
    trail.write(Action.SIGN_IN, Outcome.OK, actor_oid="oid-1")
    trail.write(Action.CASE_CREATED, Outcome.OK, case_id="case-1", target_id="case-1")
    trail.write(Action.SEARCH_CREATED, Outcome.OK, case_id="case-1", target_id="s-1")

    result = verify_chain(sink.records)
    assert result.intact, result.summary()
    assert [r.case_id for r in sink.records] == ["", "case-1", "case-1"]


def test_one_case_filter_returns_the_whole_story() -> None:
    """The reason `case_id` exists.

    `target_id` alone cannot answer "what happened to this case". It holds the
    case id on some actions and the SEARCH id on others, and nothing at all on
    a refusal — so a `target_id == case_id` filter dropped every search, every
    estimate, every export and every denial, which is the bulk of "what was
    searched, when, by whom".

    That was not noticed until someone tried to READ the trail per case. It had
    been verified as intact many times, and never as useful.
    """
    from dsar.auth.provider import Principal
    from dsar.cases.workflow import Workflow

    sink = MemorySink()
    trail = AuditTrail(sink)

    class _Ops:
        def create_search(self, **kw):  # type: ignore[no-untyped-def]
            return type("R", (), {
                "body": {"id": "search-1", "displayName": kw["display_name"]},
                "correlation_id": "corr-search",
            })()

        def run_search(self, **kw):  # type: ignore[no-untyped-def]
            return type("R", (), {"body": {}, "correlation_id": "corr-run"})()

    reader = Principal(oid="oid-1", tenant_id="t", roles=frozenset())
    denied = Workflow(_Ops(), reader, trail)  # type: ignore[arg-type]

    # A reader is refused — and the refusal must be findable under the case.
    with pytest.raises(Exception):
        denied.create_search("case-1", "Naive", 'participants:"a"')

    operator = Principal(oid="oid-2", tenant_id="t", roles=frozenset({"DSAR.Operator"}))
    allowed = Workflow(_Ops(), operator, trail)  # type: ignore[arg-type]
    allowed.create_search("case-1", "Naive", 'participants:"a"')
    allowed.run_estimate("case-1", "search-1")

    # The expansion too. On the first live trail it carried the case only in
    # target_id, so the one-case filter dropped it and the evidence pack
    # counted it unattributable — this test covered every action EXCEPT the
    # one that resolves the subject.
    from dsar.identity.expand import Subject

    allowed.expand(
        Subject(primary_email="subject@example.test"),
        identity_expansion=False,
        case_id="case-1",
    )

    for_case = [r for r in sink.records if r.case_id == "case-1"]
    actions = [(r.action, r.outcome) for r in for_case]

    assert ("search_created", "denied") in actions, "the refusal was not findable"
    assert ("search_created", "attempted") in actions
    assert ("search_created", "ok") in actions
    assert ("estimate_started", "ok") in actions
    assert ("identity_expanded", "ok") in actions, (
        "the expansion is not findable under its case"
    )

    # The old filter would have found only the ATTEMPTED record — the one whose
    # target_id happened to be the case rather than the search.
    old_filter = [r for r in sink.records if r.target_id == "case-1"]
    assert len(old_filter) < len(for_case), (
        "target_id alone is now sufficient, so this test proves nothing"
    )


def test_a_template_application_is_recorded_with_id_and_version() -> None:
    """DSA-D01. Applying a template was a pure render with no audit write.

    The search that eventually runs is recorded name-only — deliberately, the
    query names a real person — so before this record existed the trail could
    not say which reviewed narrowing shaped a search. The stamp is the
    template id and the template file's version, and nothing else: never the
    query, never the operator's input values, which carry exactly the subject
    data the record shape forbids.
    """
    from dsar.auth.provider import Principal
    from dsar.cases.workflow import Workflow

    sink = MemorySink()
    trail = AuditTrail(sink)
    operator = Principal(
        oid="oid-1", tenant_id="t", roles=frozenset({"DSAR.Operator"})
    )
    workflow = Workflow(object(), operator, trail)  # type: ignore[arg-type]

    workflow.record_template_applied("time_window", "1.0.0", case_id="case-1")

    [record] = sink.records
    assert record.action == "template_applied"
    assert record.outcome == "ok"
    assert record.case_id == "case-1"
    assert record.detail == "time_window @ 1.0.0"
    assert record.actor_oid == "oid-1"

    # And it is findable where the evidence pack looks: the one case filter.
    assert [r for r in sink.records if r.case_id == "case-1"] == [record]


def test_a_free_text_case_id_cannot_ride_into_the_trail() -> None:
    """WS10 SEC-M-01. `detail` is scrubbed and capped; `case_id` was written
    verbatim — and several workflow paths write it into an ATTEMPTED or
    TEMPLATE_APPLIED record BEFORE any Graph call could refuse it. The trail
    is append-only, hosted under an immutability policy, so a subject's name
    riding an identifier field would be subject data at rest that nobody can
    erase. Identifiers are letters, digits and hyphens, bounded; anything
    else is refused at the API boundary with nothing written."""
    from dsar.auth.provider import Principal
    from dsar.cases.workflow import Workflow
    from dsar.web.api import handle

    sink = MemorySink()
    trail = AuditTrail(sink)
    operator = Principal(
        oid="oid-1", tenant_id="t", roles=frozenset({"DSAR.Operator"})
    )
    workflow = Workflow(object(), operator, trail)  # type: ignore[arg-type]

    for path, body in (
        (
            "/api/template/apply",
            {"query": "x", "template_id": "t", "case_id": "Jordan Hale <j@x.test>"},
        ),
        (
            "/api/search/create",
            {"query": "x", "case_id": "jordan.hale@x.test employee E-2214"},
        ),
        (
            "/api/expand",
            {"primary_email": "a@x.test", "case_id": "a" * 65},
        ),
    ):
        status, payload = handle(
            path,
            body,
            principal=operator,
            cases=None,  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            workflow=workflow,
        )
        assert status == 400, path
        assert payload["error"] == "invalid_input", path

    assert sink.records == [], "a refused identifier still reached the trail"


def test_ok_records_carry_the_graph_correlation_id() -> None:
    """B-25, found reading the first live trail: every record's
    `correlation_id` was empty. The Graph client mints a `client-request-id`
    per request and Graph echoes it back — the pair that joins an audit
    record to the Graph activity log at investigation time — but the echo
    lived in the response headers and nothing read it out.

    OK records carry it. ATTEMPTED records stay empty deliberately: the id
    is minted per request inside the client, so before the call there is
    nothing true to write."""
    from dsar.auth.provider import Principal
    from dsar.cases.workflow import Workflow

    sink = MemorySink()
    trail = AuditTrail(sink)

    class _Ops:
        def create_case(self, **kw):  # type: ignore[no-untyped-def]
            return type("R", (), {
                "body": {"id": "case-7", "displayName": kw["display_name"]},
                "correlation_id": "corr-case-7",
            })()

    operator = Principal(
        oid="oid-1", tenant_id="t", roles=frozenset({"DSAR.Operator"})
    )
    Workflow(_Ops(), operator, trail).create_case("DSAR-2026-0002")  # type: ignore[arg-type]

    attempted, ok = sink.records
    assert (attempted.outcome, attempted.correlation_id) == ("attempted", "")
    assert (ok.outcome, ok.correlation_id) == ("ok", "corr-case-7")


def test_the_response_correlation_id_prefers_the_graph_echo() -> None:
    """`request-id` is Graph's own id for the request; `client-request-id` is
    ours returned. Either joins the logs; Graph's is the one its support and
    activity tooling indexes first, so it wins when both are present."""
    from dsar.graph.client import GraphResponse

    both = GraphResponse(200, {}, {"request-id": "g-1", "client-request-id": "c-1"})
    assert both.correlation_id == "g-1"
    ours_only = GraphResponse(200, {}, {"client-request-id": "c-1"})
    assert ours_only.correlation_id == "c-1"
    neither = GraphResponse(200, {}, {})
    assert neither.correlation_id == ""
