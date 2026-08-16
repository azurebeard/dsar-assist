"""The per-case evidence pack.

`dsar audit verify` answers "is the trail intact", which defends the tool. This
is what a data protection officer attaches to a response: who searched, what
for, when, and proof the record has not been edited.

Every test here was written after running the thing against a seeded trail.
Three defects only showed up that way — a paragraph printed as a Python list
repr, a refusal listed as a search called "Creating a search", and a sign-in
counted as a record that "could not be attributed to any case".
"""

from __future__ import annotations

import pytest

from dsar.audit.evidence import build_evidence
from dsar.audit.record import Action, AuditRecord, GENESIS_HASH, Outcome
from dsar.audit.sink import MemorySink
from dsar.audit.trail import AuditTrail
from dsar.audit.verify import verify_chain


@pytest.fixture
def trail() -> tuple[AuditTrail, MemorySink]:
    sink = MemorySink()
    return AuditTrail(sink), sink


def _seed(trail: AuditTrail) -> None:
    """A realistic case: sign-in, creation, expansion, two searches, a refusal,
    and a second case whose records must not appear."""
    trail.write(Action.SIGN_IN, Outcome.OK, actor_oid="oid-op", actor_upn="op@x.test",
                uti="UTI-1")
    # No case id — the case does not exist when the attempt is written.
    trail.write(Action.CASE_CREATED, Outcome.ATTEMPTED, actor_oid="oid-op",
                detail="DSAR-2026-0417")
    trail.write(Action.CASE_CREATED, Outcome.OK, actor_oid="oid-op",
                actor_upn="op@x.test", case_id="case-1", target_id="case-1",
                detail="DSAR-2026-0417", uti="UTI-1")
    trail.write(Action.IDENTITY_EXPANDED, Outcome.OK, actor_oid="oid-op",
                case_id="case-1", subject_ref="7e4ba3ab68401b36")
    trail.write(Action.SEARCH_CREATED, Outcome.ATTEMPTED, actor_oid="oid-op",
                case_id="case-1", target_id="case-1", detail="Naive")
    trail.write(Action.SEARCH_CREATED, Outcome.OK, actor_oid="oid-op",
                case_id="case-1", target_id="search-n", detail="Naive")
    trail.write(Action.ESTIMATE_STARTED, Outcome.OK, actor_oid="oid-op",
                case_id="case-1", target_id="search-n")
    trail.write(Action.SEARCH_CREATED, Outcome.DENIED, actor_oid="oid-r",
                actor_upn="auditor@x.test", case_id="case-1",
                detail="Creating a search")
    # Another case, which must not leak into the pack.
    trail.write(Action.SEARCH_CREATED, Outcome.OK, actor_oid="oid-op",
                case_id="case-2", target_id="search-x", detail="Naive")


def _pack(sink: MemorySink, case_id: str = "case-1"):  # type: ignore[no-untyped-def]
    records = list(sink.records)
    return build_evidence(records, case_id, verify_chain(records))


# ----------------------------------------------------------- what it finds


def test_it_finds_every_record_for_the_case(trail) -> None:  # type: ignore[no-untyped-def]
    """The reason `case_id` was added. `target_id` alone returned the attempted
    search creation and almost nothing else."""
    audit, sink = trail
    _seed(audit)
    pack = _pack(sink)

    actions = [(r.action, r.outcome) for r in pack.events]
    assert ("case_created", "attempted") in actions, "the attempt was not recovered"
    assert ("case_created", "ok") in actions
    assert ("identity_expanded", "ok") in actions
    assert ("search_created", "ok") in actions
    assert ("estimate_started", "ok") in actions
    assert ("search_created", "denied") in actions, "the refusal was not findable"


def test_the_attempted_creation_is_recovered_by_reference(trail) -> None:  # type: ignore[no-untyped-def]
    """It carries no case id — the case does not exist yet — so the only link
    is the reference in `detail`."""
    audit, sink = trail
    _seed(audit)
    pack = _pack(sink)
    assert pack.reference == "DSAR-2026-0417"
    attempts = [r for r in pack.events if r.outcome == Outcome.ATTEMPTED.value
                and r.action == Action.CASE_CREATED.value]
    assert len(attempts) == 1


def test_another_case_does_not_leak_in(trail) -> None:  # type: ignore[no-untyped-def]
    audit, sink = trail
    _seed(audit)
    pack = _pack(sink)
    assert all(r.case_id in ("", "case-1") for r in pack.events)
    assert "search-x" not in {r.target_id for r in pack.events}


def test_a_refusal_is_not_listed_as_a_search(trail) -> None:  # type: ignore[no-untyped-def]
    """A refusal carries the action DESCRIPTION in `detail` — "Creating a
    search" — not a search name. The first run of the pack listed it as a
    search by that name, which reads as something the operator ran."""
    audit, sink = trail
    _seed(audit)
    pack = _pack(sink)

    assert "Creating a search" not in {s.name for s in pack.searches}
    assert {s.name for s in pack.searches} == {"Naive"}
    assert len(pack.refusals) == 1
    assert pack.refusals[0].actor_upn == "auditor@x.test"


def test_a_sign_in_is_not_an_unattributed_case_event(trail) -> None:  # type: ignore[no-untyped-def]
    """A sign-in is not about a case and never was. Counting it invited a
    reader to wonder what was missing when nothing was."""
    audit, sink = trail
    _seed(audit)
    assert _pack(sink).unattributable == 0


def test_a_case_event_with_no_case_is_counted(trail) -> None:  # type: ignore[no-untyped-def]
    """Records written before case attribution existed. "We found nothing" and
    "we could not tell" are different answers and must not look alike."""
    audit, sink = trail
    _seed(audit)
    audit.write(Action.ESTIMATE_STARTED, Outcome.OK, actor_oid="oid-op",
                target_id="search-legacy")
    assert _pack(sink).unattributable == 1


def test_a_search_attempted_and_never_completed_is_flagged(trail) -> None:  # type: ignore[no-untyped-def]
    """The shape of an interrupted write, which the trail exists to expose."""
    audit, sink = trail
    audit.write(Action.CASE_CREATED, Outcome.OK, case_id="c", target_id="c",
                detail="DSAR-1")
    audit.write(Action.SEARCH_CREATED, Outcome.ATTEMPTED, case_id="c", detail="Naive")
    pack = _pack(sink, "c")
    assert [s.incomplete for s in pack.searches] == [True]


# -------------------------------------------------------- the integrity claim


def test_it_verifies_the_whole_chain_not_the_extract(trail) -> None:  # type: ignore[no-untyped-def]
    """`verify_chain` walks `prev_hash` and sequence from the genesis record,
    so a per-case subset reports a break on nearly every record. The pack
    verifies everything and quotes the case, and says which it did."""
    audit, sink = trail
    _seed(audit)
    pack = _pack(sink)

    assert pack.chain.records == len(sink.records), "verified a subset"
    assert pack.chain.records > len(pack.events)
    assert pack.trustworthy is True


def test_a_tampered_trail_yields_no_trustworthy_extract(trail) -> None:  # type: ignore[no-untyped-def]
    """Deleting the refusal is the most incriminating edit available, and it is
    exactly what the chain catches. A tampered trail cannot produce
    trustworthy evidence about part of itself."""
    audit, sink = trail
    _seed(audit)
    sink.records = [r for r in sink.records if r.outcome != Outcome.DENIED.value]

    pack = _pack(sink)
    assert pack.trustworthy is False
    assert not pack.chain.intact
    assert pack.chain.breaks


def test_the_pack_never_carries_subject_data(trail) -> None:  # type: ignore[no-untyped-def]
    """Absent from the trail by construction, so absent here. Asserted rather
    than assumed, because a renderer is exactly where a helpful extra field
    gets added later."""
    audit, sink = trail
    _seed(audit)
    pack = _pack(sink)

    rendered = repr(pack)
    for forbidden in ("participants:", "@example.com", "kind:", "E-4411"):
        assert forbidden not in rendered
    assert pack.subject_refs == ("7e4ba3ab68401b36",)


def test_the_exit_code_follows_the_chain(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A script piping this somewhere should be able to tell without parsing
    prose — the same contract `verify` already has."""
    from dsar.audit.report import run_evidence

    monkeypatch.setenv("DSAR_CLIENT_ID", "11111111-2222-3333-4444-555555555555")
    monkeypatch.setenv("DSAR_TENANT_ID", "66666666-7777-8888-9999-aaaaaaaaaaaa")
    monkeypatch.setenv("DSAR_HOME", str(tmp_path / "home"))
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("DSAR_AUDIT_DIR", str(audit_dir))

    from dsar.audit.sink import build_sink
    from dsar.config import load_config

    trail = AuditTrail(build_sink(load_config()))
    trail.write(Action.CASE_CREATED, Outcome.OK, case_id="c", target_id="c",
                detail="DSAR-1")
    assert run_evidence("c") == 0

    written = next(audit_dir.glob("audit-*.jsonl"))
    written.write_text(written.read_text().replace('"DSAR-1"', '"DSAR-2"'), "utf-8")
    assert run_evidence("c") == 1, "a tampered trail returned success"


def test_a_missing_case_id_is_refused() -> None:
    from dsar.audit.report import run_evidence

    assert run_evidence("") == 2


def test_the_json_output_refuses_a_tampered_trail_too(trail) -> None:  # type: ignore[no-untyped-def]
    """WS10 SEC-H-03 — the seventh instance, and mine.

    `_print_evidence` returned early on a broken chain. `_evidence_json`
    serialised the extract regardless: nine events, the actors and the subject
    pseudonym out of a trail known to be tampered with.

    INV-68 asserted this guarantee and its test checked `pack.trustworthy is
    False` — a dataclass property, not an output. Neither registered test
    called `as_json=True`. A guarantee checked on the wrong side of the
    boundary it protects, written in the same session as the register built to
    catch exactly that.
    """
    from dsar.audit.report import _evidence_json

    audit, sink = trail
    _seed(audit)

    intact = _evidence_json(_pack(sink), "somewhere")
    assert intact["trustworthy"] is True
    assert intact["events"], "an intact trail should still produce an extract"

    sink.records = [r for r in sink.records if r.outcome != Outcome.DENIED.value]
    refused = _evidence_json(_pack(sink), "somewhere")

    assert refused["trustworthy"] is False
    assert "refused" in refused
    for leaked in ("events", "actors", "subject_refs", "searches"):
        assert leaked not in refused, f"{leaked} emitted from a tampered trail"


def test_two_searches_with_one_name_do_not_merge(trail) -> None:  # type: ignore[no-untyped-def]
    """WS10 SEC-H-04. Keyed on name, two searches called `Expanded` merged into
    one row holding the second's creation time and the first's export time — an
    export timestamped before the search it exported, with one id gone.

    The old defence was that the tool names them `Naive` and `Expanded`. Those
    are constants, so re-running the workflow on one case collides on the
    ordinary path — and `/api/search/create` takes the name from the request
    body without constraining it.
    """
    audit, sink = trail
    audit.write(Action.CASE_CREATED, Outcome.OK, case_id="c", target_id="c",
                detail="DSAR-1")
    for search_id in ("search-a", "search-b"):
        audit.write(Action.SEARCH_CREATED, Outcome.ATTEMPTED, case_id="c",
                    detail="Expanded")
        audit.write(Action.SEARCH_CREATED, Outcome.OK, case_id="c",
                    target_id=search_id, detail="Expanded")
        audit.write(Action.ESTIMATE_STARTED, Outcome.OK, case_id="c",
                    target_id=search_id)
    audit.write(Action.EXPORT_INITIATED, Outcome.OK, case_id="c",
                target_id="search-a", detail="Expanded")

    searches = _pack(sink, "c").searches
    assert len(searches) == 2, f"merged into {len(searches)} row(s)"
    assert {s.search_id for s in searches} == {"search-a", "search-b"}

    exported = [s for s in searches if s.export_initiated_at]
    assert len(exported) == 1
    assert exported[0].search_id == "search-a", "the export moved to the wrong search"
    # And no row claims an export that predates its own creation.
    for s in searches:
        if s.export_initiated_at:
            assert s.export_initiated_at >= s.created_at
