"""Phase 2: the request list, rebuilt from Graph rather than a local store."""

from __future__ import annotations

import pytest

from dsar.auth.provider import Principal
from dsar.cases.model import parse_case, parse_search
from dsar.cases.reference import (
    PREFIX,
    InvalidReference,
    decode_reference,
    encode_reference,
    is_ours,
)
from dsar.cases.service import CaseScope, CaseService

TENANT = "66666666-7777-8888-9999-aaaaaaaaaaaa"
ME = "11111111-1111-1111-1111-111111111111"
SOMEONE_ELSE = "22222222-2222-2222-2222-222222222222"


# ------------------------------------------------------------- reference


def test_reference_round_trips() -> None:
    assert decode_reference(encode_reference("DSAR-2026-0142")) == "DSAR-2026-0142"


def test_encoded_reference_is_prefixed_and_versioned() -> None:
    """The version lets the convention change later without orphaning cases."""
    assert encode_reference("DSAR-1").startswith(PREFIX)
    assert PREFIX == "dsar:v1:"


@pytest.mark.parametrize(
    "value", ["", "   ", "x" * 65, "has:colon", "<script>", "trailing-"]
)
def test_bad_references_are_refused(value: str) -> None:
    with pytest.raises(InvalidReference):
        encode_reference(value)


def test_a_colon_is_refused_with_the_reason() -> None:
    with pytest.raises(InvalidReference, match="separator"):
        encode_reference("DSAR:2026")


@pytest.mark.parametrize(
    "external_id",
    [None, "", "some-other-tool", "dsar:v2:DSAR-1", "DSAR-2026-0142", "dsar:v1:"],
)
def test_foreign_external_ids_are_not_ours(external_id: str | None) -> None:
    """Not an error. A case created in the portal is simply not this tool's."""
    assert decode_reference(external_id) is None
    assert is_ours(external_id) is False


# ----------------------------------------------------------------- model


def test_case_parses_the_fields_the_list_needs() -> None:
    case = parse_case(
        {
            "id": "case-1",
            "displayName": "DSAR-2026-0142",
            "externalId": "dsar:v1:DSAR-2026-0142",
            "status": "active",
            "createdDateTime": "2026-08-14T10:00:00Z",
            "createdBy": {"user": {"id": ME, "displayName": "Ben"}},
        }
    )
    assert case.reference == "DSAR-2026-0142"
    assert case.is_ours and case.created_by_oid == ME


def test_case_survives_a_missing_created_by() -> None:
    """Graph does not always populate createdBy in the list projection."""
    case = parse_case({"id": "c", "externalId": "dsar:v1:R"})
    assert case.created_by_oid == ""


def test_statistics_absent_is_none_not_zero() -> None:
    """"No estimate has run" and "the estimate found nothing" are different
    facts, and a UI showing 0 for the first is lying."""
    search = parse_search({"id": "s", "displayName": "naive"})
    assert search.statistics.item_count is None
    assert search.statistics.complete is False


def test_statistics_come_from_the_expanded_operation() -> None:
    """The $expand is what makes the answer *this search's*.

    The predecessor read them off the case-level operations collection, which
    carries no reference back to the search that produced each one — so with
    several searches per case, every one reported the same numbers.
    """
    search = parse_search(
        {
            "id": "s",
            "displayName": "expanded",
            "lastEstimateStatisticsOperation": {
                "status": "succeeded",
                "indexedItemCount": 50,
                "indexedItemsSize": 1234,
                "siteCount": 3,
            },
        }
    )
    assert search.statistics.item_count == 50
    assert search.statistics.location_count == 3
    assert search.statistics.complete is True


def test_a_zero_count_is_kept_as_zero() -> None:
    search = parse_search(
        {"id": "s", "lastEstimateStatisticsOperation": {"status": "succeeded", "indexedItemCount": 0}}
    )
    assert search.statistics.item_count == 0
    assert search.statistics.complete is True


# --------------------------------------------------------------- service


class FakeOps:
    """Stands in for GraphOperations. Records calls, returns canned pages."""

    def __init__(self, pages: list[dict]) -> None:
        self.pages = pages
        self.calls = 0

    def list_cases(self, *, top: int = 100, skip_token: str = ""):  # noqa: ANN201
        from dsar.graph.client import GraphResponse

        self.calls += 1
        index = 0 if not skip_token else int(skip_token)
        return GraphResponse(200, self.pages[index], {})


def _case(case_id: str, external_id: str | None, owner: str) -> dict:
    body: dict = {
        "id": case_id,
        "displayName": case_id,
        "status": "active",
        "createdDateTime": "2026-08-14T10:00:00Z",
        "createdBy": {"user": {"id": owner, "displayName": "someone"}},
    }
    if external_id:
        body["externalId"] = external_id
    return body


def _principal() -> Principal:
    return Principal(oid=ME, tenant_id=TENANT)


def test_only_our_cases_appear() -> None:
    """A tenant is shared. Cases created in the portal are not this tool's."""
    ops = FakeOps([{"value": [
        _case("ours", "dsar:v1:DSAR-1", ME),
        _case("theirs", None, ME),
        _case("other-tool", "someothertool:1", ME),
    ]}])
    listing = CaseService(ops).list_requests(_principal())  # type: ignore[arg-type]
    assert [c.id for c in listing.cases] == ["ours"]


def test_mine_scope_excludes_other_operators_cases() -> None:
    ops = FakeOps([{"value": [
        _case("mine", "dsar:v1:A", ME),
        _case("theirs", "dsar:v1:B", SOMEONE_ELSE),
    ]}])
    service = CaseService(ops)  # type: ignore[arg-type]
    mine = service.list_requests(_principal(), scope=CaseScope.MINE)
    assert [c.id for c in mine.cases] == ["mine"]


def test_all_scope_includes_them() -> None:
    ops = FakeOps([{"value": [
        _case("mine", "dsar:v1:A", ME),
        _case("theirs", "dsar:v1:B", SOMEONE_ELSE),
    ]}])
    service = CaseService(ops)  # type: ignore[arg-type]
    every = service.list_requests(_principal(), scope=CaseScope.ALL)
    assert {c.id for c in every.cases} == {"mine", "theirs"}


def test_a_case_with_no_owner_information_is_kept_in_mine() -> None:
    """Silently hiding a case the operator created is worse than showing one
    they did not."""
    ops = FakeOps([{"value": [_case("unknown-owner", "dsar:v1:A", "")]}])
    listing = CaseService(ops).list_requests(_principal())  # type: ignore[arg-type]
    assert [c.id for c in listing.cases] == ["unknown-owner"]


def test_scope_toggle_is_only_useful_when_it_changes_something() -> None:
    only_mine = FakeOps([{"value": [_case("a", "dsar:v1:A", ME)]}])
    assert CaseService(only_mine).list_requests(_principal()).scope_toggle_useful is False  # type: ignore[arg-type]

    mixed = FakeOps([{"value": [
        _case("a", "dsar:v1:A", ME), _case("b", "dsar:v1:B", SOMEONE_ELSE)
    ]}])
    assert CaseService(mixed).list_requests(_principal()).scope_toggle_useful is True  # type: ignore[arg-type]


def test_paging_follows_the_next_link() -> None:
    ops = FakeOps([
        {"value": [_case("p1", "dsar:v1:A", ME)],
         "@odata.nextLink": "https://graph/x?$skiptoken=1&$top=100"},
        {"value": [_case("p2", "dsar:v1:B", ME)]},
    ])
    listing = CaseService(ops).list_requests(_principal())  # type: ignore[arg-type]
    assert {c.id for c in listing.cases} == {"p1", "p2"}
    assert ops.calls == 2


def test_the_read_is_cached_then_refreshable() -> None:
    ops = FakeOps([{"value": [_case("a", "dsar:v1:A", ME)]}])
    service = CaseService(ops)  # type: ignore[arg-type]
    service.list_requests(_principal())
    service.list_requests(_principal())
    assert ops.calls == 1, "a second read inside the TTL should be served from cache"
    service.list_requests(_principal(), force=True)
    assert ops.calls == 2


def test_newest_case_first() -> None:
    old = _case("old", "dsar:v1:A", ME)
    old["createdDateTime"] = "2026-01-01T00:00:00Z"
    new = _case("new", "dsar:v1:B", ME)
    new["createdDateTime"] = "2026-08-14T00:00:00Z"
    listing = CaseService(FakeOps([{"value": [old, new]}])).list_requests(_principal())  # type: ignore[arg-type]
    assert [c.id for c in listing.cases] == ["new", "old"]


# --------------------------------------------- estimate status handling


@pytest.mark.parametrize(
    "status,complete,partial",
    [
        ("succeeded", True, False),
        ("partiallySucceeded", True, True),   # the one that was missing
        ("running", False, False),
        ("notStarted", False, False),
        ("failed", False, False),
        ("submissionFailed", False, False),
    ],
)
def test_every_documented_status_is_handled(
    status: str, complete: bool, partial: bool
) -> None:
    """caseOperationStatus values, per Microsoft Graph v1.0.

    `partiallySucceeded` was absent from the complete set. Purview returns it
    when the estimate finished against some locations and not others, which is
    normal — the counts are real and the portal shows them, but this code called
    it "running" and the UI waited for a state that had already arrived.
    """
    search = parse_search(
        {"id": "s", "lastEstimateStatisticsOperation": {
            "status": status, "indexedItemCount": 40}}
    )
    assert search.statistics.complete is complete
    assert search.statistics.partial is partial
    assert search.statistics.item_count == 40, "counts are real whatever the status"


def test_locations_are_mailboxes_plus_sites() -> None:
    """`or` took the first truthy value, so 2 mailboxes and 3 sites reported 2,
    and 0 mailboxes with 3 sites reported 3 — inconsistently, depending on which
    happened to be zero."""
    search = parse_search(
        {"id": "s", "lastEstimateStatisticsOperation": {
            "status": "succeeded", "mailboxCount": 2, "siteCount": 3}}
    )
    assert search.statistics.location_count == 5
    assert search.statistics.mailbox_count == 2
    assert search.statistics.site_count == 3


def test_a_site_only_hit_is_not_lost() -> None:
    search = parse_search(
        {"id": "s", "lastEstimateStatisticsOperation": {
            "status": "succeeded", "mailboxCount": 0, "siteCount": 3}}
    )
    assert search.statistics.location_count == 3


def test_unindexed_items_are_kept_separate() -> None:
    """Folding them into the total is how a DSAR response acquires a number
    nobody can defend."""
    search = parse_search(
        {"id": "s", "lastEstimateStatisticsOperation": {
            "status": "succeeded", "indexedItemCount": 40, "unindexedItemCount": 7}}
    )
    assert search.statistics.item_count == 40
    assert search.statistics.unindexed_count == 7


# ---------------------------------- statistics fallback via operations


class FallbackOps:
    """Returns an empty expand, then an operations collection."""

    def __init__(self, operations: list[dict]) -> None:
        self.operations = operations
        self.list_calls = 0

    def get_statistics(self, *, case_id: str, search_id: str):  # noqa: ANN201
        from dsar.graph.client import GraphResponse

        return GraphResponse(200, {"id": search_id, "displayName": "naive"}, {})

    def list_operations(self, *, case_id: str):  # noqa: ANN201
        from dsar.graph.client import GraphResponse

        self.list_calls += 1
        return GraphResponse(200, {"value": self.operations}, {})


def test_statistics_fall_back_to_an_attributed_operation() -> None:
    ops = FallbackOps([
        {"action": "estimateStatistics", "status": "succeeded",
         "indexedItemCount": 40, "createdDateTime": "2026-08-14T10:00:00Z",
         "search": {"id": "search-1"}},
    ])
    search = CaseService(ops).statistics_for("case", "search-1")  # type: ignore[arg-type]
    assert search.statistics.item_count == 40
    assert ops.list_calls == 1


def test_the_fallback_never_borrows_another_searchs_numbers() -> None:
    """The predecessor matched "newest estimate in the case", so with more than
    one search every search reported the same numbers. No number is recoverable
    from; a wrong-but-plausible number is not."""
    ops = FallbackOps([
        {"action": "estimateStatistics", "status": "succeeded",
         "indexedItemCount": 999, "createdDateTime": "2026-08-14T11:00:00Z",
         "search": {"id": "a-different-search"}},
        {"action": "estimateStatistics", "status": "succeeded",
         "indexedItemCount": 888, "createdDateTime": "2026-08-14T12:00:00Z"},
    ])
    search = CaseService(ops).statistics_for("case", "search-1")  # type: ignore[arg-type]
    assert search.statistics.item_count is None
    assert search.statistics.status == ""


def test_a_failing_operations_call_does_not_become_an_error() -> None:
    class Broken(FallbackOps):
        def list_operations(self, *, case_id: str):  # noqa: ANN201
            raise RuntimeError("Graph is unhappy")

    search = CaseService(Broken([])).statistics_for("case", "s")  # type: ignore[arg-type]
    assert search.statistics.item_count is None


def test_the_expansion_json_names_former_names_and_employee_id() -> None:
    """DSA-B03. The interface groups the preview by provenance, which needs
    two facts the JSON did not carry: which mentions are former names, and
    that the employee id was used to match the directory record rather than
    searched. A chip that looks searched and is not would misstate the
    query's coverage, so the JSON states which is which."""
    from dsar.identity.expand import DirectoryResolver, Subject, expand_subject

    subject = Subject(
        primary_email="jordan.hale@example.test",
        display_name="Jordan Hale",
        aliases=("Jay",),
        former_names=("Jordan Price",),
        employee_id="E-2214",
    )
    data = expand_subject(subject, DirectoryResolver([])).to_json()

    assert data["former_names"] == ["Jordan Price"]
    # Still inside mentions for the query; the separate key is for labelling.
    assert "Jordan Price" in data["mentions"]
    # Matched against the directory, never searched.
    assert data["employee_id"] == "E-2214"
    assert "E-2214" not in data["kql"]
