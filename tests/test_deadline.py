"""The statutory clock.

The one piece of this tool whose output is a **statutory date**. A DSAR must be
answered within one calendar month of receipt, and a deadline that is quietly
wrong is worse than no deadline at all — so the arithmetic is pinned here
against the ICO's own stated rule, including the cases that make "one month"
different from "thirty days".
"""

from __future__ import annotations

from datetime import date

import pytest

from dsar.cases.deadline import Deadline, deadline_for, due_date
from dsar.cases.received import (
    BOILERPLATE,
    MARKER,
    decode_received,
    encode_received,
)


# --------------------------------------------------------------- the rule


@pytest.mark.parametrize(
    ("received", "due", "why"),
    [
        ("2026-08-14", "2026-09-14", "the ordinary case"),
        # The ICO's own worked example.
        ("2026-01-31", "2026-02-28", "31 Jan, and February is shorter"),
        ("2028-01-31", "2028-02-29", "the same, in a leap year"),
        ("2026-08-31", "2026-09-30", "31 Aug into a 30-day month"),
        ("2026-12-15", "2027-01-15", "across the year boundary"),
        ("2026-12-31", "2027-01-31", "31 Dec, and January is not shorter"),
        ("2026-02-28", "2026-03-28", "end of February is not special"),
        ("2028-02-29", "2028-03-29", "a leap day"),
        ("2026-04-30", "2026-05-30", "30 April is not the last of May"),
    ],
)
def test_one_calendar_month(received: str, due: str, why: str) -> None:
    """One calendar month is the corresponding date next month, clamped to the
    length of that month. It is not thirty days, and it is not four weeks."""
    assert due_date(date.fromisoformat(received)) == date.fromisoformat(due), why


@pytest.mark.parametrize(
    ("received", "drift_days"),
    [
        # A 31-day month: +30 lands a day EARLY, so a response sent on the
        # real deadline would look late.
        ("2026-01-15", +1),
        # February: +30 lands two days LATE, so a response sent on the +30
        # date would BE late. This is the direction that matters.
        ("2026-02-15", -2),
        # A 30-day month agrees by coincidence, which is exactly why "+30 is
        # near enough" survives casual checking.
        ("2026-04-15", 0),
        ("2026-08-31", 0),
    ],
)
def test_it_is_not_thirty_days(received: str, drift_days: int) -> None:
    """The failure this module exists to prevent, stated as a test.

    A month is 28, 29, 30 or 31 days. `+30` is right only in a 30-day month —
    and my first version of this test asserted all four cases differed, which
    was wrong for exactly that reason. Kept as a parametrised table so the
    coincidence is visible rather than mistaken for agreement.
    """
    from datetime import timedelta

    start = date.fromisoformat(received)
    assert (due_date(start) - (start + timedelta(days=30))).days == drift_days


# --------------------------------------------------------- days remaining


def test_days_remaining_counts_whole_days() -> None:
    d = deadline_for(date(2026, 8, 14), today=date(2026, 8, 20))
    assert d.due == date(2026, 9, 14)
    assert d.days_remaining == 25
    assert d.overdue is False
    assert "25 days left" in d.summary()


def test_due_today_is_not_overdue() -> None:
    """The month *ends* on the corresponding date, so that day is still in it."""
    d = deadline_for(date(2026, 8, 14), today=date(2026, 9, 14))
    assert d.days_remaining == 0
    assert d.overdue is False
    assert d.summary() == "due today (2026-09-14)"


def test_overdue_counts_up() -> None:
    d = deadline_for(date(2026, 7, 2), today=date(2026, 8, 14))
    assert d.overdue is True
    assert d.days_overdue == 12
    assert "overdue by 12 days" in d.summary()


def test_one_day_is_singular() -> None:
    assert "1 day left" in deadline_for(date(2026, 8, 14), date(2026, 9, 13)).summary()
    assert "overdue by 1 day (" in deadline_for(
        date(2026, 8, 14), date(2026, 9, 15)
    ).summary()


def test_today_is_injected_never_read_from_the_clock() -> None:
    """Every test states the day it reasons about, and nothing here depends on
    when the suite runs — a deadline test that passes in August and fails in
    September is worse than no test."""
    import inspect

    from dsar.cases import deadline as module

    source = inspect.getsource(module)
    for forbidden in ("date.today", "datetime.now", "time.time"):
        assert forbidden not in source, f"{forbidden} in the deadline module"


# ---------------------------------------------------- the received marker


def test_the_marker_round_trips() -> None:
    encoded = encode_received(date(2026, 8, 14))
    assert encoded.startswith(f"{MARKER} 2026-08-14")
    assert BOILERPLATE in encoded
    assert decode_received(encoded) == date(2026, 8, 14)


def test_no_received_date_leaves_the_description_exactly_as_before() -> None:
    """A case created without one must be byte-identical to a case created
    before this module existed."""
    assert encode_received(None) == BOILERPLATE
    assert decode_received(BOILERPLATE) is None


def test_an_operator_description_is_preserved() -> None:
    encoded = encode_received(date(2026, 8, 14), "Ticket INC-4471, urgent.")
    assert decode_received(encoded) == date(2026, 8, 14)
    assert "Ticket INC-4471, urgent." in encoded
    assert BOILERPLATE not in encoded


@pytest.mark.parametrize(
    "description",
    [
        None,
        "",
        BOILERPLATE,
        "DSAR-Received:",                       # marker, no date
        "DSAR-Received: yesterday",             # not a date
        "DSAR-Received: 14/08/2026",            # not ISO
        "DSAR-Received: 2026-13-45",            # right shape, not a real date
        "DSAR-Received: 2026-02-30",            # a day February never has
        "received 2026-08-14",                  # no marker
        "notes DSAR-Received: 2026-08-14 more", # not on its own line
    ],
)
def test_anything_that_is_not_a_date_is_not_recorded(description: str | None) -> None:
    """No partial answers and no guesses.

    `description` is free text a person can edit in the Purview portal, so the
    marker can be removed or mangled. Every failure lands on the same visible
    state as a case created before this existed — never on a plausible wrong
    date, which is the one outcome a statutory deadline cannot have.
    """
    assert decode_received(description) is None


def test_the_marker_survives_notes_appended_underneath() -> None:
    """The likeliest portal edit. A prefix survives it; a suffix would not."""
    edited = encode_received(date(2026, 8, 14)) + "\n\nChased the requester 20 Aug."
    assert decode_received(edited) == date(2026, 8, 14)


def test_case_and_whitespace_are_tolerated() -> None:
    """Read back out of a field a human types into."""
    assert decode_received("  dsar-received:   2026-08-14  \nnotes") == date(2026, 8, 14)


def test_a_deadline_can_be_built_from_a_decoded_marker() -> None:
    """The two halves meet: what is stored produces what is shown."""
    received = decode_received(encode_received(date(2026, 1, 31)))
    assert received is not None
    assert deadline_for(received, today=date(2026, 2, 1)).due == date(2026, 2, 28)


# ------------------------------------------------- through the whole path


def test_a_case_carries_its_received_date_and_deadline() -> None:
    """The shape Graph documents for the list projection, end to end.

    Note what this case demonstrates: opened on 20 August, received on 2 July.
    It was already overdue when somebody created it. Deriving the deadline from
    `createdDateTime` would have shown 20 September — 49 days late, and late in
    the direction that matters.
    """
    from dsar.cases.model import parse_case

    case = parse_case(
        {
            "id": "case-1",
            "displayName": "DSAR-2026-0417",
            "status": "active",
            "externalId": "dsar:v1:DSAR-2026-0417",
            "createdDateTime": "2026-08-20T09:00:00Z",
            "description": encode_received(date(2026, 7, 2)),
            "createdBy": {"user": {"id": "oid-1", "displayName": "B"}},
        }
    )
    assert case.received == date(2026, 7, 2)
    assert case.created.startswith("2026-08-20")

    deadline = case.deadline(today=date(2026, 8, 14))
    assert deadline is not None
    assert deadline.due == date(2026, 8, 2)
    assert deadline.overdue is True


def test_a_case_without_a_marker_has_no_deadline() -> None:
    """Never derived from `created`. The gap is the honest answer."""
    from dsar.cases.model import parse_case

    case = parse_case(
        {
            "id": "case-2",
            "displayName": "DSAR-2026-0418",
            "externalId": "dsar:v1:DSAR-2026-0418",
            "createdDateTime": "2026-08-20T09:00:00Z",
            "description": "Raised via DSAR Assist.",
        }
    )
    assert case.received is None
    assert case.deadline(today=date(2026, 8, 14)) is None


def test_the_api_refuses_a_malformed_received_date() -> None:
    """Silently dropping it would produce a case that looks like it has no
    receipt date while the operator believes they supplied one — and the
    deadline would quietly not exist."""
    from dsar.cases.reference import InvalidReference
    from dsar.web.api import _received_date

    today = date(2026, 8, 16)
    assert _received_date("", today) is None
    assert _received_date("2026-08-14", today) == date(2026, 8, 14)

    for bad in ("14/08/2026", "yesterday", "2026/08/14"):
        with pytest.raises(InvalidReference, match="YYYY-MM-DD"):
            _received_date(bad, today)

    # Right shape, not a real day — a different message, because it is a
    # different mistake and the operator fixes it differently.
    for bad in ("2026-13-45", "2026-02-30"):
        with pytest.raises(InvalidReference, match="not a real date"):
            _received_date(bad, today)


@pytest.mark.parametrize(
    "raw",
    [
        "20260814",     # fromisoformat accepts it; the error promises it will not
        "2026-W33-1",   # and this parses to 10 August — four days out, silently
    ],
)
def test_a_format_the_error_message_disowns_is_refused(raw: str) -> None:
    """WS10 SEC-M-10. `date.fromisoformat` is more generous than the message
    that describes it, and the week form is the dangerous one: an operator
    typing it gets a real date four days from the one they meant, with no
    error and a statutory deadline to match."""
    from dsar.cases.reference import InvalidReference
    from dsar.web.api import _received_date

    with pytest.raises(InvalidReference, match="YYYY-MM-DD"):
        _received_date(raw, date(2026, 8, 16))


def test_a_received_date_out_of_range_is_refused_before_it_can_break_the_list() -> None:
    """WS10 SEC-H-05, and the impact is what makes it High.

    `9999-12-31` parses, and one calendar month later is year 10000, which
    `date()` refuses. That raised inside `_deadline_json`, which runs per case
    in `_requests` — so one such case returned 500 for the request list, for
    every operator, permanently, with no `update_case` to remove it.
    """
    from dsar.cases.reference import InvalidReference
    from dsar.web.api import _received_date

    today = date(2026, 8, 16)
    with pytest.raises(InvalidReference, match="future"):
        _received_date("9999-12-31", today)
    with pytest.raises(InvalidReference, match="future"):
        _received_date("2026-08-17", today)
    with pytest.raises(InvalidReference, match="before the UK GDPR"):
        _received_date("2018-05-24", today)

    # And the boundaries themselves are accepted.
    assert _received_date("2026-08-16", today) == today
    assert _received_date("2018-05-25", today) == date(2018, 5, 25)


def test_a_description_cannot_smuggle_its_own_marker() -> None:
    """WS10 SEC-M-09. Only `_received_date` may set a deadline, and only inside
    the bounds it enforces — an operator-supplied description carrying its own
    marker line would bypass all of them."""
    smuggled = encode_received(None, "DSAR-Received: 1999-01-01\nnotes")
    assert decode_received(smuggled) is None

    # And a real marker still wins when one was actually supplied.
    both = encode_received(date(2026, 8, 14), "DSAR-Received: 1999-01-01")
    assert decode_received(both) == date(2026, 8, 14)


def test_the_marker_scan_does_not_walk_the_whole_description() -> None:
    """WS10 SEC-M-08. Scanning with `re.MULTILINE` was quadratic in the
    description's length — milliseconds at a thousand newlines, seconds at the
    request body cap, on every case in every list call."""
    import time

    big = "DSAR-Received: 2026-08-14\n" + ("x" * 40 + "\n") * 20_000
    start = time.perf_counter()
    assert decode_received(big) == date(2026, 8, 14)
    assert time.perf_counter() - start < 0.05


def test_the_request_projection_carries_the_deadline() -> None:
    from dsar.cases.model import parse_case
    from dsar.web.api import _deadline_json

    case = parse_case(
        {"id": "c", "description": encode_received(date(2026, 8, 14))}
    )
    assert _deadline_json(case, date(2026, 8, 20)) == {
        "received": "2026-08-14",
        "due": "2026-09-14",
        "days_remaining": 25,
        "overdue": False,
    }

    bare = parse_case({"id": "c"})
    assert _deadline_json(bare, date(2026, 8, 20)) == {
        "received": None,
        "due": None,
        "days_remaining": None,
        "overdue": False,
    }
