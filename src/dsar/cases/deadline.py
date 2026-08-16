"""The statutory deadline. One calendar month, and it is not thirty days.

A subject access request must be answered **within one calendar month of
receipt**. The month runs from the day the request arrived to the corresponding
date in the next month; where that month is shorter, the deadline is its last
day. The ICO's own example: a request received on 31 January is due on
28 February.

Pure arithmetic — no network, no filesystem, no configuration. That is
deliberate and asserted by a structural test: this is the one piece of the tool
whose output is a **statutory date**, and it should be provable at a glance and
testable without a tenant.

Python has no month addition. `timedelta` counts days, `+30` is a different
rule, and `dateutil` is a dependency this project's budget will not carry for
fifteen lines. So the clamping is written out.

## What this deliberately does NOT model

**The two-month extension.** A request that is complex, or one of several from
the same person, may be extended by up to two further months — but the
controller must tell the subject within the first month, and *why*. That is a
decision with a communication attached, not a calculation, and a tool that
silently offered "+2 months" would invite treating it as automatic.

**Stopping the clock.** Asking the subject for clarification pauses the month
from the day it is asked, resuming the day after they reply. That is real
state with two more dates in it.

**Weekends and bank holidays.** Whether a deadline falling on a non-working day
rolls to the next working day is *not encoded here*, because it could not be
confirmed from the ICO's guidance at the time of writing. A statutory rule that
has not been read is not a rule to implement. The date returned is the
corresponding calendar date, and an operator working to the wire should check.

All three are named in the interface rather than ignored. A deadline that is
quietly wrong is worse than one that is visibly partial.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date

__all__ = ["Deadline", "due_date", "deadline_for", "MONTHS"]

#: One calendar month. Named so the number is not mistaken for a day count by
#: someone skimming, which is the entire failure this module exists to avoid.
MONTHS = 1


def due_date(received: date, months: int = MONTHS) -> date:
    """The corresponding date `months` later, clamped to the month's length.

    >>> due_date(date(2026, 8, 14))
    datetime.date(2026, 9, 14)
    >>> due_date(date(2026, 1, 31))       # February is shorter
    datetime.date(2026, 2, 28)
    >>> due_date(date(2028, 1, 31))       # and longer in a leap year
    datetime.date(2028, 2, 29)
    """
    total = received.month - 1 + months
    year = received.year + total // 12
    month = total % 12 + 1
    # `monthrange` returns (weekday of the 1st, number of days). Clamping to
    # the second is what turns 31 January into 28 February rather than an
    # exception or a roll into March.
    last_day = calendar.monthrange(year, month)[1]
    return date(year, month, min(received.day, last_day))


@dataclass(frozen=True)
class Deadline:
    """A received date and what follows from it."""

    received: date
    due: date
    #: Negative once the deadline has passed. Whole days, counted from `today`.
    days_remaining: int

    @property
    def overdue(self) -> bool:
        return self.days_remaining < 0

    @property
    def days_overdue(self) -> int:
        return max(0, -self.days_remaining)

    def summary(self) -> str:
        """One line, for a person. Says the state, not just the number."""
        if self.overdue:
            days = self.days_overdue
            return f"overdue by {days} day{'' if days == 1 else 's'} (due {self.due})"
        if self.days_remaining == 0:
            return f"due today ({self.due})"
        days = self.days_remaining
        return f"{days} day{'' if days == 1 else 's'} left (due {self.due})"


def deadline_for(received: date, today: date) -> Deadline:
    """Build the deadline for a request received on `received`.

    `today` is passed in rather than read from the clock, so every test states
    the day it is reasoning about and nothing here depends on when it runs.
    """
    due = due_date(received)
    return Deadline(received=received, due=due, days_remaining=(due - today).days)
