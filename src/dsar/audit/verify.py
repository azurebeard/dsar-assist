"""Chain verification. Names the first break rather than reporting a boolean.

"The audit trail has been altered" is not actionable. "Record 47, written at
14:22:03, does not match its own contents" tells someone where to look.

Four ways a chain can be wrong, and they are distinguished because they mean
different things:

  altered     the record's own hash does not match its contents — edited
  broken      `prev_hash` does not match the previous record's hash — a record
              was removed, or one was inserted
  out of order  sequence numbers do not ascend by one — a record was removed
  malformed   the line is not a record at all — corruption, or a partial write

A missing record and an edited record are different incidents with different
answers, so the verifier does not collapse them into "invalid".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from dsar.audit.record import GENESIS_HASH, AuditRecord

__all__ = ["Break", "VerifyResult", "verify_chain"]


@dataclass(frozen=True)
class Break:
    seq: int
    ts: str
    kind: str
    detail: str


@dataclass(frozen=True)
class VerifyResult:
    records: int
    breaks: tuple[Break, ...]

    @property
    def intact(self) -> bool:
        return not self.breaks

    def summary(self) -> str:
        if not self.records:
            return "No audit records found."
        if self.intact:
            return f"{self.records} record(s), chain intact."
        first = self.breaks[0]
        return (
            f"{self.records} record(s), {len(self.breaks)} break(s). "
            f"First at seq {first.seq} ({first.ts}): {first.kind} — {first.detail}"
        )


def verify_chain(records: Iterable[AuditRecord]) -> VerifyResult:
    breaks: list[Break] = []
    previous: AuditRecord | None = None
    count = 0

    for record in records:
        count += 1

        expected_prev = GENESIS_HASH if previous is None else previous.hash
        if record.prev_hash != expected_prev:
            breaks.append(
                Break(
                    record.seq,
                    record.ts,
                    "broken link",
                    "prev_hash does not match the previous record; a record was "
                    "removed or inserted here",
                )
            )

        if record.recompute() != record.hash:
            breaks.append(
                Break(
                    record.seq,
                    record.ts,
                    "altered",
                    "the record's contents do not match its own hash",
                )
            )

        expected_seq = 1 if previous is None else previous.seq + 1
        if record.seq != expected_seq:
            breaks.append(
                Break(
                    record.seq,
                    record.ts,
                    "out of order",
                    f"expected seq {expected_seq}",
                )
            )

        previous = record

    return VerifyResult(records=count, breaks=tuple(breaks))
