"""The writer. Owns the sequence number and the chain, so callers cannot.

A caller says *what happened*; it does not get to choose the record's position
or its hash. Both come from here, under one lock, so two threads writing at
once produce two records in a single unbroken chain rather than two records
claiming the same predecessor.

That lock bounds this **process**. Two processes are not hypothetical: a
Container Apps rolling deployment runs the old revision and the new one
together until the new one is healthy — measured at 46s and 37s on this
instance — and `maxReplicas: 1` does not prevent it, because it bounds a
revision rather than the app (WS10 SEC-H-01).

So the sink refuses a write whose predecessor has moved, and this module
rebuilds the record on the real head and tries again. Retrying is safe
precisely because the refused write did **not** land: sequence and hash
advance only after the sink accepts.
"""

from __future__ import annotations

import logging
import threading

from dsar.audit.record import Action, AuditRecord, Outcome, build, case_pseudonym
from dsar.audit.sink import AuditSink, StaleHead

__all__ = ["AuditTrail"]

log = logging.getLogger(__name__)


#: Attempts at rebuilding a record whose predecessor moved underneath it. The
#: contended window is a deployment, with at most one other writer, so the
#: second attempt succeeds unless that writer is also mid-append. Bounded
#: rather than unbounded: a trail that blocks forever is an outage, and losing
#: one record loudly beats hanging the request that produced it.
_REBUILD_ATTEMPTS = 5


class AuditTrail:
    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink
        self._lock = threading.Lock()
        self._seq, self._prev = sink.head()

    def write(
        self,
        action: Action,
        outcome: Outcome,
        *,
        actor_oid: str = "",
        actor_upn: str = "",
        tenant_id: str = "",
        target_id: str = "",
        subject_ref: str = "",
        uti: str = "",
        correlation_id: str = "",
        detail: str = "",
    ) -> AuditRecord:
        with self._lock:
            last_error: Exception | None = None
            for attempt in range(_REBUILD_ATTEMPTS):
                record = build(
                    seq=self._seq + 1,
                    action=action,
                    outcome=outcome,
                    actor_oid=actor_oid,
                    actor_upn=actor_upn,
                    tenant_id=tenant_id,
                    target_id=target_id,
                    subject_ref=subject_ref,
                    uti=uti,
                    correlation_id=correlation_id,
                    detail=detail,
                ).with_hash(self._prev)

                try:
                    # Sequence advances only after the sink accepts it. A
                    # record that failed to persist must not leave a gap that
                    # looks like a deleted one — a gap is the shape of
                    # tampering, and inventing one by accident wastes an
                    # investigation.
                    self._sink.append(record)
                except StaleHead as exc:
                    # Another writer moved the head. The record above is
                    # chained to a predecessor that is no longer last, and the
                    # sink refused it rather than writing it there — so re-read
                    # the real head and build it again. Nothing was written, so
                    # there is nothing to undo.
                    last_error = exc
                    self._seq, self._prev = self._sink.head()
                    log.info(
                        "audit head moved underneath this writer; rebuilding "
                        "on seq %d (attempt %d)",
                        self._seq,
                        attempt + 1,
                    )
                    continue

                self._seq, self._prev = record.seq, record.hash
                return record

            raise RuntimeError(
                f"could not place an audit record after {_REBUILD_ATTEMPTS} "
                f"attempts; the head kept moving: {last_error}"
            )

    def subject_ref(self, case_id: str, identifier: str) -> str:
        """The pseudonym for a subject within a case. Never their identifier."""
        return case_pseudonym(case_id, identifier)

    @property
    def head(self) -> tuple[int, str]:
        with self._lock:
            return self._seq, self._prev
