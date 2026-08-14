"""The writer. Owns the sequence number and the chain, so callers cannot.

A caller says *what happened*; it does not get to choose the record's position
or its hash. Both come from here, under one lock, so two threads writing at
once produce two records in a single unbroken chain rather than two records
claiming the same predecessor.
"""

from __future__ import annotations

import logging
import threading

from dsar.audit.record import Action, AuditRecord, Outcome, build, case_pseudonym
from dsar.audit.sink import AuditSink

__all__ = ["AuditTrail"]

log = logging.getLogger(__name__)


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

            # Sequence advances only after the sink accepts it. A record that
            # failed to persist must not leave a gap that looks like a deleted
            # one — a gap is the shape of tampering, and inventing one by
            # accident wastes an investigation.
            self._sink.append(record)
            self._seq, self._prev = record.seq, record.hash
            return record

    def subject_ref(self, case_id: str, identifier: str) -> str:
        """The pseudonym for a subject within a case. Never their identifier."""
        return case_pseudonym(case_id, identifier)

    @property
    def head(self) -> tuple[int, str]:
        with self._lock:
            return self._seq, self._prev
