"""Where audit records go. Append only, and structurally so.

`AuditSink` exposes `append` and `head` and **no mutating method at all**.
There is no update, no delete, no truncate — not because they are guarded, but
because they do not exist. A structural test asserts the Protocol's surface, so
adding one is a visible diff rather than a quiet capability.

Four implementations, layered rather than alternatives:

  `JsonlFileSink`  the desktop trail. `O_APPEND`, mode 0600, one line per
                   record, `flush()` then `fsync()` so a record survives the
                   power going off rather than sitting in a buffer.
  `StderrSink`     always on, in addition. Container Apps ships stdout and
                   stderr to Log Analytics automatically, so this is a second
                   copy in a different trust domain for free — and it is the
                   only copy that exists before a durable sink is configured.
  `MemorySink`     tests, and a last resort when nothing else can be opened.
  `TeeSink`        fans out. `head()` comes from the primary alone, because a
                   chain with two heads is not a chain.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Iterator, Protocol

from dsar.audit.record import GENESIS_HASH, AuditRecord

__all__ = [
    "AuditSink",
    "JsonlFileSink",
    "StderrSink",
    "MemorySink",
    "TeeSink",
    "build_sink",
]

log = logging.getLogger(__name__)

audit_log = logging.getLogger("dsar.audit")


class AuditSink(Protocol):
    """Append and read the head. Deliberately nothing else."""

    def append(self, record: AuditRecord) -> None: ...

    def head(self) -> tuple[int, str]:
        """(last seq, last hash). `(0, GENESIS_HASH)` when empty."""
        ...


class MemorySink:
    """In-process. Keeps the chain, so verification is itself testable."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def append(self, record: AuditRecord) -> None:
        with self._lock:
            self.records.append(record)

    def head(self) -> tuple[int, str]:
        with self._lock:
            if not self.records:
                return 0, GENESIS_HASH
            last = self.records[-1]
            return last.seq, last.hash


class StderrSink:
    """A copy on the process's own error stream.

    Always attached, never the only sink by choice. Its value is that the
    platform collects it without being asked: on Container Apps this lands in
    Log Analytics, which is a different trust domain from the blob the durable
    sink writes to — so tampering with one does not tamper with both.
    """

    def append(self, record: AuditRecord) -> None:
        audit_log.info("%s", record.to_json())

    def head(self) -> tuple[int, str]:
        # A stream cannot be read back. It is never the primary, so this is
        # never the answer that matters.
        return 0, GENESIS_HASH


class JsonlFileSink:
    """One line per record, appended, fsynced, owner-readable only.

    `O_APPEND` is what makes concurrent writers safe: on POSIX, appends below
    `PIPE_BUF` are atomic, so two processes cannot interleave half a record.
    That matters because the desktop mode is one process today and need not
    stay that way.

    The file is opened per append rather than held. A held handle is a handle
    that survives a log rotation pointing at an unlinked inode, writing records
    nobody will ever read.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._lock = threading.Lock()

    def _path(self, record: AuditRecord) -> Path:
        # One file per UTC day. Bounded growth without a rotation policy that
        # could be misconfigured into deleting evidence.
        day = record.ts[:10] or "unknown"
        return self.directory / f"audit-{day}.jsonl"

    def append(self, record: AuditRecord) -> None:
        path = self._path(record)
        line = (record.to_json() + "\n").encode("utf-8")
        with self._lock:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line)
                # Durability is the point. A record that is only in a buffer is
                # not evidence of anything.
                os.fsync(fd)
            finally:
                os.close(fd)
            if os.name == "posix":
                # Re-asserted because a file created before an umask change, or
                # restored from a backup, may not carry the mode it was made
                # with.
                os.chmod(path, 0o600)

    def head(self) -> tuple[int, str]:
        """Resume the chain from the most recent day's last line."""
        files = sorted(self.directory.glob("audit-*.jsonl"))
        for path in reversed(files):
            last = _last_record(path)
            if last is not None:
                return last.seq, last.hash
        return 0, GENESIS_HASH

    def read_all(self) -> Iterator[AuditRecord]:
        """Every record, oldest first, across every day file."""
        for path in sorted(self.directory.glob("audit-*.jsonl")):
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        yield AuditRecord.from_json(line)


class TeeSink:
    """Write to several. `head()` is the primary's alone."""

    def __init__(self, primary: AuditSink, *others: AuditSink) -> None:
        self.primary = primary
        self.others = others

    def append(self, record: AuditRecord) -> None:
        self.primary.append(record)
        for sink in self.others:
            try:
                sink.append(record)
            except Exception:
                # A secondary copy failing must not lose the primary write.
                # The durable trail is the one that matters; the extra copies
                # are defence in depth, not the defence.
                log.warning("a secondary audit sink failed", exc_info=False)

    def head(self) -> tuple[int, str]:
        return self.primary.head()


def _last_record(path: Path) -> AuditRecord | None:
    last: AuditRecord | None = None
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    try:
                        last = AuditRecord.from_json(line)
                    except (ValueError, TypeError):
                        # A malformed tail is not a reason to refuse to write
                        # more. `verify` is what reports it; `head` only needs
                        # somewhere to chain from.
                        continue
    except OSError:
        return None
    return last


def build_sink(directory: Path | None) -> AuditSink:
    """The sink for this process: durable where possible, stderr always.

    A failure to open the durable sink degrades to stderr rather than to
    nothing, and says so loudly. Losing the trail silently is the one outcome
    worth ruling out — an audit trail that stopped without telling anyone is
    worse than one that was never claimed.
    """
    if directory is None:
        return StderrSink()
    try:
        from dsar.config import ensure_private_dir

        ensure_private_dir(directory)
        return TeeSink(JsonlFileSink(directory), StderrSink())
    except OSError as exc:
        log.error(
            "audit directory %s is unusable (%s) — records will go to stderr "
            "only and will not survive this process",
            directory,
            exc,
        )
        return StderrSink()
