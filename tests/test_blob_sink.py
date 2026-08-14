"""The hosted audit sink.

Append-only is a storage primitive here, not a convention — `comp=appendblock`
has no offset and cannot overwrite. What these tests cover is the part we
wrote: that it appends rather than replaces, that it never destroys an existing
day's trail, that it produces the same chain the file sink does, and that a
refused write is an error rather than a silent gap.

The Azure REST contract is documented, so a `MockTransport` following it is the
honest offline test. What it cannot prove is that a real storage account with
an immutability policy behaves as documented — that belongs in the deployment
verification, alongside the FIC exchange.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from dsar.audit.blob import STORAGE_API_VERSION, AppendBlobSink, BlobSinkError
from dsar.audit.record import GENESIS_HASH, AuditRecord
from dsar.audit.sink import MemorySink

CONTAINER = "https://stdsarproduks01.blob.core.windows.net/audit"


class FakeBlobStore:
    """Enough of the append-blob API to hold the contract to account."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        name = request.url.path.rsplit("/", 1)[-1]
        params = request.url.params

        if params.get("comp") == "list":
            entries = "".join(f"<Blob><Name>{n}</Name></Blob>" for n in self.blobs)
            return httpx.Response(200, text=f"<EnumerationResults>{entries}</EnumerationResults>")

        if request.method == "PUT" and params.get("comp") == "appendblock":
            if name not in self.blobs:
                return httpx.Response(404, text="BlobNotFound")
            self.blobs[name] += request.content
            return httpx.Response(201)

        if request.method == "PUT":
            if request.headers.get("x-ms-blob-type") != "AppendBlob":
                return httpx.Response(400, text="not an append blob")
            # The service honours If-None-Match: * by refusing when it exists.
            if name in self.blobs and request.headers.get("If-None-Match") == "*":
                return httpx.Response(409, text="BlobAlreadyExists")
            self.blobs[name] = b""
            return httpx.Response(201)

        if request.method == "GET":
            if name not in self.blobs:
                return httpx.Response(404, text="BlobNotFound")
            return httpx.Response(200, text=self.blobs[name].decode("utf-8"))

        return httpx.Response(405)


@pytest.fixture
def store() -> FakeBlobStore:
    return FakeBlobStore()


@pytest.fixture
def sink(store: FakeBlobStore) -> AppendBlobSink:
    return AppendBlobSink(
        CONTAINER,
        token=lambda: "storage-token",
        http=httpx.Client(transport=httpx.MockTransport(store.handler)),
    )


def _record(seq: int, action: str = "case.create") -> AuditRecord:
    return AuditRecord(
        seq=seq,
        ts=f"2026-08-14T10:0{seq}:00.000+00:00",
        action=action,
        outcome="ok",
        actor_oid="oid-1",
        tenant_id="tid-1",
    )


def _chain(sink: Any, count: int) -> list[AuditRecord]:
    seq, prev = sink.head()
    out = []
    for i in range(count):
        seq += 1
        record = _record(seq).with_hash(prev)
        sink.append(record)
        prev = record.hash
        out.append(record)
    return out


# ------------------------------------------------------------------ writing


def test_it_appends_rather_than_replacing(sink: AppendBlobSink, store: FakeBlobStore) -> None:
    _chain(sink, 3)
    body = store.blobs["audit-2026-08-14.jsonl"].decode()
    assert body.count("\n") == 3
    appends = [r for r in store.requests if r.url.params.get("comp") == "appendblock"]
    assert len(appends) == 3


def test_it_never_replaces_an_existing_day(sink: AppendBlobSink, store: FakeBlobStore) -> None:
    """`If-None-Match: *` is the whole safety property.

    Without it a second start on the same day issues a PutBlob that replaces
    the blob with an empty one — destroying the day's trail, and silently,
    because every append afterwards succeeds.
    """
    _chain(sink, 2)
    before = store.blobs["audit-2026-08-14.jsonl"]

    fresh = AppendBlobSink(
        CONTAINER,
        token=lambda: "storage-token",
        http=httpx.Client(transport=httpx.MockTransport(store.handler)),
    )
    _chain(fresh, 1)

    assert store.blobs["audit-2026-08-14.jsonl"].startswith(before)
    creates = [
        r for r in store.requests
        if r.method == "PUT" and r.headers.get("x-ms-blob-type") == "AppendBlob"
    ]
    assert all(r.headers.get("If-None-Match") == "*" for r in creates)


def test_it_sends_a_bearer_token_and_never_a_shared_key(
    sink: AppendBlobSink, store: FakeBlobStore
) -> None:
    """The storage account sets `allowSharedKeyAccess: false`, so there is no
    account key and no SAS anywhere — the same reasoning as the client
    secret."""
    _chain(sink, 1)
    for request in store.requests:
        assert request.headers["Authorization"] == "Bearer storage-token"
        assert request.headers["x-ms-version"] == STORAGE_API_VERSION
        assert "sig=" not in str(request.url), "a SAS signature reached the wire"


def test_a_refused_append_is_an_error_not_a_silent_gap(store: FakeBlobStore) -> None:
    """A dropped record is worse than a failed write: verification reports the
    gap as tampering, and the trail's whole value is that it does."""

    def refuse(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("comp") == "appendblock":
            return httpx.Response(409, text="BlockCountExceeded")
        return store.handler(request)

    sink = AppendBlobSink(
        CONTAINER,
        token=lambda: "t",
        http=httpx.Client(transport=httpx.MockTransport(refuse)),
    )
    with pytest.raises(BlobSinkError, match="refused the record"):
        sink.append(_record(1).with_hash(GENESIS_HASH))


def test_an_unreachable_account_is_not_a_traceback(store: FakeBlobStore) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    sink = AppendBlobSink(
        CONTAINER, token=lambda: "t",
        http=httpx.Client(transport=httpx.MockTransport(boom)),
    )
    with pytest.raises(BlobSinkError, match="could not be reached"):
        sink.append(_record(1).with_hash(GENESIS_HASH))


# ------------------------------------------------------------------ reading


def test_head_resumes_the_chain(sink: AppendBlobSink) -> None:
    assert sink.head() == (0, GENESIS_HASH)
    written = _chain(sink, 4)
    fresh_seq, fresh_hash = sink.head()
    assert (fresh_seq, fresh_hash) == (written[-1].seq, written[-1].hash)


def test_the_chain_it_writes_verifies_with_the_same_verifier(
    sink: AppendBlobSink,
) -> None:
    """The verifier is the same code either side, so a trail written hosted
    verifies on a laptop and vice versa. A chain only its own writer can check
    is not evidence."""
    from dsar.audit.verify import verify_chain

    _chain(sink, 5)
    result = verify_chain(sink.read_all())
    assert result.intact, result.summary()
    assert result.records == 5


def test_a_tampered_remote_record_is_still_caught(
    sink: AppendBlobSink, store: FakeBlobStore
) -> None:
    from dsar.audit.verify import verify_chain

    _chain(sink, 3)
    name = "audit-2026-08-14.jsonl"
    lines = store.blobs[name].decode().splitlines()
    lines[1] = lines[1].replace('"case.create"', '"case.delete"')
    store.blobs[name] = ("\n".join(lines) + "\n").encode()

    result = verify_chain(sink.read_all())
    assert not result.intact
    # Names the record, not merely "something is wrong".
    assert result.breaks[0].seq == 2, result.summary()


def test_it_ignores_files_it_did_not_write(
    sink: AppendBlobSink, store: FakeBlobStore
) -> None:
    """Anything else in the container is ignored rather than interpreted."""
    _chain(sink, 1)
    store.blobs["not-ours.txt"] = b"garbage\n"
    store.blobs["audit-notes.md"] = b"# notes\n"
    assert len(list(sink.read_all())) == 1


def test_it_holds_the_same_shape_as_the_file_sink(sink: AppendBlobSink) -> None:
    """Both sinks satisfy the same Protocol and produce identical chains, which
    is what makes the mode switch a deployment detail rather than a fork."""
    memory = MemorySink()
    for target in (sink, memory):
        _chain(target, 3)
    assert [r.hash for r in sink.read_all()] == [r.hash for r in memory.records]


def test_the_listing_follows_the_continuation_marker() -> None:
    """WS10 SEC-L-05. Azure returns at most 5,000 blobs per page.

    Unreachable at one blob per UTC day — 13.7 years, past the retention — but
    fixed anyway, because this module's argument is that hand-written REST is
    safe *because the contract is written down*, and that only holds where the
    contract is honoured. `read_all` feeds both `head()` and `dsar audit
    verify`, so a truncated listing yields a chain that appears to start
    mid-stream: evidence with a beginning nobody can account for.
    """
    pages = {
        None: (
            "<EnumerationResults><Blob><Name>audit-2026-08-01.jsonl</Name></Blob>"
            "<NextMarker>page2</NextMarker></EnumerationResults>"
        ),
        "page2": (
            "<EnumerationResults><Blob><Name>audit-2026-08-02.jsonl</Name></Blob>"
            "<NextMarker></NextMarker></EnumerationResults>"
        ),
    }
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("comp") == "list":
            marker = request.url.params.get("marker") or None
            seen.append(marker)
            return httpx.Response(200, text=pages[marker])
        name = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, text="")

    sink = AppendBlobSink(
        CONTAINER, token=lambda: "t",
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert list(sink.read_all()) == []
    assert seen == [None, "page2"], "the continuation marker was not followed"


def test_a_listing_that_never_terminates_refuses_rather_than_truncating() -> None:
    """A short trail is indistinguishable from a deleted one, so a runaway
    listing raises instead of returning what it has."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("comp") == "list":
            return httpx.Response(
                200,
                text="<EnumerationResults><NextMarker>always</NextMarker></EnumerationResults>",
            )
        return httpx.Response(200, text="")

    sink = AppendBlobSink(
        CONTAINER, token=lambda: "t",
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(BlobSinkError, match="did not terminate"):
        list(sink.read_all())
