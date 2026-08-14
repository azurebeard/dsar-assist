"""The hosted audit sink: an Azure Append Blob.

Append-only as a *storage primitive*, not as a convention this code observes.
`PutBlock` with `comp=appendblock` can only add to the end of an append blob;
there is no offset and no overwrite. Combined with a time-based immutability
policy carrying `allowProtectedAppendWrites`, the guarantee survives someone
with the data-plane role deciding to tidy up.

Three REST calls, written out rather than taken from an SDK:

  PUT  ?comp=appendblock   add one record
  GET  <blob>              read the trail back, for `head()` and verification
  PUT  x-ms-blob-type: AppendBlob   create it once

`azure-storage-blob` brings `azure-core` and `azure-identity` — three packages
and their own HTTP stack — for those three calls. The dependency budget is
asserted by a structural test so that trade is argued rather than absorbed, and
this is the argument.

Authentication is the operator's *container* token, obtained from the same
managed identity that mints the client assertion. The storage account sets
`allowSharedKeyAccess: false`, so there is no account key and no SAS anywhere
in the design — the same reasoning as the client secret.

One of three modules permitted to import an HTTP client.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator

import httpx

from dsar.audit.record import GENESIS_HASH, AuditRecord

__all__ = ["AppendBlobSink", "BlobSinkError", "STORAGE_API_VERSION"]

log = logging.getLogger(__name__)

#: The version that introduced `allowProtectedAppendWrites` handling we rely
#: on. Pinned rather than floating: the service changes behaviour by version,
#: and a trail that silently starts behaving differently is the one thing this
#: module exists to prevent.
STORAGE_API_VERSION = "2021-12-02"

#: Azure caps an append blob at 50,000 blocks. One record per block, so a
#: single blob holds 50,000 records — which is why the blob is per UTC day
#: rather than one for all time. At that point a `BlockCountExceeded` would
#: arrive mid-append with no obvious cause.
_MAX_BLOCKS = 50_000

_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)


class BlobSinkError(RuntimeError):
    """The append-blob trail could not be written or read."""


class AppendBlobSink:
    """Append-only, remote, and holding the same shape as the file sink.

    Deliberately mirrors `JsonlFileSink`: one JSON record per line, one blob
    per UTC day, `head()` resuming the chain from the last line. The verifier
    is the same code either side, so a trail written hosted verifies on a
    laptop and a trail written on a laptop verifies in the cloud. A chain that
    only its own writer can check is not evidence.
    """

    def __init__(
        self,
        container_url: str,
        token: Callable[[], str],
        http: httpx.Client | None = None,
    ) -> None:
        #: e.g. https://stdsarproduks01.blob.core.windows.net/audit
        self.container_url = container_url.rstrip("/")
        self._token = token
        self._http = http
        # Serialises appends within the process. It does NOT make the chain
        # safe across replicas — see the note in `head()`.
        self._lock = threading.Lock()
        self._created: set[str] = set()

    # ------------------------------------------------------------ plumbing

    def _client(self) -> httpx.Client:
        return self._http or httpx.Client(timeout=_TIMEOUT)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token()}",
            "x-ms-version": STORAGE_API_VERSION,
        }

    def _blob_url(self, day: str) -> str:
        return f"{self.container_url}/audit-{day}.jsonl"

    @staticmethod
    def _day(record: AuditRecord) -> str:
        return record.ts[:10] or "unknown"

    # -------------------------------------------------------------- append

    def append(self, record: AuditRecord) -> None:
        day = self._day(record)
        url = self._blob_url(day)
        line = (record.to_json() + "\n").encode("utf-8")

        client = self._client()
        try:
            with self._lock:
                if day not in self._created:
                    self._ensure_blob(client, url)
                    self._created.add(day)
                response = client.put(
                    url,
                    params={"comp": "appendblock"},
                    headers={**self._headers(), "Content-Length": str(len(line))},
                    content=line,
                )
                if response.status_code == 409:
                    # BlockCountExceeded, or the immutability policy refusing a
                    # non-append write. Either way the record is not stored,
                    # and pretending otherwise would put a gap in the chain
                    # that verification reports as tampering.
                    raise BlobSinkError(
                        f"the append blob refused the record ({response.status_code}): "
                        f"{response.text[:300]}. An append blob holds "
                        f"{_MAX_BLOCKS} blocks and this sink writes one per record."
                    )
                if response.status_code not in (201, 202):
                    raise BlobSinkError(
                        f"appending to {url} returned {response.status_code}: "
                        f"{response.text[:300]}"
                    )
        except httpx.HTTPError as exc:
            raise BlobSinkError(f"the audit blob could not be reached: {exc}") from exc
        finally:
            if self._http is None:
                client.close()

    def _ensure_blob(self, client: httpx.Client, url: str) -> None:
        """Create the append blob if it does not exist. Never overwrite one.

        `If-None-Match: *` is the whole safety property here. Without it, a
        second replica starting on the same day would issue a `PutBlob` that
        replaces the existing blob with an empty one — destroying the day's
        trail and doing it silently, since the appends afterwards would all
        succeed.
        """
        response = client.put(
            url,
            headers={
                **self._headers(),
                "x-ms-blob-type": "AppendBlob",
                "Content-Length": "0",
                "If-None-Match": "*",
            },
        )
        # 409 / 412 mean it already exists, which is the expected case on every
        # start after the first.
        if response.status_code in (201, 409, 412):
            return
        raise BlobSinkError(
            f"could not create the append blob at {url} "
            f"({response.status_code}): {response.text[:300]}"
        )

    # ---------------------------------------------------------------- read

    def head(self) -> tuple[int, str]:
        """Resume the chain from the most recent record.

        ⚠️ This is read once at start and then trusted, exactly as the file
        sink does. That is safe for a single replica and **only** for a single
        replica: two processes appending to one blob would each believe they
        held the head and the chain would fork. The Container App is pinned to
        `minReplicas == maxReplicas == 1` for the session store's sake already,
        and this is the second reason. Both are stated in the Bicep.
        """
        last: AuditRecord | None = None
        for record in self.read_all():
            last = record
        if last is None:
            return 0, GENESIS_HASH
        return last.seq, last.hash

    def read_all(self) -> Iterator[AuditRecord]:
        """Every record, oldest first. Days are lexicographic, which is
        chronological for ISO dates — the one place that format choice pays."""
        client = self._client()
        try:
            for name in sorted(self._list_blobs(client)):
                url = f"{self.container_url}/{name}"
                response = client.get(url, headers=self._headers())
                if response.status_code == 404:
                    continue
                if response.status_code != 200:
                    raise BlobSinkError(
                        f"reading {url} returned {response.status_code}: "
                        f"{response.text[:300]}"
                    )
                for line in response.text.splitlines():
                    line = line.strip()
                    if line:
                        yield AuditRecord.from_json(line)
        except httpx.HTTPError as exc:
            raise BlobSinkError(f"the audit blob could not be read: {exc}") from exc
        finally:
            if self._http is None:
                client.close()

    def _list_blobs(self, client: httpx.Client) -> list[str]:
        """Blob names in the container, via the list API.

        Parsed with a string scan rather than an XML parser: the response is
        Azure's own, the elements are fixed, and `xml.etree` on a remote
        document is a parser this codebase would then have to reason about.
        The names are matched against the sink's own pattern, so anything
        unexpected in the container is ignored rather than interpreted.
        """
        response = client.get(
            self.container_url,
            params={"restype": "container", "comp": "list"},
            headers=self._headers(),
        )
        if response.status_code != 200:
            raise BlobSinkError(
                f"listing the audit container returned {response.status_code}: "
                f"{response.text[:300]}"
            )
        names: list[str] = []
        for chunk in response.text.split("<Name>")[1:]:
            name = chunk.split("</Name>", 1)[0]
            if name.startswith("audit-") and name.endswith(".jsonl"):
                names.append(name)
        return names
