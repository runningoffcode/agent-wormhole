"""The ingestion seam: one interface, many chains and many transports.

Why this file exists at all. The base-rate pass proved the measurement works
against a free public RPC, but a public endpoint is a sampling instrument, not a
monitor -- it is throttled, its address indexes are pruned, and it cannot tell
you about a memo that landed thirty seconds ago. The eventual answer is a paid
stream (Helius webhooks, Yellowstone gRPC, a Base log subscription). The failure
mode we are designing against is that swapping the transport turns into a
rewrite of the scanning pipeline, and the numbers stop being comparable across
the change.

So the transport is isolated behind `Source`. A source's only job is to produce
transaction dicts in the shape `wormhole/scanners/memos.py` already parses, plus
a cursor describing where it stopped. Everything downstream -- the cascade, the
corpus, the report -- consumes that shape and never learns which endpoint it
came from. A Yellowstone source is then a new class in this package and zero
changes anywhere else.

Three properties are deliberate:

  - READ-ONLY, enforced by construction. Sources may only issue read methods;
    the guard lives in the RPC client, not in a code review convention.
  - RESUMABLE. Chain ingestion is interrupted constantly (429s, restarts,
    endpoints going away mid-page). A cursor is persisted after every batch, so
    a restart resumes rather than re-scanning -- which matters for correctness,
    not just cost: re-scanning silently inflates the "we scanned N" denominator.
  - DEGRADING, not failing. When an endpoint throttles, a monitor that crashes
    is worse than one that falls behind. Sources report partial batches and the
    reason they stopped, and the caller decides.

Boundary rule: watchtower imports from wormhole/, never the reverse.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator


class RpcError(RuntimeError):
    """Any read-RPC failure, on any chain.

    Defined here rather than per-client on purpose. The chain-specific clients
    subclass this so that a caller which wants to handle "the endpoint failed"
    -- a retry wrapper, an alerting layer, a future source that queries both
    chains -- can write one `except RpcError` and actually catch both. Two
    unrelated exception classes with the same name is the kind of thing that
    silently swallows half your failures the first time someone adds a shared
    layer above them.
    """


# --------------------------------------------------------------- cursors ---


@dataclass
class Cursor:
    """Where a source stopped, in that source's own coordinate system.

    Deliberately not a single integer. Solana pages a signature index backwards
    from the tip and resumes with an opaque signature; Base pages block numbers
    forwards. Forcing both into one scalar would mean one of them lies. Instead
    the shared fields are the ones every source can honestly fill, and `extra`
    carries whatever else that source needs to resume exactly.

    `last_signature` is a resume token, NOT a claim that everything before it was
    scanned -- a pruned public index can drop history underneath us. Anything
    published from this data must describe itself as a sample.
    """

    source: str = ""
    # Solana: the oldest signature seen (paging runs tip -> older, so this is
    # what `before` gets on resume). Base: unused.
    last_signature: str | None = None
    # Base: the last block fully ingested. Solana: last slot seen, informational.
    last_block: int | None = None
    last_block_time: int | None = None
    # Cumulative across resumes. The denominator for any published rate.
    items_seen: int = 0
    carriers_seen: int = 0
    updated_utc: float = 0.0
    extra: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "Cursor":
        data = json.loads(raw)
        known = {f for f in cls.__dataclass_fields__}
        # Unknown keys are dropped rather than raising: a cursor written by a
        # newer build must not brick an older one mid-incident.
        return cls(**{k: v for k, v in data.items() if k in known})


class CursorStore:
    """Crash-safe cursor persistence on the local filesystem.

    Atomic replace, because the alternative is a truncated cursor file after a
    kill -9 and a monitor that resumes from the beginning of time. A corrupt or
    missing file yields a fresh cursor rather than an exception -- losing your
    place is recoverable, refusing to start is not.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self, source: str = "") -> Cursor:
        try:
            cur = Cursor.from_json(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return Cursor(source=source)
        if source and cur.source and cur.source != source:
            # A cursor from a different source is meaningless here; a Base block
            # number used as a Solana resume token would silently produce
            # garbage. Start clean instead.
            return Cursor(source=source)
        return cur

    def save(self, cursor: Cursor) -> None:
        cursor.updated_utc = time.time()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(cursor.to_json())
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


# ---------------------------------------------------------------- batches ---


# Why a batch stopped. The caller needs this to decide between "keep polling",
# "back off", and "page an operator" -- collapsing them into an exception loses
# the distinction, and a monitor that treats throttling as a crash is useless.
STOP_TARGET = "target-reached"      # got what was asked for
STOP_EXHAUSTED = "source-exhausted"  # index/blocks ran out; caught up
STOP_RATE_LIMITED = "rate-limited"   # endpoint pushed back; retry later
STOP_ERROR = "error"                 # something else; partial data is still valid


@dataclass
class Batch:
    """Transactions in wormhole's expected shape, plus how we got them.

    `transactions` is directly consumable by
    `wormhole.scanners.memos.scan_memos` with no adaptation. That is the whole
    contract of this package.

    Partial batches are normal and are NOT errors. When an endpoint 429s
    halfway, the transactions already fetched are real and the cursor is valid;
    throwing them away would mean a throttled monitor makes no progress at all.
    """

    source: str = ""
    transactions: list = field(default_factory=list)
    cursor: Cursor = field(default_factory=Cursor)
    stop_reason: str = STOP_TARGET
    # Stage-0 accounting. `items_scanned` is the denominator (signatures or
    # transactions looked at); `carriers_found` is how many carried a payload
    # field at all. Both are measured here rather than inferred downstream.
    items_scanned: int = 0
    carriers_found: int = 0
    errors: list = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        return self.stop_reason in (STOP_RATE_LIMITED, STOP_ERROR)

    def __len__(self) -> int:
        return len(self.transactions)


class Source:
    """A pluggable origin of carrier-bearing transactions.

    Subclasses implement `poll`. The public RPC pollers are here today; a
    Helius webhook drain or a Yellowstone gRPC subscription implements the same
    two methods and slots in with no downstream change. That is the entire
    reason this class exists -- it is not abstraction for its own sake, it is
    the guarantee that the paid-transport migration is not a rewrite.
    """

    name = "source"

    def poll(self, cursor: Cursor, limit: int) -> Batch:
        """Fetch up to `limit` carrier-bearing transactions after `cursor`."""
        raise NotImplementedError

    def stream(
        self,
        store: CursorStore,
        limit: int,
        max_batches: int = 1,
        on_batch=None,
    ) -> Iterator[Batch]:
        """Poll repeatedly, persisting the cursor after every batch.

        The cursor is saved BEFORE the batch is yielded. If the consumer crashes
        while scanning, the restart resumes after this batch rather than
        replaying it. That direction is chosen on purpose: for a base-rate
        measurement, double-counting corrupts the denominator, whereas a small
        gap is honest sampling. A pipeline that must not miss anything (canary
        monitoring) should commit the cursor itself after processing instead.
        """
        cursor = store.load(self.name)
        for _ in range(max_batches):
            batch = self.poll(cursor, limit)
            cursor = batch.cursor
            store.save(cursor)
            if on_batch:
                on_batch(batch)
            yield batch
            if batch.stop_reason in (STOP_EXHAUSTED, STOP_RATE_LIMITED, STOP_ERROR):
                break
            if not batch.transactions and batch.stop_reason != STOP_TARGET:
                break


# ----------------------------------------------------------- rate limiting ---


class RateLimiter:
    """Token bucket with adaptive backoff on push-back.

    A fixed sleep is the wrong instrument for a shared public endpoint: it is
    too slow when the endpoint is healthy and too fast when it is not. This
    halves the rate on a 429 and recovers slowly, so a throttled run degrades to
    a slower run instead of a failed one.

    Not thread-safe by design. Sources are single-threaded on purpose --
    parallel requests against a free endpoint just get you throttled harder.
    """

    def __init__(self, rps: float = 3.0, floor_rps: float = 0.25) -> None:
        self.base_rps = max(rps, 0.0)
        self.rps = self.base_rps
        self.floor_rps = floor_rps
        self._last = 0.0
        self.throttle_events = 0
        self.sleep_total = 0.0

    @property
    def min_interval(self) -> float:
        return 1.0 / self.rps if self.rps > 0 else 0.0

    def wait(self) -> None:
        gap = time.monotonic() - self._last
        need = self.min_interval - gap
        if need > 0:
            time.sleep(need)
            self.sleep_total += need
        self._last = time.monotonic()

    def penalize(self) -> None:
        """Endpoint pushed back: halve the rate, down to a floor."""
        self.throttle_events += 1
        self.rps = max(self.rps / 2.0, self.floor_rps)

    def recover(self, step: float = 1.15) -> None:
        """A clean call: creep back toward the configured rate, never past it."""
        if self.rps < self.base_rps:
            self.rps = min(self.rps * step, self.base_rps)
