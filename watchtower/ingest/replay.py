"""Replay a saved transaction dump through the same Source interface.

Three reasons this is not just a testing convenience.

  1. It makes the ingestion pipeline testable with zero network. Every other
     source needs an endpoint that throttles, prunes its indexes, and returns
     different data every run -- which is the opposite of what a regression
     test needs. Sources are interchangeable by construction, so a test that
     drives ReplaySource proves the seam works for all of them.
  2. It makes a measurement reproducible. A published "we scanned N and found
     X" claim is only checkable if someone else can re-run it over the same
     bytes. Saving the raw batch and replaying it is how that number stays
     falsifiable after the chain has moved on.
  3. It is the degradation path. When an endpoint is down or the budget is
     spent, an operator can still run the corpus over yesterday's capture
     instead of getting nothing.

Reuses `wormhole.scanners.memos.load_transactions` for parsing rather than
reimplementing it, so the file shapes accepted here are exactly the shapes the
offline CLI accepts -- JSON list, single object, JSONL, and the common
`result`/`transactions`/`data`/`items` envelopes.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from .base import STOP_EXHAUSTED, STOP_TARGET, Batch, Cursor, Source

# The one permitted direction of dependency: watchtower -> wormhole.
from wormhole.scanners.memos import extract_memos, load_transactions  # noqa: E402


class ReplaySource(Source):
    """Serve transactions from a local dump, paging with an offset cursor.

    `carriers_found` counts transactions that actually yield a memo, measured
    with the same `extract_memos` the scanner uses. Counting differently here
    would let the report's denominator drift from what was really scanned.
    """

    name = "replay"

    def __init__(self, path: str | Path, only_carriers: bool = False) -> None:
        self.path = str(path)
        self.only_carriers = only_carriers
        self._txs: list | None = None

    def _load(self) -> list:
        if self._txs is None:
            self._txs = load_transactions(self.path)
        return self._txs

    def poll(self, cursor: Cursor, limit: int) -> Batch:
        cursor = cursor or Cursor(source=self.name)
        batch = Batch(source=self.name, cursor=cursor)
        txs = self._load()

        offset = int(cursor.extra.get("offset") or 0)
        i = offset
        while i < len(txs) and len(batch.transactions) < limit:
            tx = txs[i]
            i += 1
            batch.items_scanned += 1
            if not isinstance(tx, dict):
                continue
            has_memo = bool(extract_memos(tx))
            if has_memo:
                batch.carriers_found += 1
            elif self.only_carriers:
                continue
            batch.transactions.append(tx)

        cursor.source = self.name
        cursor.extra["offset"] = i
        cursor.extra["total_in_file"] = len(txs)
        cursor.items_seen += batch.items_scanned
        cursor.carriers_seen += batch.carriers_found
        batch.cursor = cursor
        batch.stop_reason = STOP_EXHAUSTED if i >= len(txs) else STOP_TARGET
        return batch
