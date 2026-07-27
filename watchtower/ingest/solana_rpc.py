"""Read-only Solana Memo-program ingestion over public RPC.

This module NEVER signs, sends, or simulates a transaction. It issues exactly
two read methods: getSignaturesForAddress and getTransaction.

Boundary rule: watchtower imports from wormhole/, never the reverse.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

import requests

PUBLIC_MAINNET = "https://api.mainnet-beta.solana.com"

# Memo program IDs. v1 and v2 match wormhole.scanners.memos.MEMO_PROGRAM_IDS.
# v4 (Pinocchio rewrite, ~26x cheaper compute) is NOT in the local package's
# set; the watchtower carries it because cheap memos are exactly the traffic a
# volume spammer would choose.
MEMO_V1 = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"
MEMO_V2 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
MEMO_V4 = "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH"

MEMO_PROGRAMS = (MEMO_V2, MEMO_V1, MEMO_V4)

# Public endpoint documented limits: 100 req/10s/IP overall, 40 req/10s/IP for
# a single method. 40/10s == 4 rps; we stay under it deliberately.
DEFAULT_RPS = 3.0


class RpcError(RuntimeError):
    pass


@dataclass
class RpcStats:
    """Every number the measurement report cites must come from here."""

    calls: int = 0
    errors: int = 0
    retries: int = 0
    rate_limited: int = 0
    by_method: dict = field(default_factory=dict)

    def note(self, method: str) -> None:
        self.calls += 1
        self.by_method[method] = self.by_method.get(method, 0) + 1


class SolanaRPC:
    """Minimal, polite, read-only JSON-RPC client.

    Structured so a Helius/QuickNode endpoint slots in by changing `url` and
    raising `rps`; no other code needs to change.
    """

    READ_ONLY_METHODS = {
        "getHealth",
        "getSignaturesForAddress",
        "getTransaction",
        "getSlot",
        "getBlockTime",
    }

    def __init__(
        self,
        url: str = PUBLIC_MAINNET,
        rps: float = DEFAULT_RPS,
        timeout: int = 45,
        max_retries: int = 5,
        stats: RpcStats | None = None,
    ) -> None:
        self.url = url
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self.timeout = timeout
        self.max_retries = max_retries
        self.stats = stats or RpcStats()
        self._session = requests.Session()
        self._last_call = 0.0
        self._id = 0

    def _throttle(self) -> None:
        gap = time.monotonic() - self._last_call
        if gap < self.min_interval:
            time.sleep(self.min_interval - gap)
        self._last_call = time.monotonic()

    def call(self, method: str, params: list):
        if method not in self.READ_ONLY_METHODS:
            # Hard guard: the watchtower is read-only by construction, not by
            # convention. sendTransaction can never be reached from here.
            raise RpcError(f"method not allowed (read-only service): {method}")

        backoff = 1.0
        last_exc = None
        for attempt in range(self.max_retries):
            self._throttle()
            self._id += 1
            try:
                resp = self._session.post(
                    self.url,
                    json={
                        "jsonrpc": "2.0",
                        "id": self._id,
                        "method": method,
                        "params": params,
                    },
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:  # network flake
                last_exc = exc
                self.stats.retries += 1
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            self.stats.note(method)

            if resp.status_code in (429, 503):
                self.stats.rate_limited += 1
                self.stats.retries += 1
                retry_after = resp.headers.get("retry-after")
                sleep_for = float(retry_after) if retry_after else backoff
                time.sleep(min(sleep_for, 60))
                backoff = min(backoff * 2, 30)
                continue

            if resp.status_code != 200:
                last_exc = RpcError(f"HTTP {resp.status_code}: {resp.text[:200]}")
                self.stats.retries += 1
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            body = resp.json()
            if "error" in body:
                err = body["error"]
                # -32602/-32004 style permanent errors: do not retry forever.
                if err.get("code") in (-32602, -32601):
                    self.stats.errors += 1
                    raise RpcError(f"{method}: {err}")
                last_exc = RpcError(f"{method}: {err}")
                self.stats.retries += 1
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            return body.get("result")

        self.stats.errors += 1
        raise RpcError(f"{method} failed after {self.max_retries} attempts: {last_exc}")

    def health(self) -> str:
        return self.call("getHealth", [])

    def signatures_for_address(
        self,
        address: str,
        limit: int = 1000,
        before: str | None = None,
        until: str | None = None,
    ) -> list:
        opts = {"limit": min(limit, 1000)}
        if before:
            opts["before"] = before
        if until:
            opts["until"] = until
        return self.call("getSignaturesForAddress", [address, opts]) or []

    def get_transaction(self, signature: str) -> dict | None:
        # encoding=jsonParsed is LOAD-BEARING. With any other encoding the memo
        # instruction arrives as undecoded base58 `data`, wormhole's
        # extract_memos returns nothing, and the base rate would silently be a
        # fabrication. Do not change this without also decoding `data` yourself.
        return self.call(
            "getTransaction",
            [
                signature,
                {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0},
            ],
        )


def iter_memo_signatures(
    rpc: SolanaRPC,
    program_id: str,
    target: int,
    only_with_memo_field: bool = True,
    max_pages: int = 200,
    progress: Callable[[str], None] | None = None,
) -> Iterator[dict]:
    """Walk a memo program's signature index backwards from the chain tip.

    getSignaturesForAddress returns a `memo` field that the RPC node populates
    for recognized memo programs. When `only_with_memo_field` is True we use it
    as a free stage-0 prefilter so the expensive getTransaction budget is spent
    only on transactions that actually carry a memo.

    Honest limitation, stated so the report can repeat it: public-node address
    indexes are pruned, so this is a SAMPLE of recent memo traffic near the
    chain tip, not a chain-wide census.
    """
    seen = 0
    before = None
    for page_no in range(max_pages):
        page = rpc.signatures_for_address(program_id, limit=1000, before=before)
        if not page:
            return
        before = page[-1]["signature"]
        for entry in page:
            if only_with_memo_field and not entry.get("memo"):
                continue
            yield entry
            seen += 1
            if seen >= target:
                return
        if progress:
            progress(f"    page {page_no + 1}: scanned {len(page)} sigs, kept {seen}/{target}")


def fetch_transactions(
    rpc: SolanaRPC,
    signatures: Iterable[dict],
    progress: Callable[[str], None] | None = None,
) -> Iterator[dict]:
    """Fetch full jsonParsed transactions, preserving provenance.

    extract_memos' 3-tuple drops slot/blockTime/programId, so we attach them to
    the tx dict here. A publishable "tx <sig> contains <rule>" claim needs the
    FULL signature; wormhole's scan_memos truncates it to 16 chars in
    Finding.path, so we never read the signature back out of a Finding.
    """
    for i, entry in enumerate(signatures, 1):
        sig = entry["signature"]
        try:
            tx = rpc.get_transaction(sig)
        except RpcError as exc:
            if progress:
                progress(f"    ! {sig[:16]}: {exc}")
            continue
        if not tx:
            continue
        # extract_memos reads a top-level `signature`; ensure it is the full one.
        tx["signature"] = sig
        tx["_watchtower"] = {
            "signature": sig,
            "slot": entry.get("slot") or tx.get("slot"),
            "blockTime": entry.get("blockTime") or tx.get("blockTime"),
            "err": entry.get("err"),
            "index_memo": entry.get("memo"),
        }
        yield tx
        if progress and i % 25 == 0:
            progress(f"    fetched {i} transactions")
