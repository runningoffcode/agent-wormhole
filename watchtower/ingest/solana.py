"""Solana Memo-program ingestion, emitting wormhole's transaction shape.

Two sources live here because the chain offers two instruments with genuinely
different trade-offs, and blending them produces a number that means nothing:

  SolanaIndexSource  -- getSignaturesForAddress only. The RPC node populates a
      `memo` field for recognized memo programs, so one paged call yields up to
      1000 signatures AND their memo text. ~1 call per 1000 signatures. This is
      the WIDE instrument: it produced the 40,000-signature base-rate sample.
      Its fidelity is lower -- the field is the node's own rendering, prefixed
      `[<len>] `, and multiple memos in one transaction are concatenated.

  SolanaRpcSource    -- getSignaturesForAddress as a stage-0 prefilter, then a
      full jsonParsed getTransaction per hit. ~1 call per transaction. This is
      the PRECISE instrument: real instruction text, per-instruction separation,
      inner instructions, and the program that actually emitted each memo.
      On a free public endpoint it is ~40x more expensive and throttles fast.

Report them separately, always. A wide denominator with narrow fidelity and a
narrow denominator with full fidelity are two different measurements.

The load-bearing encoding detail, restated because getting it wrong fabricates a
zero rather than erroring: with any encoding other than jsonParsed, a memo
instruction arrives as undecoded base58 `data`, and wormhole's `extract_memos`
deliberately does not decode it -- so the scan silently finds nothing. We force
jsonParsed, and `synthesize_parsed_memos` exists to repair the raw case if a
future endpoint returns one anyway.

Read-only. This module issues four read methods and can issue nothing else.
"""

from __future__ import annotations

import base64
import re
from .base import (
    STOP_ERROR,
    STOP_EXHAUSTED,
    STOP_RATE_LIMITED,
    STOP_TARGET,
    Batch,
    Cursor,
    Source,
)
from .solana_rpc import (
    MEMO_PROGRAMS,
    PUBLIC_MAINNET,
    RpcError,
    SolanaRPC,
)

# The node renders an indexed memo as "[<byte-len>] <text>". That framing is the
# node's, not the sender's, and scanning it would put node-generated digits into
# the corpus. Shared with wide_sample.unwrap, which pinned this behaviour first.
_INDEX_PREFIX = re.compile(r"^\[\d+\]\s?")


def unwrap_index_memo(raw: str) -> str:
    return _INDEX_PREFIX.sub("", raw, count=1)


def _b58_decode(text: str) -> bytes | None:
    """Minimal base58 decode. No dependency, and the alphabet is fixed.

    Returns None on any non-alphabet character rather than raising -- this is
    applied speculatively to attacker-supplied strings.
    """
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    index = {c: i for i, c in enumerate(alphabet)}
    num = 0
    for ch in text:
        if ch not in index:
            return None
        num = num * 58 + index[ch]
    out = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + out


def synthesize_parsed_memos(tx: dict) -> dict:
    """Repair a transaction whose memo instructions arrived undecoded.

    `wormhole.scanners.memos.extract_memos` reads `ix["parsed"]` and leaves raw
    base58/base64 `data` alone -- decoding attacker-supplied binary is not the
    offline package's job. That is correct for the free CLI and fatal for an
    ingester: an endpoint returning base64 encoding would yield zero memos and a
    base rate of 0.0% that is an artifact of the transport, not a fact about the
    chain.

    So the decode happens HERE, in the network-connected service, and the result
    is written into `parsed` so the unmodified scanner sees it. Mutates in place
    and returns the same dict.
    """
    message = (tx.get("transaction") or {}).get("message") or {}
    groups = [message.get("instructions") or []]
    for inner in (tx.get("meta") or {}).get("innerInstructions") or []:
        groups.append(inner.get("instructions") or [])

    for group in groups:
        for ix in group:
            if not isinstance(ix, dict):
                continue
            if ix.get("programId") not in MEMO_PROGRAMS and \
                    ix.get("program") != "spl-memo":
                continue
            if ix.get("parsed"):
                continue  # already decoded by the node
            data = ix.get("data")
            if not isinstance(data, str) or not data:
                continue
            raw = _b58_decode(data)
            if raw is None:
                try:
                    raw = base64.b64decode(data, validate=True)
                except (ValueError, TypeError):
                    continue
            text = raw.decode("utf-8", errors="replace").strip()
            if text:
                ix["parsed"] = text
    return tx


def _tx_from_index_entry(entry: dict, program_id: str) -> dict:
    """Build wormhole's expected tx dict from one signature-index entry.

    The flat {"memo": ...} form is one of the shapes `extract_memos` already
    accepts (it exists for enhanced APIs), so no adaptation is needed
    downstream. accountKeys carries the fee payer so `_sender` resolves --
    informational only, never a trust signal.

    Provenance that the 3-tuple `(text, sig, sender)` would otherwise drop --
    slot, blockTime, and which program emitted it -- is attached under
    `_watchtower`. `extract_memos` ignores unknown keys, and a publishable
    "tx <sig> matched <rule>" claim needs the FULL signature, which is not
    recoverable from Finding.path (scan_memos truncates it to 16 chars).
    """
    sig = entry.get("signature") or ""
    memo = unwrap_index_memo(entry.get("memo") or "")
    tx: dict = {
        "signature": sig,
        "memo": memo,
        "transaction": {"message": {"accountKeys": [], "instructions": []}},
        "meta": {"err": entry.get("err")},
        "_watchtower": {
            "chain": "solana",
            "signature": sig,
            "slot": entry.get("slot"),
            "blockTime": entry.get("blockTime"),
            "err": entry.get("err"),
            "program_id": program_id,
            "carrier": "memo",
            "instrument": "signature-index",
            "index_memo_raw": entry.get("memo"),
        },
    }
    return tx


class SolanaIndexSource(Source):
    """Wide sampler: signature index only, ~1 RPC call per 1000 signatures.

    Pages backwards from the chain tip, which is the only direction
    getSignaturesForAddress supports. `cursor.last_signature` is therefore the
    OLDEST signature reached, and resuming means continuing further back in
    history -- not catching up to new traffic. For tip-following, reset the
    cursor and use `until`.

    Honest limitation for any report built on this: public-node address indexes
    are pruned, so this walks recent memo traffic near the tip. It is a sample,
    never a census.
    """

    name = "solana-index"

    def __init__(
        self,
        rpc: SolanaRPC | None = None,
        programs=MEMO_PROGRAMS,
        url: str = PUBLIC_MAINNET,
        rps: float = 3.0,
        page_size: int = 1000,
    ) -> None:
        self.rpc = rpc or SolanaRPC(url=url, rps=rps)
        self.programs = tuple(programs)
        self.page_size = page_size

    def poll(self, cursor: Cursor, limit: int) -> Batch:
        cursor = cursor or Cursor(source=self.name)
        batch = Batch(source=self.name, cursor=cursor)
        # Per-program resume tokens: the programs are independent indexes and a
        # single scalar cursor cannot describe three of them.
        befores = dict(cursor.extra.get("before_by_program") or {})
        exhausted = set(cursor.extra.get("exhausted") or [])
        stop = STOP_TARGET

        for pid in self.programs:
            if pid in exhausted or len(batch.transactions) >= limit:
                continue
            while len(batch.transactions) < limit:
                try:
                    page = self.rpc.signatures_for_address(
                        pid, limit=self.page_size, before=befores.get(pid)
                    )
                except RpcError as exc:
                    # Partial data is still real data. Record why we stopped and
                    # keep everything already collected.
                    batch.errors.append(f"{pid[:8]}: {exc}")
                    stop = (
                        STOP_RATE_LIMITED
                        if self.rpc.stats.rate_limited
                        else STOP_ERROR
                    )
                    break
                if not page:
                    exhausted.add(pid)
                    break

                befores[pid] = page[-1]["signature"]
                batch.items_scanned += len(page)
                for entry in page:
                    if not entry.get("memo"):
                        continue  # stage 0: no carrier, discard
                    batch.carriers_found += 1
                    batch.transactions.append(_tx_from_index_entry(entry, pid))
                    if entry.get("slot"):
                        cursor.last_block = entry["slot"]
                    if entry.get("blockTime"):
                        cursor.last_block_time = entry["blockTime"]
                    if len(batch.transactions) >= limit:
                        break
            if stop in (STOP_RATE_LIMITED, STOP_ERROR):
                break

        if stop == STOP_TARGET and len(exhausted) == len(self.programs):
            stop = STOP_EXHAUSTED

        cursor.source = self.name
        cursor.extra["before_by_program"] = befores
        cursor.extra["exhausted"] = sorted(exhausted)
        cursor.last_signature = befores.get(self.programs[0]) or cursor.last_signature
        cursor.items_seen += batch.items_scanned
        cursor.carriers_seen += batch.carriers_found
        batch.cursor = cursor
        batch.stop_reason = stop
        return batch


class SolanaRpcSource(Source):
    """Precise sampler: index prefilter, then a full jsonParsed getTransaction.

    ~40x the RPC cost of the index source, which on a free endpoint is the
    difference between a 40,000-signature sample and a few hundred. Use it to
    adjudicate what the wide pass surfaced, or run it against a paid endpoint.

    `only_with_memo_field` uses the index's own memo field as a free stage-0
    filter so the expensive per-transaction budget is spent only on
    transactions that actually carry one. Set it False to measure how often the
    index field misses a memo the full transaction does contain -- that
    difference is itself a number worth publishing, and it is the honest way to
    bound the wide instrument's error.
    """

    name = "solana-rpc"

    def __init__(
        self,
        rpc: SolanaRPC | None = None,
        programs=MEMO_PROGRAMS,
        url: str = PUBLIC_MAINNET,
        rps: float = 3.0,
        only_with_memo_field: bool = True,
        page_size: int = 1000,
    ) -> None:
        self.rpc = rpc or SolanaRPC(url=url, rps=rps)
        self.programs = tuple(programs)
        self.only_with_memo_field = only_with_memo_field
        self.page_size = page_size

    def poll(self, cursor: Cursor, limit: int) -> Batch:
        cursor = cursor or Cursor(source=self.name)
        batch = Batch(source=self.name, cursor=cursor)
        befores = dict(cursor.extra.get("before_by_program") or {})
        exhausted = set(cursor.extra.get("exhausted") or [])
        stop = STOP_TARGET

        for pid in self.programs:
            if pid in exhausted or len(batch.transactions) >= limit:
                continue
            while len(batch.transactions) < limit:
                try:
                    page = self.rpc.signatures_for_address(
                        pid, limit=self.page_size, before=befores.get(pid)
                    )
                except RpcError as exc:
                    batch.errors.append(f"{pid[:8]}: {exc}")
                    stop = (
                        STOP_RATE_LIMITED
                        if self.rpc.stats.rate_limited
                        else STOP_ERROR
                    )
                    break
                if not page:
                    exhausted.add(pid)
                    break
                befores[pid] = page[-1]["signature"]
                batch.items_scanned += len(page)

                for entry in page:
                    if self.only_with_memo_field and not entry.get("memo"):
                        continue
                    sig = entry.get("signature")
                    if not sig:
                        continue
                    try:
                        tx = self.rpc.get_transaction(sig)
                    except RpcError as exc:
                        batch.errors.append(f"{sig[:16]}: {exc}")
                        if self.rpc.stats.rate_limited:
                            stop = STOP_RATE_LIMITED
                            break
                        continue
                    if not tx:
                        continue
                    # extract_memos reads a top-level `signature`; make sure it
                    # is the full one, not whatever the node nested.
                    tx["signature"] = sig
                    synthesize_parsed_memos(tx)
                    tx["_watchtower"] = {
                        "chain": "solana",
                        "signature": sig,
                        "slot": entry.get("slot") or tx.get("slot"),
                        "blockTime": entry.get("blockTime") or tx.get("blockTime"),
                        "err": entry.get("err"),
                        "program_id": pid,
                        "carrier": "memo",
                        "instrument": "jsonParsed-transaction",
                        "index_memo_raw": entry.get("memo"),
                    }
                    batch.carriers_found += 1
                    batch.transactions.append(tx)
                    if entry.get("slot"):
                        cursor.last_block = entry["slot"]
                    if entry.get("blockTime"):
                        cursor.last_block_time = entry["blockTime"]
                    if len(batch.transactions) >= limit:
                        break
                if stop == STOP_RATE_LIMITED:
                    break
            if stop in (STOP_RATE_LIMITED, STOP_ERROR):
                break

        if stop == STOP_TARGET and len(exhausted) == len(self.programs):
            stop = STOP_EXHAUSTED

        cursor.source = self.name
        cursor.extra["before_by_program"] = befores
        cursor.extra["exhausted"] = sorted(exhausted)
        cursor.last_signature = befores.get(self.programs[0]) or cursor.last_signature
        cursor.items_seen += batch.items_scanned
        cursor.carriers_seen += batch.carriers_found
        batch.cursor = cursor
        batch.stop_reason = stop
        return batch
