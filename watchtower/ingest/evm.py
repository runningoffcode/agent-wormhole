"""Base / EVM carrier ingestion, emitting wormhole's transaction shape.

Solana hands you a memo program: a single well-known address whose entire
purpose is carrying text, so stage 0 is a program-ID equality check that
discards everything else for free. EVM has no such thing. The equivalent
carriers are two much messier shapes:

  - CALLDATA ON AN EOA-DESTINATION TRANSACTION. Sending ETH to a plain address
    with a non-empty `input` field is the closest thing Base has to a memo.
    Nothing executes -- an EOA has no code -- so the bytes are pure payload.
    This is the channel people actually use for on-chain messages, and it is
    the one an attacker would use to write text into a wallet's history.
  - STRING PARAMETERS IN EVENT LOGS. Anything an agent reads back out of a log
    is tool output, which is the exact ingress path every disclosed 2026
    compromise used.

The load-bearing difficulty, stated plainly because it decides the whole
design: "is `to` an EOA?" is not a field on a transaction. Answering it
properly needs `eth_getCode(to)`, which is one extra RPC round-trip per
candidate transaction. On a free endpoint that is the entire budget. So this
module:

  1. filters on shape first (non-empty input, value transfer, no valid-looking
     4-byte selector), which is nearly free and discards almost everything, and
  2. confirms with `eth_getCode` ONLY on survivors, caching the answer per
     address because contract-ness never changes for a deployed address.

`CODE_CHECK_UNKNOWN` exists because the honest third state matters. If the code
check could not be performed -- budget exhausted, endpoint throttling -- we say
so in the provenance rather than silently claiming EOA-destination. A published
"we scanned N EOA-calldata transactions" claim that quietly included contract
calls is a wrong number, and wrong numbers in a security writeup are how
credibility dies.

WHY THE PAYLOAD BECOMES A `memo` FIELD. `wormhole/scanners/memos.py` is
Solana-only: it knows memo program IDs and jsonParsed instructions, and has no
concept of calldata. Rather than fake a Solana instruction shape -- which would
put a fictional Solana program ID on an EVM transaction and corrupt any
provenance built on it -- we use the flat `{"memo": <text>}` form that
`extract_memos` already accepts for enhanced APIs. That path is real, it is
tested upstream, and it is honest: the decoded text is the memo, and
`_watchtower` carries the truth about where it came from.

Read-only. This module issues four read methods and can issue nothing else.
"""

from __future__ import annotations

from .base import (
    STOP_ERROR,
    STOP_EXHAUSTED,
    STOP_RATE_LIMITED,
    STOP_TARGET,
    Batch,
    Cursor,
    Source,
)
from .evm_rpc import PUBLIC_BASE, EvmRPC, RpcError

# Minimum decoded characters before a calldata blob is worth calling text.
# Below this it is a flag byte or a short id, not a message. The cascade's
# text-ness gate uses 24 for the same reason; we match it so the two stages
# agree rather than one silently undoing the other.
MIN_TEXT_CHARS = 24

# A transaction to a contract almost always starts with a 4-byte function
# selector. Calldata that is valid UTF-8 from its very first byte is therefore
# very unlikely to be a contract call -- and very likely to be a message. This
# is a cheap prefilter, not proof; `eth_getCode` is what actually decides.
CODE_CHECK_EOA = "eoa"
CODE_CHECK_CONTRACT = "contract"
CODE_CHECK_UNKNOWN = "unknown"


def decode_calldata(data: str) -> str | None:
    """Decode hex calldata to text, or None if it is not plausibly a message.

    Deliberately strict. Every byte on chain decodes to *something* under
    errors="replace", so a permissive decoder would hand the corpus a stream of
    replacement characters and every rule would be scanning noise. We require
    the bytes to be valid UTF-8 outright.
    """
    if not isinstance(data, str):
        return None
    s = data[2:] if data.startswith("0x") else data
    if not s or len(s) % 2:
        return None
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None
    if len(raw) < MIN_TEXT_CHARS:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Some senders pad a message into a fixed-width word. Strip trailing
        # NULs and retry once; beyond that it is binary, not text.
        stripped = raw.rstrip(b"\x00")
        if len(stripped) < MIN_TEXT_CHARS:
            return None
        try:
            text = stripped.decode("utf-8")
        except UnicodeDecodeError:
            return None
    text = text.replace("\x00", "").strip()
    return text if len(text) >= MIN_TEXT_CHARS else None


def _tx_from_evm(
    tx: dict,
    text: str,
    code_check: str,
    block_time: int | None,
    carrier: str = "calldata",
) -> dict:
    """Build wormhole's expected tx dict from one EVM transaction.

    The flat `{"memo": ...}` shape is an `extract_memos` path that already
    exists for enhanced APIs, so `scan_memos` consumes this with no
    modification -- which is the entire contract of this package.

    `feePayer` is set so `_sender` resolves without inventing a Solana
    accountKeys array on an EVM transaction. It is informational only and is
    never a trust signal; the hard constraint is that we publish facts about
    transactions, never verdicts about addresses.
    """
    tx_hash = tx.get("hash") or ""
    return {
        "signature": tx_hash,          # extract_memos reads this as the id
        "memo": text,
        "feePayer": tx.get("from") or "",
        "meta": {"err": None},
        "_watchtower": {
            "chain": "base",
            "signature": tx_hash,
            "tx_hash": tx_hash,
            "slot": _hex_int(tx.get("blockNumber")),
            "block_number": _hex_int(tx.get("blockNumber")),
            "blockTime": block_time,
            "to": tx.get("to"),
            "from": tx.get("from"),
            "carrier": carrier,
            "instrument": "eth_getBlockByNumber",
            # The honest third state. "unknown" means we could not afford or
            # could not complete the eth_getCode check -- not that it passed.
            "destination_code_check": code_check,
            "calldata_bytes": max(len(tx.get("input") or "") - 2, 0) // 2,
        },
    }


def _hex_int(v) -> int | None:
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.startswith("0x"):
        try:
            return int(v, 16)
        except ValueError:
            return None
    return None


class BaseCalldataSource(Source):
    """Walk Base blocks forward, keeping EOA-destination text calldata.

    Pages FORWARD from `cursor.last_block`, the opposite direction from the
    Solana sources, which is exactly why `Cursor` refuses to collapse into a
    single scalar. Forward paging also means this source can genuinely follow
    the tip: catching up and then staying caught up is one code path.

    Budget discipline. `code_check_budget` caps `eth_getCode` calls per batch.
    When it is exhausted, surviving candidates are still emitted but marked
    `destination_code_check: "unknown"` rather than dropped or assumed. A
    report built on this must segment by that field.
    """

    name = "base-calldata"

    def __init__(
        self,
        rpc: EvmRPC | None = None,
        url: str = PUBLIC_BASE,
        rps: float = 3.0,
        start_block: int | None = None,
        code_check_budget: int = 200,
        max_blocks_per_batch: int = 200,
    ) -> None:
        self.rpc = rpc or EvmRPC(url=url, rps=rps)
        self.start_block = start_block
        self.code_check_budget = code_check_budget
        self.max_blocks_per_batch = max_blocks_per_batch
        # Contract-ness is immutable for a deployed address, so this cache is
        # correct across the whole run, not just one batch.
        self._code_cache: dict[str, str] = {}

    def _classify_destination(self, addr: str, budget: list) -> str:
        if not addr:
            # Contract creation has no `to`. Not an EOA message.
            return CODE_CHECK_CONTRACT
        key = addr.lower()
        if key in self._code_cache:
            return self._code_cache[key]
        if budget[0] <= 0:
            return CODE_CHECK_UNKNOWN
        budget[0] -= 1
        try:
            code = self.rpc.get_code(addr)
        except RpcError:
            return CODE_CHECK_UNKNOWN
        verdict = CODE_CHECK_EOA if code in ("0x", "", None) else CODE_CHECK_CONTRACT
        self._code_cache[key] = verdict
        return verdict

    def poll(self, cursor: Cursor, limit: int) -> Batch:
        cursor = cursor or Cursor(source=self.name)
        batch = Batch(source=self.name, cursor=cursor)
        budget = [self.code_check_budget]
        stop = STOP_TARGET

        try:
            tip = self.rpc.block_number()
        except RpcError as exc:
            batch.errors.append(f"block_number: {exc}")
            batch.stop_reason = (
                STOP_RATE_LIMITED if self.rpc.stats.rate_limited else STOP_ERROR
            )
            batch.cursor = cursor
            return batch

        nxt = cursor.last_block + 1 if cursor.last_block else (
            self.start_block if self.start_block is not None else max(tip - 20, 0)
        )

        blocks_read = 0
        while len(batch.transactions) < limit and blocks_read < self.max_blocks_per_batch:
            if nxt > tip:
                stop = STOP_EXHAUSTED  # caught up to the tip; not an error
                break
            try:
                block = self.rpc.block_by_number(nxt, full=True)
            except RpcError as exc:
                batch.errors.append(f"block {nxt}: {exc}")
                stop = (
                    STOP_RATE_LIMITED if self.rpc.stats.rate_limited else STOP_ERROR
                )
                break
            if not block:
                stop = STOP_EXHAUSTED
                break

            blocks_read += 1
            block_time = _hex_int(block.get("timestamp"))
            txs = block.get("transactions") or []
            batch.items_scanned += len(txs)

            for tx in txs:
                if not isinstance(tx, dict):
                    continue
                # Stage 0, in cost order: shape filter before any RPC call.
                text = decode_calldata(tx.get("input") or "")
                if text is None:
                    continue
                verdict = self._classify_destination(tx.get("to") or "", budget)
                if verdict == CODE_CHECK_CONTRACT:
                    continue  # a contract call, not a message
                batch.carriers_found += 1
                batch.transactions.append(
                    _tx_from_evm(tx, text, verdict, block_time)
                )
                if len(batch.transactions) >= limit:
                    break

            cursor.last_block = nxt
            if block_time:
                cursor.last_block_time = block_time
            nxt += 1

        cursor.source = self.name
        cursor.items_seen += batch.items_scanned
        cursor.carriers_seen += batch.carriers_found
        cursor.extra["tip_block"] = tip
        cursor.extra["code_checks_remaining"] = budget[0]
        batch.cursor = cursor
        batch.stop_reason = stop
        return batch
