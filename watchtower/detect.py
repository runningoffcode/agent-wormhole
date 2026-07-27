#!/usr/bin/env python3
"""Stages 0-2 of the detection cascade, as one instrumented, reusable unit.

WHY THIS EXISTS SEPARATELY FROM cascade.py
------------------------------------------
`cascade.py` holds the stage-1 gate and the stage-2 normalizer as pure
functions. It has no stage 0 and no clock. The two measurement scripts each
grew their own private copy of "extract, gate, normalize, scan, build a record
dict", which meant:

  * stage 0 existed only as a side effect of calling wormhole's
    `extract_memos`, so carriers that function deliberately skips (see
    RAW-DATA GAP below) were invisible and nobody could tell;
  * the cost model was a guess. The cascade is justified by being
    cheapest-first, but nothing measured whether stage 1 actually discards
    what it claims to, or what stage 2's recursive decode really costs.

This module is the single instrumented path. It reuses cascade.py for stages
1-2 rather than reimplementing them, and it reuses `wormhole.rules.injection.
scan_text` for detection. It adds only what was missing: carrier extraction,
timing, and an evidence record with an integrity guarantee.

RAW-DATA GAP (stage 0's actual job)
-----------------------------------
`wormhole.scanners.memos.extract_memos` reads only *parsed* memo instructions.
A memo fetched with any encoding other than `jsonParsed` arrives as an
undecoded base58 `data` field and extracts as nothing -- silently. During the
base-rate work that was handled by forcing `encoding=jsonParsed` on every RPC
call, which is correct for RPC but does not cover archives, Dune exports, or a
future streaming provider that hands over raw instruction bytes.

Stage 0 here decodes base58/base64 `data` on a memo-program instruction and
synthesizes the text itself, so a carrier is extracted regardless of source
encoding. It reports `decoded_raw_data` per carrier so a run can prove which
path found what. This is NOT a reimplementation of memo parsing: parsed
instructions still go through `extract_memos`. Stage 0 only covers the shapes
that function documents itself as leaving alone.

EVIDENCE INTEGRITY
------------------
The original carrier bytes are stored once, hashed, and never written again.
Normalization is destructive by design -- NFKC rewrites characters, the
invisible-strip deletes the very bytes WORM-005/006 detect, and the confusable
fold rewrites letters. If evidence were taken from a normalized variant, a
published "tx <sig> contains <string>" fact would not match what is actually on
chain, and the whole verifiability claim collapses.

So `Carrier.raw_text` is the only thing quoted as evidence, `raw_sha256`
pins it, and `assert_evidence_intact()` re-derives the hash after scanning.
Findings carry the variant label that produced them, so a reader can reproduce
the transform. Nothing here mutates a Finding (`scan_memos` does; we call
`scan_text` directly to avoid it).

NOT DONE HERE
-------------
Stage 3 adjudication is a human queue, not code in this module. Behavioral
signals (fan-out, sweeps, approves, temporal correlation) need no payload text
and are a different pipeline entirely. EVM calldata carriers are stubbed with
an explicit NotImplementedError rather than a half-working path, because a
carrier extractor that silently finds nothing produces a fabricated denominator
-- the exact failure this module was written to make impossible.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WATCHTOWER = Path(__file__).resolve().parent
for _p in (str(REPO_ROOT), str(WATCHTOWER)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# The ONE permitted direction of dependency: watchtower -> wormhole.
from wormhole.rules.injection import scan_text  # noqa: E402
from wormhole.scanners.memos import (  # noqa: E402
    ACTIONABLE,
    MEMO_PROGRAM_IDS,
    extract_memos,
)

from cascade import Normalized, normalize, textness_gate  # noqa: E402

# Memo program v4 (Pinocchio rewrite, ~26x cheaper compute) is not in the local
# package's MEMO_PROGRAM_IDS. Being far cheaper it is the rational choice for
# anyone emitting memos at volume, so stage 0 must know about it. We extend a
# local copy; we never mutate the imported set.
MEMO_V4 = "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH"
CARRIER_PROGRAM_IDS = frozenset(MEMO_PROGRAM_IDS) | {MEMO_V4}

# Solana memo payload cap for single-byte UTF-8 in an unsigned instruction.
# Used only as a sanity bound on decoded raw data, never to reject a carrier.
MEMO_MAX_BYTES = 566

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def b58decode(s: str) -> bytes | None:
    """Minimal base58 decode. Returns None on any invalid input.

    Implemented here rather than pulled in as a dependency: it is twenty lines,
    and the watchtower's dependency list is worth keeping short even though it
    is allowed to have one.
    """
    if not s:
        return None
    num = 0
    for ch in s:
        idx = _B58_INDEX.get(ch)
        if idx is None:
            return None
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


# =========================================================== stage 0 ========

@dataclass
class Carrier:
    """One extracted carrier plus its provenance. `raw_text` is the evidence."""

    raw_text: str
    signature: str = ""
    sender: str = ""
    slot: int | None = None
    block_time: int | None = None
    program_id: str = ""
    source: str = "parsed"       # parsed | raw-data | flat
    tx_err: bool = False
    decoded_raw_data: bool = False
    raw_sha256: str = ""
    raw_bytes: int = 0

    def __post_init__(self) -> None:
        if not self.raw_sha256:
            encoded = self.raw_text.encode("utf-8", errors="replace")
            self.raw_sha256 = hashlib.sha256(encoded).hexdigest()
            self.raw_bytes = len(encoded)


def _decode_instruction_data(data) -> str | None:
    """Decode a raw memo instruction's `data` field to text, or None.

    Solana RPC returns instruction data as base58 by default and as
    `[payload, "base64"]` under some encodings. Both are handled. A decode that
    is not valid UTF-8 is not a memo carrier and is dropped -- memos are UTF-8
    by specification, so this is a definition, not a heuristic.
    """
    if isinstance(data, (list, tuple)):
        # jsonParsed/base64 form: [payload, encoding]
        if len(data) != 2 or not isinstance(data[0], str):
            return None
        payload, enc = data[0], str(data[1]).lower()
        if enc == "base64":
            import base64 as _b64
            try:
                raw = _b64.b64decode(payload + "=" * (-len(payload) % 4))
            except Exception:
                return None
        elif enc in ("base58", "bs58"):
            raw = b58decode(payload)
        else:
            return None
    elif isinstance(data, str):
        raw = b58decode(data)
    else:
        return None

    if not raw:
        return None
    # A memo far over the protocol cap is not a memo; refuse to build a giant
    # carrier out of some other program's misattributed payload.
    if len(raw) > MEMO_MAX_BYTES * 4:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text.strip() else None


def _iter_instructions(tx: dict):
    """Yield every instruction in a tx, top-level and inner."""
    msg = ((tx.get("transaction") or {}).get("message")) or {}
    for ix in msg.get("instructions") or []:
        if isinstance(ix, dict):
            yield ix
    for group in (tx.get("meta") or {}).get("innerInstructions") or []:
        if isinstance(group, dict):
            for ix in group.get("instructions") or []:
                if isinstance(ix, dict):
                    yield ix


def _tx_meta(tx: dict) -> dict:
    wt = tx.get("_watchtower") or {}
    return {
        "slot": wt.get("slot", tx.get("slot")),
        "block_time": wt.get("blockTime", tx.get("blockTime")),
        "err": wt.get("err", (tx.get("meta") or {}).get("err")),
        "signature": wt.get("signature", ""),
    }


def extract_carriers(tx: dict) -> list[Carrier]:
    """Stage 0. Program-ID + shape filter over one transaction.

    Parsed memos come from wormhole's `extract_memos` (do not reimplement it).
    Raw base58/base64 instruction data on a memo program -- which that function
    documents itself as leaving alone -- is decoded here, so the carrier count
    does not silently depend on which encoding the source used.
    """
    if not isinstance(tx, dict):
        return []
    meta = _tx_meta(tx)
    tx_err = meta["err"] is not None
    out: list[Carrier] = []
    seen: set[str] = set()

    for text, sig, sender in extract_memos(tx):
        if text in seen:
            continue
        seen.add(text)
        out.append(
            Carrier(
                raw_text=text,
                signature=sig or meta["signature"],
                sender=sender,
                slot=meta["slot"],
                block_time=meta["block_time"],
                source="parsed",
                tx_err=tx_err,
            )
        )

    # Raw-data path: only for memo-program instructions with no parsed form.
    for ix in _iter_instructions(tx):
        if ix.get("programId") not in CARRIER_PROGRAM_IDS:
            if ix.get("program") != "spl-memo":
                continue
        if ix.get("parsed") is not None:
            continue  # already covered by extract_memos
        text = _decode_instruction_data(ix.get("data"))
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(
            Carrier(
                raw_text=text,
                signature=meta["signature"] or _fallback_sig(tx),
                sender=_fallback_sender(tx),
                slot=meta["slot"],
                block_time=meta["block_time"],
                program_id=ix.get("programId") or "",
                source="raw-data",
                tx_err=tx_err,
                decoded_raw_data=True,
            )
        )
    return out


def _fallback_sig(tx: dict) -> str:
    for key in ("signature", "txHash", "transactionSignature"):
        v = tx.get(key)
        if isinstance(v, str):
            return v
    sigs = ((tx.get("transaction") or {}).get("signatures")) or []
    return sigs[0] if sigs and isinstance(sigs[0], str) else ""


def _fallback_sender(tx: dict) -> str:
    for key in ("feePayer", "from", "source"):
        v = tx.get(key)
        if isinstance(v, str):
            return v
    keys = (((tx.get("transaction") or {}).get("message")) or {}).get("accountKeys") or []
    if keys:
        first = keys[0]
        if isinstance(first, str):
            return first
        if isinstance(first, dict):
            return first.get("pubkey", "") or ""
    return ""


def extract_evm_carriers(tx: dict) -> list[Carrier]:
    """Stage 0 for Base/EVM. Deliberately not implemented.

    A carrier extractor that silently returns nothing manufactures a clean
    denominator and a fabricated base rate. Failing loudly is the honest
    behaviour until EOA-destination calldata and string-param event logs are
    actually built and validated against real Base data.
    """
    raise NotImplementedError(
        "EVM calldata carrier extraction is not implemented. Do not report an "
        "EVM base rate from this module -- it would have a denominator of zero "
        "that looks like a measurement."
    )


# ================================================ instrumentation ==========

@dataclass
class StageTimer:
    """Wall-clock nanoseconds per stage, plus how many items each stage saw.

    Measured, not estimated. The cascade's whole justification is that each
    stage is cheaper than the next and discards most of its input; without
    these counters that is an assertion rather than a result.
    """

    ns: dict = field(default_factory=lambda: {
        "stage0_extract": 0, "stage1_gate": 0,
        "stage2_normalize": 0, "stage2_scan": 0,
    })
    counts: dict = field(default_factory=lambda: {
        "transactions": 0, "carriers": 0,
        "gate_passed": 0, "gate_rejected": 0,
        "variants_scanned": 0, "carriers_with_findings": 0,
    })

    def add(self, stage: str, elapsed_ns: int) -> None:
        self.ns[stage] = self.ns.get(stage, 0) + elapsed_ns

    def bump(self, key: str, n: int = 1) -> None:
        self.counts[key] = self.counts.get(key, 0) + n

    def report(self) -> dict:
        total = sum(self.ns.values()) or 1
        per = {}
        for stage, ns in self.ns.items():
            per[stage] = {
                "ms": round(ns / 1e6, 3),
                "pct": round(100.0 * ns / total, 1),
            }
        c = self.counts
        carriers = c.get("carriers", 0) or 1
        return {
            "counts": dict(c),
            "per_stage": per,
            "total_ms": round(total / 1e6, 3),
            "us_per_carrier": round((total / 1e3) / carriers, 2),
            # The discard rate stage 1 actually achieved, not the claimed one.
            "stage1_discard_pct": round(
                100.0 * c.get("gate_rejected", 0) / carriers, 2
            ),
            "variants_per_carrier": round(
                c.get("variants_scanned", 0) / carriers, 2
            ),
        }


# ================================================ stages 1 + 2 =============

@dataclass
class Detection:
    rule_id: str
    severity: str
    title: str
    variant: str
    excerpt: str | None
    needs_adjudication: bool


@dataclass
class Result:
    """Evidence record for one carrier. `raw_text`/`raw_sha256` are the fact."""

    carrier: Carrier
    gate_passed: bool
    gate_reason: str
    printable_run: int
    entropy: float
    variants_scanned: int = 0
    variant_labels: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    had_suppression_directive: bool = False
    had_zero_width: bool = False
    had_tag_chars: bool = False

    @property
    def rule_ids(self) -> list:
        return [f.rule_id for f in self.findings]

    def assert_evidence_intact(self) -> None:
        """Re-derive the carrier hash. Raises if evidence was mutated.

        Cheap, and it converts "we promise normalization does not touch the
        evidence" into something checked at runtime and in tests.
        """
        actual = hashlib.sha256(
            self.carrier.raw_text.encode("utf-8", errors="replace")
        ).hexdigest()
        if actual != self.carrier.raw_sha256:
            raise AssertionError(
                f"evidence mutated for {self.carrier.signature or '<nosig>'}: "
                f"stored {self.carrier.raw_sha256[:16]} != actual {actual[:16]}"
            )

    def to_dict(self) -> dict:
        d = {
            "signature": self.carrier.signature,
            "sender": self.carrier.sender,
            "slot": self.carrier.slot,
            "block_time": self.carrier.block_time,
            "source": self.carrier.source,
            "decoded_raw_data": self.carrier.decoded_raw_data,
            "tx_err": self.carrier.tx_err,
            # Evidence: original bytes, never a normalized variant.
            "raw_text": self.carrier.raw_text,
            "raw_sha256": self.carrier.raw_sha256,
            "raw_bytes": self.carrier.raw_bytes,
            "gate_passed": self.gate_passed,
            "gate_reason": self.gate_reason,
            "printable_run": self.printable_run,
            "entropy": round(self.entropy, 3),
            "variants_scanned": self.variants_scanned,
            "variant_labels": list(self.variant_labels),
            "had_suppression_directive": self.had_suppression_directive,
            "had_zero_width": self.had_zero_width,
            "had_tag_chars": self.had_tag_chars,
            "findings": [asdict(f) for f in self.findings],
        }
        return d


def detect_carrier(carrier: Carrier, timer: StageTimer | None = None) -> Result:
    """Run stages 1-2 over one carrier. Never mutates `carrier.raw_text`."""
    timer = timer or StageTimer()

    t0 = time.perf_counter_ns()
    gate = textness_gate(carrier.raw_text)
    timer.add("stage1_gate", time.perf_counter_ns() - t0)
    timer.bump("gate_passed" if gate.passed else "gate_rejected")

    res = Result(
        carrier=carrier,
        gate_passed=gate.passed,
        gate_reason=gate.reason,
        printable_run=gate.printable_run,
        entropy=gate.entropy,
    )
    if not gate.passed:
        res.assert_evidence_intact()
        return res

    t0 = time.perf_counter_ns()
    norm: Normalized = normalize(carrier.raw_text)
    timer.add("stage2_normalize", time.perf_counter_ns() - t0)

    res.had_suppression_directive = norm.had_suppression
    res.had_zero_width = norm.had_zero_width
    res.had_tag_chars = norm.had_tag_chars
    res.variants_scanned = len(norm.variants)
    res.variant_labels = [v.label for v in norm.variants]
    timer.bump("variants_scanned", len(norm.variants))

    # rule_id -> cheapest variant that produced it. `scan_text` is called
    # directly, NOT `scan_memos`: that function mutates Finding.detail and
    # .remediation with operator-facing prose and truncates the signature to
    # 16 chars in Finding.path, neither of which belongs in a tx-fact record.
    hits: dict[str, Detection] = {}
    t0 = time.perf_counter_ns()
    for variant in norm.variants:
        for f in scan_text(variant.text, path=f"memo:{carrier.signature}"):
            if f.rule_id not in ACTIONABLE or f.rule_id in hits:
                continue
            hits[f.rule_id] = Detection(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f.title,
                variant=variant.label,
                excerpt=f.excerpt,
                # Anything visible only after a transform carries the highest
                # false-positive risk and must not be published unadjudicated.
                needs_adjudication=variant.label != "raw",
            )
    timer.add("stage2_scan", time.perf_counter_ns() - t0)

    res.findings = sorted(hits.values(), key=lambda d: d.rule_id)
    if res.findings:
        timer.bump("carriers_with_findings")

    # The load-bearing check: normalization must not have touched the evidence.
    res.assert_evidence_intact()
    return res


def detect_transactions(txs, timer: StageTimer | None = None) -> tuple[list, StageTimer]:
    """Stages 0-2 over an iterable of transaction dicts."""
    timer = timer or StageTimer()
    results: list[Result] = []
    for tx in txs:
        timer.bump("transactions")
        t0 = time.perf_counter_ns()
        carriers = extract_carriers(tx)
        timer.add("stage0_extract", time.perf_counter_ns() - t0)
        timer.bump("carriers", len(carriers))
        for c in carriers:
            results.append(detect_carrier(c, timer))
    return results, timer


def summarize(results: list, timer: StageTimer) -> dict:
    """Aggregate for a report. Facts about transactions, never about addresses."""
    from collections import Counter

    by_rule = Counter()
    by_variant = Counter()
    adjudication = 0
    for r in results:
        for f in r.findings:
            by_rule[f.rule_id] += 1
            by_variant[f.variant] += 1
            if f.needs_adjudication:
                adjudication += 1
    hits = [r for r in results if r.findings]
    carriers = len(results) or 1
    return {
        # Per-rule counts are CARRIERS-THAT-MATCHED, not occurrence counts:
        # scan_text emits at most one finding per rule per call.
        "findings_by_rule": dict(by_rule),
        "findings_by_variant": dict(by_variant),
        "carriers_with_findings": len(hits),
        "needs_adjudication": adjudication,
        "base_rate_pct": round(100.0 * len(hits) / carriers, 6),
        "carriers_decoded_from_raw_data": sum(
            1 for r in results if r.carrier.decoded_raw_data
        ),
        "zero_width_carriers": sum(1 for r in results if r.had_zero_width),
        "tag_char_carriers": sum(1 for r in results if r.had_tag_chars),
        "suppression_directives": sum(
            1 for r in results if r.had_suppression_directive
        ),
        "timing": timer.report(),
    }


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Detection cascade stages 0-2.")
    ap.add_argument("--path", required=True, help="transaction dump (JSON/JSONL, or -)")
    ap.add_argument("--json-out", help="write full records here")
    args = ap.parse_args(argv)

    from wormhole.scanners.memos import load_transactions

    txs = load_transactions(args.path)
    results, timer = detect_transactions(txs)
    summary = summarize(results, timer)

    print(json.dumps(summary, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {"summary": summary, "records": [r.to_dict() for r in results]},
                indent=2,
                ensure_ascii=False,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
