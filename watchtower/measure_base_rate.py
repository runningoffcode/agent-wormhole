#!/usr/bin/env python3
"""Base-rate measurement: how many injection-shaped memos are actually on chain?

Runs the EXISTING wormhole corpus over a real sample of Solana Memo-program
transactions and reports what it found -- including nothing, if that is the
answer. A credible "we scanned N and found X" is publishable either way; an
invented epidemic would be falsifiable in minutes.

  python3 watchtower/measure_base_rate.py --source rpc --target 1000
  python3 watchtower/measure_base_rate.py --source file --path corpus/devnet-memos-history.json

Read-only. Never signs, sends, or writes anything on chain.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# The ONE permitted direction of dependency: watchtower -> wormhole.
from wormhole.rules.injection import scan_text  # noqa: E402
from wormhole.scanners.memos import (  # noqa: E402
    ACTIONABLE,
    extract_memos,
    load_transactions,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cascade import normalize, textness_gate  # noqa: E402


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------- scanning ---

def scan_one_memo(text: str, sig: str, sender: str, meta: dict) -> dict:
    """Stage 1 + stage 2 for a single carrier. Returns a record dict."""
    gate = textness_gate(text)
    rec = {
        "signature": sig,
        "sender": sender,
        "slot": meta.get("slot"),
        "block_time": meta.get("blockTime"),
        "tx_err": meta.get("err") is not None,
        "memo_text": text,
        "memo_bytes": len(text.encode("utf-8", errors="replace")),
        "gate_passed": gate.passed,
        "gate_reason": gate.reason,
        "printable_run": gate.printable_run,
        "entropy": round(gate.entropy, 3),
        "findings": [],
        "variants_scanned": 0,
        "had_suppression_directive": False,
        "had_zero_width": False,
        "had_tag_chars": False,
    }
    if not gate.passed:
        return rec

    norm = normalize(text)
    rec["had_suppression_directive"] = norm.had_suppression
    rec["had_zero_width"] = norm.had_zero_width
    rec["had_tag_chars"] = norm.had_tag_chars
    rec["variants_scanned"] = len(norm.variants)

    # rule_id -> cheapest variant label that produced it.
    hits: dict[str, dict] = {}
    for variant in norm.variants:
        # scan_text directly, NOT scan_memos: scan_memos mutates Finding.detail
        # and .remediation with operator-facing prose ("If an agent already read
        # this memo...") that is inappropriate for a public tx-fact feed, and it
        # truncates the signature to 16 chars in Finding.path.
        for f in scan_text(variant.text, path=f"memo:{sig}"):
            if f.rule_id not in ACTIONABLE:
                continue
            if f.rule_id in hits:
                continue
            hits[f.rule_id] = {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "variant": variant.label,
                "excerpt": f.excerpt,
                # A finding present ONLY in the folded variant is the highest
                # false-positive risk and must not be published unadjudicated.
                "needs_adjudication": variant.label != "raw",
            }
    rec["findings"] = sorted(hits.values(), key=lambda h: h["rule_id"])
    return rec


def scan_transactions(txs, progress_every: int = 200) -> dict:
    """Run the cascade over a list of transaction dicts."""
    records: list[dict] = []
    tx_count = 0
    memo_count = 0
    tx_with_memo = 0

    for tx in txs:
        tx_count += 1
        memos = extract_memos(tx)
        if memos:
            tx_with_memo += 1
        wt = tx.get("_watchtower") or {}
        meta = {
            "slot": wt.get("slot", tx.get("slot")),
            "blockTime": wt.get("blockTime", tx.get("blockTime")),
            "err": wt.get("err", (tx.get("meta") or {}).get("err")),
        }
        for text, sig, sender in memos:
            memo_count += 1
            records.append(
                scan_one_memo(text, sig or wt.get("signature", ""), sender, meta)
            )
        if progress_every and tx_count % progress_every == 0:
            _log(f"    scanned {tx_count} txs / {memo_count} memos")

    return {
        "transactions_sampled": tx_count,
        "transactions_with_memo": tx_with_memo,
        "memos_extracted": memo_count,
        "records": records,
    }


# ---------------------------------------------------------------- sources ---

def source_rpc(target: int, programs, rpc_url: str, rps: float) -> tuple[list, dict]:
    from ingest.solana_rpc import (  # noqa: E402
        MEMO_PROGRAMS,
        SolanaRPC,
        fetch_transactions,
        iter_memo_signatures,
    )

    rpc = SolanaRPC(url=rpc_url, rps=rps)
    _log(f"  RPC health: {rpc.health()}")

    program_list = programs or list(MEMO_PROGRAMS)
    txs: list = []
    per_program: dict = {}

    for pid in program_list:
        if len(txs) >= target:
            break
        want = target - len(txs)
        _log(f"  program {pid}: seeking {want} memo-bearing signatures")
        try:
            sigs = list(
                iter_memo_signatures(rpc, pid, target=want, progress=_log)
            )
        except Exception as exc:  # noqa: BLE001
            _log(f"  ! {pid}: {exc}")
            per_program[pid] = {"signatures": 0, "error": str(exc)}
            continue
        _log(f"  program {pid}: {len(sigs)} candidate signatures")
        got = list(fetch_transactions(rpc, sigs, progress=_log))
        per_program[pid] = {"signatures": len(sigs), "transactions": len(got)}
        txs.extend(got)

    return txs, {
        "mode": "solana-mainnet-rpc",
        "endpoint": rpc_url,
        "programs": program_list,
        "per_program": per_program,
        "rpc_calls": rpc.stats.calls,
        "rpc_by_method": rpc.stats.by_method,
        "rpc_errors": rpc.stats.errors,
        "rpc_retries": rpc.stats.retries,
        "rpc_rate_limited": rpc.stats.rate_limited,
        "sampling": (
            "Backward walk of each Memo program's signature index from the "
            "chain tip, prefiltered on the RPC-populated `memo` field. Public "
            "node address indexes are pruned, so this is a sample of recent "
            "memo traffic near the tip, NOT a chain-wide census."
        ),
    }


def source_file(path: str) -> tuple[list, dict]:
    txs = load_transactions(path)
    return txs, {
        "mode": "file",
        "path": str(path),
        "sampling": "Fixed local transaction dump; not a mainnet sample.",
    }


# ----------------------------------------------------------------- report ---

def build_report(scan: dict, provenance: dict) -> dict:
    records = scan["records"]
    fired = [r for r in records if r["findings"]]

    by_rule = Counter()
    by_rule_raw = Counter()
    for r in fired:
        for f in r["findings"]:
            by_rule[f["rule_id"]] += 1
            if not f["needs_adjudication"]:
                by_rule_raw[f["rule_id"]] += 1

    gated_out = Counter(
        r["gate_reason"] for r in records if not r["gate_passed"]
    )

    memos = scan["memos_extracted"]
    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "provenance": provenance,
        "volume": {
            "transactions_sampled": scan["transactions_sampled"],
            "transactions_with_memo": scan["transactions_with_memo"],
            "memos_extracted": memos,
            "memos_passing_textness_gate": sum(
                1 for r in records if r["gate_passed"]
            ),
            "memos_rejected_by_gate": dict(gated_out),
            "unique_memo_texts": len({r["memo_text"] for r in records}),
        },
        "findings": {
            "memos_with_any_finding": len(fired),
            "base_rate_percent": round(100.0 * len(fired) / memos, 6) if memos else 0.0,
            "by_rule_id": dict(by_rule),
            "by_rule_id_raw_variant_only": dict(by_rule_raw),
            "note": (
                "scan_text emits at most one finding per rule per call, so "
                "these are counts of MEMOS THAT MATCHED, not occurrence counts."
            ),
        },
        "signals": {
            "memos_with_zero_width": sum(1 for r in records if r["had_zero_width"]),
            "memos_with_tag_chars": sum(1 for r in records if r["had_tag_chars"]),
            "memos_with_suppression_directive": sum(
                1 for r in records if r["had_suppression_directive"]
            ),
        },
        "triage_queue": [
            {
                "signature": r["signature"],
                "slot": r["slot"],
                "block_time": r["block_time"],
                "sender": r["sender"],
                "memo_bytes": r["memo_bytes"],
                "entropy": r["entropy"],
                "full_memo_text": r["memo_text"],
                "findings": r["findings"],
            }
            for r in fired
        ],
    }


def print_report(rep: dict) -> None:
    v, f, s = rep["volume"], rep["findings"], rep["signals"]
    p = rep["provenance"]
    W = 74
    print("=" * W)
    print("AGENT WORMHOLE -- CHAIN WATCHTOWER: BASE-RATE MEASUREMENT")
    print("=" * W)
    print(f"generated      : {rep['generated_utc']}")
    print(f"source         : {p['mode']}")
    if p.get("endpoint"):
        print(f"endpoint       : {p['endpoint']}")
    if p.get("path"):
        print(f"path           : {p['path']}")
    print()
    print("-" * W)
    print("VOLUME")
    print("-" * W)
    print(f"transactions sampled         : {v['transactions_sampled']}")
    print(f"transactions carrying a memo : {v['transactions_with_memo']}")
    print(f"memos extracted              : {v['memos_extracted']}")
    print(f"unique memo texts            : {v['unique_memo_texts']}")
    print(f"passed text-ness gate        : {v['memos_passing_textness_gate']}")
    for reason, n in sorted(v["memos_rejected_by_gate"].items()):
        print(f"  rejected [{reason}]{' ' * max(0, 12 - len(reason))}: {n}")
    print()
    print("-" * W)
    print("FINDINGS BY RULE ID")
    print("-" * W)
    if not f["by_rule_id"]:
        print("  (none -- zero memos matched any WORM-001..007 rule)")
    else:
        for rid, n in sorted(f["by_rule_id"].items()):
            raw = f["by_rule_id_raw_variant_only"].get(rid, 0)
            print(f"  {rid} : {n}   (raw-variant: {raw}, normalized-only: {n - raw})")
    print()
    print(f"memos with >=1 finding : {f['memos_with_any_finding']}")
    print(f"base rate              : {f['base_rate_percent']}%  "
          f"({f['memos_with_any_finding']}/{v['memos_extracted']})")
    print(f"  note: {f['note']}")
    print()
    print("-" * W)
    print("PAYLOAD-SHAPE SIGNALS")
    print("-" * W)
    print(f"memos containing zero-width chars      : {s['memos_with_zero_width']}")
    print(f"memos containing Unicode tag chars     : {s['memos_with_tag_chars']}")
    print(f"memos containing suppression directive : {s['memos_with_suppression_directive']}")
    print()
    print("-" * W)
    print("TRIAGE QUEUE -- full text of everything that fired")
    print("-" * W)
    if not rep["triage_queue"]:
        print("  (empty)")
    for i, t in enumerate(rep["triage_queue"], 1):
        print(f"\n[{i}] sig={t['signature']}")
        print(f"    slot={t['slot']}  block_time={t['block_time']}")
        print(f"    sender={t['sender']}  bytes={t['memo_bytes']}  entropy={t['entropy']}")
        for h in t["findings"]:
            flag = "  <-- NORMALIZED-ONLY, ADJUDICATE" if h["needs_adjudication"] else ""
            print(f"    {h['rule_id']} [{h['severity']}] via '{h['variant']}': {h['title']}{flag}")
        print(f"    FULL MEMO TEXT: {t['full_memo_text']!r}")
    print()
    print("=" * W)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", choices=("rpc", "file"), default="rpc")
    ap.add_argument("--path", help="transaction dump for --source file")
    ap.add_argument("--target", type=int, default=1000,
                    help="memo-bearing transactions to sample from RPC")
    ap.add_argument("--rpc-url",
                    default=os.environ.get("WATCHTOWER_RPC_URL",
                                           "https://api.mainnet-beta.solana.com"))
    ap.add_argument("--rps", type=float, default=3.0)
    ap.add_argument("--program", action="append", dest="programs")
    ap.add_argument("--json-out", help="write the full machine-readable report here")
    args = ap.parse_args()

    _log(f"[watchtower] source={args.source}")
    if args.source == "rpc":
        txs, prov = source_rpc(args.target, args.programs, args.rpc_url, args.rps)
    else:
        if not args.path:
            ap.error("--source file requires --path")
        txs, prov = source_file(args.path)

    _log(f"[watchtower] {len(txs)} transactions in hand; scanning")
    scan = scan_transactions(txs)

    # Guard against the silent-zero failure mode: with jsonParsed missing, memo
    # extraction yields nothing and the base rate would be a fabrication.
    if scan["transactions_sampled"] and not scan["memos_extracted"]:
        _log("[watchtower] WARNING: sampled transactions but extracted ZERO memos.")
        _log("[watchtower] Do NOT report a base rate from this run. Check that "
             "getTransaction used encoding=jsonParsed.")

    rep = build_report(scan, prov)
    print_report(rep)

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(rep, indent=2, ensure_ascii=False))
        _log(f"[watchtower] wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
