#!/usr/bin/env python3
"""Wide-sample base rate using ONLY the signature index (no per-tx fetch).

Motivation: getSignaturesForAddress already returns a `memo` field that the RPC
node populates for recognized Memo programs, formatted as `[<len>] <text>`. One
paged call returns up to 1000 signatures, so a wide sample costs ~1 RPC call per
1000 signatures instead of 1 call per transaction. Against a throttling public
endpoint that is the difference between a 1k sample and a 100k+ sample.

Trade-off, stated so the report can repeat it: the index `memo` field is a
node-side convenience string, not the raw instruction bytes. It concatenates
multiple memos in one tx and is the node's lossy rendering. It is therefore the
right instrument for a WIDE denominator, and measure_base_rate.py --source rpc
(full jsonParsed fetch) remains the authoritative instrument for PRECISION.
Report both; never blend them into one number.

Read-only. Never signs, sends, or writes anything on chain.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# The ONE permitted direction of dependency: watchtower -> wormhole.
from wormhole.rules.injection import scan_text  # noqa: E402
from wormhole.scanners.memos import ACTIONABLE  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cascade import normalize, textness_gate  # noqa: E402
from ingest.solana_rpc import (  # noqa: E402
    MEMO_PROGRAMS,
    SolanaRPC,
)

# The node renders the memo as "[<byte-len>] <text>". Strip that prefix so the
# corpus scans the actual memo text, not the node's framing.
_PREFIX = re.compile(r"^\[\d+\]\s?")


def unwrap(raw: str) -> str:
    return _PREFIX.sub("", raw, count=1)


def scan_memo_text(text: str, sig: str, meta: dict) -> dict:
    gate = textness_gate(text)
    rec = {
        "signature": sig,
        "slot": meta.get("slot"),
        "block_time": meta.get("blockTime"),
        "memo_text": text,
        "gate_passed": gate.passed,
        "gate_reason": gate.reason,
        "entropy": round(gate.entropy, 3),
        "findings": [],
        "had_zero_width": False,
        "had_tag_chars": False,
        "had_suppression_directive": False,
    }
    if not gate.passed:
        return rec

    norm = normalize(text)
    rec["had_zero_width"] = norm.had_zero_width
    rec["had_tag_chars"] = norm.had_tag_chars
    rec["had_suppression_directive"] = norm.had_suppression

    hits: dict[str, dict] = {}
    for variant in norm.variants:
        for f in scan_text(variant.text, path=f"memo:{sig}"):
            if f.rule_id not in ACTIONABLE or f.rule_id in hits:
                continue
            hits[f.rule_id] = {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "variant": variant.label,
                "excerpt": f.excerpt,
                "needs_adjudication": variant.label != "raw",
            }
    rec["findings"] = sorted(hits.values(), key=lambda h: h["rule_id"])
    return rec


def run(target_pages: int, programs, rpc_url: str, rps: float) -> dict:
    rpc = SolanaRPC(url=rpc_url, rps=rps)
    print(f"  RPC health: {rpc.health()}", file=sys.stderr, flush=True)

    sigs_scanned = 0
    memos_seen = 0
    records: list[dict] = []
    per_program: dict = {}

    for pid in (programs or list(MEMO_PROGRAMS)):
        before = None
        p_sigs = p_memos = 0
        for page_no in range(target_pages):
            try:
                page = rpc.signatures_for_address(pid, limit=1000, before=before)
            except Exception as exc:  # noqa: BLE001
                print(f"  ! {pid}: {exc}", file=sys.stderr, flush=True)
                break
            if not page:
                break
            before = page[-1]["signature"]
            p_sigs += len(page)
            sigs_scanned += len(page)
            for e in page:
                raw = e.get("memo")
                if not raw:
                    continue
                p_memos += 1
                memos_seen += 1
                records.append(
                    scan_memo_text(
                        unwrap(raw),
                        e["signature"],
                        {"slot": e.get("slot"), "blockTime": e.get("blockTime")},
                    )
                )
            if (page_no + 1) % 5 == 0:
                print(
                    f"    {pid[:8]} page {page_no+1}: {p_sigs} sigs, {p_memos} memos",
                    file=sys.stderr, flush=True,
                )
        per_program[pid] = {"signatures_scanned": p_sigs, "memos": p_memos}
        print(f"  {pid}: {p_sigs} sigs -> {p_memos} memos",
              file=sys.stderr, flush=True)

    fired = [r for r in records if r["findings"]]
    by_rule = Counter()
    by_rule_raw = Counter()
    for r in fired:
        for f in r["findings"]:
            by_rule[f["rule_id"]] += 1
            if not f["needs_adjudication"]:
                by_rule_raw[f["rule_id"]] += 1

    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "provenance": {
            "mode": "solana-mainnet-rpc-signature-index",
            "endpoint": rpc_url,
            "per_program": per_program,
            "rpc_calls": rpc.stats.calls,
            "rpc_by_method": rpc.stats.by_method,
            "rpc_rate_limited": rpc.stats.rate_limited,
            "instrument": (
                "getSignaturesForAddress `memo` field only; no getTransaction. "
                "The field is the node's rendering of the memo, prefixed with "
                "[<len>]. Wide denominator, lower fidelity than a jsonParsed "
                "fetch. Public node address indexes are pruned, so this walks "
                "recent memo traffic near the chain tip, NOT a chain-wide census."
            ),
        },
        "volume": {
            "signatures_scanned": sigs_scanned,
            "memos_extracted": memos_seen,
            "memo_bearing_rate_percent": (
                round(100.0 * memos_seen / sigs_scanned, 4) if sigs_scanned else 0.0
            ),
            "unique_memo_texts": len({r["memo_text"] for r in records}),
            "memos_passing_textness_gate": sum(1 for r in records if r["gate_passed"]),
        },
        "findings": {
            "memos_with_any_finding": len(fired),
            "base_rate_percent": (
                round(100.0 * len(fired) / memos_seen, 6) if memos_seen else 0.0
            ),
            "by_rule_id": dict(by_rule),
            "by_rule_id_raw_variant_only": dict(by_rule_raw),
            "note": (
                "scan_text emits at most one finding per rule per call, so these "
                "are counts of MEMOS THAT MATCHED, not occurrence counts."
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
                "entropy": r["entropy"],
                "full_memo_text": r["memo_text"],
                "findings": r["findings"],
            }
            for r in fired
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pages", type=int, default=40,
                    help="pages of 1000 signatures per program")
    ap.add_argument("--rpc-url", default="https://api.mainnet-beta.solana.com")
    ap.add_argument("--rps", type=float, default=3.0)
    ap.add_argument("--program", action="append", dest="programs")
    ap.add_argument("--json-out")
    args = ap.parse_args()

    rep = run(args.pages, args.programs, args.rpc_url, args.rps)

    v, f, s = rep["volume"], rep["findings"], rep["signals"]
    W = 74
    print("=" * W)
    print("CHAIN WATCHTOWER -- WIDE BASE-RATE SAMPLE (signature index)")
    print("=" * W)
    print(f"generated  : {rep['generated_utc']}")
    print(f"endpoint   : {rep['provenance']['endpoint']}")
    print()
    print(f"signatures scanned      : {v['signatures_scanned']}")
    print(f"memos extracted         : {v['memos_extracted']} "
          f"({v['memo_bearing_rate_percent']}% of signatures)")
    print(f"unique memo texts       : {v['unique_memo_texts']}")
    print(f"passed text-ness gate   : {v['memos_passing_textness_gate']}")
    print()
    print("FINDINGS BY RULE ID")
    if not f["by_rule_id"]:
        print("  (none -- zero memos matched any WORM-001..007 rule)")
    for rid, n in sorted(f["by_rule_id"].items()):
        raw = f["by_rule_id_raw_variant_only"].get(rid, 0)
        print(f"  {rid} : {n}   (raw-variant: {raw}, normalized-only: {n - raw})")
    print()
    print(f"memos with >=1 finding : {f['memos_with_any_finding']}")
    print(f"base rate              : {f['base_rate_percent']}%  "
          f"({f['memos_with_any_finding']}/{v['memos_extracted']})")
    print()
    print(f"zero-width chars       : {s['memos_with_zero_width']}")
    print(f"Unicode tag chars      : {s['memos_with_tag_chars']}")
    print(f"suppression directives : {s['memos_with_suppression_directive']}")
    print()
    print("TRIAGE QUEUE -- full text of everything that fired")
    if not rep["triage_queue"]:
        print("  (empty)")
    for i, t in enumerate(rep["triage_queue"], 1):
        print(f"\n[{i}] sig={t['signature']}")
        print(f"    slot={t['slot']}  block_time={t['block_time']}  entropy={t['entropy']}")
        for h in t["findings"]:
            flag = "  <-- NORMALIZED-ONLY, ADJUDICATE" if h["needs_adjudication"] else ""
            print(f"    {h['rule_id']} [{h['severity']}] via '{h['variant']}': {h['title']}{flag}")
        print(f"    FULL MEMO TEXT: {t['full_memo_text']!r}")
    print("=" * W)

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(rep, indent=2, ensure_ascii=False))
        print(f"[watchtower] wrote {args.json_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
