#!/usr/bin/env python3
"""Chain Watchtower ingestion driver: pull carriers, scan them, persist a cursor.

This is the thin thing that turns the `ingest/` package into something an
operator can run. It does four jobs and no more:

  1. build a source by name (public RPC today, a paid stream later -- same
     interface, no downstream change),
  2. poll it in batches, persisting the resume cursor after every one,
  3. hand the transactions to `wormhole.scanners.memos.scan_memos` UNMODIFIED,
  4. write out what was scanned, what fired, and why ingestion stopped.

The `--capture` flag exists for a specific honesty reason: a published
"we scanned N and found X" number is only checkable if someone else can re-run
the corpus over the same bytes. Capturing the raw batch and replaying it later
with `--source replay` is what keeps that claim falsifiable after the chain has
moved on.

WHAT THIS DELIBERATELY DOES NOT DO. It emits facts about transactions -- this
signature carried this text, which matched this rule -- and never a verdict
about an address. "tx <sig> contains a string matching WORM-002" is something a
reader can check in a block explorer in thirty seconds. "0xABC is malicious" is
an unfalsifiable claim about a party, and it is where both the defamation
exposure and the false-positive damage live. The sender address is carried in
provenance because it is a fact about the transaction, and it is never
aggregated into a reputation.

No paid key required: the defaults point at free public endpoints, and
`--source replay` needs no network at all.

Read-only. Nothing here can sign, send, or write to a chain.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _p in (str(_ROOT), str(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# The one permitted direction of dependency: watchtower -> wormhole.
from wormhole.rules.injection import scan_text  # noqa: E402
from wormhole.scanners.memos import ACTIONABLE, extract_memos  # noqa: E402

from cascade import normalize, textness_gate  # noqa: E402

from ingest import (  # noqa: E402
    STOP_RATE_LIMITED,
    CursorStore,
    SOURCES,
    build_source,
)


def _provenance(tx: dict) -> dict:
    return tx.get("_watchtower") or {}


def resolve_signature(tx: dict) -> str:
    """Get the transaction id out of whatever shape the source handed us.

    Mirrors `wormhole.scanners.memos.extract_memos` exactly, and that is the
    point: a real `getParsedTransaction` dump carries the id at
    `transaction.signatures[0]`, NOT at the top level. Reading only a top-level
    key produced findings with an empty signature on every replayed dump --
    which turns "tx <sig> matched WORM-002", a claim anyone can check in a block
    explorer, into an unverifiable assertion. Live sources stamp `_watchtower`
    provenance and were fine; replay is the path used for reproducible
    published numbers, so it is the one that mattered most.
    """
    prov = _provenance(tx)
    v = prov.get("signature")
    if isinstance(v, str) and v:
        return v
    for key in ("signature", "txHash", "transactionSignature"):
        v = tx.get(key)
        if isinstance(v, str) and v:
            return v
    sigs = (tx.get("transaction") or {}).get("signatures")
    if isinstance(sigs, list) and sigs and isinstance(sigs[0], str):
        return sigs[0]
    return ""


def scan_batch(batch, findings_out: list, rule_counter: Counter) -> int:
    """Run the full cascade over one batch. Returns memos scanned.

    This drives stages 1 and 2 per memo -- the text-ness gate, then
    `cascade.normalize` to produce every variant worth scanning, then the
    UNMODIFIED corpus (`scan_text`) over each variant.

    Running `scan_memos` on the raw text alone, which this used to do, meant one
    line of attacker effort defeated the whole driver: a base64-, hex-, or
    URL-encoded payload scanned clean, as did Cyrillic homoglyph substitution.
    The defense already existed in cascade.py and simply was not called. It also
    made two artifacts that look like the same measurement have different
    detection depth, so a published "we scanned N and found X" understated X and
    the two denominators could not honestly be merged.

    `scan_text` is called rather than `scan_memos` deliberately: `scan_memos`
    rewrites `.detail`/`.remediation` in place with operator prose and truncates
    the signature into `Finding.path`, neither of which belongs in a
    transaction-fact record.

    Findings are deduped by (rule_id, signature) and keep the CHEAPEST variant
    that produced them. Anything visible only after a transform carries the most
    false-positive risk, so it is flagged `needs_adjudication` and must not be
    published unreviewed.
    """
    memos = 0
    for tx in batch.transactions:
        tx_sig = resolve_signature(tx)
        prov = _provenance(tx)
        for memo in extract_memos(tx):
            memos += 1
            sig = tx_sig
            # extract_memos yields (text, signature, sender). Its signature is
            # already resolved from the nested shape, so prefer it and fall
            # back to ours only if it is empty.
            if isinstance(memo, (tuple, list)):
                text = memo[0] if memo else ""
                inner = memo[1] if len(memo) > 1 else ""
                if isinstance(inner, str) and inner:
                    sig = inner
            else:
                text = memo if isinstance(memo, str) else str(memo)
            if not text:
                continue

            gate = textness_gate(text)
            if not gate.passed:
                continue

            norm = normalize(text)
            hits: dict[str, dict] = {}
            for variant in norm.variants:
                for f in scan_text(variant.text, path=f"memo:{sig}"):
                    if f.rule_id not in ACTIONABLE or f.rule_id in hits:
                        continue
                    hits[f.rule_id] = {
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "title": f.title,
                        "excerpt": f.excerpt,
                        "variant": variant.label,
                        "needs_adjudication": variant.label != "raw",
                        # The full, independently verifiable transaction id.
                        "signature": sig,
                        "provenance": prov,
                    }

            for rule_id, rec in sorted(hits.items()):
                rule_counter[rule_id] += 1
                findings_out.append(rec)
    return memos


def run(args) -> dict:
    kwargs: dict = {}
    if args.source == "replay":
        if not args.file:
            raise SystemExit("--source replay requires --file")
        kwargs["path"] = args.file
    else:
        kwargs["rps"] = args.rps
        if args.rpc_url:
            kwargs["url"] = args.rpc_url
        if args.source == "base-calldata" and args.start_block is not None:
            kwargs["start_block"] = args.start_block

    source = build_source(args.source, **kwargs)
    # No --cursor means a one-shot scan from the beginning. A temp path keeps
    # the store's interface intact without leaving state that a later run
    # would silently resume from.
    cursor_path = args.cursor
    if cursor_path and args.reset_cursor:
        try:
            Path(cursor_path).unlink()
        except OSError:
            pass
    if not cursor_path:
        cursor_path = str(Path(tempfile.mkdtemp(prefix="wt-cursor-")) / "c.json")
    store = CursorStore(cursor_path)

    findings: list = []
    rules: Counter = Counter()
    items = carriers = memos = 0
    captured: list = []
    errors: list = []
    stop = "not-started"
    batches = 0

    def note(batch) -> None:
        print(
            f"  batch {batches}: scanned={batch.items_scanned} "
            f"carriers={batch.carriers_found} stop={batch.stop_reason}",
            file=sys.stderr,
            flush=True,
        )

    for batch in source.stream(store, limit=args.limit, max_batches=args.batches):
        batches += 1
        items += batch.items_scanned
        carriers += batch.carriers_found
        memos += scan_batch(batch, findings, rules)
        errors.extend(batch.errors)
        stop = batch.stop_reason
        if args.capture:
            captured.extend(batch.transactions)
        note(batch)
        if batch.degraded:
            # Degrade, do not fail. Partial data is real data; the cursor is
            # already persisted, so the next run resumes where this one stopped.
            print(
                f"  ! degraded ({batch.stop_reason}) -- keeping "
                f"{len(batch.transactions)} transactions already fetched",
                file=sys.stderr,
                flush=True,
            )

    cursor = store.load(source.name)
    if args.capture:
        Path(args.capture).parent.mkdir(parents=True, exist_ok=True)
        Path(args.capture).write_text(
            json.dumps(captured, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": source.name,
        "provenance": {
            "endpoint": getattr(getattr(source, "rpc", None), "url", args.file or "local"),
            "batches": batches,
            "stop_reason": stop,
            "rpc_calls": getattr(getattr(source, "rpc", None), "stats", None)
            and source.rpc.stats.calls,
            "rpc_rate_limited": getattr(getattr(source, "rpc", None), "stats", None)
            and source.rpc.stats.rate_limited,
            "errors": errors[:20],
            "limitation": (
                "Public-node indexes are pruned and this walks a bounded window. "
                "This is a SAMPLE of recent traffic, never a chain-wide census."
            ),
        },
        "volume": {
            "items_scanned": items,
            "carriers_found": carriers,
            "memos_extracted": memos,
            "cursor_items_seen_cumulative": cursor.items_seen,
        },
        "findings": {
            "count": len(findings),
            "by_rule_id": dict(rules),
            "note": (
                "scan_text emits at most one finding per rule per call, so these "
                "are counts of MEMOS THAT MATCHED, not occurrence counts."
            ),
            "items": findings,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", default="replay", choices=sorted(SOURCES))
    ap.add_argument("--file", help="dump to replay (--source replay)")
    ap.add_argument("--rpc-url", help="override the endpoint (paid key slots in here)")
    ap.add_argument("--rps", type=float, default=3.0)
    ap.add_argument("--limit", type=int, default=500, help="carriers per batch")
    ap.add_argument("--batches", type=int, default=1)
    ap.add_argument("--start-block", type=int, help="base-calldata: first block")
    # Deliberately no default. A relative default resolved against whatever
    # the CWD happened to be, so a cursor left exhausted by an earlier run
    # made the tool print "items scanned: 0, findings: 0" on a file full of
    # known payloads -- a silent, confident zero indistinguishable from the
    # headline measurement. Opt in to resumption; do not inherit it.
    ap.add_argument("--cursor",
                    help="persist/resume progress here. Omit for a one-shot "
                         "scan that always starts from the beginning.")
    ap.add_argument("--reset-cursor", action="store_true",
                    help="ignore any stored position and rescan from the start")
    ap.add_argument("--capture", help="write raw transactions here for replay")
    ap.add_argument("--json-out")
    ap.add_argument("--list-sources", action="store_true")
    args = ap.parse_args()

    if args.list_sources:
        for name, desc in sorted(SOURCES.items()):
            print(f"  {name:16s} {desc}")
        return 0

    rep = run(args)
    v, f = rep["volume"], rep["findings"]
    W = 74
    print("=" * W)
    print("CHAIN WATCHTOWER -- INGESTION")
    print("=" * W)
    print(f"source          : {rep['source']}")
    print(f"endpoint        : {rep['provenance']['endpoint']}")
    print(f"stop reason     : {rep['provenance']['stop_reason']}")
    print()
    print(f"items scanned   : {v['items_scanned']}")
    print(f"carriers found  : {v['carriers_found']}")
    print(f"memos extracted : {v['memos_extracted']}")
    print()
    # A zero denominator is not a clean result. An exhausted cursor, a dead
    # endpoint, or a bad path all produce "0 findings", and that is
    # indistinguishable from a real measurement unless it is called out --
    # the same silent-pass shape as a truncated scan reading as clean.
    if v["items_scanned"] == 0:
        print("!! NOTHING WAS SCANNED -- this is not a clean result.")
        print(f"   stop reason: {rep['provenance']['stop_reason']}")
        if rep["provenance"]["stop_reason"] == "source-exhausted":
            print("   A stored cursor may already be at the end of this "
                  "source.")
            print("   Re-run with --reset-cursor, or omit --cursor for a "
                  "one-shot scan.")
        print()

    print("FINDINGS BY RULE ID")
    if not f["by_rule_id"]:
        if v["items_scanned"] == 0:
            print("  (nothing scanned -- see the warning above)")
        else:
            print("  (none -- zero memos matched any WORM-001..007 rule)")
    for rid, n in sorted(f["by_rule_id"].items()):
        print(f"  {rid} : {n}")
    for item in f["items"][:20]:
        print(f"\n  {item['rule_id']} [{item['severity']}] {item['title']}")
        print(f"    tx      : {item['signature']}")
        print(f"    excerpt : {item['excerpt']!r}")
    if rep["provenance"]["errors"]:
        print("\nERRORS (ingestion degraded, partial data kept)")
        for e in rep["provenance"]["errors"]:
            print(f"  {e}")
    print("=" * W)

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(
            json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"[watchtower] wrote {args.json_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
