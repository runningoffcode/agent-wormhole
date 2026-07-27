# Chain Watchtower

An **opt-in, network-connected** service that reads public chain data and applies
the existing Agent Wormhole detection corpus to it.

It is **not** part of the free local `wormhole` package.

## The boundary (load-bearing)

The free CLI's promise — 100% local, offline, zero runtime dependencies, no
account, no telemetry — is the product. The watchtower must never erode it.

| | free `wormhole/` | `watchtower/` |
|---|---|---|
| Network | never | yes, read-only |
| Dependencies | zero | `requests`, `certifi` |
| Direction of import | never imports watchtower | imports `wormhole` freely |

`watchtower → wormhole` is the **only** permitted direction. Two tests in
`test_watchtower.py` enforce it by scanning `wormhole/**.py` for any import of
the watchtower or of a network library, so a future refactor cannot quietly
break the offline guarantee.

## Read-only by construction

The RPC client whitelists five read methods and raises on anything else, so
`sendTransaction` is unreachable from this code path — not by convention, but
because the call is rejected before it is made.

The watchtower **never sends transactions, never dusts wallets, never writes
memos.** A memo cannot carry protection: memos are copyable public text that
execute nothing, and sending unsolicited ones is address-poisoning — the exact
pattern this tool scans for.

## Publish facts, never verdicts

> `tx <sig> contains a string matching WORM-002`  ✅ independently verifiable
>
> `0xABC is malicious`  ❌ an unfalsifiable claim about a party

This wall is also the false-positive containment strategy. At scale even a
0.001% FP rate becomes many false accusations per day, so nothing is published
about an *address*, and anything that fires goes to a human triage queue with
its full text attached.

## The detection cascade

Cheapest-first. **No LLM and no billing on any hot path.**

| Stage | Does | Discards |
|---|---|---|
| 0 carrier extraction | program-ID / shape filter | >99.9% |
| 1 text-ness gate | UTF-8, printable run, entropy band | binary blobs |
| 2 normalize + **existing corpus** | NFKC, strip invisibles, homoglyph fold, recursive decode (depth 3) → `scan_text` | — |
| 3 adjudication | human triage; nothing auto-published | — |

Stage 2 **does not reimplement detection.** It produces labelled *variants* of
the carrier text and hands each to `wormhole.rules.injection.scan_text`.

### Two subtleties worth keeping

**The raw variant is always scanned.** Stripping invisible characters destroys
the very evidence WORM-005/006 detect. Scanning only the normalized form would
lose them; scanning only the raw form loses whatever the decode was for. Every
finding records which variant produced it, and anything seen *only* in a
normalized variant is flagged `needs_adjudication`.

**Hidden text is signal, not noise.** A pure Unicode-tag-block payload has a
printable run of **zero** — the whole instruction is invisible. A naive
run-length gate therefore rejects the attack *because it is well hidden*, which
is exactly backwards. Invisible-character carriers bypass the run test, and
short carriers (`invoice #4417` + smuggled zero-width is 16 chars) are judged on
printable ratio instead. This regressed once and is now pinned by tests.

## Usage

```bash
pip install -r watchtower/requirements.txt

# Positive control — the known-malicious devnet corpus (FN=0, FP=0)
python3 watchtower/measure_base_rate.py --source file \
  --path corpus/devnet-memos-history.json

# Live mainnet sample over public RPC (no paid key needed)
python3 watchtower/measure_base_rate.py --source rpc --target 1200 \
  --json-out watchtower/out/mainnet-sample.json

python3 -m pytest watchtower/test_watchtower.py -q
```

A Helius/QuickNode endpoint slots in by changing `--rpc-url` and raising
`--rps`; no other code changes.

## Honest limitations

- **This is a sample, not a census.** Public-node address indexes are pruned, so
  `getSignaturesForAddress` walks recent memo traffic near the chain tip and
  cannot enumerate all memo transactions chain-wide. Any published number must
  repeat this caveat. For a true chain-wide denominator, use Dune's
  `solana.instruction_calls` (its `data` column is VARBINARY, so memo bytes come
  out directly) or the BigQuery Solana dataset.
- **`encoding=jsonParsed` is mandatory.** With any other encoding the memo
  arrives as undecoded base58 `data`, `extract_memos` returns nothing, and the
  base rate would silently be a fabrication. The script warns loudly if it
  sampled transactions but extracted zero memos.
- **Per-rule counts are memos-that-matched, not occurrences.** `scan_text`
  emits at most one finding per rule per call.
- **Solana only.** Base/EVM carrier extraction is not implemented here;
  `memos.py` has no calldata or event-log-string path.
- **Memo program v4** (`Memo4c2pN8...`, the Pinocchio rewrite, ~26x cheaper
  compute) is covered here but is *not* in the local package's
  `MEMO_PROGRAM_IDS`. Being far cheaper, it is the rational choice for anyone
  spamming memos at volume.

## Not yet built

Behavioral signals that need no payload text — fan-out burst, full-balance sweep
to a fresh address, unlimited approve to a newly-deployed spender, cross-agent
temporal correlation. These catch what text scanning cannot: the Grok/Bankr
drain was a boring ERC-20 transfer with no hostile string anywhere.

Canaries — addresses appearing in no legitimate quote, so any contact is an
attacker by construction (structurally zero false positives). **The canary list
must stay private**; publishing it hands worm authors an avoidance list. Canary
addresses must never appear in a Dune query, which would publish them.
