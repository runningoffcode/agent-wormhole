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

# WIDE sample — signature index only, ~1 RPC call per 1000 signatures
python3 watchtower/wide_sample.py --pages 40 \
  --json-out watchtower/out/wide.json

# DEEP sample — full jsonParsed fetch, 1 RPC call per transaction
python3 watchtower/measure_base_rate.py --source rpc --target 1000 \
  --json-out watchtower/out/mainnet-sample.json

python3 -m pytest watchtower/test_watchtower.py -q
```

### Two instruments, deliberately not blended

`getSignaturesForAddress` already returns a `memo` field (rendered `[<len>] <text>`),
so a **wide** pass costs ~1 call per 1000 signatures while a **deep** pass costs 1
call per transaction. Against a throttling public endpoint that is the difference
between a 1k and a 40k+ sample.

| | wide (`wide_sample.py`) | deep (`measure_base_rate.py --source rpc`) |
|---|---|---|
| Cost | ~1 call / 1000 sigs | 1 call / tx |
| Fidelity | node's rendering, concatenates multi-memo txs | full `jsonParsed` instruction data |
| Use for | the denominator | precision / adjudication |

Report both numbers separately. Never average them into one figure.

## Measured result — Solana mainnet, 2026-07-27

Public RPC (`api.mainnet-beta.solana.com`), Memo v2 program, walking back from
the chain tip:

```
signatures scanned : 40,000
memos extracted    :  1,064   (2.66% of signatures carried a memo)
unique memo texts  :  1,000
findings           :      0   — zero memos matched any WORM-001..007 rule
zero-width chars   :      0
Unicode tag chars  :      0
base rate          :  0.0%    (0 / 1,064)
```

**The measured base rate of injection-shaped memos is zero.** Not "low" — zero,
in this sample, at this time, near the chain tip.

This is the expected and honest result, and it is publishable as-is. What real
memo traffic actually contains is machine-to-machine bookkeeping: bridge
attestation hashes (`0x7010…`), protocol round-settlement records
(`fm:v2:round_settle:round-175093:…`), UUID payment references, JSON state
blobs, and short tags like `Auto-Claim`. Across 1,064 memos there was **not one
natural-language sentence**, let alone an instruction aimed at an agent.

The detector is not silent because it is broken. The same pipeline scores
**6/6 detections with 0 false positives** on the seeded devnet corpus, and a
positive control confirms it recovers instruction text hidden by zero-width
splitting, base64, and Cyrillic homoglyphs. A zero from this pipeline is a real
zero.

**Do not extrapolate this to "memo injection is impossible."** It is a
point-in-time sample of one program near the tip, and absence of a payload class
today is not absence of the attack tomorrow — the value of a measured zero is
that it is a *baseline*: the first anomalous memo is now a visible deviation
rather than a guess. Equally, it is evidence that text scanning alone is not the
whole product, which is exactly why the behavioral signals below matter — the
Grok/Bankr drain carried no hostile string at all.

### Deep-pass status: incomplete, and therefore not reported

The `--source rpc` deep pass (full `jsonParsed` fetch, 1000 transactions) was
started and reached 400 transactions before the public endpoint's rate limiting
made the remaining ~600 impractical; it was stopped without producing a report.
The partial log is kept as `out/mainnet-2026-07-27-INCOMPLETE.log`.

**No base rate is claimed from that run.** A partial fetch has a denominator
nobody can verify, and reporting one would be exactly the kind of number this
whole exercise exists to avoid. The 40k-signature wide sample above is the only
mainnet figure quoted here. Completing the deep pass needs a paid endpoint
(`--rpc-url` + higher `--rps`), which is a cost decision, not a code change.

A Helius/QuickNode endpoint slots in by changing `--rpc-url` and raising
`--rps`; no other code changes.

## Honest limitations

- **This is a sample, not a census.** Public-node address indexes are pruned, so
  `getSignaturesForAddress` walks recent memo traffic near the chain tip and
  cannot enumerate all memo transactions chain-wide. Any published number must
  repeat this caveat. For a true chain-wide denominator, use Dune's
  `solana.instruction_calls` (its `data` column is VARBINARY, so memo bytes come
  out directly) or the BigQuery Solana dataset.
- **The 40k sample covers Memo v2 only**, walking back from the tip. v1 and v4
  were not swept in that run. A zero here is a zero for *that* slice of traffic.
- **The wide instrument sees the node's rendering**, not raw instruction bytes.
  It concatenates multiple memos in one transaction and is therefore the right
  tool for a denominator and the wrong one for adjudicating a specific hit.
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
