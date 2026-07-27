# We scanned 40,000 Solana transactions for AI-agent prompt injection and found none

**2026-07-27 · Agent Wormhole · [agentwormhole.com](https://agentwormhole.com)**

An on-chain memo is the cheapest way to put text in front of an AI agent. Anyone
can attach arbitrary UTF-8 to a transaction for a fraction of a cent,
unsolicited, with no relationship and no approval step. The payload lands when
the agent reads its own transaction history — *"what came in today?"* — and it
arrives as tool output, which is the path every publicly disclosed 2026 agent
compromise actually used.

So we measured whether anyone is doing it.

**They are not. Zero of 1,064 memos matched any injection rule.**

## The numbers

| | |
|---|---|
| Signatures scanned | **40,000** |
| Memos extracted | **1,064** (2.66% of transactions) |
| Unique memo texts | 1,000 |
| **Memos matching any injection rule** | **0** |
| Memos containing zero-width characters | 0 |
| Memos containing Unicode tag-block characters | 0 |
| RPC calls | 44 |
| Cost | **$0** (public endpoint) |

Solana Memo program v2
(`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`), near chain tip, 2026-07-27.
Rules applied: WORM-001 through WORM-007 — self-replicating instructions,
instruction-override phrasing, credential exfiltration, directives hidden in
HTML comments, zero-width characters, Unicode tag-block smuggling
(U+E0000–U+E007F), and concealment directives.

Raw output: [`out/wide-2026-07-27.json`](out/wide-2026-07-27.json).

## Zero is an instrument reading, not a broken scanner

A detector that finds nothing anywhere is worthless as evidence. This one finds
everything it is fed:

| Obfuscation | Result |
|---|---|
| base64-wrapped payload | WORM-001 |
| hex-encoded payload | WORM-001 |
| URL-encoded payload | WORM-001 |
| Cyrillic homoglyph substitution | WORM-002 |
| zero-width character splitting | WORM-005 |
| Unicode tag-block smuggling | WORM-006 |

Against a devnet corpus of transactions we sent and fetched back ourselves:
**6/6 payload shapes detected, 0 false positives on 5 ordinary payment
references.**

## Why the zero, mechanically

We hand-classified 252 of the 1,064 memos. What memo traffic actually contains:

- bridge attestation hashes
- round-settlement strings and sequence numbers
- UUIDs and internal correlation IDs
- JSON state blobs
- exchange and protocol tags (`jupiter-…:buyback`)

**Not one natural-language sentence in 1,064 memos.**

That is the explanation, and it is a mechanism rather than a coincidence. A
prompt injection needs a reader. Memo traffic today is machine-to-machine
bookkeeping written by programs, for programs. There is no audience of agents
reading memos, so nobody writes instructions into them.

## What this does and does not mean

**What we can say:** we scanned 40,000 mainnet signatures with a detector
demonstrably capable of catching obfuscated payloads, and found zero. This is a
measured baseline, not a blind spot.

**What we cannot say:**

- ~~"The chain is clean."~~ We sampled one memo program near the tip. Public
  node address indexes are pruned, so this is recent traffic, not a census.
  Memo v1 and v4 are unswept on the precise path.
- ~~"We detect on-chain agent worms."~~ We detected zero. Nothing is happening
  in this channel.
- ~~"Base is clean."~~ Our EVM calldata reader requires valid UTF-8 from byte
  zero, so selector-prefixed calls — every ordinary contract call — are
  invisible to it. **A low Base number is an instrument limitation, not
  evidence.**

Carriers under 24 bytes are dropped by the text-ness gate, so a very short
imperative would be missed.

We publish the limits because a security measurement whose caveats are hidden
is not a measurement.

## Why publish a null result

Because the value of a baseline is that it makes the first occurrence visible.

Prompt injection reaching agents is real and rising — TrapDoor wrote invisible
instructions into developers' `CLAUDE.md` files via poisoned npm and PyPI
packages in May 2026, and the Grok/Bankr incident drained roughly $175,000
because a payment bot treated another AI's public reply as authorization. The
mechanism is established. The on-chain memo channel is simply not being used
for it yet.

When it is, the interesting question will be *"when did this start?"* — and that
question needs a before-number. This is ours. As far as we can determine, nobody
else has published one.

## Reproduce it

```bash
git clone https://github.com/runningoffcode/agent-wormhole
cd agent-wormhole/watchtower
python3 wide_sample.py            # public RPC, no key required
```

The scanner itself is free, offline, and dependency-free:

```bash
pipx install wormhole-guard
solana transaction-history <ADDRESS> --output json | wormhole memos -
```

`wormhole memos` never touches an RPC endpoint — it reads a history dump you
already fetched, for the same reason the rest of the tool stays offline. The
watchtower is the opt-in, network-connected half, and it is a separate package:
nothing in the installed CLI imports it.

## Honest caveat on detection

Content rules are evadable by rewriting content. Our own mutation harness
(`loop/mutate.py`) drives detection from 100% on verbatim payloads to about 76%
after one round of synonym substitution and roughly 71% under combined
paraphrase. Non-English payloads, base32 and rot13 are 0%.

So the zero above means *no payload matching known shapes*, not *no payload*. A
sufficiently rewritten instruction would pass. That is why the durable controls
in this project are the ones that recognise nothing: hashing a file flags any
change however it is worded, and comparing a signed payment against the
merchant's independent quote does not care how persuasive the prose was.

---

*Agent Wormhole is Apache-2.0. Findings are published as facts about
transactions, with signatures, never as verdicts about addresses.*
