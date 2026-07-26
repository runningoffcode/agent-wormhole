# wormhole-x402

[![npm](https://img.shields.io/npm/v/wormhole-x402)](https://www.npmjs.com/package/wormhole-x402)
[![npm downloads](https://img.shields.io/npm/dm/wormhole-x402)](https://www.npmjs.com/package/wormhole-x402)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](../LICENSE)
[![Offline](https://img.shields.io/badge/network%20calls-none-brightgreen)](#offline)
[![Tests](https://img.shields.io/badge/tests-21%20passing-informational)](test/)

**Your agent is about to sign a payment. Is it the one it was quoted?**

```
ALLOW    pays the quoted merchant, quoted amount
REFUSE   pays an ATTACKER instead
         [X402-001] payment destination is not the account derived from the quote
REFUSE   pays the merchant but 900x the amount
         [X402-002] payment amount does not match the quoted amount
REFUSE   pays correctly + silently approves a delegate
         [X402-006] Approve — delegates spending authority over the account
ABSTAIN  garbage bytes
         could not deserialize — refusing to report it as safe

5 transactions checked in 5ms — no RPC, no network
```

---

## The gap

Every transaction-security product answers the same question: **what will this
transaction do?** Simulation, asset diffs, address reputation. All useful.

None of it helps an agent, because **a payment to an attacker's address
simulates perfectly.** Correct balances. No revert. Clean verdict. The
transaction is entirely valid — it is simply not the one that was asked for.

Nobody answers *is this the transaction that was asked for?*

In the leading provider's API that question is not merely unimplemented, it is
**not expressible**. Their Solana scan request carries `origin` — *"DApp domain
proposing these transactions"* — and has no field for the agent's instructions
at all. The stack is shaped around a human approving a website's request. A
headless agent has neither a website nor a human.

## How it decides

<img src="https://raw.githubusercontent.com/runningoffcode/agent-wormhole/main/assets/diagram/x402-guard-2x.png" alt="Diagram: the x402 quote arrives on a channel the model never touches and the merchant's token account is derived from it by pure math; the unsigned transaction is authored in the model's context; a single comparison allows the quoted payment and refuses a wrong destination, a wrong amount, or an added delegate." width="820">

## Install

```bash
npm install wormhole-x402
```

```ts
import { guardSigner } from "wormhole-x402";

// `quote` is the PaymentRequirements from the server's HTTP 402 response.
const wallet = guardSigner(myWallet, () => currentQuote);

// Signing now throws unless the transaction matches the quote.
await wallet.signTransaction(tx);
```

Or inspect without wrapping:

```ts
import { inspectPayment } from "wormhole-x402";

const verdict = inspectPayment(serializedTx, {
  payTo: "merchant address from the 402 response",
  asset: "token mint",
  amount: "1000000",           // base units, exact
});
// → { decision: "allow" | "refuse" | "abstain", findings: [...] }
```

## The one design constraint

**Intent must never be something the agent states.**

If intent is a field the model fills in, a compromised model fills in *both
sides* of the comparison and validates its own forgery. That is worse than no
check at all, because it manufactures confidence at the exact moment funds move
irreversibly.

x402 is the case where this works cleanly. The recipient, amount and mint
arrive as structured JSON in the server's HTTP 402 response — **before the
transaction exists**, on a channel entirely separate from the model's context.
That is a genuinely independent second input.

And the comparison is pure arithmetic: the destination token account derives
deterministically from `(recipient, mint)`. No RPC required.

## What it checks

| Code | Check |
|---|---|
| `X402-001` | Destination is not the account derived from the quote |
| `X402-002` | Amount does not match the quote exactly |
| `X402-003` | A program outside the x402 `exact` allowlist is invoked |
| `X402-006` | `Approve` / `SetAuthority` / `CloseAccount` riding along |
| `X402-007` | A SOL transfer riding beside the token payment |
| `X402-008` | Memo contains instruction-shaped text |

Programs are an **allowlist**, not a blocklist — so it holds against
instructions nobody has catalogued yet.

## What it does not do

**It is not a simulator and does not replace one.** Run both; they answer
different questions. Simulation tells you what a transaction does. This tells
you whether it is the one you asked for.

**It abstains rather than guessing.** A versioned transaction can hide accounts
behind an address lookup table, and those pubkeys live in on-chain account data
that cannot be read offline. That returns `abstain` — never `allow`. A guard
that reports safe on a transaction it could not fully read is worse than no
guard, because the operator believes it was checked.

**It cannot help when intent only ever existed as natural language.** *"Pay the
invoice Alice emailed me"* has no independent channel, so the guard would be
diffing against text that lived in the same context the attacker poisoned. That
case is **refused rather than approximated** — an approximation there
manufactures false confidence precisely when money moves.

**The memo scan is not load-bearing.** It is shape matching over
attacker-controlled text, evadable by rewording. It is there to surface an
obvious attempt, not to be relied on.

## Fails closed

No quote means refuse.

Every optional security parameter with a permissive default ends up unset in
production, and then the guard reports green on 100% of traffic and nobody
notices. This one has no permissive default.

## Offline

No RPC. No network calls. No telemetry. Nothing leaves the process.

Everything above is computed from the serialized transaction bytes you already
hold, plus the quote you already received. Measured at **~1ms per transaction**.

---

Apache 2.0 · Part of [Agent Wormhole](https://agentwormhole.com) ·
[wormhole-guard](https://pypi.org/project/wormhole-guard/) protects the
instruction files your coding agents read.
