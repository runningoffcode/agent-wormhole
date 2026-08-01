# Scope: the x402 facilitator conformance watchtower

Drafted 2026-08-01. A design, not an implementation. The question it answers:
which x402 facilitators conform to the spec right now, checked continuously from
the outside, published as a public scoreboard with a token-gated live query API
on top.

## Why this, why now

Three facts make this the right build:

1. **The demand exists and is fresh.** *When HTTP 402 Meets the Blockchain*
   (arXiv 2607.19545, July 2026) found 31 vulnerabilities across 15 facilitators
   handling 99% of x402 traffic, mapped to four attack classes (free shopping,
   asset theft, service denial, gas abuse). *Free-Riding the Agentic Web*
   (2605.30998) formalised five invariants (I1–I5) and found violations in ALL
   fifteen. "Affected parties adopted mitigations" — which means the state
   changes, and nobody publishes which facilitator fixed which, live.

2. **It is externally observable — proven.** The 402 study used a *semi-automated
   black-box tool*. And a facilitator's declared behaviour is a public endpoint:
   `GET https://x402.org/facilitator/supported` returns, with no auth, the schemes
   and networks it claims to support (verified: 11 kinds, `exact`/`upto`/
   `batch-settlement` across Base, Solana, Aptos, Stellar, XRPL, and more). Actual
   behaviour is probeable via `/verify` and `/settle`. A watchtower does not need
   source; it needs to send a crafted request and read the response.

3. **The lane is open.** `x402scan.com` indexes what servers EXIST (discovery). No
   one publishes whether they CONFORM. Discovery answers "who is here";
   conformance answers "who is safe to route through". Different product.

## The targets

Four facilitators each process >10M transactions and are the meaningful surface:

| Facilitator | Share | Notes |
| --- | --- | --- |
| **Dexter** | ~50% of daily | overtook Coinbase since mid-December |
| **Coinbase CDP** | large | Base, Solana, Stellar; free tier; `x402.org/facilitator` is CDP |
| **PayAI** | >10M | |
| **DayDreams** | >10M | |

Plus the self-hosted long tail (the awesome-x402 list shows dozens of sellers
running their own facilitator). The scoreboard covers the big four by name and
offers a "probe any facilitator URL" path for the rest.

## What it checks — the invariants, made black-box

The five invariants from 2605.30998, each turned into an OUTSIDE-observable probe.
A watchtower cannot see a facilitator's code, so each check is a request whose
RESPONSE reveals conformance or its absence.

| Inv. | Name | Black-box probe |
| --- | --- | --- |
| **I1** | Payment Integrity | Present a valid-looking auth for resource A; confirm the facilitator will not report `valid` without a settling tx. |
| **I2** | Value Consistency | Present an auth whose value is BELOW the quoted price; a conforming facilitator rejects it. Underpay-accept is the tell. |
| **I3** | Context Binding | Take a valid auth for resource A and present it for resource B at the same price (cross-resource substitution, the paper's F1). Accept = violation. |
| **I4** | Authorization Uniqueness | Replay one nonce concurrently (duplicate-settlement race, F2). More than one `valid` for one nonce = violation. |
| **I5** | Execution Conservation | Timing: does the facilitator report `valid` before settlement finality, opening the deliver-then-never-paid window (F4)? |

Every one of these is a request-and-read. None needs the facilitator's source. I3
and I4 in particular are the ones the paper found "near-universal" — 38% of hosts
exposed same-price sibling clusters — so they are the highest-signal, lowest-cost
first probes.

**Safety rail, non-negotiable.** These probes involve real payment
authorisations. The watchtower NEVER sends value it is not prepared to lose and
NEVER completes a settlement it induced — a conformance probe that itself moves a
victim's money is the exact harm the project exists to prevent. Probes run
against a dedicated, funded-to-a-cap test wallet, and any probe that would settle
is aborted at the `valid`/`invalid` verdict, before settlement. This rail is a
launch blocker, not a nicety.

## Architecture — reuses what already exists

The `wormhole-verify` service and the watchtower harness already have the shape:
an injectable RPC/HTTP source, a scan-and-record loop, a store keyed by tenant,
and honest degraded states. This is the same skeleton pointed at facilitators
instead of wallets.

```
probe scheduler ──> per-facilitator prober ──> conformance store
   (cron, per                (I1–I5 black-box       (facilitator, invariant,
    facilitator)              request/read)          verdict, observed_at)
        │                                                    │
        │                                                    ├──> public scoreboard  (free, cited)
        │                                                    └──> /v1/facilitator     (token-gated, live)
```

- **Prober**: one module per invariant, each a pure `(facilitatorUrl) -> verdict`
  over the injected HTTP source — so it is testable against a fake facilitator
  exactly the way the watch poller is testable against a fake tx source.
- **Store**: `facilitator_conformance(facilitator, invariant, verdict, evidence_code, observed_at)`.
  Evidence is a CODE, never the raw response — same discipline as the scanner.
- **Scoreboard**: a `/facilitators` page listing each facilitator × invariant,
  last-checked, and pass/fail. Free, reproducible, built to be cited. This is the
  marketing and the credibility, and gating it would defeat both.
- **`/v1/facilitator` query**: the token-gated product (see below).

## The token gate — where it goes, and where it must not

**The scoreboard is free and public.** Its whole value is being trusted and
cited, like the three research pages. A conformance report behind a paywall is a
report nobody reads, cites, or trusts — which removes the reason to hold the
token. Gating the reputation engine is self-defeating.

**The live per-call query is the token-gated product.** A buyer agent, in its
payment loop, asks before routing:

```
GET /v1/facilitator?url=<facilitator>&check=I3,I4   →  { pass | fail | stale, last_checked, codes }
```

That real-time, programmatic, per-payment answer is what an agent pays for or
holds tokens to access — it is the thing that is worth money in the loop, not the
static page. Same free-library / paid-hosted split as PRICING.md:

- **Free forever**: the scoreboard page, the probe methodology, the invariant
  definitions, the reproducible scripts.
- **Token-gated (100k / 500k / 1M tiers, already designed)**: the live
  `/v1/facilitator` check, historical conformance timelines, and a webhook that
  fires when a facilitator an agent depends on starts failing an invariant.

The token gives real-time access to a signal that DECAYS — a conformance verdict
is only useful fresh, and freshness is what the hosted service provides and a fork
of the free scoreboard cannot.

## What makes it un-forkable

The scoreboard is Apache and copyable. What is not: **the continuous, cross-
facilitator, timestamped signal**. A merchant-side hardening library (FurlPay)
protects one facilitator's own code; a discovery index (x402scan) lists servers.
Neither answers "is Dexter violating I4 as of five minutes ago". That answer needs
traffic, a probe cadence, and a history — exactly the cross-customer moat
PRICING.md identified, pointed at facilitators.

## Honest limits, stated up front

- **Probing is adversarial-adjacent.** A crafted underpay or replay against a live
  facilitator must be indistinguishable-in-harm from a real user error, run
  against our own test wallet, and never settle. If a facilitator treats the
  probe as an attack and blocks us, that is itself a finding (and a rate-limit to
  respect). Get this wrong and the project becomes the thing it warns about.
- **A pass is a snapshot, not a guarantee.** "Conforming at 12:05" is not
  "conforming now". The scoreboard states the check time; the API returns
  staleness. Neither claims more.
- **Coverage is the big four plus opt-in.** The long tail of self-hosted
  facilitators is probed on request, not swept — sweeping unknown endpoints with
  payment probes is the reckless version.
- **AP2 is the watch item.** If Google's Cart Mandate ships merchant price
  attestation, the payment-value invariant (I2) partly closes from above. The
  facilitator-behaviour invariants (I3/I4/I5) do not — a signed cart says nothing
  about whether the facilitator double-settles a nonce. So this build is more
  durable against AP2 than the pure quote-conformance pitch.

## First slice (what to build first, if greenlit)

Not all five invariants. **I3 (cross-resource substitution) and I4
(duplicate-settlement) only**, against Coinbase CDP and Dexter only, read-only
where possible (many I3 checks can be run without settling by stopping at the
`valid` verdict). Publish that two-invariant, two-facilitator scoreboard, verify
the probe never moves value, and measure whether the verdicts are useful — the
same "one real signal before you scale" gate as everything else. If the verdicts
are useful, widen to I1/I2/I5 and the other facilitators.
