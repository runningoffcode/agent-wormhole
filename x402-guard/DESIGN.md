# x402-guard: Quote-Conformance Verifier API — Architecture & Honest Constraints

## What it is, in one sentence

A security checkpoint an AI agent calls **once, immediately before it signs an
x402 payment**, to answer a single question: *does this payment match the quote
the merchant issued?* It spans Solana (SVM) and EVM. It returns
`refuse` / `allow` / `abstain` plus a signed, offline-replayable receipt. It is
the auditor at the door, not the guard who holds the key.

---

## 1. The one-endpoint model — checkpoint, not proxy

There is exactly one endpoint:

```
POST /v1/verify   ->   { decision, findings, reason?, receipt?, signature?, billable }
```

The request is a `VerifyRequest { network, quote, payload, options? }`. The
handler (`createVerifyHandler` in `server.ts`) does four transport things —
stamps time, signs, meters, dispatches — and nothing else. Every verdict lives
in `verify(req, ctx)` (`verify.ts`). The transport contains no judgement, by
rule, so the hosted API and the free offline tool can never drift.

**Why a checkpoint and not a proxy — the contrast that defines the product:**

| | A proxy / gateway | This checkpoint |
|---|---|---|
| Position | Sits *in* the money path; the payment flows through it | Sits *beside* the path; the payment never touches it |
| On our downtime | Payments stall — we are a single point of failure on someone's revenue | Caller falls back to the local guard and signs anyway; we block nothing |
| What we hold | Funds, keys, or the connection that moves them | Nothing. No key material in the core (`sign` is injected), no funds, ever |
| What we see | Full traffic, indefinitely | One request, judged, then forgotten — receipts carry codes + digests, never plaintext |
| Trust demand | "Route all your money through us" | "Ask us one yes/no question you can verify yourself later" |

The checkpoint stance is load-bearing for the whole trust story. Because
`verify()` takes time as an input (`ctx.issuedAt`, never `Date.now()`), reads no
network, runs no LLM, and holds no key, a verdict is a **pure function of its
request**. The same code runs behind the paid endpoint and inside the free CLI
at the signing site. A caller who cannot reach us loses the *attestation*, not
the *protection* — the identical logic already ran locally. Our being down must
never block a legitimate payment; the local guard is the floor and we are the
notarized ceiling.

**Abstain is never an allow.** An unresolved network, a thrown lane, an
undecodable payload — all return `{ decision: "abstain", reason }` with **no
receipt**. A receipt for "we could not tell" would be a notary trap, and a crash
that read as a verdict is the failure mode this project exists to avoid: a
verifier that answers "invalid" to its own unhandled exceptions cannot tell a
refusal from a breakage, so neither can anyone relying on it. `verify.ts` wraps
each lane in `try/catch` and both the handler and `listen()` convert any thrown
verifier into an abstained 200, never a 500 a client might retry into a signed
payment.

---

## 2. The two tiers — same core, tier decided at the transport

The verdict logic **never knows which tier called it.** Tier is a property of
the caller relationship, resolved entirely in `server.ts`; `verify()` receives
only a `VerifyContext { quoteProvenance, issuedAt, sign? }` and returns the same
`VerifyResult` regardless.

### Tier A — per-call USDC metering
- Pay ~$0.002–0.005 per verification in USDC, priced by provenance (table in §4).
- Billing is recorded through the injected `Meter` hook and **never awaited**
  (`server.ts` fires `opts.meter(...)` after the decision, inside its own
  `try/catch`, and discards failures). Our payment rail being down cannot delay
  or block a verdict.
- Only the three trusted provenances are billed; `caller_asserted` is answered
  free.

### Tier B — monthly subscription
Adds three things on top of the identical core:
1. **A per-tenant signing key.** The tenant's `signingKey` is passed as a
   `ServerOptions` field for that tenant's handler instance; the published public
   half lets anyone replay their receipts offline. The core stays keyless —
   `sign` is just the injected closure `edSign(null, Buffer.from(canonical),
   key)`.
2. **Cross-agent correlation** (§3): "N of your agents refused the same redirect
   in this window." This is computed **downstream of the verdict**, from metered
   events, never on the hot path.
3. **A dashboard** over that tenant's metered stream.

### Why the same core stays true across tiers
Two existing seams make this structural, not aspirational:

- **The `Meter` hook.** Its event is deliberately minimal —
  `{ digest, provenance, decision, chainId, issuedAt }`. No quote text, no payee,
  no amount figure. Tier B's correlation is built **only** from these fields plus
  the receipt's `amount_bucket`. Because metering is downstream and non-blocking,
  adding correlation for subscribers changes nothing on the decision path and
  nothing in `verify.ts`.
- **`quote_provenance`.** It rides in the `VerifyContext` and lands in every
  receipt. It is the one field that says how much a verdict can be relied upon,
  and it is set by the transport from the relationship (`X-Quote-Provenance`
  header), never read from the payload under suspicion. Tiering and billing key
  off provenance; the verdict does not.

The dividing line: **the transport decides who you are and what you owe; the core
only decides whether the payment matches the quote.**

---

## 3. The correlation signal (Tier B) — without plaintext

The monthly tier answers fleet-level questions like *"N of your agents refused
the same redirect inside a 10-minute window"* using only non-reversible fields
that already exist on the metered event and the receipt:

- **`request_digest`** — `SHA-256` over the canonical `{network, quote{payTo,
  asset, amount}, payload{to,value,from}}` (see `digest()` in `verify.ts`). Free
  quote text is *excluded by construction*. Identical digests across many of a
  tenant's agents in a short window = the same payment being pushed at the fleet.
  This is the sharpest signal and the primary cluster key.
- **Co-occurrence of `refuse` + `code` + `chain_id` + `amount_bucket`** — when
  digests differ, a spike of the same refuse code (e.g. a payTo-mismatch code) on
  the same chain in the same coarse amount band still clusters a campaign. Codes
  are rule ids only (`X402-1xx` EVM, `X402-0xx` SVM, `X402-2xx` quote-text
  injection); the bucket is a power-of-ten band over the base-unit integer
  (`amountBucket` in `sink.ts`), never the figure.
- **Time windows** — everything is bucketed over `issuedAt`, a caller-supplied
  ISO timestamp, so a "window" is a pure function of receipt data and needs no
  server clock.

**Known weakness, stated plainly.** A patient attacker who mutates the payload
per target — a distinct `payTo` or `value` for each victim agent — produces a
**different `request_digest` every time**, and the digest cluster dissolves. This
is inherent to hashing verdict-determining fields: exact-match correlation only
catches exact-match reuse.

**Structural / behavioral fallback for the mutated case.** When digests scatter,
correlation falls back to the coarser co-occurrence signal above: same *refuse
code* + same *chain_id* + same *amount_bucket* + same *window*, across N agents,
is a fleet-level indicator even when no two payloads are byte-identical. It keys
on the *shape and outcome* of the attack (a burst of destination-mismatch
refusals in one amount band on one chain) rather than the literal bytes. It is
weaker and noisier than digest clustering — that is the honest cost of carrying
no plaintext — but it degrades gracefully instead of going blind, and it never
requires storing a quote or a payment to do so.

---

## 4. Provenance-based billing

`quote_provenance` (from `VerifyContext`, set by the `X-Quote-Provenance` header)
is the sole billing determinant. `BILLABLE` in `server.ts` is exactly the first
three; the handler meters only when `result.receipt` exists **and**
`BILLABLE.has(provenance)`.

| Provenance | Meaning | Tier A | Tier B | Billable? |
|---|---|---|---|---|
| `independent_fetch` | We (or a trusted path) fetched the quote from the merchant ourselves | ✓ | ✓ | **Yes** |
| `merchant_signed` | Quote carries the merchant's own signature | ✓ | ✓ | **Yes** |
| `facilitator_held` | Quote is held/attested by the x402 facilitator | ✓ | ✓ | **Yes** |
| `caller_asserted` | Caller simply pasted a quote; we cannot vouch for its origin | ✓ (answered) | ✓ (answered) | **No** |

`caller_asserted` is the default when the header is absent or unrecognized
(`readProvenance`). It is **answered** — the caller still gets a verdict and
findings — but it is **never billed** and, per the non-negotiables, **must never
be logged or relied upon as an allow a third party can trust**. The response
still returns `billable: false` so the caller knows the attestation is
uncharged and unwarranted. A caller who wants a billable, relied-upon attestation
must present the quote through a path that *proves* one of the three trusted
provenances.

---

## 5. Honest market constraints

- **Small volume.** Cumulative x402 payment flow is on the order of **$50M**,
  with **sub-$1 average transaction size**. Per-verification pricing in
  fractions of a cent means revenue is small until agent commerce is much
  larger. We do not pretend otherwise.
- **Likely-acquisition outcome.** The realistic exit is being **absorbed by a
  facilitator or wallet** that wants conformance built in, not a standalone
  recurring-revenue business at current volumes. That shapes the goal below.
- **Be the named reference implementation.** The strategic aim is to be the
  **cited, correct conformance verifier** for x402 quote-matching — the offline-
  replayable receipt and the keyless-core design are the differentiators a
  facilitator would want to adopt or acquire, precisely because a USENIX review
  found *all fifteen* surveyed facilitators out of conformance. Correctness and
  a receipt anyone can independently verify are the moat, not volume.

### 8-week KILL CRITERION

If, within **8 weeks**, we cannot:

> take a **real Base USDC payment** an agent is about to sign, verify it against
> a **real merchant quote**, and produce a **receipt that a third party replays
> entirely offline** — recomputing the `request_digest` and verifying the
> ed25519 `signature` against the published public key, with no access to our
> server —

then the thesis is dead and we stop. This is the single, concrete, falsifiable
milestone. It is not "traction" or "logos"; it is the one capability the whole
product reduces to, on the one chain that matters, end to end.

---

## 6. Explicit non-goals

Stated so they are never assumed into scope:

- **No agent management.** We do not orchestrate, schedule, or manage agents. We
  answer one question at one checkpoint.
- **No inline injection / worm / traffic monitoring on this path.** Quote-text
  injection *screening* exists (`inspectQuoteText`, `X402-2xx`) only to stop a
  poisoned quote from corrupting the amount/destination comparison — it is a
  precondition of the verdict, not a monitor. Continuous worm-propagation
  detection and memo scanning stay in the **free local CLI** (Agent Wormhole),
  never in the hosted payment path.
- **No holding funds.** We never custody, escrow, or route money. We are beside
  the money path, never in it.
- **No LLM anywhere on the path.** Not for the verdict, not for correlation, not
  for billing. The hot path is deterministic string/BigInt arithmetic so a
  receipt replays identically offline. An LLM would make the verdict
  irreproducible and the receipt unverifiable — the opposite of the product.
- **No plaintext retention.** Receipts and metered events carry codes, buckets,
  and digests only. `sink.ts` constructs each record field-by-field and re-checks
  it with `assertNoPlaintext()` (an allowlist) so no quote text or payment bytes
  can ever reach disk or the wire.

---

## Appendix — the receipt, and why it is the whole point

```
Receipt {
  v: 1,
  decision,              // allow | refuse   (abstain never gets a receipt)
  codes[],               // sorted rule ids only — never quote text
  amount_bucket,         // coarse power-of-ten band — never the figure
  chain_id, lane,        // resolved rail
  quote_provenance,      // reliability class (see §4)
  request_digest,        // SHA-256 of canonical verdict-determining inputs
  issued_at              // caller-supplied ISO time; core never reads a clock
}
```

`canonicalReceipt(r)` produces a stable-key-order string; the transport signs it
with ed25519 (`sign(null, Buffer.from(canonical), key)` — **not** `createSign`,
which throws for Ed25519 because Ed25519 hashes internally). A third party, given
the published public key, verifies the signature and recomputes `request_digest`
from the same inputs — **with no access to our server**. That offline
replayability is what makes this a correctness product and not a notary you have
to trust, and it is the exact capability the 8-week kill criterion demands.