# First-slice findings — the instrument, and one blocker left

Updated 2026-08-01, second session.

## The headline

The prober no longer lies. Given the same requests that previously produced a
confident **PASS** against Coinbase CDP, it now reports:

```
I3  UNKNOWN  control=refused  CONF-CONTROL-REFUSED
I4  UNKNOWN  control=refused  CONF-CONTROL-REFUSED
```

That is the correct answer, and getting from the first to the second is the
entire value of this session.

## What went wrong the first time

The original prober read `isValid` from a single crafted request and treated
`false` as conformance. Against the live CDP facilitator that produced PASS on
both invariants. Then a control request — malformed in a way unrelated to either
invariant — returned:

```json
{"isValid": false, "invalidReason": "unexpected_error",
 "invalidMessage": "Cannot use 'in' operator to search for 'permit2Authorization' in undefined"}
```

CDP answers `isValid: false` to **everything** it cannot process, including its
own unhandled exceptions. So a lone `false` cannot distinguish:

1. checked the invariant and refused ← the only real pass
2. rejected on signature grounds before reaching the check
3. crashed and defaulted to false

Our probe used a fake signature, so (2) was almost certainly what happened.
Publishing that as conformance would have been a green result from an instrument
that cannot tell green from broken — the same failure the injection base rates use
controls to avoid, inverted.

## The fix: a differential control, enforced structurally

Every probe now sends a **matched pair**:

- **CONTROL** — valid in every way the invariant is about. If this is refused, the
  facilitator is refusing for unrelated reasons and the probe learned nothing.
- **TREATMENT** — identical except for the one property the invariant governs.

`pass` requires **control-accepted AND treatment-refused**. Every other
combination is `unknown`. This is decided in a single function (`decide`), so a
future probe cannot report a pass without its control, and a test sweeps seven
facilitator behaviours asserting *no result is ever `pass` with `control !==
"accepted"`*.

A `CONF-FACILITATOR-ERROR` class was added for non-evaluative reasons
(`unexpected_error`, `missing_parameters`), so a facilitator is never credited
with conformance for crashing.

**23 tests**, including one that replays CDP's exact observed response and asserts
we report `unknown`.

## The payload shape, established empirically

The live facilitator was walked through its own rejections one at a time. Each
error named the next missing piece:

| Payload state | Facilitator response |
| --- | --- |
| fake signature | rejected — never reaches the invariant |
| real signature, no `extra` | `invalid_exact_evm_missing_eip712_domain` |
| + `extra: {name, version}` | `unexpected_error` — "Cannot convert undefined to a BigInt" |
| + `amount` (alongside `maxAmountRequired`) | **reaches on-chain simulation** |
| final state | `invalid_exact_evm_insufficient_balance` |

That last line is the good news: the facilitator recovered our signer
(`payer: 0x121D59c1…`), validated the EIP-712 domain, and simulated the real
`transferWithAuthorization` call. **The payload is correct. The only thing missing
is a funded wallet.**

This shape is now encoded in `craft()` with the table above as its comment, so the
next person does not have to rediscover it.

## The one blocker: funding

A Base Sepolia probe wallet exists (address in `.env`, gitignored, mode 600,
testnet-only). It has **0 ETH and 0 USDC**.

Funding could not be automated: Circle's faucet API requires an API key, and the
web faucets are browser flows behind captchas. **This step needs a human.**

Once the wallet holds a small amount of Base Sepolia USDC, the control becomes
acceptable and every `unknown` above turns into a real `pass` or `fail` with no
further code changes — the signer hook (`ProbeContext.sign`) is already wired and
tested.

## Incidental finding — reported, not published

CDP surfaces **two** distinct unhandled exception messages to unauthenticated
callers:

- `Cannot use 'in' operator to search for 'permit2Authorization' in undefined`
- `Cannot convert undefined to a BigInt`

Both are internal errors leaked in `invalidMessage`. Low severity — no value
moves, no secret leaks — but they are real robustness defects, and the second one
also leaks the internal library version (`viem@2.48.11`) plus a full contract-call
trace.

Still **not being published**. They were found while calibrating our own
instrument, the severity is low, and leading a scoreboard launch with an
accidental crash message would be the "describe a mechanism as a loss" mistake the
ACP writeup avoided. The responsible path is a direct report to Coinbase.

## Status

- Safety rail: **done**, 10 adversarial tests, settlement unreachable by construction.
- Probers + differential control: **done**, 23 tests, calibrated against real behaviour.
- Payload shape: **solved**, verified to reach on-chain simulation.
- Real verdicts: **blocked on a faucet**, which is a human step.
- Scoreboard: **must not ship** until verdicts are real.

---

# Second session, funded: two reproduced violations

Updated 2026-08-01, after the probe wallet was funded with 20 testnet USDC.

## The result

With a real EIP-3009 signature from a funded Base Sepolia wallet, the control is
accepted and the verdicts become real:

```
I3  FAIL  control=accepted  CONF-I3-ACCEPTED   accepted a resource-mismatched authorization
I4  FAIL  control=accepted  CONF-I4-ACCEPTED   accepted the same nonce twice, concurrently
```

`control=accepted` is the load-bearing part: the facilitator accepted our valid
payload, which means it genuinely evaluated the request rather than rejecting it
upstream. These are not the false passes of the first session.

## The negative controls, which the finding had to survive

A finding this size must fail when it should. Every check below was run against
`https://x402.org/facilitator` (Coinbase CDP), Base Sepolia:

| Probe | Response | Meaning |
| --- | --- | --- |
| Bad signature (65 zero bytes) | `invalid_exact_evm_signature` | not accept-everything |
| Amount above balance | `invalid_exact_evm_insufficient_balance` | really simulates on-chain |
| **Control**: requirements and payload name the same resource | **`isValid: true`** | the control works |
| **I3**: requirements say B, payload says A | **`isValid: true`** | ← violation |
| **I4**: same nonce, two concurrent requests | **both `isValid: true`** | ← violation |

The first two prove the instrument discriminates. The third proves the control is
meaningful. Only then do the last two mean anything.

## Why these are the published attacks, not our interpretation

*Free-Riding the Agentic Web* (arXiv 2605.30998) §5.2 states the I4 fix belongs at
the verification stage:

> "To enforce Authorization Uniqueness (I4), the verification logic must
> transition from a stateless 'Check-then-Act' model to a stateful
> 'Check-and-Set' ... a lightweight pending-state layer at the Facilitator
> ingress ... even if N concurrent requests pass the signature check, only the
> first to acquire the atomic lock proceeds to settlement and delivery."

A `/verify` that answers `true` twice for one nonce is stateless Check-then-Act —
the F2 duplicate-settlement race, exactly as described. Likewise I3: the paper's
F1 is a signature detached from its resource and re-attached to another, which is
what the mismatched-resource acceptance permits.

## The honest limits, which belong in any writeup

1. **This is `/verify` behaviour, not proven settlement behaviour.** We never
   called `/settle` — the safety rail makes it unreachable. Whether a second
   settlement would actually land on-chain is untested, and it is possible the
   on-chain `transferWithAuthorization` would revert on nonce reuse even though
   `/verify` said yes. **What is demonstrated is that a merchant relying on
   `/verify` to gate delivery can be told "yes" twice for one authorization** —
   which is precisely the free-shopping condition the paper describes, because
   merchants deliver on the verify verdict.
2. **`/verify` may not claim to enforce these.** Coinbase's documentation does not
   state what `/verify` guarantees versus `/settle`. If their position is that
   verify is advisory and settlement is authoritative, that is a legitimate design
   — and the finding becomes "the advisory endpoint merchants gate on does not
   bind context or linearize nonces", which is still worth publishing but is a
   different sentence. **This must be put to Coinbase before publication.**
3. **Testnet only.** Base Sepolia. Mainnet behaviour is untested and must not be
   assumed identical.
4. **One facilitator.** Dexter, PayAI and DayDreams are unprobed.

## Disclosure position

These are reproduced instances of *published* vulnerability classes in a
production payment facilitator. That earns coordinated disclosure, not a
scoreboard launch.

**The sequence is: report to Coinbase, give them time, then publish.** Leading
with "Coinbase fails two invariants" before they have seen it would be the
opposite of how the ACP writeup handled a live protocol, and the credibility of
the whole scoreboard depends on getting this first disclosure right.

Also still unreported: the two unhandled exception messages from the first
session (`Cannot use 'in' operator...`, `Cannot convert undefined to a BigInt`),
the second of which leaks `viem@2.48.11` and a full contract-call trace.

## Status

- Instrument: **calibrated and validated** with negative controls.
- Finding: **real and reproducible**, with stated limits.
- Publication: **blocked on coordinated disclosure**, deliberately.

---

# Third session: it is systemic, not one vendor

Updated 2026-08-01. Evidence in `evidence/`, reproducible with `evidence/reproduce.mjs`.

## Both of the two largest facilitators fail both invariants

```
                                  Coinbase CDP    Dexter
  neg-control: bad signature        REFUSED       REFUSED     ← instrument discriminates
  neg-control: over balance         REFUSED       REFUSED     ← really simulates on-chain
  CONTROL: resource matches         accepted      accepted    ← control is meaningful
  I3: resource MISMATCH             ACCEPTED      ACCEPTED    ← violation
  I4: nonce reused, concurrent      ACCEPTED×2    ACCEPTED×2  ← violation
```

Dexter was probed on the same Base Sepolia network with the same wallet and the
same code — one URL change. It passed both negative controls independently, so
this is not "a facilitator that accepts everything"; it is the same two failures,
twice.

Between them these two handle the majority of x402 traffic (Dexter overtook
Coinbase around mid-December and runs roughly half of daily transactions).

## The spec sentence that makes this matter

From the x402 specification's facilitator page:

> "If the `Verification Response` is valid, the resource server performs the work
> to fulfil the request."

**The spec says merchants deliver on the verify verdict.** And verify's stated job
is to "confirm that the client's payment payload meets the server's declared
payment requirements" — the requirements name the resource. So a resource
mismatch that verify does not catch is verify failing its own documented purpose,
not an optional extra.

That closes the "verify is only advisory" defence to a large extent. It may still
be raised, and it should still be put to both operators before publication, but
the spec does not describe verify as advisory — it describes it as the gate the
merchant acts on.

## What is demonstrated, precisely

- A merchant gating delivery on `/verify` can be told **"valid"** for an
  authorization whose resource does not match what is being bought (F1,
  cross-resource substitution).
- A merchant can be told **"valid" twice concurrently for one nonce** (F2,
  duplicate-settlement race). arXiv 2605.30998 §5.2 places this fix explicitly at
  facilitator ingress: "even if N concurrent requests pass the signature check,
  only the first to acquire the atomic lock proceeds".

## What is still NOT demonstrated

Unchanged from the second session and still the honest boundary:

1. **Settlement was never called.** The rail forbids it. Whether two settlements
   would land on-chain is untested — the ERC-20 may well reject the second nonce
   use. The loss demonstrated is at the **merchant**, which delivers on verify,
   not necessarily on-chain.
2. **Testnet only** (Base Sepolia). Mainnet untested.
3. **Two facilitators.** PayAI and DayDreams are unprobed.
4. Neither operator has been contacted yet.

## Disclosure, and why the "better facilitator" idea has to wait

The obvious next thought is to build a facilitator that passes these probes. That
is a legitimate endgame and the sequencing in the strategy memo supports it — but
it must not be the reason this is published. A conformance scoreboard whose author
launches a competing facilitator alongside the first report reads as marketing,
not research, and the credibility that makes the scoreboard worth anything is
spent in that moment.

**Order: report to both operators, give them time, publish the survey, and only
then talk about building one.** The survey is the asset. A facilitator built on
top of an established, trusted scoreboard is defensible; a scoreboard published to
sell a facilitator is not.

---

# Fourth session: the full survey, and a second, different finding

Updated 2026-08-01. Raw output in `evidence/`.

## All four facilitators, honestly graded

```
                  controls sane   control accepted   I3      I4
  Coinbase CDP    yes             yes                FAIL    FAIL
  Dexter          yes             yes                FAIL    FAIL
  PayAI           yes             NO                 unknown unknown   (invalid_payload)
  DayDreams       no              NO                 unknown unknown   (Unauthorized — needs a key)
```

PayAI and DayDreams are **not** graded. PayAI rejects our payload shape (it
advertises short network names like `base-sepolia` and likely wants a different
schema); DayDreams requires an API key. In both cases the control was never
accepted, so the probe learned nothing and the instrument says so. **`unknown` is
not a pass and is not an accusation** — it is two facilitators we have not yet
been able to measure.

That leaves the finding as: **the two largest facilitators, handling the majority
of x402 traffic, both fail I3 and I4.**

## A SECOND finding, and it is a different kind

The invariant failures above are payment-authorization logic — no text, no model,
no prompt. Separately, we probed the **text surface**: `paymentRequirements`
carries `description`, which a merchant controls and a buying agent's model reads
when deciding whether to purchase.

```
                       Coinbase CDP   Dexter    our scanner
  instruction override   ACCEPTED     ACCEPTED   X402-202
  role spoof             ACCEPTED     ACCEPTED   X402-209
  exfiltration           ACCEPTED     ACCEPTED   X402-203
  role delimiter         ACCEPTED     ACCEPTED   X402-209
```

Both facilitators return `isValid: true` for a payment whose `description` is a
prompt-injection payload. Neither flags any of the four. Our scanner flags all
four on the same inputs.

**This is not a facilitator bug in the same sense as I3/I4** — nothing in the spec
asks a facilitator to scan prose, and a facilitator that started refusing payments
over their text would be a censor. It is a *gap in the ecosystem*, and the x402
spec itself frames it: the v2 bazaar extension applies content rules to exactly
three cosmetic fields (`serviceName`, `tags`, `iconUrl`) and explicitly names the
facilitator a trust boundary, because "clients echo the resource block from
PaymentRequired into PaymentPayload, so a malicious client could submit hostile
metadata". The authors identified the threat and then defended only the display
fields. `description` — the one carrying persuasive prose to the model — has no
content validation in either spec version.

So the honest framing is: **the merchant-controlled text that reaches a buying
agent's model passes through the payment layer unchecked, by design, and the two
largest facilitators confirm it empirically.** That is an argument for a
buyer-side control, which is what `wormhole-x402` is — not an accusation against
the facilitators.

## Do NOT conflate the two findings

I3/I4 are authorization logic bugs against published invariants — those are
facilitator defects and warrant coordinated disclosure. The text surface is an
unclaimed responsibility, and calling it a facilitator vulnerability would be
wrong and would weaken the first finding by association.

Write them as two separate things: *"the two largest facilitators fail two
published invariants"* and *"the payment layer does not sanitise the text your
agent reads, and nobody claims to."*
