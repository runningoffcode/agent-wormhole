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
