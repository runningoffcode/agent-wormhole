# First-slice findings, and why the scoreboard is not live yet

Dated 2026-08-01, at the end of the first build session.

## What was built

- `src/safety.ts` — the rail. Settlement is unreachable by construction:
  `SafeOperation` is a union of two read-only strings, the URL is re-checked for
  settle-shaped paths on **every** request, and every constructed amount passes a
  hard ceiling of 1000 base units. 10 tests, including adversarial ones that try
  to reach `/settle` and fail.
- `src/probes.ts` — I3 (context binding) and I4 (authorization uniqueness) as
  black-box probes over `/verify` only. Three-valued verdicts where `unknown` is
  never `pass`.
- 21 tests, all passing, against conforming / violating / hostile / unreadable
  fake facilitators.

The rail works. The probers work against fakes. **The probes are not yet a valid
measurement of a real facilitator**, and the reason is below.

## The blocker: a PASS does not currently mean what it should

Probing the live Coinbase CDP facilitator returned:

```
I3  PASS  refused a cross-resource authorization
I4  PASS  did not accept the same nonce twice
```

Then a control request — a payload malformed in a way unrelated to either
invariant — returned:

```json
{"isValid":false,"invalidReason":"unexpected_error",
 "invalidMessage":"Cannot use 'in' operator to search for 'permit2Authorization' in undefined"}
```

The facilitator answers `isValid: false` to **everything** it cannot parse,
including its own internal crash. So our probes' `false` — which the prober reads
as "correctly refused" — may mean:

- the facilitator checked context binding and refused (a real PASS), **or**
- the facilitator rejected the payload on signature grounds before reaching that
  check, **or**
- the facilitator threw an exception and defaulted to `false`.

Only the first is conformance. The other two are a rejection we have learned
nothing from. **Publishing these as PASS would be exactly the failure mode the
base-rate work exists to avoid: a green result from an instrument that cannot
tell green from broken.**

This is the same discipline as the injection base rates — a zero from a blind
detector measures nothing — applied to a scoreboard instead of a scanner.

## What has to be true before a scoreboard goes live

**1. A differential control on every probe.** Each probe must send a matched pair:
one payload that is invalid *only* in the way the invariant tests, and one that is
otherwise identical and should be *accepted*. A PASS is only meaningful when the
control is accepted and the probe is refused. If both are refused, the verdict is
`unknown` — the facilitator rejected for some other reason and the probe told us
nothing.

That requires a payload the facilitator would actually accept, which requires a
**real signature from a funded test wallet on Base Sepolia**. That is the next
piece of work, and it is why the scoreboard is not live today.

**2. `invalidReason` mapped, not just `isValid`.** The facilitator distinguishes
`missing_parameters`, `unexpected_error`, and presumably reason codes for real
conformance failures. The prober currently reads only the boolean. Reading the
reason lets us separate "refused for the right reason" from "crashed", which is
most of the ambiguity above — without it, `isValid: false` is too coarse to grade.

**3. The prerequisite fixes in x402-guard.** The moment we publicly grade other
people's payment security, our own shipped guard is the first thing an adversarial
reader audits. The `guardSigner` TOCTOU, the SPL blocklist→allowlist, and payer
binding must be fixed before launch — not because they block this code, but
because they are indefensible on a page that grades others.

## Incidental finding, reported not published

The CDP facilitator returns an unhandled exception message
(`Cannot use 'in' operator to search for 'permit2Authorization' in undefined`) in
its `invalidMessage` field for a malformed payload. That is an internal error
surfaced to an unauthenticated caller. It is low severity — no value moves, no
secret leaks — but it is a real robustness defect and it is the kind of thing the
scoreboard would eventually record.

It is **not** being published as a finding. It was observed while validating our
own instrument, the severity is low, and the responsible move is to report it to
Coinbase rather than lead a scoreboard launch with it. Publishing a crash message
we found by accident, before we have a working measurement, would be exactly the
"describe a mechanism as a loss" mistake the ACP writeup was careful to avoid.

## Honest status

The safety rail is done and proven. The probe skeleton is done and tested. The
measurement is **not** valid yet, and the scoreboard must not ship until the
differential control exists — otherwise the first thing the conformance project
publishes is an unearned green.
