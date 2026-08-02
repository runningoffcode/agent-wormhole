/**
 * The conformance probes. Each turns one invariant from *Free-Riding the Agentic
 * Web* (arXiv 2605.30998) into a question a facilitator answers from the outside.
 *
 * ═══ WHAT A PROBE IS, AND WHY IT CAN BE HONEST ═══
 *
 * A probe is not a classifier. It does not guess whether a facilitator is safe;
 * it asks a question whose correct answer is known in advance and records which
 * answer came back. `/verify` returns `{ isValid }` — a boolean — and for a
 * deliberately-malformed authorisation the conforming answer is `false`. So a
 * probe has no false-negative rate to argue about: either the facilitator said
 * `isValid: true` to something it should have refused, or it did not.
 *
 * That is why this is sellable in a way a detector is not. It is arithmetic on a
 * yes/no, the same shape as quote conformance.
 *
 * ═══ THE FIRST SLICE IS I3 AND I4, AND ONLY THOSE ═══
 *
 * Both are observable entirely at `/verify`, which does not move value. I1, I2
 * and I5 need settlement or timing to be meaningful, so they are deliberately not
 * in this slice — see safety.ts. The paper found I3 and I4 violations to be
 * near-universal (38% of hosts exposed same-price sibling clusters), so this is
 * also where the signal is densest.
 *
 * ═══ VERDICTS ARE THREE-VALUED, AND `unknown` IS NOT A PASS ═══
 *
 * A facilitator that rate-limits us, times out, or returns a shape we cannot read
 * yields `unknown`. It never yields `pass`. "We could not check" and "we checked
 * and it was fine" are different statements, and a scoreboard that conflates them
 * publishes a clean bill of health it did not earn. This is the same rule as the
 * watch poller's `last_poll_ok`.
 */

import {
  assertProbeSafeValue,
  type ProbeTransport,
} from "./safety.js";

export type Verdict = "pass" | "fail" | "unknown";

export interface ProbeResult {
  invariant: "I3" | "I4";
  verdict: Verdict;
  /** A stable code, never a raw facilitator response. Groupable in a dashboard. */
  code: string;
  /** One line a human can read. Contains no facilitator response body. */
  detail: string;
  observedAt: number;
}

export const CODES = {
  OK: "CONF-OK",
  ACCEPTED_CROSS_RESOURCE: "CONF-I3-ACCEPTED",
  ACCEPTED_REPLAY: "CONF-I4-ACCEPTED",
  UNREADABLE: "CONF-UNREADABLE",
  TRANSPORT: "CONF-TRANSPORT",
  RATE_LIMITED: "CONF-RATELIMIT",
} as const;

/**
 * Read `{ isValid }` out of a facilitator response.
 *
 * Returns `undefined` when the response is not a shape we recognise — which
 * becomes `unknown`, never `pass`. A facilitator whose reply we cannot parse has
 * not demonstrated conformance.
 */
function readIsValid(json: unknown): boolean | undefined {
  if (typeof json !== "object" || json === null) return undefined;
  const v = (json as { isValid?: unknown }).isValid;
  return typeof v === "boolean" ? v : undefined;
}

/**
 * A minimal, deliberately-invalid payment payload and its requirements.
 *
 * Every constructed amount goes through `assertProbeSafeValue`, so a probe can
 * never carry a value worth having even if every other layer failed. The
 * signature is a fixed non-signature: it is not a real authorisation and cannot
 * become one, which is the point — we are testing whether the facilitator
 * notices, not smuggling a payment past it.
 */
function craftedPayload(opts: {
  network: string;
  scheme: string;
  resource: string;
  amount: string;
  payTo: string;
  asset: string;
}) {
  assertProbeSafeValue(opts.amount, "crafted probe payload");
  return {
    paymentPayload: {
      x402Version: 2,
      accepted: { scheme: opts.scheme, network: opts.network },
      payload: {
        // Not a valid signature and not derived from any key we hold. A
        // conforming facilitator rejects this on signature grounds alone; the
        // probe is interesting only when it does NOT.
        signature: "0x" + "00".repeat(65),
        authorization: {
          from: "0x0000000000000000000000000000000000000001",
          to: opts.payTo,
          value: opts.amount,
          validAfter: "0",
          validBefore: "0",
          nonce: "0x" + "11".repeat(32),
        },
      },
    },
    paymentRequirements: {
      scheme: opts.scheme,
      network: opts.network,
      resource: opts.resource,
      payTo: opts.payTo,
      asset: opts.asset,
      maxAmountRequired: opts.amount,
      maxTimeoutSeconds: 60,
    },
  };
}

export interface ProbeContext {
  transport: ProbeTransport;
  baseUrl: string;
  network: string;
  scheme: string;
  payTo: string;
  asset: string;
  now?: () => number;
}

/**
 * I3 — Context Binding. "A payment authorization must be cryptographically bound
 * to the resource it is intended for."
 *
 * The probe: present one authorisation whose REQUIREMENTS name resource B while
 * the payload was framed for resource A. A facilitator that binds context
 * notices the mismatch. One that only checks value and payee does not — that is
 * the paper's F1, cross-resource substitution, and it is what lets a signature
 * bought for a cheap endpoint unlock an expensive one at the same price.
 *
 * A `false` here is a PASS: the facilitator refused, which is correct. We are
 * probing for a wrong `true`.
 */
export async function probeI3(ctx: ProbeContext): Promise<ProbeResult> {
  const now = ctx.now ?? (() => Date.now());
  const body = craftedPayload({
    network: ctx.network,
    scheme: ctx.scheme,
    resource: "https://probe.invalid/resource-B",
    amount: "1",
    payTo: ctx.payTo,
    asset: ctx.asset,
  });
  // The tell: the payload's own resource framing disagrees with the
  // requirements. A context-binding facilitator refuses on that alone.
  (body.paymentPayload as Record<string, unknown>)["resource"] =
    "https://probe.invalid/resource-A";

  let res: { status: number; json: unknown };
  try {
    res = await ctx.transport(ctx.baseUrl, "verify", body);
  } catch (e) {
    return {
      invariant: "I3",
      verdict: "unknown",
      code: CODES.TRANSPORT,
      detail: `could not reach the facilitator (${(e as Error).name})`,
      observedAt: now(),
    };
  }
  if (res.status === 429) {
    return { invariant: "I3", verdict: "unknown", code: CODES.RATE_LIMITED, detail: "rate limited", observedAt: now() };
  }
  const isValid = readIsValid(res.json);
  if (isValid === undefined) {
    return {
      invariant: "I3",
      verdict: "unknown",
      code: CODES.UNREADABLE,
      detail: `response did not contain a readable isValid (HTTP ${res.status})`,
      observedAt: now(),
    };
  }
  return isValid
    ? {
        invariant: "I3",
        verdict: "fail",
        code: CODES.ACCEPTED_CROSS_RESOURCE,
        detail: "accepted an authorization whose resource did not match the requirements",
        observedAt: now(),
      }
    : {
        invariant: "I3",
        verdict: "pass",
        code: CODES.OK,
        detail: "refused a cross-resource authorization",
        observedAt: now(),
      };
}

/**
 * I4 — Authorization Uniqueness. "A payment authorization containing nonce n is
 * consumed exactly once, regardless of how many concurrent HTTP requests."
 *
 * The probe: send the SAME nonce twice, concurrently. A facilitator with an
 * atomic nonce claim answers at most one of them affirmatively. One that reads
 * the nonce's state before either request writes it can answer both — the
 * paper's F2 duplicate-settlement race, where concurrent requests each get the
 * service and one pays.
 *
 * Note what this probe does NOT do: it does not settle either request. It reads
 * whether the facilitator would have accepted both, at the verify stage. That is
 * a weaker signal than observing a real double-settle, and the scoreboard says so
 * rather than claiming it proved settlement behaviour.
 */
export async function probeI4(ctx: ProbeContext): Promise<ProbeResult> {
  const now = ctx.now ?? (() => Date.now());
  const body = craftedPayload({
    network: ctx.network,
    scheme: ctx.scheme,
    resource: "https://probe.invalid/resource-A",
    amount: "1",
    payTo: ctx.payTo,
    asset: ctx.asset,
  });

  let a: { status: number; json: unknown };
  let b: { status: number; json: unknown };
  try {
    [a, b] = await Promise.all([
      ctx.transport(ctx.baseUrl, "verify", body),
      ctx.transport(ctx.baseUrl, "verify", body),
    ]);
  } catch (e) {
    return {
      invariant: "I4",
      verdict: "unknown",
      code: CODES.TRANSPORT,
      detail: `could not reach the facilitator (${(e as Error).name})`,
      observedAt: now(),
    };
  }
  if (a.status === 429 || b.status === 429) {
    return { invariant: "I4", verdict: "unknown", code: CODES.RATE_LIMITED, detail: "rate limited", observedAt: now() };
  }
  const va = readIsValid(a.json);
  const vb = readIsValid(b.json);
  if (va === undefined || vb === undefined) {
    return {
      invariant: "I4",
      verdict: "unknown",
      code: CODES.UNREADABLE,
      detail: "one or both responses did not contain a readable isValid",
      observedAt: now(),
    };
  }
  return va && vb
    ? {
        invariant: "I4",
        verdict: "fail",
        code: CODES.ACCEPTED_REPLAY,
        detail: "accepted the same nonce twice under concurrent verification",
        observedAt: now(),
      }
    : {
        invariant: "I4",
        verdict: "pass",
        code: CODES.OK,
        detail: "did not accept the same nonce twice",
        observedAt: now(),
      };
}

/** Run the first-slice probes against one facilitator. */
export async function probeFacilitator(ctx: ProbeContext): Promise<ProbeResult[]> {
  // Sequential, not parallel across invariants: a watchtower that arrives as a
  // burst looks like the attack it is checking for, and a facilitator that
  // rate-limits us produces `unknown` rather than data.
  const i3 = await probeI3(ctx);
  const i4 = await probeI4(ctx);
  return [i3, i4];
}
