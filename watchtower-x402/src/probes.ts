/**
 * The conformance probes. Each turns one invariant from *Free-Riding the Agentic
 * Web* (arXiv 2605.30998) into a question a facilitator answers from the outside.
 *
 * ═══ THE DIFFERENTIAL CONTROL, AND WHY IT IS THE WHOLE DESIGN ═══
 *
 * The first version of this file read `isValid` from one crafted request and
 * called `false` a pass. Probing the real Coinbase CDP facilitator returned PASS
 * on both invariants — and then a control showed it answers `isValid: false` to
 * EVERYTHING malformed, including its own unhandled exception
 * (`Cannot use 'in' operator to search for 'permit2Authorization' in undefined`).
 *
 * So a lone `false` is uninterpretable. It can mean:
 *   1. the facilitator checked the invariant and refused        ← conformance
 *   2. it rejected on signature grounds before reaching that check
 *   3. it threw and defaulted to false
 *
 * Only (1) is a pass, and a probe carrying a fake signature almost certainly
 * produces (2). Publishing that as conformance would be a green result from an
 * instrument that cannot tell green from broken — the exact failure the injection
 * base rates use controls to avoid, inverted: there a blind scanner made
 * everything look clean; here a facilitator that refuses everything makes every
 * probe look like a pass.
 *
 * The fix is structural. Every probe sends a MATCHED PAIR:
 *
 *   CONTROL — a payload that is valid in every way the probe is about. If the
 *             facilitator refuses this too, it is refusing for reasons unrelated
 *             to the invariant and the probe has learned NOTHING.
 *   TREATMENT — the same payload, differing ONLY in the property the invariant
 *             governs.
 *
 * A `pass` requires control-accepted AND treatment-refused. Any other combination
 * is `unknown`. That is enforced in one place (`decide`) so no probe can report a
 * pass without its control, and a test asserts it.
 *
 * ═══ WHY `unknown` IS THE COMMON ANSWER AND THAT IS CORRECT ═══
 *
 * Without a real signature from a funded wallet, the control cannot be accepted,
 * so honest verdicts are `unknown` almost everywhere. That is the instrument
 * telling the truth about its own calibration. A scoreboard full of `unknown` is
 * a scoreboard that has not lied.
 */

import { assertProbeSafeValue, type ProbeTransport } from "./safety.js";

export type Verdict = "pass" | "fail" | "unknown";
export type Invariant = "I3" | "I4";

export interface ProbeResult {
  invariant: Invariant;
  verdict: Verdict;
  /** A stable code, never a raw facilitator response. Groupable in a dashboard. */
  code: string;
  /** One line a human can read. Contains no facilitator response body. */
  detail: string;
  /** What the control did. A pass is only meaningful when this is `accepted`. */
  control: "accepted" | "refused" | "unreadable";
  observedAt: number;
}

export const CODES = {
  OK: "CONF-OK",
  ACCEPTED_CROSS_RESOURCE: "CONF-I3-ACCEPTED",
  ACCEPTED_REPLAY: "CONF-I4-ACCEPTED",
  /** The control was refused too — the facilitator rejected for unrelated reasons. */
  CONTROL_REFUSED: "CONF-CONTROL-REFUSED",
  /** The facilitator crashed rather than answering. Its own robustness defect. */
  FACILITATOR_ERROR: "CONF-FACILITATOR-ERROR",
  UNREADABLE: "CONF-UNREADABLE",
  TRANSPORT: "CONF-TRANSPORT",
  RATE_LIMITED: "CONF-RATELIMIT",
} as const;

/** What a single /verify call told us, normalised. */
interface Reply {
  isValid?: boolean;
  /** The facilitator's own reason string, used ONLY to classify, never published. */
  reason?: string;
  status: number;
}

function readReply(res: { status: number; json: unknown }): Reply {
  const out: Reply = { status: res.status };
  if (typeof res.json === "object" && res.json !== null) {
    const j = res.json as { isValid?: unknown; invalidReason?: unknown };
    if (typeof j.isValid === "boolean") out.isValid = j.isValid;
    if (typeof j.invalidReason === "string") out.reason = j.invalidReason;
  }
  return out;
}

/**
 * Reasons that mean "the facilitator did not evaluate the invariant".
 *
 * `unexpected_error` is the one observed live: an unhandled exception surfaced as
 * a refusal. Treating that as a conformance pass would credit a facilitator for
 * crashing. `missing_parameters` likewise means it never got far enough to check.
 */
const NON_EVALUATIVE = /unexpected_error|missing_parameters|invalid_request|malformed/i;

/**
 * THE ONE PLACE A VERDICT IS DECIDED. Every probe routes through this, so the
 * control requirement cannot be bypassed by a future probe that forgets it.
 */
function decide(opts: {
  invariant: Invariant;
  control: Reply;
  treatment: Reply;
  acceptedCode: string;
  passDetail: string;
  failDetail: string;
  now: number;
}): ProbeResult {
  const { invariant, control, treatment, now } = opts;

  const base = { invariant, observedAt: now } as const;

  if (control.status === 429 || treatment.status === 429) {
    return { ...base, verdict: "unknown", code: CODES.RATE_LIMITED, detail: "rate limited", control: "unreadable" };
  }

  // A facilitator that crashes has not evaluated anything.
  if (
    (control.reason && NON_EVALUATIVE.test(control.reason)) ||
    (treatment.reason && NON_EVALUATIVE.test(treatment.reason))
  ) {
    return {
      ...base,
      verdict: "unknown",
      code: CODES.FACILITATOR_ERROR,
      detail: "the facilitator returned a non-evaluative error, so the invariant was never reached",
      control: "unreadable",
    };
  }

  if (control.isValid === undefined || treatment.isValid === undefined) {
    return {
      ...base,
      verdict: "unknown",
      code: CODES.UNREADABLE,
      detail: "a response did not contain a readable isValid",
      control: "unreadable",
    };
  }

  // THE CONTROL GATE. Without an accepted control we cannot attribute the
  // treatment's refusal to the invariant, so there is no pass available here.
  if (!control.isValid) {
    return {
      ...base,
      verdict: "unknown",
      code: CODES.CONTROL_REFUSED,
      detail:
        "the control payload was refused too, so the refusal is unrelated to this invariant " +
        "(needs a signature the facilitator would accept)",
      control: "refused",
    };
  }

  return treatment.isValid
    ? { ...base, verdict: "fail", code: opts.acceptedCode, detail: opts.failDetail, control: "accepted" }
    : { ...base, verdict: "pass", code: CODES.OK, detail: opts.passDetail, control: "accepted" };
}

/**
 * A payment payload. `signature` is injected: with no signer it is a fixed
 * non-signature and the control can never be accepted (honest `unknown`); with a
 * real testnet signer the control becomes acceptable and verdicts become real.
 */
export interface PayloadParts {
  network: string;
  scheme: string;
  resource: string;
  amount: string;
  payTo: string;
  asset: string;
  signature: string;
  from: string;
  nonce: string;
  /** EIP-712 domain name of the asset. Facilitators require it in `extra`. */
  assetName?: string;
  assetVersion?: string;
}

function craft(p: PayloadParts) {
  assertProbeSafeValue(p.amount, "crafted probe payload");
  return {
    paymentPayload: {
      x402Version: 2,
      accepted: { scheme: p.scheme, network: p.network },
      resource: p.resource,
      payload: {
        signature: p.signature,
        authorization: {
          from: p.from,
          to: p.payTo,
          value: p.amount,
          validAfter: "0",
          validBefore: String(Math.floor(Date.now() / 1000) + 3600),
          nonce: p.nonce,
        },
      },
    },
    // The exact shape a live facilitator accepts, established empirically against
    // Coinbase CDP on 2026-08-01 by walking its rejections one at a time:
    //   no `extra`            -> invalid_exact_evm_missing_eip712_domain
    //   no `amount`           -> unexpected_error "Cannot convert undefined to a BigInt"
    //   both present          -> reaches on-chain simulation (insufficient_balance)
    // `maxAmountRequired` is kept alongside `amount` because v1-shaped
    // facilitators read the former and v2 reads the latter; sending both is
    // compatible with each and is how one probe serves both.
    paymentRequirements: {
      scheme: p.scheme,
      network: p.network,
      resource: p.resource,
      payTo: p.payTo,
      asset: p.asset,
      amount: p.amount,
      maxAmountRequired: p.amount,
      maxTimeoutSeconds: 60,
      description: "agent-wormhole conformance probe",
      mimeType: "application/json",
      extra: { name: p.assetName ?? "USDC", version: p.assetVersion ?? "2" },
    },
  };
}

/** The unsigned placeholder. Guarantees an honest `unknown` rather than a fake pass. */
export const NO_SIGNATURE = "0x" + "00".repeat(65);

export interface ProbeContext {
  transport: ProbeTransport;
  baseUrl: string;
  network: string;
  scheme: string;
  payTo: string;
  asset: string;
  /** The address the authorization is from. Must match the signer when signing. */
  from?: string;
  /**
   * Produces a real signature over a crafted authorization. Absent means every
   * control is refused and every verdict is honestly `unknown`.
   */
  sign?: (parts: PayloadParts) => Promise<string>;
  now?: () => number;
}

const DEAD_FROM = "0x0000000000000000000000000000000000000001";

async function send(
  ctx: ProbeContext,
  parts: PayloadParts,
): Promise<Reply | { transportError: string }> {
  const signature = ctx.sign ? await ctx.sign(parts) : NO_SIGNATURE;
  try {
    const res = await ctx.transport(ctx.baseUrl, "verify", craft({ ...parts, signature }));
    return readReply(res);
  } catch (e) {
    return { transportError: (e as Error).name || "error" };
  }
}

function transportFailed(r: unknown): r is { transportError: string } {
  return typeof r === "object" && r !== null && "transportError" in r;
}

/**
 * I3 — Context Binding. "A payment authorization must be cryptographically bound
 * to the resource it is intended for."
 *
 *   CONTROL   — payload and requirements name the SAME resource. Should be accepted.
 *   TREATMENT — identical, except the payload was framed for a DIFFERENT resource.
 *
 * A facilitator that binds context accepts the first and refuses the second. One
 * that checks only value and payee accepts both — the paper's F1, which is what
 * lets a signature bought for a cheap endpoint unlock an expensive one.
 */
export async function probeI3(ctx: ProbeContext): Promise<ProbeResult> {
  const now = (ctx.now ?? (() => Date.now()))();
  const common = {
    network: ctx.network,
    scheme: ctx.scheme,
    amount: "1",
    payTo: ctx.payTo,
    asset: ctx.asset,
    from: ctx.from ?? DEAD_FROM,
    nonce: "0x" + "11".repeat(32),
  };
  const RESOURCE_A = "https://probe.invalid/resource-A";
  const RESOURCE_B = "https://probe.invalid/resource-B";

  const control = await send(ctx, { ...common, resource: RESOURCE_A, signature: "" });
  if (transportFailed(control)) {
    return {
      invariant: "I3", verdict: "unknown", code: CODES.TRANSPORT,
      detail: `could not reach the facilitator (${control.transportError})`,
      control: "unreadable", observedAt: now,
    };
  }

  // Treatment: requirements say B, the payload was framed for A.
  const treatmentBody = craft({
    ...common, resource: RESOURCE_B,
    signature: ctx.sign ? await ctx.sign({ ...common, resource: RESOURCE_A, signature: "" }) : NO_SIGNATURE,
  });
  (treatmentBody.paymentPayload as Record<string, unknown>)["resource"] = RESOURCE_A;

  let treatment: Reply;
  try {
    treatment = readReply(await ctx.transport(ctx.baseUrl, "verify", treatmentBody));
  } catch (e) {
    return {
      invariant: "I3", verdict: "unknown", code: CODES.TRANSPORT,
      detail: `could not reach the facilitator (${(e as Error).name})`,
      control: "unreadable", observedAt: now,
    };
  }

  return decide({
    invariant: "I3",
    control,
    treatment,
    acceptedCode: CODES.ACCEPTED_CROSS_RESOURCE,
    passDetail: "accepted a matching resource and refused a mismatched one",
    failDetail: "accepted an authorization whose resource did not match the requirements",
    now,
  });
}

/**
 * I4 — Authorization Uniqueness. "A payment authorization containing nonce n is
 * consumed exactly once, regardless of how many concurrent HTTP requests."
 *
 *   CONTROL   — one authorization, sent once. Should be accepted.
 *   TREATMENT — the SAME nonce sent again, concurrently.
 *
 * A facilitator with an atomic nonce claim accepts at most one. One that reads
 * nonce state before either request writes it accepts both — the F2
 * duplicate-settlement race.
 *
 * What this does NOT do: settle either request. It observes whether the
 * facilitator would have accepted both at the verify stage, which is a weaker
 * signal than a real double-settle, and the scoreboard says so rather than
 * claiming it proved settlement behaviour.
 */
export async function probeI4(ctx: ProbeContext): Promise<ProbeResult> {
  const now = (ctx.now ?? (() => Date.now()))();
  const parts: PayloadParts = {
    network: ctx.network,
    scheme: ctx.scheme,
    resource: "https://probe.invalid/resource-A",
    amount: "1",
    payTo: ctx.payTo,
    asset: ctx.asset,
    from: ctx.from ?? DEAD_FROM,
    nonce: "0x" + "22".repeat(32),
    signature: "",
  };
  const signature = ctx.sign ? await ctx.sign(parts) : NO_SIGNATURE;
  const body = craft({ ...parts, signature });

  let a: Reply, b: Reply;
  try {
    const [ra, rb] = await Promise.all([
      ctx.transport(ctx.baseUrl, "verify", body),
      ctx.transport(ctx.baseUrl, "verify", body),
    ]);
    a = readReply(ra);
    b = readReply(rb);
  } catch (e) {
    return {
      invariant: "I4", verdict: "unknown", code: CODES.TRANSPORT,
      detail: `could not reach the facilitator (${(e as Error).name})`,
      control: "unreadable", observedAt: now,
    };
  }

  // The first response is the control (one use should be accepted); the second
  // is the treatment (the same nonce again).
  return decide({
    invariant: "I4",
    control: a,
    treatment: b,
    acceptedCode: CODES.ACCEPTED_REPLAY,
    passDetail: "accepted one use of a nonce and refused the concurrent duplicate",
    failDetail: "accepted the same nonce twice under concurrent verification",
    now,
  });
}

/** Run the first-slice probes against one facilitator, sequentially. */
export async function probeFacilitator(ctx: ProbeContext): Promise<ProbeResult[]> {
  // Sequential across invariants: a watchtower that arrives as a burst looks
  // like the attack it is checking for.
  return [await probeI3(ctx), await probeI4(ctx)];
}
