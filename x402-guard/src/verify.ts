/**
 * The verifier core behind the hosted API.
 *
 * One question, answered for any supported rail: does the payment an agent is
 * about to sign match the quote the merchant issued? This module is the whole
 * product minus the HTTP — deliberately, so it stays testable without a server
 * and so the same code runs offline in the free tool and behind the paid
 * endpoint. The transport is a thin adapter (see `server.ts`); the decision
 * lives here.
 *
 * It does not manage agents, watch traffic, or hold funds. It is called once,
 * at the signing checkpoint, and returns refuse/allow plus a receipt. Nothing
 * on the hot path: no LLM, no network, no per-call I/O. A caller that cannot
 * reach us falls back to the same logic locally and signs nothing we would
 * have refused.
 */

import { inspectPayment, inspectPaymentPayload, quoteFromRequirements } from "./index.js";
import type { PaymentQuote, Verdict, Finding, InspectOptions } from "./index.js";
import { inspectAuthorization, evmQuoteFromRequirements } from "./evm.js";
import type { EvmPaymentQuote, EvmPayload } from "./evm.js";
import { inspectQuoteText } from "./quotetext.js";
import { parseNetwork } from "./network.js";
import { amountBucket } from "./sink.js";
import { createHash } from "node:crypto";

/** Which rail a request is on. Resolved from the quote's network string. */
export type Lane = "svm" | "evm";

/**
 * The request every caller sends. `network` is the x402 network string as it
 * appeared in the 402 response (CAIP-2 `eip155:<id>`, `solana`, `base`, …).
 * `quote` and `payload` are passed through to the lane that owns them; they are
 * intentionally left as `unknown` here because each lane validates its own
 * shape and abstains rather than trusts.
 */
export interface VerifyRequest {
  /** x402 network string from the merchant's 402 response. */
  network: string;
  /** The merchant quote. SVM: PaymentQuote. EVM: EvmPaymentQuote. */
  quote: unknown;
  /** The payment the agent is about to send. Bytes/base64 (SVM) or payload (EVM). */
  payload: unknown;
  /** Optional per-lane options (priority-fee cap, expected owner, …). */
  options?: InspectOptions & Record<string, unknown>;
}

/** A receipt is what makes this a correctness product and not a notary. */
export interface Receipt {
  /** Stable schema version so an offline replayer knows how to read it. */
  v: 1;
  /** The decision this receipt attests. */
  decision: Verdict["decision"];
  /** Rule ids only — never the payment, never the quote text. */
  codes: string[];
  /** Coarse bucket of the quoted amount, never the exact figure. */
  amount_bucket: string | null;
  /** Resolved chain id, or null if the network could not be resolved. */
  chain_id: number | null;
  /** Which lane produced the decision. */
  lane: Lane | null;
  /**
   * Where the quote came from, per the non-negotiables: only the first three
   * are billable attestations. `caller_asserted` must never read as an allow
   * a third party can rely on.
   */
  quote_provenance: QuoteProvenance;
  /** SHA-256 over the canonical request, so a replayer verifies same-input. */
  request_digest: string;
  /**
   * Caller-supplied timestamp, echoed. This module never calls Date.now() —
   * time is an input, so a receipt is a pure function of its request and
   * replays identically. The transport stamps it.
   */
  issued_at: string;
}

export type QuoteProvenance =
  | "independent_fetch"
  | "merchant_signed"
  | "facilitator_held"
  | "caller_asserted";

export interface VerifyResult {
  decision: Verdict["decision"];
  findings: Finding[];
  /** Present only for a non-abstain decision; the offline-replayable artifact. */
  receipt?: Receipt;
  /** Set on abstain so it is never mistaken for an allow. */
  reason?: string;
}

/**
 * Resolve the lane from the network string. Solana has no chain id in the
 * EVM sense; everything parseNetwork resolves to a chainId is EVM. Anything
 * else is unresolved and the caller must abstain rather than guess a rail.
 */
export function laneFor(network: string): { lane: Lane | null; chainId: number | null } {
  const n = typeof network === "string" ? network.trim().toLowerCase() : "";
  if (n === "solana" || n === "svm" || n.startsWith("solana:")) {
    return { lane: "svm", chainId: null };
  }
  const chainId = parseNetwork(network);
  if (chainId !== null) return { lane: "evm", chainId };
  return { lane: null, chainId: null };
}

/**
 * The one call. Runs the quote-text guard first (an injected or unicode-tagged
 * quote poisons every downstream comparison), then dispatches to the rail that
 * owns the payment shape. Returns a receipt only for a decisive verdict —
 * an abstain gets a reason instead, because a receipt for "we could not tell"
 * is exactly the notary trap.
 */
export async function verify(
  req: VerifyRequest,
  ctx: VerifyContext,
): Promise<VerifyResult> {
  const findings: Finding[] = [];

  // 0. The quote text itself, before it is trusted for anything. A quote that
  //    carries an injected directive or invisible unicode is refused here so it
  //    never reaches the amount/destination comparison as authoritative.
  const quoteText = extractQuoteText(req.quote);
  if (quoteText) {
    const textVerdict = inspectQuoteText(quoteText);
    if (textVerdict.decision === "refuse") {
      // A poisoned quote is decisive on its own — do not proceed to compare
      // against a quote we already do not trust.
      return finalize("refuse", textVerdict.findings, req, ctx, null, null);
    }
    findings.push(...textVerdict.findings);
  }

  // 1. Pick the rail. An unresolved network abstains — never a default chain.
  const { lane, chainId } = laneFor(req.network);
  if (lane === null) {
    return {
      decision: "abstain",
      findings,
      reason: `unresolved network "${String(req.network)}" — refusing to guess a rail`,
    };
  }

  // 2. Dispatch to the lane that owns the payment shape. Both return the same
  //    Verdict, so the merge below is uniform.
  let laneVerdict: Verdict;
  try {
    if (lane === "svm") {
      laneVerdict = inspectPayment(
        req.payload as Uint8Array | string,
        req.quote as PaymentQuote,
        (req.options ?? {}) as InspectOptions,
      );
    } else {
      laneVerdict = await inspectAuthorization(
        req.quote as EvmPaymentQuote,
        req.payload as EvmPayload | unknown,
        (req.options ?? {}) as object,
      );
    }
  } catch (err) {
    // A lane throwing is an abstain, not an allow. A crash must never read as
    // a clean payment — a verifier that answers "invalid" to its own unhandled
    // exceptions cannot tell a refusal from a breakage.
    return {
      decision: "abstain",
      findings,
      reason: `verifier error on ${lane} lane: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (laneVerdict.decision === "abstain") {
    return {
      decision: "abstain",
      findings: [...findings, ...laneVerdict.findings],
      reason: laneVerdict.reason ?? `${lane} lane abstained`,
    };
  }

  const merged = [...findings, ...laneVerdict.findings];
  // Any refuse finding makes the whole verdict a refuse; the quote-text guard
  // above can only add warnings by this point (a refuse there returned early).
  const decision: Verdict["decision"] =
    laneVerdict.decision === "refuse" || merged.some((f) => f.severity === "critical")
      ? "refuse"
      : laneVerdict.decision;

  return finalize(decision, merged, req, ctx, lane, chainId);
}

/** Context the transport supplies. Kept out of the request so the core stays pure. */
export interface VerifyContext {
  /** Provenance of the quote, asserted by the transport, not the caller payload. */
  quoteProvenance: QuoteProvenance;
  /** Caller-supplied timestamp; the core never reads the clock itself. */
  issuedAt: string;
  /** Signs a canonical receipt string, returning base64. Kept injectable so
   *  the core has no key material and the same logic runs unsigned offline. */
  sign?: (canonical: string) => string;
}

function finalize(
  decision: Verdict["decision"],
  findings: Finding[],
  req: VerifyRequest,
  ctx: VerifyContext,
  lane: Lane | null,
  chainId: number | null,
): VerifyResult {
  const receipt = buildReceipt(decision, findings, req, ctx, lane, chainId);
  return { decision, findings, receipt };
}

function buildReceipt(
  decision: Verdict["decision"],
  findings: Finding[],
  req: VerifyRequest,
  ctx: VerifyContext,
  lane: Lane | null,
  chainId: number | null,
): Receipt {
  const amount = readAmount(req.quote);
  return {
    v: 1,
    decision,
    codes: findings.map((f) => f.code).sort(),
    amount_bucket: amountBucket(amount),
    chain_id: chainId,
    lane,
    quote_provenance: ctx.quoteProvenance,
    request_digest: requestDigest(req),
    issued_at: ctx.issuedAt,
  };
}

/**
 * SHA-256 over a canonicalized view of the request. Only the fields that
 * determine the verdict go in — never free quote text — so the digest lets an
 * offline replayer confirm "same inputs" without carrying plaintext.
 *
 * Exported so the offline replayer in `receipt.ts` recomputes the digest with
 * the *exact* same logic the issuer used. Previously private; promoted to a
 * shared export so the replayer and the issuer cannot drift.
 */
export function requestDigest(req: VerifyRequest): string {
  const canonical = JSON.stringify({
    network: req.network,
    quote: canonicalizeQuote(req.quote),
    payload: canonicalizePayload(req.payload),
  });
  return createHash("sha256").update(canonical).digest("hex");
}

/** Canonical receipt string a transport signs. Stable key order, no plaintext. */
export function canonicalReceipt(r: Receipt): string {
  return JSON.stringify({
    v: r.v,
    decision: r.decision,
    codes: r.codes,
    amount_bucket: r.amount_bucket,
    chain_id: r.chain_id,
    lane: r.lane,
    quote_provenance: r.quote_provenance,
    request_digest: r.request_digest,
    issued_at: r.issued_at,
  });
}

// --- small, defensive extractors -------------------------------------------
// Every one tolerates an unknown shape and returns undefined/null rather than
// throwing, because the caller's input is exactly the thing under suspicion.

function extractQuoteText(quote: unknown): string | undefined {
  if (typeof quote === "string") return quote;
  if (quote && typeof quote === "object") {
    const q = quote as Record<string, unknown>;
    const parts: string[] = [];
    for (const k of ["description", "memo", "note", "resource", "extra"]) {
      const v = q[k];
      if (typeof v === "string") parts.push(v);
    }
    return parts.length ? parts.join("\n") : undefined;
  }
  return undefined;
}

function readAmount(quote: unknown): unknown {
  if (quote && typeof quote === "object") {
    return (quote as Record<string, unknown>).amount;
  }
  return null;
}

function canonicalizeQuote(quote: unknown): unknown {
  if (!quote || typeof quote !== "object") return quote ?? null;
  const q = quote as Record<string, unknown>;
  // Only verdict-determining fields; free text is excluded on purpose.
  return {
    payTo: q.payTo ?? null,
    asset: q.asset ?? null,
    amount: q.amount ?? null,
  };
}

function canonicalizePayload(payload: unknown): unknown {
  if (typeof payload === "string") {
    // Bytes/base64 — hash-stable as-is (the SVM lane; the signed transaction
    // bytes already bind every field including the destination).
    return payload;
  }
  if (payload && typeof payload === "object") {
    const p = payload as Record<string, unknown>;

    // EIP-3009 / EVM shape nests the binding fields under `authorization`, and
    // the signature commits to all of them. Reading only top-level `to/value`
    // here was blind to the destination — two payloads differing only in payee
    // hashed identically, so a receipt for a legitimate payment could be
    // replay-bound to a redirected one. Prefer the authorization + signature,
    // which uniquely determine where the money goes.
    const auth = p.authorization as Record<string, unknown> | undefined;
    if (auth && typeof auth === "object") {
      return {
        // The signature alone binds the whole authorization; include it plus
        // the human-legible fields so the digest changes on any of them.
        signature: p.signature ?? null,
        to: auth.to ?? null,
        from: auth.from ?? null,
        value: auth.value ?? null,
        validAfter: auth.validAfter ?? null,
        validBefore: auth.validBefore ?? null,
        nonce: auth.nonce ?? null,
      };
    }

    // Fallback for a flat payload shape: bind top-level fields, and the
    // signature if one is present.
    return {
      signature: p.signature ?? null,
      to: p.to ?? null,
      value: p.value ?? p.amount ?? null,
      from: p.from ?? null,
    };
  }
  return payload ?? null;
}

// Re-export the quote builders so a caller can go from a raw 402 to a verify
// request without importing three modules.
export { quoteFromRequirements, evmQuoteFromRequirements };
