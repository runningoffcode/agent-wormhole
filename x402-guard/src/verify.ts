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
/**
 * The most a REQUEST may raise the priority-fee cap to.
 *
 * The package default is 0.01 SOL (10,000,000 lamports). This ceiling is
 * deliberately higher — some legitimate payers do pay real priority fees
 * during congestion — but bounded, because an unbounded caller-supplied cap is
 * not a cap at all. An operator who needs more sets it in their own call to
 * `inspectPayment`, which is trusted code rather than a wire request.
 */
const MAX_CALLER_PRIORITY_FEE_LAMPORTS = 100_000_000n; // 0.1 SOL

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

  // 1b. SANITISE CALLER OPTIONS (AW-09).
  //
  // Three option keys are the ONLY thing behind three checks, one of which
  // this package rates critical:
  //   maxPriorityFeeLamports -> X402-010 (critical)
  //   nowSeconds, clockSkewSeconds -> X402-105
  //
  // On the HTTP path there is no BigInt revival, and that is worse rather
  // than better in two ways. Relational comparison between a BigInt and a
  // JSON number is legal, so `feeLamports > cap` silently honours an
  // un-revived number and the fee cap becomes caller-settable over plain
  // HTTP. And with a STRING operand `now + skew` is string concatenation:
  // 1780000000n + "0" === "17800000000", pushing the expiry bound to roughly
  // the year 2534. Measured: an authorization that expired an hour ago
  // refuses bare and allows with `{"clockSkewSeconds":"0"}`.
  //
  // The rule this package already applies to `assetTransferMethod` and
  // `expectedPayer` is: a value we cannot read is an abstain, never a pass.
  // The clock keys are test seams — the transport stamps time — so on a
  // caller-supplied request they are dropped outright rather than trusted.
  const rawOptions = (req.options ?? {}) as Record<string, unknown>;
  const optionFindings: Finding[] = [];
  // A NULL PROTOTYPE, deliberately. My first version of this sanitiser used a
  // plain object literal, and `safeOptions[k] = v` for k === "__proto__"
  // invokes the Object.prototype setter rather than creating an own key: the
  // attacker's object becomes the prototype, and safeOptions.nowSeconds /
  // .maxPriorityFeeLamports then read back THEIR values through the chain.
  // Zero findings are emitted, so the bypass is silent and restores exactly
  // the caller control of the clock and the critical X402-010 fee cap that
  // this function exists to remove. Verified: 0 findings, nowSeconds
  // 9999999999, cap "99999999999999".
  const safeOptions: Record<string, unknown> = Object.create(null);
  for (const [k, v] of Object.entries(rawOptions)) {
    // Explicit, so the drop is visible rather than merely harmless.
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      optionFindings.push({
        code: "X402-011",
        severity: "medium",
        message: `option ${k} was ignored: it cannot name a verifier option`,
      });
      continue;
    }
    if (k === "nowSeconds" || k === "clockSkewSeconds") {
      // A REQUEST must not be able to move the clock its own verdict is
      // judged against. These remain available to direct callers of
      // inspectAuthorization/inspectPayment, which is what a test seam is
      // for; they are not something a wire request may carry. Dropping is
      // safe because both default to real time and zero skew.
      optionFindings.push({
        code: "X402-011",
        severity: "medium",
        message: `caller-supplied ${k} was ignored: the clock is stamped by the transport, not the request`,
      });
      continue;
    }
    if (k === "maxPriorityFeeLamports") {
      // Only a real integer may weaken a check. A string, float or NaN is a
      // value we cannot read, so the option is dropped and said out loud.
      let asBig: bigint | null = null;
      try {
        if (typeof v === "bigint") asBig = v;
        else if (typeof v === "number" && Number.isSafeInteger(v)) asBig = BigInt(v);
        else if (typeof v === "string" && /^-?[0-9]+$/.test(v.trim())) asBig = BigInt(v.trim());
      } catch {
        asBig = null;
      }
      if (asBig === null || asBig < 0n) {
        optionFindings.push({
          code: "X402-011",
          severity: "medium",
          message: `option ${k} is not a non-negative integer and was ignored`,
        });
        continue;
      }
      // AW-09, the fee half. The shape was validated and the VALUE never was,
      // so a caller could hand themselves any ceiling they liked: a real v0
      // transaction carrying a 1.4 SOL priority fee refuses with X402-010 —
      // which this package rates critical — and allows with zero findings once
      // the request carries `maxPriorityFeeLamports: "99999999999999"`.
      //
      // That is the same shape as the clock half fixed above: an option the
      // attacker controls disarming the check it is checked against. The fee
      // is the one Solana field that drains the payer while the payment itself
      // stays perfectly conforming, so the cap is a control, not a preference.
      //
      // A caller may TIGHTEN the cap — that is their own money and a stricter
      // answer is always safe. Loosening it past the operator's ceiling is
      // refused and said out loud, rather than silently clamped, because a
      // caller who asked for a weaker check and got a stronger one should know
      // the answer they received is not the one they requested.
      if (asBig > MAX_CALLER_PRIORITY_FEE_LAMPORTS) {
        optionFindings.push({
          code: "X402-011",
          severity: "medium",
          message:
            `option ${k} (${asBig.toString()}) exceeds the ceiling this ` +
            `verifier will accept from a request ` +
            `(${MAX_CALLER_PRIORITY_FEE_LAMPORTS.toString()}) and was ignored — ` +
            `a caller may tighten the priority-fee cap but never loosen it`,
        });
        continue;
      }
      safeOptions[k] = asBig;
      continue;
    }
    safeOptions[k] = v;
  }

  // 2. Dispatch to the lane that owns the payment shape. Both return the same
  //    Verdict, so the merge below is uniform.
  let laneVerdict: Verdict;
  try {
    if (lane === "svm") {
      laneVerdict = inspectPayment(
        req.payload as Uint8Array | string,
        req.quote as PaymentQuote,
        safeOptions as InspectOptions,
      );
    } else {
      /* THE QUOTE INHERITS THE REQUEST'S NETWORK WHEN IT HAS NONE OF ITS OWN.
       *
       * `verify()` resolves the rail from the top-level `network`, but the EVM
       * lane looks the EIP-712 domain up by the quote's OWN network — so a
       * caller who sent `network` exactly where the docs say to, and nowhere
       * else, got an abstain reading "quote network (undefined) could not be
       * resolved". Two fields, one of them undocumented, and the failure
       * looked like an unsupported chain rather than a missing field.
       *
       * The request's network is the merchant's 402 network, which is what the
       * quote's network means, so carrying it across is the same fact and not
       * a guess. A quote that DOES carry its own network keeps it: if the two
       * disagree that is a real contradiction, and the lane's own chain check
       * must be the thing that catches it. */
      const quote = req.quote as EvmPaymentQuote | undefined;
      const evmQuote =
        quote && typeof quote === "object" && typeof quote.network !== "string"
          ? ({ ...quote, network: req.network } as EvmPaymentQuote)
          : (quote as EvmPaymentQuote);
      laneVerdict = await inspectAuthorization(
        evmQuote,
        req.payload as EvmPayload | unknown,
        safeOptions as object,
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
      findings: [...findings, ...optionFindings, ...laneVerdict.findings],
      reason: laneVerdict.reason ?? `${lane} lane abstained`,
    };
  }

  const merged = [...findings, ...optionFindings, ...laneVerdict.findings];
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
  // AW-08. The digest used to hash three things, so inputs that MOVE THE
  // VERDICT sat outside it: `options` was never hashed at all, yet
  // expectedPayer (X402-108), the clock keys (X402-105) and
  // maxPriorityFeeLamports (X402-010) each flip the answer. Measured: an
  // identical request plus `options.expectedPayer` refused where the bare one
  // allowed, at the SAME digest, and `replayMatches` returned true for both.
  //
  // A digest that omits a verdict-determining input makes `replayMatches` —
  // documented as "is it this exact request?" — answer yes to a different
  // question. Options are canonicalised by sorted key so ordering cannot
  // fork the digest, and BigInt is stringified because JSON.stringify throws
  // on it.
  const canonicalOptions = (() => {
    const o = req.options as Record<string, unknown> | undefined;
    if (!o || typeof o !== "object") return null;
    // Only the options that can actually STEER the verdict. My first version
    // hashed the raw object, which had it backwards in both directions: two
    // byte-identical verdicts got different digests because one carried a
    // nowSeconds the verifier had already discarded, and a key the verifier
    // ignores could fork the digest of an otherwise identical request.
    //
    // The digest answers "is it this exact request?", so it must cover
    // exactly what the answer depends on — no more, no less.
    const STEERING = ["expectedPayer", "maxPriorityFeeLamports"];
    const out: Record<string, unknown> = {};
    for (const k of STEERING.slice().sort()) {
      if (!Object.prototype.hasOwnProperty.call(o, k)) continue;
      const v = o[k];
      out[k] = typeof v === "bigint" ? String(v) : v;
    }
    return Object.keys(out).length > 0 ? out : null;
  })();

  const canonical = JSON.stringify({
    network: req.network,
    quote: canonicalizeQuote(req.quote),
    payload: canonicalizePayload(req.payload),
    options: canonicalOptions,
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

/**
 * Make a value safe to hash, without changing what it means.
 *
 * `JSON.stringify` THROWS on a BigInt, and every real EVM authorization carries
 * them (`value`, `validAfter`, `validBefore` are all bigint in the documented
 * shape). `replayMatches` catches that throw and returns false, so before this
 * existed, wiring the digest check into the client path would have failed every
 * genuine EVM payment closed and reported it as `digest_mismatch` — a
 * serialisation bug misdiagnosed to the operator as a replay attack.
 *
 * A `toJSON()` method is the same hazard from the other side: the client hashes
 * the live object while the server hashed whatever `JSON.stringify` produced on
 * the wire, so an honest request forks into two digests. Reading the primitive
 * out here means both sides hash the same bytes.
 */
/**
 * Hash a value the verifier reads as an INTEGER by its numeric value, not its
 * spelling.
 *
 * `toBig` in the EVM lane accepts `10000`, `"10000"` and `"0x2710"` as the same
 * amount and allows all three. Hashing the spelling instead gave one payment
 * three digests: an agent that verified in-process with a bigint and replayed
 * on the wire as a decimal string got `digest_mismatch` on its own honest
 * request. Mirrors toBig deliberately — if that widens, this must widen with
 * it, or the two disagree about what "the same request" means.
 */
function hashableAmount(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "number") {
    return Number.isSafeInteger(v) && v >= 0 ? BigInt(v).toString() : hashable(v);
  }
  if (typeof v === "string") {
    const t = v.trim();
    if (/^0x[0-9a-fA-F]+$/.test(t) || /^[0-9]+$/.test(t)) {
      try {
        return BigInt(t).toString();
      } catch {
        return hashable(v);
      }
    }
  }
  return hashable(v);
}

function hashable(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (v === null || v === undefined) return null;
  if (typeof v === "object") {
    // Dates, class instances and anything with toJSON serialise differently
    // depending on whether they crossed a socket. Collapse to the wire form.
    const j = (v as { toJSON?: () => unknown }).toJSON;
    if (typeof j === "function") {
      try {
        return hashable(j.call(v));
      } catch {
        return null;
      }
    }
    return null;
  }
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
    return v;
  }
  // Functions, symbols: not data, and not hashable. Never silently skipped.
  return null;
}

function canonicalizeQuote(quote: unknown): unknown {
  if (!quote || typeof quote !== "object") return quote ?? null;
  const q = quote as Record<string, unknown>;
  // Only verdict-determining fields; free text is excluded on purpose.
  //
  // `network` is here because it STEERS THE VERDICT: verifyEvm reads it to
  // resolve the chainId, and the chainId keys the trusted EIP-712 domain
  // table. Without it, a receipt genuinely signed for a Base payment replayed
  // as `network: "polygon"` still matched — a signed, digest-bound allow for a
  // payment on a different chain.
  return {
    network: hashable(q.network),
    payTo: hashable(q.payTo),
    asset: hashable(q.asset),
    amount: hashableAmount(q.amount),
    // THE TEXT IS NOT DECORATION. `verify()` runs `inspectQuoteText` over
    // exactly these five fields and a hit is a hard, early refuse. Leaving
    // them out of the digest meant a clean quote and a prompt-injected one
    // shared a digest, so a MITM could submit the clean twin, keep the
    // genuinely signed allow, and return it for the poisoned request —
    // `verified: true` on a quote the verifier would have refused.
    //
    // Hashed rather than inlined so the request digest still carries no quote
    // plaintext; that property is why a receipt can be published at all.
    text: textDigest(q),
    // Routes the EVM lane to a permit2 / erc7710 abstain or an X402-103
    // refuse. Decisive, therefore in the digest.
    assetTransferMethod: hashable(
      (q.extra as Record<string, unknown> | undefined)?.["assetTransferMethod"],
    ),
  };
}

/**
 * SHA-256 over the quote's free-text fields, or null when it carries none.
 *
 * Reads the SAME five keys `extractQuoteText` feeds to the injection scanner,
 * so the digest covers precisely what can flip the verdict. If that list ever
 * widens, this must widen with it — a field the scanner refuses on but the
 * digest ignores is a receipt that binds to the wrong request.
 */
function textDigest(q: Record<string, unknown>): string | null {
  const parts: string[] = [];
  for (const k of ["description", "memo", "note", "resource", "extra"]) {
    const v = q[k];
    if (typeof v === "string") parts.push(`${k}=${v}`);
  }
  if (parts.length === 0) return null;
  return createHash("sha256").update(parts.join("\u0000")).digest("hex");
}

/**
 * A permit grants standing authority, so its presence and its limit both
 * change what a verdict means. Hashed field-by-field rather than whole so a
 * BigInt `value` — the normal shape — cannot throw the digest.
 */
function canonicalizePermit(permit: unknown): unknown {
  if (!permit || typeof permit !== "object") return hashable(permit);
  const p = permit as Record<string, unknown>;
  return {
    spender: hashable(p.spender),
    value: hashableAmount(p.value ?? p.amount),
    deadline: hashableAmount(p.deadline),
    nonce: hashable(p.nonce),
  };
}

function canonicalizePayload(payload: unknown): unknown {
  if (typeof payload === "string") {
    // Bytes/base64 — hash-stable as-is (the SVM lane; the signed transaction
    // bytes already bind every field including the destination).
    return payload;
  }
  // The SVM lane also accepts raw bytes, and they used to fall into the object
  // branch below where every field collapsed to null — so ALL Uint8Array
  // payloads digested identically and a receipt minted for one transaction
  // replay-matched a completely different one. Normalising to base64 also
  // makes the same transaction hash the same whether it arrived as bytes or as
  // the base64 the wire carries.
  if (ArrayBuffer.isView(payload) || payload instanceof ArrayBuffer) {
    const view =
      payload instanceof ArrayBuffer
        ? new Uint8Array(payload)
        : new Uint8Array(
            (payload as ArrayBufferView).buffer,
            (payload as ArrayBufferView).byteOffset,
            (payload as ArrayBufferView).byteLength,
          );
    return Buffer.from(view).toString("base64");
  }
  if (payload && typeof payload === "object") {
    const p = payload as Record<string, unknown>;

    // EIP-3009 / EVM shape nests the binding fields under `authorization`, and
    // the signature commits to all of them. Reading only top-level `to/value`
    // here was blind to the destination — two payloads differing only in payee
    // hashed identically, so a receipt for a legitimate payment could be
    // replay-bound to a redirected one. Prefer the authorization + signature,
    // which uniquely determine where the money goes.
    // `primaryType` and `permit` steer the verdict too: inspectAuthorization
    // gates on primaryType, and `permit` is the standing-authority-grant path.
    // Omitting them let a signed allow for an EIP-3009 transfer be replayed
    // onto a payload that also carried an unlimited Permit.
    const steering = {
      primaryType: hashable(p.primaryType),
      permit: canonicalizePermit(p.permit),
      asset: hashable(p.asset),
      // Routes to the permit2 / erc7710 abstains and the X402-103 refuse.
      assetTransferMethod: hashable(p.assetTransferMethod),
    };

    const auth = p.authorization as Record<string, unknown> | undefined;
    if (auth && typeof auth === "object") {
      return {
        // The signature alone binds the whole authorization; include it plus
        // the human-legible fields so the digest changes on any of them.
        signature: hashable(p.signature),
        to: hashable(auth.to),
        from: hashable(auth.from),
        value: hashableAmount(auth.value),
        validAfter: hashableAmount(auth.validAfter),
        validBefore: hashableAmount(auth.validBefore),
        nonce: hashable(auth.nonce),
        ...steering,
      };
    }

    // Fallback for a flat payload shape: bind top-level fields, and the
    // signature if one is present.
    return {
      signature: hashable(p.signature),
      to: hashable(p.to),
      value: hashableAmount(p.value ?? p.amount),
      from: hashable(p.from),
      ...steering,
    };
  }
  return payload ?? null;
}

// Re-export the quote builders so a caller can go from a raw 402 to a verify
// request without importing three modules.
export { quoteFromRequirements, evmQuoteFromRequirements };
