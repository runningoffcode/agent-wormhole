// src/client.ts
/**
 * The one-line client an agent puts in front of `sign()`.
 *
 * This is the caller's side of the checkpoint: it takes the merchant quote and
 * the payment the agent is about to sign, asks the verifier a single yes/no
 * question, and returns a boolean the agent gates on. It spans both rails
 * because the verifier does — the SDK never inspects the payment itself, it
 * only shapes the request and interprets the verdict.
 *
 * The verifier is reached through an injected transport (an async function),
 * never a hardcoded URL or `fetch`. That is the load-bearing choice: the exact
 * same `guardedPay` runs against the local core (import `verify` directly) or a
 * remote endpoint (via `makeHttpTransport`), so the free offline path and the
 * paid path can never drift. Importing this module opens no socket — the only
 * place one is touched is inside the transport `makeHttpTransport` returns, and
 * that is opt-in.
 */

import type {
  VerifyRequest,
  VerifyResult,
  Receipt,
  QuoteProvenance,
} from "./verify.js";
import type { Finding, Verdict } from "./index.js";

/**
 * A verified answer as the client sees it: the verifier's `VerifyResult` plus
 * the detached ed25519 `signature` over the canonical receipt, when the remote
 * produced one.
 *
 * The signature lives OUTSIDE `VerifyResult` on the wire (the core signs no
 * receipts — the transport does), so it is carried here as a sibling field. It
 * is what makes the receipt replay offline: a third party verifies it against
 * the published public key and recomputes the request_digest with no server
 * access. Dropping it would hand the agent a receipt it cannot prove, so the
 * transport threads it through rather than discarding it.
 */
export interface VerifiedResult extends VerifyResult {
  /** base64 ed25519 signature over `canonicalReceipt(receipt)`; absent when the
   *  verifier ran unsigned or produced no receipt (abstain). */
  signature?: string;
}

/**
 * The verifier as the client sees it: request in, verified answer out.
 * Deliberately the same async signature whether it wraps the in-process core or
 * an HTTP call, so `guardedPay` is transport-agnostic and this module opens no
 * socket by itself. An in-process transport that never signs simply omits
 * `signature`.
 */
export type VerifyTransport = (req: VerifyRequest) => Promise<VerifiedResult>;

/** Options for a single guarded payment check. */
export interface GuardedPayOptions {
  /** x402 network string from the merchant's 402 response. */
  network: string;
  /** The merchant quote (SVM `PaymentQuote` | EVM `EvmPaymentQuote`). */
  quote: unknown;
  /** The payment the agent is about to sign — bytes/base64 (SVM) or payload (EVM). */
  payload: unknown;
  /** How to reach the verifier. Injected, never constructed here. */
  transport: VerifyTransport;
  /** Optional per-lane options passed straight through to the verifier. */
  options?: VerifyRequest["options"];
}

/** The verdict the agent gates on, plus the artifact it can replay offline. */
export interface GuardedPayResult {
  /** True only on a decisive `allow`. `refuse` and `abstain` are both false. */
  allow: boolean;
  decision: Verdict["decision"];
  findings: Finding[];
  /** Present only for a decisive verdict; absent on abstain. */
  receipt?: Receipt;
  /** Detached ed25519 signature over the receipt, for offline replay. Absent on
   *  abstain, and when the verifier ran unsigned. */
  signature?: string;
  /** Set on abstain so it can never be read as an allow. */
  reason?: string;
}

/**
 * Ask the checkpoint whether this payment matches this quote, and return a
 * boolean to gate signing on.
 *
 * Invariant: abstain is not an allow. `allow` is true only when the decision is
 * exactly `"allow"`; a `refuse` and an `abstain` (verifier down, undecodable
 * input, unresolved rail) both yield `allow: false`. The verifier is reached
 * only through the injected transport, so this call opens no socket of its own.
 */
export async function guardedPay(
  opts: GuardedPayOptions,
): Promise<GuardedPayResult> {
  let result: VerifiedResult;
  try {
    result = await opts.transport({
      network: opts.network,
      quote: opts.quote,
      payload: opts.payload,
      options: opts.options,
    });
  } catch (err) {
    // A transport that throws (verifier unreachable, malformed response) is an
    // abstain, never an allow — the agent falls back to its local guard and we
    // block nothing, but we also attest nothing.
    return {
      allow: false,
      decision: "abstain",
      findings: [],
      reason: `transport_error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  return {
    allow: result.decision === "allow",
    decision: result.decision,
    findings: result.findings,
    receipt: result.receipt,
    signature: result.signature,
    reason: result.reason,
  };
}

/** Options for the HTTP transport factory. */
export interface HttpTransportOptions {
  /**
   * Value for the `X-Quote-Provenance` header. The server bills only the three
   * trusted provenances; omit (or use `caller_asserted`) for a free, unbilled
   * answer. The provenance is asserted by the caller relationship here, never
   * derived from the payload.
   */
  provenanceHeader?: QuoteProvenance;
  /** Optional extra headers (auth token, etc.). */
  headers?: Record<string, string>;
}

/** The wire shape the hosted `/v1/verify` returns, mapped back to a VerifiedResult. */
interface VerifyWireResponse {
  decision: Verdict["decision"];
  findings?: Finding[];
  reason?: string;
  receipt?: Receipt;
  signature?: string;
  billable?: boolean;
}

/**
 * Build an HTTP transport that POSTs to `<baseUrl>/v1/verify` using the global
 * `fetch`, forwarding the `X-Quote-Provenance` header.
 *
 * Invariant: this is the ONLY place in the SDK that touches a socket, and it is
 * opt-in — merely importing this module, or building a transport, opens nothing;
 * the socket is touched only when the returned function is called. `fetch` is
 * checked at call time so a runtime without it fails loudly here rather than
 * silently degrading a verdict into an allow.
 */
export function makeHttpTransport(
  baseUrl: string,
  opts: HttpTransportOptions = {},
): VerifyTransport {
  const endpoint = `${baseUrl.replace(/\/+$/, "")}/v1/verify`;
  return async (req: VerifyRequest): Promise<VerifiedResult> => {
    const f = (globalThis as { fetch?: typeof fetch }).fetch;
    if (typeof f !== "function") {
      throw new Error(
        "global fetch is not available; inject a transport that provides one",
      );
    }
    const headers: Record<string, string> = {
      "content-type": "application/json",
      ...(opts.headers ?? {}),
    };
    if (opts.provenanceHeader) {
      headers["x-quote-provenance"] = opts.provenanceHeader;
    }
    const res = await f(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      // A non-2xx from the endpoint is not a verdict — surface it as a throw so
      // guardedPay treats it as an abstain, never as an allow.
      throw new Error(`verify endpoint returned ${res.status}`);
    }
    const body = (await res.json()) as VerifyWireResponse;
    return {
      decision: body.decision,
      findings: body.findings ?? [],
      receipt: body.receipt,
      // The detached signature over the canonical receipt is carried through so
      // the receipt stays offline-replayable; dropping it would strip the only
      // proof a third party can check against the published public key.
      signature: body.signature,
      reason: body.reason,
    };
  };
}

/** Options for the ergonomic 402-aware fetch wrapper. */
export interface GuardedFetchOptions {
  /** The merchant quote to verify the constructed payment against. */
  quote: unknown;
  /**
   * Given the 402 response, produce the network + payment the agent would sign.
   * Runs only on a 402. Returning `undefined` means "could not construct" and
   * yields an abstain — never an allow.
   */
  extractPayment: (
    res: Response,
  ) =>
    | Promise<{ network: string; payload: unknown } | undefined>
    | { network: string; payload: unknown }
    | undefined;
  /** How to reach the verifier. Injected, never constructed here. */
  transport: VerifyTransport;
  /** Optional per-lane options passed through to the verifier. */
  options?: VerifyRequest["options"];
}

/** The outcome of a guarded fetch: the response, plus the guard verdict if a 402 was hit. */
export interface GuardedFetchResult {
  /** The HTTP response (the original, or the 402 that triggered the check). */
  response: Response;
  /** True when no payment was required (non-402), or when the guard allowed it. */
  allow: boolean;
  /** The guard verdict, present only when a 402 was encountered and verified. */
  guard?: GuardedPayResult;
}

/**
 * Perform an HTTP request and, if it comes back `402 Payment Required`, verify
 * the payment the agent would construct against the merchant quote before the
 * agent is cleared to sign and retry.
 *
 * Invariant: abstain is not an allow. A non-402 response is allowed untouched;
 * on a 402, `allow` mirrors `guardedPay` — true only on a decisive `allow`, and
 * a failure to construct the payment (`extractPayment` returning `undefined`)
 * abstains rather than clears. `fetch` is resolved at call time and its absence
 * throws rather than degrading into an allow.
 */
export async function guardedFetch(
  url: string | URL,
  init: RequestInit | undefined,
  opts: GuardedFetchOptions,
): Promise<GuardedFetchResult> {
  const f = (globalThis as { fetch?: typeof fetch }).fetch;
  if (typeof f !== "function") {
    throw new Error("global fetch is not available for guardedFetch");
  }

  const response = await f(url, init);
  if (response.status !== 402) {
    // No payment demanded — nothing to guard, allow the response through.
    return { response, allow: true };
  }

  const constructed = await opts.extractPayment(response);
  if (!constructed) {
    // Could not build the payment to check — abstain, never allow.
    return {
      response,
      allow: false,
      guard: {
        allow: false,
        decision: "abstain",
        findings: [],
        reason: "could_not_construct_payment_from_402",
      },
    };
  }

  const guard = await guardedPay({
    network: constructed.network,
    quote: opts.quote,
    payload: constructed.payload,
    transport: opts.transport,
    options: opts.options,
  });

  return { response, allow: guard.allow, guard };
}