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
import {
  verifyReceipt,
  replayMatches,
  type PublicKeyInput,
} from "./receipt.js";

/**
 * The only three decisions this package recognises.
 *
 * A verdict arriving over a socket is attacker-shaped until proven otherwise,
 * and `decision === "allow"` is a comparison that silently says false for
 * anything unexpected — which reads as safe until you notice it also means a
 * caller reading `decision` gets handed whatever the wire said. Narrow first,
 * then compare.
 */
const DECISIONS = new Set<string>(["allow", "refuse", "abstain"]);

/** Type guard, so narrowing the wire value is checked rather than asserted. */
function isDecision(v: unknown): v is Verdict["decision"] {
  return typeof v === "string" && DECISIONS.has(v);
}

/** Why a decisive verdict was downgraded to abstain. Machine-readable. */
export type IntegrityFailure =
  /** A decisive verdict carried no receipt. */
  | "no_receipt"
  /** A receipt was present but unsigned — the verifier runs without a key. */
  | "no_signature"
  /** A signature was present but the caller configured no key to check it. */
  | "no_verifying_key"
  /** The signature did not verify against the configured key. */
  | "signature_invalid"
  /** The signature verified, but the receipt attests a DIFFERENT request. */
  | "digest_mismatch"
  /** The receipt's own decision contradicts the envelope's. */
  | "envelope_mismatch"
  /** `decision` was not one of allow | refuse | abstain. */
  | "malformed_verdict";

/**
 * How `guardedPay` establishes that a decisive verdict is authentic.
 *
 * There is no default. Every implicit default here is either a silent
 * downgrade of the caller's security or a surprise breakage of their code, and
 * an explicit choice is the only honest option: `required` for anything that
 * crosses a network, `trusted_transport` for an in-process `verify()` call.
 */
export type VerifyIntegrity =
  | {
      /** Require a signed receipt, bound by digest to THIS request. */
      mode: "required";
      /**
       * The verifier's ed25519 public key. The hosted verifier publishes its
       * key at `GET <base>/v1/key`; `publicKeyFromSpkiBase64` parses that wire
       * format. Pinned by the caller, never hardcoded here — self-hosting has
       * to keep working, and a key this package chose would be a key the
       * caller cannot rotate.
       */
      publicKey: PublicKeyInput;
    }
  | {
      /**
       * Accept an unsigned verdict. ONLY correct when the transport is not a
       * network boundary — an in-process `verify()`, or a test double. A
       * remote transport under this mode has no integrity check whatsoever.
       */
      mode: "trusted_transport";
      /** Why this transport is trusted. Recorded, so the choice has a name. */
      reason: string;
    };

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
  /**
   * REQUIRED. How to establish that a decisive verdict is authentic.
   *
   * Omitting it is a compile error, and at runtime yields an abstain — never
   * an allow. This is a breaking change made deliberately: the previous
   * behaviour was to believe whatever the transport said, and there is no way
   * to fix that without the caller stating which transport they trust.
   */
  integrity: VerifyIntegrity;
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
  /**
   * True only when a signature was cryptographically verified AND the receipt
   * was bound by digest to this exact request AND the receipt's own decision
   * agreed with the envelope's. False under `trusted_transport` — which is
   * honest: an unverified verdict may well be correct, but this package did
   * not check it.
   */
  verified: boolean;
  /** Set iff a decisive verdict was downgraded to abstain for integrity. */
  integrityFailure?: IntegrityFailure;
  /** What the transport claimed, when that claim was downgraded. */
  claimedDecision?: string;
}

/**
 * Ask the checkpoint whether this payment matches this quote, and return a
 * boolean to gate signing on.
 *
 * Invariant: abstain is not an allow. `allow` is true only when the decision is
 * exactly `"allow"`; a `refuse` and an `abstain` (verifier down, undecodable
 * input, unresolved rail) both yield `allow: false`. The verifier is reached
 * only through the injected transport, so this call opens no socket of its own.
 *
 * ═══ A VERDICT OFF A SOCKET IS A CLAIM, NOT AN ANSWER (AW-07) ═══
 *
 * This function used to do `allow = result.decision === "allow"` on whatever
 * the transport returned. A stub answering `{"decision":"allow"}` with HTTP
 * 200 — no receipt, no signature — cleared a payment redirected to an
 * attacker. That made the attacker "anyone who can answer as the verifier": a
 * TLS-terminating proxy, a DNS hijack, a compromised hosted service.
 *
 * Under `mode: "required"` a decisive verdict now has to survive four checks,
 * and failing any one downgrades it to abstain (never to refuse, and never to
 * allow):
 *
 *   1. the decision is one of the three we recognise;
 *   2. a receipt is present and carries a signature that verifies against the
 *      caller's pinned key;
 *   3. `replayMatches` binds that receipt to THIS request, so a receipt
 *      lifted from some other payment does not clear this one;
 *   4. the receipt's own `decision` agrees with the envelope's.
 *
 * Check 4 is not in the audit's prescription and is not optional. Without it,
 * a MITM keeps a genuine, validly-signed *refuse* receipt and flips only the
 * envelope's `decision` to `"allow"`: signature verifies, digest matches, and
 * the guard clears a payment its own verifier refused — a complete bypass
 * built entirely from bytes the honest server emitted. Proven against this
 * code before the fix landed.
 *
 * Downgrading rather than refusing is deliberate. An attacker who can forge an
 * allow can also suppress a refuse, but suppression buys them nothing they did
 * not already have by killing the connection: both land on abstain, and
 * abstain is `allow: false`. Relabelling an unverified refuse as abstain is
 * also the honest statement — on an unsigned channel we do not know the
 * verifier refused, and consumers who blacklist a merchant on `refuse` would
 * otherwise be acting on attacker-supplied evidence.
 */
export async function guardedPay(
  opts: GuardedPayOptions,
): Promise<GuardedPayResult> {
  // The request exactly as it goes on the wire, reused for the digest check so
  // the replay comparison can never drift from what was actually sent.
  const request: VerifyRequest = {
    network: opts.network,
    quote: opts.quote,
    payload: opts.payload,
    options: opts.options,
  } as VerifyRequest;

  const integrity = opts.integrity;
  if (integrity === null || typeof integrity !== "object") {
    return {
      allow: false,
      decision: "abstain",
      findings: [],
      verified: false,
      integrityFailure: "no_verifying_key",
      reason:
        "integrity_not_configured: guardedPay requires an `integrity` option — " +
        "pass {mode:'required', publicKey} for any transport that crosses a " +
        "network, or {mode:'trusted_transport', reason} for an in-process one.",
    };
  }

  let result: VerifiedResult;
  try {
    result = await opts.transport(request);
  } catch (err) {
    // A transport that throws (verifier unreachable, malformed response) is an
    // abstain, never an allow — the agent falls back to its local guard and we
    // block nothing, but we also attest nothing.
    return {
      allow: false,
      decision: "abstain",
      findings: [],
      verified: false,
      reason: `transport_error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const claimed: unknown = (result as { decision?: unknown } | null)?.decision;
  const findings = Array.isArray(result?.findings) ? result.findings : [];

  // 1. Shape. Applies in BOTH modes: an unrecognised decision is not a verdict,
  //    and passing it through would hand the caller a `decision` field holding
  //    whatever the wire said.
  if (!isDecision(claimed)) {
    return {
      allow: false,
      decision: "abstain",
      findings,
      verified: false,
      integrityFailure: "malformed_verdict",
      claimedDecision: typeof claimed === "string" ? claimed : typeof claimed,
      reason:
        `malformed_verdict: the transport returned a decision of ` +
        `${JSON.stringify(claimed)?.slice(0, 60)}, which is not one of ` +
        `allow | refuse | abstain — treated as abstain.`,
    };
  }

  // 2. An abstain has nothing to downgrade to, and carries no clearance.
  if (claimed === "abstain") {
    return {
      allow: false,
      decision: "abstain",
      findings,
      receipt: result.receipt,
      signature: result.signature,
      reason: result.reason,
      verified: false,
    };
  }

  // 3. A transport the caller has declared not to be a network boundary.
  if (integrity.mode === "trusted_transport") {
    return {
      allow: claimed === "allow",
      decision: claimed,
      findings,
      receipt: result.receipt,
      signature: result.signature,
      reason: result.reason,
      // Never true here: nothing was checked, and saying otherwise would make
      // `verified` useless as a signal.
      verified: false,
    };
  }

  // 4. mode === "required". `claimed` is "allow" or "refuse".
  const downgrade = (
    failure: IntegrityFailure,
    detail: string,
  ): GuardedPayResult => ({
    allow: false,
    decision: "abstain",
    findings,
    // The artifact that failed is kept: an operator debugging a downgrade
    // needs to see the receipt and signature that did not check out.
    receipt: result.receipt,
    signature: result.signature,
    verified: false,
    integrityFailure: failure,
    claimedDecision: claimed,
    reason:
      `integrity_failed (${failure}): the verifier claimed "${claimed}" but ` +
      `${detail} — treated as abstain, which is not an allow.`,
  });

  if (integrity.publicKey === undefined || integrity.publicKey === null) {
    return downgrade(
      "no_verifying_key",
      "integrity.mode is 'required' and no publicKey was supplied to check it against",
    );
  }
  const receipt = result.receipt;
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)) {
    return downgrade(
      "no_receipt",
      "the response carried no receipt object, so there is nothing to verify",
    );
  }
  if (typeof result.signature !== "string" || result.signature.length === 0) {
    return downgrade(
      "no_signature",
      "the receipt is unsigned — a verifier running without a signing key " +
        "cannot produce a verdict a third party can check",
    );
  }

  const check = verifyReceipt(receipt, result.signature, integrity.publicKey);
  if (!check.valid) {
    return downgrade(
      "signature_invalid",
      `the receipt signature did not verify (${check.reason ?? "unknown reason"})`,
    );
  }
  if (!replayMatches(receipt, request)) {
    return downgrade(
      "digest_mismatch",
      "the receipt is correctly signed but attests a DIFFERENT request — it " +
        "does not bind to the payment being checked",
    );
  }
  if (receipt.decision !== claimed) {
    return downgrade(
      "envelope_mismatch",
      `the signed receipt attests "${String(receipt.decision)}" — only the ` +
        "unsigned envelope says otherwise, and the envelope is not evidence",
    );
  }

  // `verified` covers the DECISION, and this is where that is made precise.
  //
  // `findings` and `reason` are unsigned wire fields. The receipt's `codes` is
  // the signed finding list, and nothing forced the two to agree: a genuine
  // signed allow carrying `codes: ["X402-301","X402-402"]` could be returned
  // with `findings: []` and `reason: "all clear"`, and the caller got that
  // contradiction stamped `verified: true`. Reconcile against the signed list
  // rather than trusting the envelope's.
  const signedCodes = Array.isArray(receipt.codes) ? receipt.codes : [];
  const wireCodes = new Set(
    findings.map((f) => (f && typeof f === "object" ? f.code : undefined)),
  );
  const reconciled: Finding[] = findings.filter(
    (f) => f && typeof f === "object" && signedCodes.includes(f.code),
  );
  for (const code of signedCodes) {
    if (wireCodes.has(code)) continue;
    // The receipt attests a finding the envelope omitted. Surfacing the code
    // without a message is worse than the alternative only if the caller reads
    // messages and not codes; dropping it silently is worse always.
    reconciled.push({
      code,
      severity: "critical",
      message:
        "attested by the signed receipt but omitted from the response body — " +
        "the verifier recorded this finding and the transport did not relay it",
    });
  }

  return {
    allow: claimed === "allow",
    decision: claimed,
    findings: reconciled,
    receipt,
    signature: result.signature,
    // Deliberately NOT threaded through on a verified result: `reason` is
    // unsigned free text, and next to `verified: true` it reads as though the
    // verifier said it.
    verified: true,
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
  /**
   * Permit a credential header over plaintext `http:` to a non-loopback host.
   *
   * Default false, and the transport throws rather than sending. An API key on
   * the wire in clear is a key anyone on the path keeps, and the failure is
   * silent — the request succeeds, so nothing ever tells the operator. A
   * loopback host (localhost, 127.0.0.0/8, ::1) is exempt because there is no
   * path to be on.
   */
  allowInsecureAuth?: boolean;
}

/** Hosts where plaintext carries no credential exposure: there is no network. */
export function isLoopback(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return (
    h === "localhost" ||
    h === "::1" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h) ||
    /^::ffff:127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h) ||
    // WHATWG URL normalises [::ffff:127.0.0.1] to this hex form.
    /^::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}$/.test(h)
  );
}

/** Headers that carry a credential, and so must not cross a plaintext hop. */
export function carriesCredential(headers: Record<string, string>): string | null {
  for (const name of Object.keys(headers)) {
    const n = name.toLowerCase();
    if (n === "authorization" || n === "x-api-key" || n === "cookie") return name;
  }
  return null;
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

  // A credential must not cross a plaintext hop to a host on a network. This
  // is checked HERE, at construction, rather than per-request: a
  // misconfiguration should fail when the transport is built, not silently
  // leak the key on every call until someone notices. The request would
  // otherwise succeed, so nothing ever surfaces it.
  const credential = carriesCredential(opts.headers ?? {});
  if (credential !== null && opts.allowInsecureAuth !== true) {
    let url: URL | null = null;
    try {
      url = new URL(endpoint);
    } catch {
      throw new Error(`verify endpoint is not a valid URL: ${endpoint}`);
    }
    if (url.protocol !== "https:" && !isLoopback(url.hostname)) {
      throw new Error(
        `refusing to send the "${credential}" header over ${url.protocol}// to ` +
          `${url.hostname} — a credential on a plaintext hop is a credential ` +
          `anyone on the path keeps, and the request would succeed so nothing ` +
          `would tell you. Use https:, or set allowInsecureAuth: true if this ` +
          `hop is genuinely private.`,
      );
    }
  }

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
    const raw: unknown = await res.json();
    // Narrow before anything downstream reads a field. The old code cast the
    // parsed body straight to `VerifyWireResponse`, which is a compile-time
    // assertion and a runtime no-op: a JSON array, a bare string, or `null`
    // all satisfied it, and `body.decision` on a string is simply undefined.
    // `Object.create(null)` is not enough on its own here, so the fields are
    // read individually and anything unexpected is dropped rather than coerced.
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error(
        "verify endpoint returned a non-object body — not a verdict",
      );
    }
    const body = raw as Record<string, unknown>;
    const decision = body["decision"];
    if (typeof decision !== "string" || !DECISIONS.has(decision)) {
      throw new Error(
        `verify endpoint returned an unrecognised decision ` +
          `${JSON.stringify(decision)?.slice(0, 40)}`,
      );
    }
    const receipt = body["receipt"];
    const signature = body["signature"];
    return {
      decision: decision as Verdict["decision"],
      findings: Array.isArray(body["findings"])
        ? (body["findings"] as Finding[])
        : [],
      receipt:
        receipt !== null && typeof receipt === "object" && !Array.isArray(receipt)
          ? (receipt as Receipt)
          : undefined,
      // The detached signature over the canonical receipt is carried through so
      // the receipt stays offline-replayable; dropping it would strip the only
      // proof a third party can check against the published public key.
      signature:
        typeof signature === "string" && signature.length > 0
          ? signature
          : undefined,
      reason: typeof body["reason"] === "string" ? body["reason"] : undefined,
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
  /**
   * REQUIRED, and threaded verbatim into `guardedPay`. See `VerifyIntegrity`:
   * a 402 flow is the case where the transport is most likely to be remote.
   */
  integrity: VerifyIntegrity;
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
        verified: false,
      },
    };
  }

  const guard = await guardedPay({
    network: constructed.network,
    quote: opts.quote,
    payload: constructed.payload,
    transport: opts.transport,
    options: opts.options,
    integrity: opts.integrity,
  });

  return { response, allow: guard.allow, guard };
}