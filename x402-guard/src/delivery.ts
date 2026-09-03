// src/delivery.ts
/**
 * Delivery conformance — "did I get what I paid for?"
 *
 * x402 as deployed is pay-then-hope: the quote names a resource, the payment
 * settles, and nothing anywhere verifies that the response delivered is the
 * resource quoted. Both failure classes are documented in the wild — served-
 * but-not-paid's mirror, PAID-BUT-DENIED (a 4xx/5xx after settlement), and
 * the double-charge shape (a second 402 for a payment already made). This
 * module closes the loop the same way the payment side does: arithmetic over
 * what actually arrived, offline, no RPC, no LLM.
 *
 * THE CODE FAMILY IS A DELIBERATE MNEMONIC. X402-401 paid-but-denied,
 * X402-402 asked-to-pay-again, X402-403 wrong content type, X402-404 empty
 * body, X402-406 unparseable JSON — each echoes the HTTP status semantics a
 * reader already knows. The echo is the point: these findings are ABOUT the
 * HTTP exchange.
 *
 * THE TRUST HALO IS THE SECOND HALF. Paid content is the cheapest injection
 * delivery channel ever built — the agent pays the attacker to hand it text
 * it will then trust precisely because it paid. So textual bodies are also
 * run through the quote-text scanner, and its findings ride in the same
 * verdict: a paid response carrying "ignore your previous instructions" is
 * not a good delivery, whatever the status code said.
 *
 * THE RECEIPT completes the chain the verify receipt starts: request_digest
 * links back to the pre-signature verification of the same purchase, and
 * resource_digest (sha256 over the delivered bytes) is the "got a" half of
 * paid-a-got-a. A third party holding the response bytes replays the digest
 * with no server access. Codes and digests only — the receipt never carries
 * the content.
 */

import { createHash } from "node:crypto";
import type { Finding, Verdict } from "./index.js";
import { inspectQuoteText } from "./quotetext.js";

/** What the transport hands us about the delivered response. */
export interface DeliveredResponse {
  /** HTTP status of the response received AFTER paying. */
  status: number;
  /** Content-Type header, if any. Parameters (charset etc.) are ignored. */
  contentType?: string | null;
  /** The delivered body. String is treated as UTF-8 text. */
  body?: Uint8Array | string;
  /** The delivered body as base64 (the MCP path). Wins over `body` if set. */
  bodyBase64?: string;
}

/** The quote fields delivery cares about — a subset of any x402 quote shape. */
export interface DeliveryQuote {
  /** The mimeType the merchant quoted, if any. */
  mimeType?: string;
  [k: string]: unknown;
}

export interface DeliveryReceipt {
  v: 1;
  decision: Verdict["decision"];
  /** Rule ids only — never the content. */
  codes: string[];
  /** sha256 over the delivered bytes — the "got a" half of paid-a-got-a. */
  resource_digest: string | null;
  byte_len: number | null;
  http_status: number;
  /** Normalized media type ("application/json"), or null when absent. */
  content_type: string | null;
  /** Links to the verify receipt of the same purchase, when the caller has it. */
  request_digest: string | null;
  /** Transport-stamped, or null when no transport stamped one. */
  issued_at: string | null;
}

export interface DeliveryOptions {
  /** The verify receipt's request_digest, to chain the two receipts. */
  requestDigest?: string;
  /** Transport-supplied timestamp; this module never reads the clock. */
  issuedAt?: string;
  /** Cap on how much body text the injection scan reads. Default 128KiB. */
  maxScanBytes?: number;
}

export interface DeliveryResult extends Verdict {
  receipt?: DeliveryReceipt;
}

const DEFAULT_MAX_SCAN_BYTES = 128 * 1024;
/** Bodies above this abstain rather than being half-judged. */
const MAX_BODY_BYTES = 32 * 1024 * 1024;

/** "application/json; charset=utf-8" -> "application/json". */
function mediaType(v: string | null | undefined): string | null {
  if (typeof v !== "string") return null;
  const t = v.split(";")[0].trim().toLowerCase();
  return t.length > 0 ? t : null;
}

function isTextual(mt: string | null): boolean {
  if (mt === null) return false;
  return (
    mt.startsWith("text/") ||
    mt === "application/json" ||
    mt.endsWith("+json") ||
    mt === "application/xml" ||
    mt.endsWith("+xml")
  );
}

/**
 * The check. Pure: bytes in, verdict out; time arrives as an option. Fails
 * closed the same way the payment side does — a body that cannot be decoded
 * abstains, because "checked" on bytes nobody checked is the failure mode
 * this package exists to prevent.
 */
export function inspectDelivery(
  quote: DeliveryQuote,
  response: DeliveredResponse,
  opts: DeliveryOptions = {},
): DeliveryResult {
  const findings: Finding[] = [];

  if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
    return abstain("response status is not a readable HTTP status", quote, response, opts);
  }

  // --- the body bytes -------------------------------------------------------
  let bytes: Uint8Array | null = null;
  if (typeof response.bodyBase64 === "string") {
    try {
      bytes = Uint8Array.from(Buffer.from(response.bodyBase64, "base64"));
    } catch {
      return abstain("body is not decodable base64", quote, response, opts);
    }
  } else if (typeof response.body === "string") {
    bytes = new TextEncoder().encode(response.body);
  } else if (response.body instanceof Uint8Array) {
    bytes = response.body;
  }
  if (bytes !== null && bytes.length > MAX_BODY_BYTES) {
    return abstain(
      `body exceeds ${MAX_BODY_BYTES} bytes — refusing to half-judge a truncated delivery`,
      quote, response, opts,
    );
  }

  const contentType = mediaType(response.contentType);

  // --- 1. asked to pay AGAIN (X402-402) ------------------------------------
  if (response.status === 402) {
    findings.push({
      code: "X402-402",
      severity: "critical",
      message:
        "the server answered 402 again AFTER payment — a request to pay a second " +
        "time for the same resource. Do not pay again without the operator; a " +
        "facilitator that lost the payment and a merchant double-charging look " +
        "identical from here",
      actual: "HTTP 402",
    });
  }
  // --- 2. paid but denied (X402-401) ---------------------------------------
  else if (response.status >= 400) {
    findings.push({
      code: "X402-401",
      severity: "critical",
      message:
        "the payment settled and the resource was refused — paid-but-denied. " +
        "The quote was for the resource, not for the attempt",
      actual: `HTTP ${response.status}`,
    });
  }

  const delivered = response.status >= 200 && response.status < 300;

  // --- 3. wrong content type (X402-403) ------------------------------------
  const quoted = mediaType(quote.mimeType ?? null);
  if (delivered && quoted !== null && contentType !== null && contentType !== quoted) {
    findings.push({
      code: "X402-403",
      severity: "high",
      message:
        "delivered content-type contradicts what the quote promised — the bytes " +
        "may be an error page, a decoy, or the wrong resource entirely",
      expected: quoted,
      actual: contentType,
    });
  }

  // --- 4. empty delivery (X402-404) ----------------------------------------
  if (delivered && bytes !== null && bytes.length === 0) {
    findings.push({
      code: "X402-404",
      severity: "high",
      message: "a successful status delivered zero bytes — paid for nothing",
      actual: "0 bytes",
    });
  }

  // --- 5. quoted JSON that does not parse (X402-406) ------------------------
  if (delivered && bytes !== null && bytes.length > 0 && quoted !== null &&
      (quoted === "application/json" || quoted.endsWith("+json"))) {
    try {
      JSON.parse(new TextDecoder("utf-8", { fatal: false }).decode(bytes));
    } catch {
      findings.push({
        code: "X402-406",
        severity: "high",
        message:
          "the quote promised JSON and the delivered body does not parse — " +
          "whatever arrived, it is not the quoted resource",
      });
    }
  }

  // --- 6. the trust halo: scan textual paid content -------------------------
  // Paid content is the cheapest injection channel ever built: the agent pays
  // the attacker to hand it text it will then trust BECAUSE it paid. Textual
  // bodies run through the same scanner the quote does; its codes ride along.
  if (delivered && bytes !== null && bytes.length > 0 &&
      isTextual(contentType ?? quoted)) {
    const cap = opts.maxScanBytes ?? DEFAULT_MAX_SCAN_BYTES;
    const text = new TextDecoder("utf-8", { fatal: false })
      .decode(bytes.subarray(0, cap));
    const scan = inspectQuoteText(text);
    findings.push(...scan.findings);
  }

  const decision: Verdict["decision"] = findings.some((f) => f.severity === "critical")
    ? "refuse"
    : "allow";
  return {
    decision,
    findings,
    receipt: buildReceipt(decision, findings, response.status, contentType, bytes, opts),
  };
}

function abstain(
  reason: string,
  _quote: DeliveryQuote,
  response: DeliveredResponse,
  opts: DeliveryOptions,
): DeliveryResult {
  // An abstain still gets a receipt SHAPE (status is a fact we observed), but
  // no resource digest — we are not attesting bytes we refused to judge.
  return {
    decision: "abstain",
    findings: [],
    reason,
    receipt: buildReceipt(
      "abstain",
      [],
      Number.isInteger(response.status) ? response.status : 0,
      mediaType(response.contentType),
      null,
      opts,
    ),
  };
}

function buildReceipt(
  decision: Verdict["decision"],
  findings: Finding[],
  status: number,
  contentType: string | null,
  bytes: Uint8Array | null,
  opts: DeliveryOptions,
): DeliveryReceipt {
  return {
    v: 1,
    decision,
    codes: [...new Set(findings.map((f) => f.code))].sort(),
    resource_digest:
      bytes === null ? null : createHash("sha256").update(bytes).digest("hex"),
    byte_len: bytes === null ? null : bytes.length,
    http_status: status,
    content_type: contentType,
    request_digest: opts.requestDigest ?? null,
    issued_at: opts.issuedAt ?? null,
  };
}

/** Canonical string a transport signs. Stable key order, no content. */
export function canonicalDeliveryReceipt(r: DeliveryReceipt): string {
  return JSON.stringify({
    v: r.v,
    decision: r.decision,
    codes: r.codes,
    resource_digest: r.resource_digest,
    byte_len: r.byte_len,
    http_status: r.http_status,
    content_type: r.content_type,
    request_digest: r.request_digest,
    issued_at: r.issued_at,
  });
}

/**
 * The offline replay: does this receipt describe these exact bytes? A third
 * party holding the response needs no server and no key to check the claim.
 */
export function deliveryMatches(receipt: DeliveryReceipt, body: Uint8Array): boolean {
  if (receipt.resource_digest === null) return false;
  const digest = createHash("sha256").update(body).digest("hex");
  return digest === receipt.resource_digest && receipt.byte_len === body.length;
}
