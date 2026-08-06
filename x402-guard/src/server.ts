/**
 * The HTTP transport for the verifier. Deliberately thin: it stamps time,
 * signs receipts, meters, and hands off to `verify()`. All the judgement lives
 * in verify.ts — this file must contain no verdict logic, so that the offline
 * tool and the hosted API can never drift apart.
 *
 * Built on Node's own `http` so the package keeps its zero-runtime-dependency
 * property, which is load-bearing for the trust story (the free import path
 * opens no socket unless you start this server explicitly).
 *
 * Design rules enforced here, from the product non-negotiables:
 *   - No LLM, no blocking I/O on the request path.
 *   - Billing is recorded, never awaited: our payment rail being down must not
 *     block a legitimate verification. We are the auditor, not the gatekeeper.
 *   - Only `merchant_signed` / `independent_fetch` / `facilitator_held` are
 *     billable attestations. `caller_asserted` is answered but not billed and
 *     is marked unbillable in the receipt's provenance.
 *   - No prompt/payload plaintext is retained: the receipt carries codes,
 *     buckets and a digest — never the quote text or the payment bytes.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { sign as edSign, type KeyObject } from "node:crypto";
import {
  verify,
  canonicalReceipt,
  type VerifyRequest,
  type QuoteProvenance,
} from "./verify.js";

const BILLABLE: ReadonlySet<QuoteProvenance> = new Set([
  "independent_fetch",
  "merchant_signed",
  "facilitator_held",
]);

/** Records one billable verification. Injected so the core never touches a DB. */
export type Meter = (event: {
  digest: string;
  provenance: QuoteProvenance;
  decision: string;
  chainId: number | null;
  issuedAt: string;
}) => void;

export interface ServerOptions {
  /** ed25519 private key used to sign receipts. Public half is published so
   *  anyone can verify a receipt offline. Omit to run unsigned (dev only). */
  signingKey?: KeyObject;
  /** Called once per billable verification. Must not block; enqueue and return. */
  meter?: Meter;
  /** Supplies the current time as ISO-8601. Injected so tests are deterministic
   *  and so the core never reads the clock. Defaults to Date.now at request time. */
  now?: () => string;
  /** Max request body in bytes. A verify request is small; cap it hard. */
  maxBodyBytes?: number;
}

/**
 * Build the request handler. Exposed separately from `listen` so it can be
 * mounted inside an existing server or exercised directly in tests without a
 * socket.
 */
export function createVerifyHandler(opts: ServerOptions = {}) {
  const now = opts.now ?? (() => new Date().toISOString());
  const maxBody = opts.maxBodyBytes ?? 64 * 1024;

  // Ed25519 signs the message directly (it hashes internally); the streaming
  // createSign("sha256") path throws "Unsupported crypto operation" for it.
  const sign = opts.signingKey
    ? (canonical: string): string =>
        edSign(null, Buffer.from(canonical), opts.signingKey!).toString("base64")
    : undefined;

  return async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") return send(res, 405, { error: "method_not_allowed" });
    const url = req.url ?? "";
    if (!url.startsWith("/v1/verify")) return send(res, 404, { error: "not_found" });

    let body: VerifyRequest;
    try {
      body = await readJson(req, maxBody);
    } catch (err) {
      return send(res, 400, { error: "bad_request", detail: String(err instanceof Error ? err.message : err) });
    }

    // Provenance is asserted by the transport/caller relationship, never taken
    // from the payload being judged. Absent header ⇒ caller_asserted (answered,
    // not billed). A caller wanting a billable attestation must present the
    // quote through a path that proves one of the trusted provenances.
    const provenance = readProvenance(req);
    const issuedAt = now();

    let result;
    try {
      result = await verify(body, { quoteProvenance: provenance, issuedAt, sign });
    } catch (err) {
      // A thrown verifier is an abstain to the caller — never a 500 that a
      // client might retry into a signed payment.
      return send(res, 200, {
        decision: "abstain",
        findings: [],
        reason: `verifier_error: ${err instanceof Error ? err.message : String(err)}`,
      });
    }

    // Sign the receipt if we produced one and have a key. The signature covers
    // the canonical receipt string, so a third party verifies it offline
    // against the published public key.
    let signature: string | undefined;
    if (result.receipt && sign) {
      signature = sign(canonicalReceipt(result.receipt));
    }

    // Meter after deciding, never before, and never awaited. Only billable
    // provenances count; caller_asserted is free.
    if (opts.meter && result.receipt && BILLABLE.has(provenance)) {
      try {
        opts.meter({
          digest: result.receipt.request_digest,
          provenance,
          decision: result.decision,
          chainId: result.receipt.chain_id,
          issuedAt,
        });
      } catch {
        // A metering failure must never affect the verdict returned. Swallow.
      }
    }

    return send(res, 200, {
      decision: result.decision,
      findings: result.findings,
      reason: result.reason,
      receipt: result.receipt,
      signature,
      billable: BILLABLE.has(provenance),
    });
  };
}

/** Start a standalone server. Returns the http.Server so a caller can close it. */
export function listen(port: number, opts: ServerOptions = {}) {
  const handler = createVerifyHandler(opts);
  const server = createServer((req, res) => {
    handler(req, res).catch(() => send(res, 200, { decision: "abstain", findings: [], reason: "internal_abstain" }));
  });
  server.listen(port);
  return server;
}

// --- helpers ---------------------------------------------------------------

function readProvenance(req: IncomingMessage): QuoteProvenance {
  const h = req.headers["x-quote-provenance"];
  const v = Array.isArray(h) ? h[0] : h;
  switch (v) {
    case "independent_fetch":
    case "merchant_signed":
    case "facilitator_held":
      return v;
    default:
      return "caller_asserted";
  }
}

function readJson(req: IncomingMessage, maxBytes: number): Promise<VerifyRequest> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > maxBytes) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!parsed || typeof parsed !== "object") return reject(new Error("body must be an object"));
        if (typeof parsed.network !== "string") return reject(new Error("network is required"));
        resolve(parsed as VerifyRequest);
      } catch (e) {
        reject(new Error("invalid json"));
      }
    });
    req.on("error", reject);
  });
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(json),
    // A verifier that leaks its own responses into a cache is a bug.
    "cache-control": "no-store",
  });
  res.end(json);
}
