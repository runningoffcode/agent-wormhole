// src/receipt.ts
/**
 * Offline receipt verification — the piece that makes a receipt trustworthy
 * without ever touching our servers.
 *
 * A receipt is only as good as a third party's ability to check it alone. This
 * module is exactly that check: given a receipt, its base64 ed25519 signature,
 * and our published public key, anyone can confirm (a) we signed this receipt
 * and (b) it is the receipt for a specific request they hold — with no network
 * call, no database, no plaintext quote, and no access to us.
 *
 * Two independent claims, verified separately:
 *   - `verifyReceipt` — authenticity. The signature is ours over the canonical
 *     receipt bytes. This alone says nothing about *which* request it covers.
 *   - `replayMatches` — binding. The receipt's `request_digest` equals the
 *     digest of the request the verifier claims it is for. Recomputed with the
 *     issuer's own `requestDigest`, so the replayer can never silently drift
 *     from how the receipt was minted.
 *
 * Zero runtime dependencies. Node's built-in crypto only. Ed25519 signatures
 * are verified with `verify(null, ...)` — NOT `createVerify`, which throws for
 * Ed25519 because the curve hashes the message internally.
 */

import { verify as edVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import {
  canonicalReceipt,
  requestDigest,
  type Receipt,
  type VerifyRequest,
} from "./verify.js";

/** Result of an authenticity check. `reason` is set only when `valid` is false. */
export interface ReceiptCheck {
  valid: boolean;
  reason?: string;
}

/** A public key accepted for verification: a PEM string or a node KeyObject. */
export type PublicKeyInput = string | KeyObject;

/**
 * Verify a receipt's ed25519 signature against a published public key, offline.
 *
 * Recomputes the canonical receipt string with the issuer's own
 * `canonicalReceipt` (so key order and field selection match exactly), then
 * checks the signature over those bytes. Returns `{valid:true}` only when the
 * signature verifies; every failure path returns `{valid:false, reason}` and
 * never throws for ordinary bad input — a receipt under suspicion must not be
 * able to crash the checker.
 *
 * @param receipt         The receipt object as issued (schema v:1).
 * @param signatureBase64 The base64 ed25519 signature the issuer returned.
 * @param publicKey       Our published public key, PEM or KeyObject.
 */
export function verifyReceipt(
  receipt: Receipt,
  signatureBase64: string,
  publicKey: PublicKeyInput,
): ReceiptCheck {
  if (!receipt || typeof receipt !== "object") {
    return { valid: false, reason: "receipt is not an object" };
  }
  if (receipt.v !== 1) {
    return { valid: false, reason: `unsupported receipt version ${String(receipt.v)}` };
  }
  if (typeof signatureBase64 !== "string" || signatureBase64.length === 0) {
    return { valid: false, reason: "signature is missing or not a base64 string" };
  }

  let signature: Buffer;
  try {
    signature = Buffer.from(signatureBase64, "base64");
  } catch (err) {
    return { valid: false, reason: `signature is not valid base64: ${message(err)}` };
  }
  if (signature.length === 0) {
    return { valid: false, reason: "signature decoded to zero bytes" };
  }

  let canonical: string;
  try {
    canonical = canonicalReceipt(receipt);
  } catch (err) {
    return { valid: false, reason: `could not canonicalize receipt: ${message(err)}` };
  }

  try {
    // Ed25519: algorithm MUST be null. createVerify() throws for Ed25519 keys.
    const ok = edVerify(null, Buffer.from(canonical, "utf8"), publicKey, signature);
    return ok ? { valid: true } : { valid: false, reason: "signature does not verify" };
  } catch (err) {
    // A malformed key or wrong key type lands here — not a valid signature.
    return { valid: false, reason: `verification error: ${message(err)}` };
  }
}

/**
 * Confirm a receipt is the receipt for a specific request, offline.
 *
 * Recomputes the request digest with the issuer's own `requestDigest` (imported
 * from `verify.ts` rather than reimplemented — the replayer and the issuer must
 * hash identical bytes or this proof is worthless) and compares it, constant of
 * intent, against `receipt.request_digest`. Proves same-input without us ever
 * having stored the request.
 *
 * Authenticity is a separate question: a `true` here on an unsigned or forged
 * receipt means only that the digests match. Always pair with `verifyReceipt`.
 *
 * @param receipt The receipt whose `request_digest` is being checked.
 * @param request The request a third party believes the receipt covers.
 * @returns true iff the recomputed digest equals the receipt's digest.
 */
export function replayMatches(receipt: Receipt, request: VerifyRequest): boolean {
  if (!receipt || typeof receipt !== "object") return false;
  if (typeof receipt.request_digest !== "string" || receipt.request_digest.length === 0) {
    return false;
  }
  let recomputed: string;
  try {
    recomputed = requestDigest(request);
  } catch {
    // An undecodable request cannot bind to a receipt. Never true on error.
    return false;
  }
  return timingSafeStrEqual(recomputed, receipt.request_digest);
}

/**
 * Length-independent, content-constant string comparison for the two hex
 * digests. Both are our own hex output so this is belt-and-suspenders, but a
 * plain `===` on a security-relevant equality is a smell worth avoiding.
 */
function timingSafeStrEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** Narrow an unknown throw to a printable message without leaking a stack. */
function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * CLI-style entry point: `node receipt.js <receipt.json> <sig.b64> <pubkey.pem>`.
 *
 * Reads the receipt JSON, the base64 signature, and a PEM public key from disk,
 * verifies authenticity, and prints `valid` / `invalid`. Exits non-zero on an
 * invalid or malformed receipt so it composes in a shell pipeline. This does
 * NOT run at import time — it is invoked only from the import.meta guard below,
 * and only reaches for `node:fs` when actually run, keeping the import path
 * dependency- and I/O-free.
 */
export async function main(argv: string[]): Promise<number> {
  const [receiptPath, sigPath, pubkeyPath] = argv;
  if (!receiptPath || !sigPath || !pubkeyPath) {
    process.stderr.write(
      "usage: receipt <receipt.json> <signature.b64> <pubkey.pem>\n",
    );
    return 2;
  }

  // fs is imported lazily, inside main, so the module's import path opens no
  // handle and the zero-dependency free path stays pure.
  const { readFile } = await import("node:fs/promises");

  let receipt: Receipt;
  let signatureBase64: string;
  let publicKeyPem: string;
  try {
    receipt = JSON.parse(await readFile(receiptPath, "utf8")) as Receipt;
    signatureBase64 = (await readFile(sigPath, "utf8")).trim();
    publicKeyPem = await readFile(pubkeyPath, "utf8");
  } catch (err) {
    process.stderr.write(`could not read inputs: ${message(err)}\n`);
    return 2;
  }

  const result = verifyReceipt(receipt, signatureBase64, publicKeyPem);
  if (result.valid) {
    process.stdout.write("valid\n");
    return 0;
  }
  process.stdout.write(`invalid: ${result.reason ?? "unknown"}\n`);
  return 1;
}

// Run main() only when this file is the process entry point, never on import.
// Compare properly URL-encoded file URLs: `import.meta.url` is percent-encoded
// (spaces, etc.), so `pathToFileURL(argv[1]).href` — not a naive `file://` +
// argv[1] concatenation — is the only comparison that holds for real paths.
// This block does no I/O of its own; it only reads process.argv and, when this
// is the entry point, calls main() which lazy-imports fs. Importing the module
// still opens nothing.
if (
  typeof process !== "undefined" &&
  Array.isArray(process.argv) &&
  typeof process.argv[1] === "string" &&
  process.argv[1].length > 0
) {
  // pathToFileURL is imported here at eval time of the guard, not at module
  // top level, and only when there is an argv[1] to compare — the free import
  // path (no argv, or imported as a dependency) never reaches this line.
  const { pathToFileURL } = await import("node:url");
  if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    main(process.argv.slice(2)).then(
      (code) => process.exit(code),
      (err) => {
        process.stderr.write(`${message(err)}\n`);
        process.exit(2);
      },
    );
  }
}