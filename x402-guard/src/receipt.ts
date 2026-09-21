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

import { createPublicKey, verify as edVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import {
  canonicalReceipt,
  requestDigest,
  type Receipt,
  type VerifyRequest,
} from "./verify.js";

/** An ed25519 signature is exactly this long. Anything else is not one. */
const ED25519_SIGNATURE_BYTES = 64;

/**
 * The only keys `canonicalReceipt` signs. Anything else on a receipt object is
 * outside the signature, so a receipt carrying one is not the object that was
 * signed. Kept in lockstep with `canonicalReceipt` — if that gains a field,
 * this must gain it too, or genuine receipts start failing.
 */
const SIGNED_RECEIPT_KEYS: ReadonlySet<string> = new Set([
  "v",
  "decision",
  "codes",
  "amount_bucket",
  "chain_id",
  "lane",
  "quote_provenance",
  "request_digest",
  "issued_at",
]);

/** Result of an authenticity check. `reason` is set only when `valid` is false. */
export interface ReceiptCheck {
  valid: boolean;
  reason?: string;
}

/** A public key accepted for verification: a PEM string or a node KeyObject. */
export type PublicKeyInput = string | KeyObject;

/**
 * Parse the published wire format of a verifier key into a usable KeyObject.
 *
 * The hosted verifier publishes its key at `GET <base>/v1/key` as
 * `{"algorithm":"ed25519","format":"spki-der-base64","public_key":"MCowBQYDK2Vw..."}`.
 * That is base64 of SPKI DER, NOT PEM, and `createPublicKey` will not take it
 * directly. Without this helper every consumer hand-writes the PEM armouring,
 * and the ones who get it wrong reach for the opt-out instead — which is how a
 * verification control quietly stops being used.
 *
 * Throws on anything that is not an ed25519 public key. That is deliberate: a
 * key that cannot be parsed must fail loudly at configuration time, not turn
 * into a silent "cannot verify" at payment time.
 */
export function publicKeyFromSpkiBase64(base64: string): KeyObject {
  if (typeof base64 !== "string" || base64.trim().length === 0) {
    throw new Error("verifier public key is empty");
  }
  const der = Buffer.from(base64.trim(), "base64");
  if (der.length === 0) {
    throw new Error("verifier public key is not valid base64");
  }
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  if (key.type !== "public") {
    throw new Error("verifier key is not a public key");
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error(
      `verifier public key is ${String(key.asymmetricKeyType)}, not ed25519 — ` +
        "this package verifies ed25519 receipt signatures only",
    );
  }
  return key;
}

/**
 * Read a PEM string as a key WITHOUT silently deriving a public key from a
 * private one.
 *
 * `createPublicKey` accepts a private PEM and hands back its public half, which
 * is exactly the behaviour that let a pasted signing key verify. Parsing as a
 * public key only means a private PEM lands in the catch and is reported as
 * what it is.
 */
function createPublicKeyFromPem(pem: string): KeyObject {
  if (/PRIVATE KEY/.test(pem)) {
    throw new Error("a PRIVATE key was supplied where the public key belongs");
  }
  return createPublicKey(pem);
}

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
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    // An Array with the receipt's keys set as properties canonicalises to a
    // byte-identical string, so it verified. Nothing downstream expects an
    // array, and a checker that accepts one accepts a shape its callers do not
    // model.
    return { valid: false, reason: "receipt is not an object" };
  }
  if (receipt.v !== 1) {
    return { valid: false, reason: `unsupported receipt version ${String(receipt.v)}` };
  }
  // `canonicalReceipt` serialises exactly nine keys, so any OTHER key rides
  // along entirely unsigned — an attacker staples `policy:{spend_cap_waived:
  // true}` or `operator_note:"kill switch disabled"` onto a genuine receipt,
  // the signature still verifies, and a consumer that renders the receipt
  // shows attacker text beside a verified stamp. "Valid" has to mean THIS
  // OBJECT was signed, not that nine of its keys were.
  for (const key of Object.keys(receipt)) {
    if (!SIGNED_RECEIPT_KEYS.has(key)) {
      return {
        valid: false,
        reason: `receipt carries an unsigned field "${key.slice(0, 40)}" — the ` +
          "signature covers only the standard receipt fields",
      };
    }
  }
  if (typeof signatureBase64 !== "string" || signatureBase64.length === 0) {
    return { valid: false, reason: "signature is missing or not a base64 string" };
  }

  // `Buffer.from(s, "base64")` SILENTLY DISCARDS every character outside the
  // base64 alphabet, so it never throws and the catch below was dead code:
  // `sig + "!!!!"`, `sig + "\n\n"` and a base64url-swapped `sig` all decoded to
  // the same 64 bytes and verified. That makes the signature string a
  // non-canonical identifier — any cache, dedupe or log keyed on it is
  // bypassable by appending a newline. Reject the encoding itself, then check
  // the length ed25519 actually has.
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64)) {
    return {
      valid: false,
      reason: "signature is not canonical base64",
    };
  }
  const signature = Buffer.from(signatureBase64, "base64");
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    return {
      valid: false,
      reason: `signature is ${signature.length} bytes, not ${ED25519_SIGNATURE_BYTES}`,
    };
  }

  let canonical: string;
  try {
    canonical = canonicalReceipt(receipt);
  } catch (err) {
    return { valid: false, reason: `could not canonicalize receipt: ${message(err)}` };
  }

  // A key of type "private" verifies happily, because node derives the public
  // half. An operator who pastes the signing key into the verifying slot then
  // has a working checker and a leaked private key, and nothing tells them.
  //
  // My first version of this check guarded on `typeof publicKey === "object"`,
  // which covered the KeyObject half of `PublicKeyInput` and left the STRING
  // half — the PEM an operator is most likely to paste — completely
  // unchecked, while the comment claimed the case was handled. Normalise both
  // shapes to a KeyObject first, then ask the question once.
  let key: KeyObject;
  try {
    key =
      typeof publicKey === "string"
        ? createPublicKeyFromPem(publicKey)
        : (publicKey as KeyObject);
  } catch (err) {
    return { valid: false, reason: `verifying key could not be read: ${message(err)}` };
  }
  if (key === null || typeof key !== "object") {
    return { valid: false, reason: "verifying key is not a key" };
  }
  if (key.type !== "public") {
    return {
      valid: false,
      reason: `verifying key is a ${String(key.type)} key, not a public key`,
    };
  }
  if (key.asymmetricKeyType !== "ed25519") {
    return {
      valid: false,
      reason: `verifying key is ${String(key.asymmetricKeyType)}, not ed25519`,
    };
  }

  try {
    // Ed25519: algorithm MUST be null. createVerify() throws for Ed25519 keys.
    const ok = edVerify(null, Buffer.from(canonical, "utf8"), key, signature);
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