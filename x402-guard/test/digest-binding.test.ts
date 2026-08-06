/**
 * Regression: the request digest must bind the EIP-3009 destination.
 *
 * `requestDigest` originally read only top-level `payload.to/value/from`, but an
 * EIP-3009 payload nests those under `payload.authorization`. The result was a
 * digest blind to the payee: two payments identical except for where the money
 * went hashed the same. That defeats the whole point of `replayMatches` — a
 * receipt issued for a legitimate payment could be replay-bound to a redirected
 * one, which is exactly the substitution this product exists to refuse.
 *
 * These tests pin the binding directly, so the blindness cannot return quietly.
 */

import { describe, it, expect } from "vitest";
import { requestDigest, type VerifyRequest, type Receipt } from "../src/verify.js";
import { replayMatches } from "../src/receipt.js";

const QUOTE = {
  payTo: "0x1111111111111111111111111111111111111111",
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  amount: "1000000",
};

function evmReq(to: string, signature = "0xabc"): VerifyRequest {
  return {
    network: "eip155:8453",
    quote: QUOTE,
    payload: {
      signature,
      assetTransferMethod: "eip3009",
      authorization: {
        from: "0xSIGNER",
        to,
        value: "1000000",
        validAfter: "0",
        validBefore: "0",
        nonce: "0xaa",
      },
    },
  };
}

const MERCHANT = "0x1111111111111111111111111111111111111111";
const ATTACKER = "0x2222222222222222222222222222222222222222";

describe("requestDigest binds the EIP-3009 destination", () => {
  it("a redirected payee changes the digest", () => {
    expect(requestDigest(evmReq(MERCHANT))).not.toBe(requestDigest(evmReq(ATTACKER)));
  });

  it("the same request hashes identically (stable)", () => {
    expect(requestDigest(evmReq(MERCHANT))).toBe(requestDigest(evmReq(MERCHANT)));
  });

  it("a different signature changes the digest", () => {
    expect(requestDigest(evmReq(MERCHANT, "0xabc"))).not.toBe(
      requestDigest(evmReq(MERCHANT, "0xdef")),
    );
  });

  it("a changed authorization value changes the digest", () => {
    const inflated = evmReq(MERCHANT);
    (inflated.payload as any).authorization.value = "900000000";
    expect(requestDigest(evmReq(MERCHANT))).not.toBe(requestDigest(inflated));
  });

  it("replayMatches rejects a receipt rebound to a redirected payment", () => {
    // A receipt legitimately issued for the merchant payment...
    const legit = evmReq(MERCHANT);
    const receipt: Receipt = {
      v: 1,
      decision: "allow",
      codes: [],
      amount_bucket: null,
      chain_id: 8453,
      lane: "evm",
      quote_provenance: "merchant_signed",
      request_digest: requestDigest(legit),
      issued_at: "2033-05-18T03:33:20.000Z",
    };
    // ...must NOT validate against the attacker-redirected payment.
    expect(replayMatches(receipt, legit)).toBe(true);
    expect(replayMatches(receipt, evmReq(ATTACKER))).toBe(false);
  });
});
