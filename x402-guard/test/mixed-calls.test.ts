/**
 * A signing call that carries an already-signed payment beside anything else
 * is refused by the guard itself, with the typed request's own findings first
 * (0.10.1), and a converted quote's timeout does not count against the
 * quote-text scan's field limit.
 *
 * The wallets here sign with a real key, and each refusal is checked to come
 * before the wallet is called: refusing later, inside the wallet library,
 * left the outcome to the library.
 */

import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import { EIP3009, evmQuoteFromRequirements, guardEvmSigner, inspectQuoteText, type EvmPaymentQuote } from "../src/evm.js";

const account = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex);
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MERCHANT = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";
const NOW = 2_000_000_000n;

const quote: EvmPaymentQuote = { network: "eip155:8453", asset: USDC, payTo: MERCHANT, amount: "1000000" };
const domain = { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: USDC };
let n = 1;
const message = (to: string, o: { validAfter?: bigint; validBefore?: bigint } = {}) => ({
  from: account.address,
  to,
  value: "1000000",
  validAfter: (o.validAfter ?? 0n).toString(),
  validBefore: (o.validBefore ?? NOW + 300n).toString(),
  nonce: `0x${(n++).toString(16).padStart(64, "0")}`,
});
const request = (m: Record<string, unknown>) => ({ domain, types: EIP3009.TYPES, primaryType: EIP3009.PRIMARY_TYPE, message: m });

/** A signed payment for the merchant, valid at NOW. */
async function signedPayment() {
  const m = message(MERCHANT);
  const signature = await account.signTypedData(request(m) as never);
  return { signature, authorization: m };
}

/** A wallet that counts the calls that reach it. */
function wallet() {
  const w = {
    calls: 0,
    async signTypedData(...args: unknown[]) {
      w.calls++;
      return account.signTypedData(args[0] as never);
    },
  };
  return w;
}

describe("a signed payment beside other objects is refused before the wallet", () => {
  it("refuses a signed payment placed before a typed-data request", async () => {
    const w = wallet();
    const g = guardEvmSigner(w, () => quote, { nowSeconds: NOW });
    await expect(g.signTypedData(await signedPayment(), request(message(MERCHANT)))).rejects.toThrow(
      /typed-data request and an already-signed payment/,
    );
    expect(w.calls).toBe(0);
  });

  it("refuses a signed payment where ethers reads the types", async () => {
    const w = wallet();
    const g = guardEvmSigner(w, () => quote, { nowSeconds: NOW });
    await expect(g.signTypedData(domain, await signedPayment(), message(MERCHANT))).rejects.toThrow(/refusing/);
    expect(w.calls).toBe(0);
  });

  it("CONTROL: a signed payment alone still takes the signed path", async () => {
    const w = wallet();
    const g = guardEvmSigner(w, () => ({ ...quote, payTo: OTHER }), { nowSeconds: NOW });
    await expect(g.signTypedData(await signedPayment())).rejects.toThrow(/X402-101/);
    expect(w.calls).toBe(0);
  });
});

describe("a mixed call's refusal leads with the typed request's own findings", () => {
  it("names a viem request's wrong payee before its ambiguity", async () => {
    const w = wallet();
    const g = guardEvmSigner(w, () => quote, { nowSeconds: NOW });
    await expect(g.signTypedData(request(message(OTHER)), await signedPayment())).rejects.toThrow(/X402-101/);
    expect(w.calls).toBe(0);
  });

  it("names a finding that would not refuse the request alone", async () => {
    const w = wallet();
    const g = guardEvmSigner(w, () => quote, { nowSeconds: NOW });
    // Not yet valid: reported on an allowed request, and kept on a mixed one.
    const later = request(message(MERCHANT, { validAfter: NOW + 60n, validBefore: NOW + 300n }));
    await expect(g.signTypedData(domain, EIP3009.TYPES, later.message, await signedPayment())).rejects.toThrow(/X402-105/);
    await expect(g.signTypedData(later, await signedPayment())).rejects.toThrow(/X402-105/);
    expect(w.calls).toBe(0);
  });
});

describe("the converted timeout and the quote-text field limit", () => {
  it("reads a converted quote with as many fields as one without the timeout", () => {
    // Four string fields plus 3,990 keys in extra is one field short of the scan's limit.
    const extra = Object.fromEntries(Array.from({ length: 3990 }, (_, i) => [`k${i}`, null]));
    const req = { scheme: "exact", network: "eip155:8453", asset: USDC, payTo: MERCHANT, amount: "1000000", extra };
    const without = inspectQuoteText(evmQuoteFromRequirements(req));
    const withTimeout = inspectQuoteText(evmQuoteFromRequirements({ ...req, maxTimeoutSeconds: 300 }));
    expect(without.decision).toBe("allow");
    expect(withTimeout.decision).toBe(without.decision);
    // A timeout that is text, not a number, is still scanned.
    expect(inspectQuoteText({ ...evmQuoteFromRequirements(req), maxTimeoutSeconds: "300" }).decision).not.toBe("allow");
  });
});
