/**
 * guardEvmSigner reads a typed-data call the way the signer reads it (0.10.1).
 *
 * viem signs its one request object, the first argument; ethers signs domain,
 * types and value at positions 0 to 2. The guard used to take the first
 * argument anywhere that looked like a whole request, so a request carried
 * inside an ethers value, or passed after the three, was checked while ethers
 * signed the three it reads. These signers sign exactly what viem or ethers
 * would, with a real key, so a call that slipped through would show as a
 * signature over the unchecked message.
 */

import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import { EIP3009, guardEvmSigner, type EvmPaymentQuote } from "../src/evm.js";

const account = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex,
);
const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MERCHANT = "0x1111111111111111111111111111111111111111";
const SECOND_PAYEE = "0x2222222222222222222222222222222222222222";
const NOW = 2_000_000_000n;

const quote: EvmPaymentQuote = { network: "eip155:8453", asset: BASE_USDC, payTo: MERCHANT, amount: "1000000" };
const domain = { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: BASE_USDC };

let n = 1;
const message = (to: string, value: string) => ({
  from: account.address,
  to,
  value,
  validAfter: "0",
  validBefore: (NOW + 300n).toString(),
  nonce: `0x${(n++).toString(16).padStart(64, "0")}`,
});
const request = (m: Record<string, unknown>) => ({ domain, types: EIP3009.TYPES, primaryType: EIP3009.PRIMARY_TYPE, message: m });

/** Signs what ethers signs: the domain, types and value at positions 0 to 2. */
function ethersSigner() {
  const signed: unknown[] = [];
  return {
    signed,
    async signTypedData(d: unknown, t: unknown, v: unknown) {
      signed.push(v);
      return account.signTypedData({ domain: d, types: t, primaryType: EIP3009.PRIMARY_TYPE, message: v } as never);
    },
  };
}

/** Signs what viem signs: its one request object. */
function viemSigner() {
  const signed: unknown[] = [];
  return {
    signed,
    async signTypedData(r: unknown) {
      signed.push(r);
      return account.signTypedData(r as never);
    },
  };
}

describe("ethers: the three arguments it signs are the ones checked", () => {
  it("a value carrying a request of its own is held to its own fields", async () => {
    const s = ethersSigner();
    const g = guardEvmSigner(s, () => quote, { nowSeconds: NOW });
    // The value's own fields pay a second payee; the request inside it pays the merchant.
    const value = JSON.parse(JSON.stringify({ ...message(SECOND_PAYEE, "1000000"), ...request(message(MERCHANT, "1000000")) }));
    await expect(g.signTypedData(domain, EIP3009.TYPES, value)).rejects.toThrow(/X402-101/);
    expect(s.signed).toEqual([]);
  });

  it("a request passed after the three does not stand in for them", async () => {
    const s = ethersSigner();
    const g = guardEvmSigner(s, () => quote, { nowSeconds: NOW });
    const later = request(message(MERCHANT, "1000000"));
    await expect(g.signTypedData(domain, EIP3009.TYPES, message(MERCHANT, "25000000000"), later)).rejects.toThrow(/X402-102/);
    expect(s.signed).toEqual([]);
  });

  it("CONTROL: an honest ethers call signs, and an options object after the three changes nothing", async () => {
    const s = ethersSigner();
    const g = guardEvmSigner(s, () => quote, { nowSeconds: NOW });
    await expect(g.signTypedData(domain, EIP3009.TYPES, message(MERCHANT, "1000000"))).resolves.toMatch(/^0x[0-9a-f]{130}$/);
    await expect(g.signTypedData(domain, EIP3009.TYPES, message(MERCHANT, "1000000"), { timeout: 30 })).resolves.toMatch(/^0x/);
    expect(s.signed).toHaveLength(2);
  });
});

describe("viem: its one request object is the one checked", () => {
  it("a request first, with objects an ethers signer would read after it, is refused", async () => {
    const s = ethersSigner();
    const g = guardEvmSigner(s, () => quote, { nowSeconds: NOW });
    // As viem: the first request, which pays the merchant. As ethers: the first
    // argument's own domain fields, then these types and this value.
    const first = { ...request(message(MERCHANT, "1000000")), ...domain };
    await expect(g.signTypedData(first, EIP3009.TYPES, message(SECOND_PAYEE, "1000000"))).rejects.toThrow(/more than one typed-data request/);
    expect(s.signed).toEqual([]);
  });

  it("CONTROL: an honest viem call signs, with primitive arguments after it", async () => {
    const s = viemSigner();
    const g = guardEvmSigner(s, () => quote, { nowSeconds: NOW });
    await expect(g.signTypedData(request(message(MERCHANT, "1000000")))).resolves.toMatch(/^0x[0-9a-f]{130}$/);
    await expect(g.signTypedData(request(message(MERCHANT, "1000000")), undefined)).resolves.toMatch(/^0x/);
    expect(s.signed).toHaveLength(2);
  });

  it("a viem request paying a second payee is refused as before", async () => {
    const s = viemSigner();
    const g = guardEvmSigner(s, () => quote, { nowSeconds: NOW });
    await expect(g.signTypedData(request(message(SECOND_PAYEE, "1000000")))).rejects.toThrow(/X402-101/);
    expect(s.signed).toEqual([]);
  });
});
