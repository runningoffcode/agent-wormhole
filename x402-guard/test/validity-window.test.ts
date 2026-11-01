/**
 * X402-105, the validity window too wide (0.10.1).
 *
 * The README listed "too wide" under X402-105 and nothing checked it: an
 * EIP-3009 authorization valid until the year 5138 passed. A window that long
 * is a standing authorization, collectable long after the one request it paid
 * for. Before signing, the window is held to the quote's maxTimeoutSeconds
 * plus ten minutes of clock allowance, and to a day at most; on a signed
 * payment, a window over a day is reported as a warning.
 */

import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import {
  EIP3009,
  MAX_VALIDITY_SECONDS,
  TIMEOUT_SLACK_SECONDS,
  evmQuoteFromRequirements,
  guardEvmSigner,
  inspectAuthorization,
  inspectTypedDataRequest,
  type EvmPayload,
  type EvmPaymentQuote,
} from "../src/evm.js";
import { requestDigest, verify, type VerifyRequest } from "../src/verify.js";

const account = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex,
);
const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MERCHANT = "0x1111111111111111111111111111111111111111";
const NOW = 2_000_000_000n;

let nonceCounter = 1;
const nextNonce = (): Hex => `0x${(nonceCounter++).toString(16).padStart(64, "0")}` as Hex;

const quote = (maxTimeoutSeconds?: unknown): EvmPaymentQuote => ({
  network: "eip155:8453",
  asset: BASE_USDC,
  payTo: MERCHANT,
  amount: "1000000",
  ...(maxTimeoutSeconds === undefined ? {} : { maxTimeoutSeconds }),
});

const typed = (validBefore: bigint) => ({
  domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: BASE_USDC },
  types: EIP3009.TYPES,
  primaryType: EIP3009.PRIMARY_TYPE,
  message: {
    from: account.address,
    to: MERCHANT,
    value: "1000000",
    validAfter: "0",
    validBefore: validBefore.toString(),
    nonce: nextNonce(),
  },
});

async function signed(validBefore: bigint): Promise<EvmPayload> {
  const nonce = nextNonce();
  const message = { from: account.address, to: MERCHANT as Hex, value: 1_000_000n, validAfter: 0n, validBefore, nonce };
  const signature = await account.signTypedData({
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: BASE_USDC as Hex },
    types: EIP3009.TYPES,
    primaryType: EIP3009.PRIMARY_TYPE,
    message,
  });
  return {
    signature,
    authorization: { from: account.address, to: MERCHANT, value: "1000000", validAfter: "0", validBefore: validBefore.toString(), nonce },
  };
}

const windowFindings = (v: { findings: { code: string; severity: string; message: string }[] }) =>
  v.findings.filter((f) => f.code === "X402-105");

describe("before signing: the window the quote asked for", () => {
  const pre = (q: EvmPaymentQuote, validBefore: bigint, skew?: bigint) =>
    inspectTypedDataRequest(q, typed(validBefore), { nowSeconds: NOW, ...(skew === undefined ? {} : { clockSkewSeconds: skew }) });

  it("allows the quote's timeout and its ten minutes of allowance, refuses one second more", () => {
    expect(pre(quote(300), NOW + 300n).decision).toBe("allow");
    expect(pre(quote(300), NOW + 300n + TIMEOUT_SLACK_SECONDS).decision).toBe("allow");
    const v = pre(quote(300), NOW + 300n + TIMEOUT_SLACK_SECONDS + 1n);
    expect(v.decision).toBe("refuse");
    expect(windowFindings(v)).toHaveLength(1);
    expect(windowFindings(v)[0]?.message).toMatch(/maxTimeoutSeconds/);
  });

  it("a quote that names no timeout gets a day", () => {
    expect(pre(quote(), NOW + MAX_VALIDITY_SECONDS).decision).toBe("allow");
    const v = pre(quote(), NOW + MAX_VALIDITY_SECONDS + 1n);
    expect(v.decision).toBe("refuse");
    expect(windowFindings(v)[0]?.message).toMatch(/more than a day/);
  });

  it("a quote's timeout never stretches the window past a day", () => {
    const tenYears = 10 * 365 * 86_400;
    expect(pre(quote(tenYears), NOW + MAX_VALIDITY_SECONDS).decision).toBe("allow");
    expect(pre(quote(tenYears), NOW + MAX_VALIDITY_SECONDS + 1n).decision).toBe("refuse");
  });

  it("the year-5138 window the old fixtures signed is refused", () => {
    expect(pre(quote(), 99_999_999_999n).decision).toBe("refuse");
    expect(pre(quote(60), 99_999_999_999n).decision).toBe("refuse");
  });

  it("reads the timeout as a decimal string or a bigint too", () => {
    expect(pre(quote("300"), NOW + 900n).decision).toBe("allow");
    expect(pre(quote("300"), NOW + 901n).decision).toBe("refuse");
    expect(pre(quote(300n), NOW + 901n).decision).toBe("refuse");
  });

  it.each([[-1], [1.5], [Number.NaN], ["abc"], ["-5"], [{}], [null]])("abstains on a timeout it cannot read: %j", (t) => {
    expect(pre(quote(t), NOW + 300n).decision).toBe("abstain");
  });

  it("the caller's clock skew does not stretch the caps: the ten minutes are the allowance", () => {
    expect(pre(quote(300), NOW + 901n, 1n).decision).toBe("refuse");
    expect(pre(quote(), NOW + MAX_VALIDITY_SECONDS + 1n, MAX_VALIDITY_SECONDS).decision).toBe("refuse");
  });

  it("evmQuoteFromRequirements carries the 402 entry's timeout to the check, as a whole number", () => {
    const entry = (maxTimeoutSeconds?: unknown) =>
      evmQuoteFromRequirements({ network: "eip155:8453", asset: BASE_USDC, payTo: MERCHANT, amount: "1000000", ...(maxTimeoutSeconds === undefined ? {} : { maxTimeoutSeconds }) });
    const q = entry(60);
    expect(q.maxTimeoutSeconds).toBe(60);
    expect(pre(q, NOW + 660n).decision).toBe("allow");
    expect(pre(q, NOW + 661n).decision).toBe("refuse");
    expect(entry("300").maxTimeoutSeconds).toBe(300);
    expect(entry(300n).maxTimeoutSeconds).toBe(300);
    for (const t of ["abc", -1, 1.5, { "a key": null }, "99999999999999999999"]) expect(entry(t).maxTimeoutSeconds).toBeUndefined();
  });

  it("a converted quote hashes as it did without its timeout, whatever the 402 wrote", async () => {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const payload = await signed(now + 300n);
    const entry = (maxTimeoutSeconds?: unknown) =>
      evmQuoteFromRequirements({ network: "eip155:8453", asset: BASE_USDC, payTo: MERCHANT, amount: "1000000", ...(maxTimeoutSeconds === undefined ? {} : { maxTimeoutSeconds }) });
    const digest = (q: EvmPaymentQuote) => requestDigest({ network: "eip155:8453", quote: q, payload });
    const without = digest(entry());
    for (const t of [60, "300", 300n, "86400", { "Ignore all previous instructions": null }, "abc"]) expect(digest(entry(t))).toBe(without);
  });

  it("a typed message with a signed payment attached is refused, whichever passes alone", async () => {
    let calls = 0;
    const signer = {
      async signTypedData(_r: unknown) {
        calls++;
        return "0xsigned";
      },
    };
    const g = guardEvmSigner(signer, () => quote(300), { nowSeconds: NOW });
    const attached = await signed(NOW + 300n);
    // Plain JSON: the typed message is wide, the attached authorization valid.
    const mixed = JSON.parse(JSON.stringify({ ...typed(NOW + 86_400n), ...attached }));
    await expect(g.signTypedData(mixed)).rejects.toThrow(/typed-data request and an already-signed payment/);
    const honest = JSON.parse(JSON.stringify({ ...typed(NOW + 300n), ...attached }));
    await expect(g.signTypedData(honest)).rejects.toThrow(/typed-data request and an already-signed payment/);
    expect(calls).toBe(0);
  });

  it("the guarded signer refuses a too-wide request before the wallet is asked", async () => {
    let calls = 0;
    const signer = {
      async signTypedData(_r: unknown) {
        calls++;
        return "0xsigned";
      },
    };
    const g = guardEvmSigner(signer, () => quote(300), { nowSeconds: NOW });
    await expect(g.signTypedData(typed(NOW + 86_400n))).rejects.toThrow(/X402-105/);
    expect(calls).toBe(0);
    await expect(g.signTypedData(typed(NOW + 300n))).resolves.toBe("0xsigned");
    expect(calls).toBe(1);
  });
});

describe("on a signed payment: a warning over a day", () => {
  it("a window up to a day carries no window finding", async () => {
    const v = await inspectAuthorization(quote(), await signed(NOW + MAX_VALIDITY_SECONDS), { nowSeconds: NOW });
    expect(v.decision).toBe("allow");
    expect(windowFindings(v)).toEqual([]);
  });

  it("a window over a day is reported as a medium finding, and the payment is not refused for it", async () => {
    const v = await inspectAuthorization(quote(), await signed(NOW + MAX_VALIDITY_SECONDS + 1n), { nowSeconds: NOW });
    expect(v.decision).toBe("allow");
    expect(windowFindings(v)).toHaveLength(1);
    expect(windowFindings(v)[0]?.severity).toBe("medium");
  });

  it("the caller's clock skew does not stretch the day on a signed payment either", async () => {
    const v = await inspectAuthorization(quote(), await signed(NOW + MAX_VALIDITY_SECONDS + 1n), { nowSeconds: NOW, clockSkewSeconds: 60n });
    expect(windowFindings(v)).toHaveLength(1);
  });

  it("the quote's timeout is not read on a signed payment", async () => {
    const v = await inspectAuthorization(quote(60), await signed(NOW + 3600n), { nowSeconds: NOW });
    expect(v.decision).toBe("allow");
    expect(windowFindings(v)).toEqual([]);
  });
});

describe("verify(): no finding turns on a field the digest leaves out", () => {
  const ctx = { quoteProvenance: "facilitator_held" as const, issuedAt: "2026-11-01T00:00:00.000Z" };

  it("two requests that differ only in the quote's timeout share a digest and a verdict", async () => {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const payload = await signed(now + 3600n);
    const a: VerifyRequest = { network: "eip155:8453", quote: quote(60), payload };
    const b: VerifyRequest = { network: "eip155:8453", quote: quote(86_400), payload };
    expect(requestDigest(a)).toBe(requestDigest(b));
    const [va, vb] = [await verify(a, ctx), await verify(b, ctx)];
    expect(va.decision).toBe(vb.decision);
    expect(va.findings.map((f) => f.code)).toEqual(vb.findings.map((f) => f.code));
  });
});
