import { describe, expect, it } from "vitest";
import { verify, requestDigest } from "../src/verify.js";

/**
 * AW-08 and AW-09 — what a caller may change about its own verdict.
 *
 * Measured by zauth against the real createVerifyHandler with a signing key:
 * an authorization that expired an hour ago refused bare, and ALLOWED with
 * `{"clockSkewSeconds":"0"}` — a string, so `now + skew` was string
 * concatenation and the expiry bound moved to roughly the year 2534. The
 * signed receipt recorded no trace, because options were outside the digest.
 */

const ctx = { issuedAt: () => "2026-09-21T00:00:00.000Z" };

/** An EIP-3009 authorization that expired an hour ago. */
const expiredRequest = (options?: Record<string, unknown>) => ({
  network: "eip155:8453",
  quote: {
    network: "eip155:8453",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    payTo: "0x4C097f1D075275D01D16c76c0febe058c830f96A",
    amount: "3000",
    extra: { name: "USD Coin", version: "2", assetTransferMethod: "eip3009" },
  },
  payload: {
    signature: `0x${"11".repeat(65)}`,
    authorization: {
      from: "0x3295F6B84f33Fc63096f6191139841F3f5C157DF",
      to: "0x4C097f1D075275D01D16c76c0febe058c830f96A",
      value: "3000",
      validAfter: "0",
      validBefore: String(Math.floor(Date.now() / 1000) - 3600),
      nonce: `0x${"5".repeat(64)}`,
    },
  },
  ...(options ? { options } : {}),
});

describe("AW-09 — a request may not move the clock its own verdict is judged against", () => {
  it("REGRESSION: a string clockSkewSeconds no longer rescues an expired authorization", async () => {
    const bare = await verify(expiredRequest() as never, ctx);
    const skewed = await verify(expiredRequest({ clockSkewSeconds: "0" }) as never, ctx);
    // The bare request is the control: whatever it decides, the option must
    // not IMPROVE it. Before the fix, refuse became allow.
    expect(skewed.decision).toBe(bare.decision);
    expect(skewed.decision).not.toBe("allow");
  });

  it("says out loud that it ignored the clock, rather than dropping it silently", async () => {
    const r = await verify(expiredRequest({ nowSeconds: "1" }) as never, ctx);
    expect(r.findings.some((f) => f.code === "X402-011")).toBe(true);
  });

  it("ignores a clock option however it is spelled — bigint, number or string", async () => {
    for (const v of [0, "0", 999_999_999]) {
      const r = await verify(expiredRequest({ clockSkewSeconds: v }) as never, ctx);
      expect(r.decision).not.toBe("allow");
    }
  });

  it("refuses to read a fee cap it cannot parse, rather than honouring it", async () => {
    // A value we cannot read is an abstain, never a pass — the rule this
    // package already applies to assetTransferMethod and expectedPayer.
    const r = await verify(
      { ...expiredRequest(), options: { maxPriorityFeeLamports: "not-a-number" } } as never,
      ctx,
    );
    expect(r.findings.some((f) => f.code === "X402-011")).toBe(true);
  });
});

describe("AW-08 — the digest must cover what steered the verdict", () => {
  const base = {
    network: "eip155:8453",
    quote: {
      network: "eip155:8453",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      payTo: "0x4C097f1D075275D01D16c76c0febe058c830f96A",
      amount: "3000",
    },
    payload: { authorization: { from: "0xaa", to: "0xbb", value: "3000" } },
  };

  it("REGRESSION: adding expectedPayer changes the digest", () => {
    // Measured: identical request + options.expectedPayer refused where the
    // bare one allowed, at the SAME digest, and replayMatches said true for
    // both. A digest that omits a verdict-determining input makes
    // "is it this exact request?" answer a different question.
    const bare = requestDigest(base as never);
    const optioned = requestDigest({ ...base, options: { expectedPayer: "0xdEaD" } } as never);
    expect(optioned).not.toBe(bare);
  });

  it("is stable under key order, so ordering cannot fork the digest", () => {
    const a = requestDigest({ ...base, options: { expectedPayer: "0x1", nowSeconds: 5 } } as never);
    const b = requestDigest({ ...base, options: { nowSeconds: 5, expectedPayer: "0x1" } } as never);
    expect(a).toBe(b);
  });

  it("treats absent and empty options as the same request", () => {
    expect(requestDigest({ ...base, options: {} } as never)).toBe(requestDigest(base as never));
  });

  it("does not throw on a BigInt option", () => {
    expect(() =>
      requestDigest({ ...base, options: { maxPriorityFeeLamports: 10n } } as never),
    ).not.toThrow();
  });
});
