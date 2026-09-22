import { describe, expect, it } from "vitest";
import { verify, requestDigest } from "../src/verify.js";
import {
  Keypair,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
  ComputeBudgetProgram,
} from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  createTransferCheckedInstruction,
} from "@solana/spl-token";

/**
 * AW-08 and AW-09 — what a caller may change about its own verdict.
 *
 * Measured against the real createVerifyHandler with a signing key:
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

/**
 * AW-09, the fee half.
 *
 * The clock half was fixed and this one was not: the sanitiser validated the
 * SHAPE of `maxPriorityFeeLamports` and never its VALUE, so a caller could
 * hand themselves any ceiling they liked. Measured on a real v0 transaction
 * carrying a 1.4 SOL priority fee: bare → `refuse [X402-010]`, which this
 * package rates critical, and `{"maxPriorityFeeLamports":"99999999999999"}` →
 * `allow` with zero findings.
 *
 * The fee is the one Solana field that drains the payer while the payment
 * itself stays perfectly conforming, so the cap is a control rather than a
 * preference — and a control the request can set is not a control.
 */
describe("the priority-fee cap cannot be raised by the request (AW-09)", () => {
  const USDC = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
  const payer = Keypair.generate();
  const merchant = Keypair.generate();
  const ata = (o: any) => getAssociatedTokenAddressSync(USDC, o);
  const quote = {
    payTo: merchant.publicKey.toBase58(),
    asset: USDC.toBase58(),
    amount: "1000000",
  };
  const ctx = {
    quoteProvenance: "merchant_signed" as const,
    issuedAt: "2033-05-18T03:33:20.000Z",
  };

  const txWithFee = (microLamports: bigint) =>
    Buffer.from(
      new VersionedTransaction(
        new TransactionMessage({
          payerKey: payer.publicKey,
          recentBlockhash: PublicKey.default.toBase58(),
          instructions: [
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
            ComputeBudgetProgram.setComputeUnitPrice({ microLamports }),
            createTransferCheckedInstruction(
              ata(payer.publicKey), USDC, ata(merchant.publicKey),
              payer.publicKey, 1_000_000n, 6,
            ),
          ],
        }).compileToV0Message(),
      ).serialize(),
    ).toString("base64");

  // 1.4M CU at 1e9 microLamports = 1.4 SOL.
  const EXPENSIVE = txWithFee(1_000_000_000n);
  const NORMAL = txWithFee(1_000n);

  it("refuses a 1.4 SOL priority fee with no options", async () => {
    const v = await verify(
      { network: "solana", quote, payload: EXPENSIVE } as never, ctx,
    );
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-010")).toBe(true);
  });

  for (const cap of ["99999999999999", "100000001"]) {
    it(`still refuses when the request raises the cap to ${cap}`, async () => {
      const v = await verify(
        {
          network: "solana", quote, payload: EXPENSIVE,
          options: { maxPriorityFeeLamports: cap },
        } as never,
        ctx,
      );
      expect(v.decision).toBe("refuse");
      // The original finding survives, AND the ignored option is reported.
      expect(v.findings.some((f) => f.code === "X402-010")).toBe(true);
      expect(v.findings.some((f) => f.code === "X402-011")).toBe(true);
    });
  }

  it("lets a caller TIGHTEN the cap — that is their own money", async () => {
    const v = await verify(
      {
        network: "solana", quote, payload: NORMAL,
        options: { maxPriorityFeeLamports: "100" },
      } as never,
      ctx,
    );
    expect(v.decision).toBe("refuse");
  });

  it("and an in-range cap still allows an ordinary congestion fee", async () => {
    const v = await verify(
      {
        network: "solana", quote, payload: NORMAL,
        options: { maxPriorityFeeLamports: "50000000" },
      } as never,
      ctx,
    );
    expect(v.decision).toBe("allow");
    expect(v.findings).toEqual([]);
  });
});
