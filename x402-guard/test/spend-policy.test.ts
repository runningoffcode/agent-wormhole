/**
 * The opt-in spending policy (0.10.0, src/policy.ts).
 *
 * The case it exists for is V12's first critical x402 SDK finding: a hostile
 * API quotes the wallet's whole balance, and the payment matches its quote
 * exactly — conformance allows it, because the quote is the attack. These
 * tests hold the policy to that case on both lanes and through verify(), and
 * hold the rest of the package to its old answers when no policy is given.
 */

import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import {
  Keypair,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  createTransferCheckedInstruction,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";
import {
  EIP3009,
  guardEvmSigner,
  inspectAuthorization,
  inspectTypedDataRequest,
  type EvmPayload,
  type EvmPaymentQuote,
} from "../src/evm.js";
import { guardSigner, inspectPayment, type PaymentQuote } from "../src/index.js";
import { requestDigest, verify, type VerifyRequest } from "../src/verify.js";
import { replayMatches } from "../src/receipt.js";

// --- EVM fixtures ------------------------------------------------------------

const account = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex,
);
const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MERCHANT = "0x1111111111111111111111111111111111111111";
const ATTACKER = "0x2222222222222222222222222222222222222222";
const OTHER_TOKEN = "0x3333333333333333333333333333333333333333";
// The real clock: the same fixtures go through checks pinned to NOW and through
// verify(), which reads the clock itself, and an authorization is valid for an
// hour from it, as a real one is (a window over a day is X402-105).
const NOW = BigInt(Math.floor(Date.now() / 1000));
const VALID_BEFORE = NOW + 3600n;
const ONE_USDC = 1_000_000n;
const BALANCE = 25_000_000_000n; // the wallet's whole 25,000 USDC

let nonceCounter = 1;
const nextNonce = (): Hex => `0x${(nonceCounter++).toString(16).padStart(64, "0")}` as Hex;

async function signAuth(to: string, value: bigint): Promise<EvmPayload> {
  const nonce = nextNonce();
  const message = { from: account.address, to: to as Hex, value, validAfter: 0n, validBefore: VALID_BEFORE, nonce };
  const signature = await account.signTypedData({
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: BASE_USDC as Hex },
    types: EIP3009.TYPES,
    primaryType: EIP3009.PRIMARY_TYPE,
    message,
  });
  return {
    signature,
    authorization: { from: account.address, to, value: value.toString(), validAfter: "0", validBefore: VALID_BEFORE.toString(), nonce },
  };
}

function typedRequest(to: string, value: bigint) {
  return {
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: BASE_USDC },
    types: EIP3009.TYPES,
    primaryType: EIP3009.PRIMARY_TYPE,
    message: { from: account.address, to, value: value.toString(), validAfter: "0", validBefore: VALID_BEFORE.toString(), nonce: nextNonce() },
  };
}

const quoteOf = (payTo: string, amount: bigint): EvmPaymentQuote => ({
  network: "eip155:8453",
  asset: BASE_USDC,
  payTo,
  amount: amount.toString(),
});

const codes = (v: { findings: { code: string }[] }) => v.findings.map((f) => f.code).sort();

// --- the EVM lane ------------------------------------------------------------

describe("EVM: no policy means the old answers", () => {
  it("a hostile quote for the whole balance is still allowed without a policy — the gap the policy closes", async () => {
    const v = await inspectAuthorization(quoteOf(ATTACKER, BALANCE), await signAuth(ATTACKER, BALANCE), { nowSeconds: NOW });
    expect(v.decision).toBe("allow");
  });
});

describe("EVM: the per-payment cap (X402-501)", () => {
  const policy = { maxPerPayment: { [BASE_USDC]: "1000000" } };

  it("refuses the case-study attack: a quote for the whole balance, matched exactly", async () => {
    const v = await inspectAuthorization(quoteOf(ATTACKER, BALANCE), await signAuth(ATTACKER, BALANCE), { nowSeconds: NOW, spendPolicy: policy });
    expect(v.decision).toBe("refuse");
    expect(codes(v)).toEqual(["X402-501"]);
  });

  it("allows a payment at the cap and below it", async () => {
    for (const amount of [ONE_USDC, 10_000n]) {
      const v = await inspectAuthorization(quoteOf(MERCHANT, amount), await signAuth(MERCHANT, amount), { nowSeconds: NOW, spendPolicy: policy });
      expect(v.decision, amount.toString()).toBe("allow");
    }
  });

  it("refuses one unit over the cap", async () => {
    const v = await inspectAuthorization(quoteOf(MERCHANT, ONE_USDC + 1n), await signAuth(MERCHANT, ONE_USDC + 1n), { nowSeconds: NOW, spendPolicy: policy });
    expect(codes(v)).toEqual(["X402-501"]);
  });

  it("reads the cap whatever the address's spelling", async () => {
    const lower = { maxPerPayment: { [BASE_USDC.toLowerCase()]: 1_000_000n } };
    const v = await inspectAuthorization(quoteOf(ATTACKER, BALANCE), await signAuth(ATTACKER, BALANCE), { nowSeconds: NOW, spendPolicy: lower });
    expect(codes(v)).toEqual(["X402-501"]);
  });

  it("refuses an asset the caps do not name (X402-502)", async () => {
    const v = await inspectAuthorization(quoteOf(MERCHANT, ONE_USDC), await signAuth(MERCHANT, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { maxPerPayment: { [OTHER_TOKEN]: "1000000" } },
    });
    expect(codes(v)).toEqual(["X402-502"]);
  });

  it("keeps the conformance findings beside the policy's", async () => {
    // The quote says $0.01 to the merchant; the signed payment is the balance to the attacker.
    const v = await inspectAuthorization(quoteOf(MERCHANT, 10_000n), await signAuth(ATTACKER, BALANCE), { nowSeconds: NOW, spendPolicy: policy });
    expect(codes(v)).toEqual(["X402-101", "X402-102", "X402-501"]);
  });
});

describe("EVM: the allowed assets and payees (X402-502, X402-503)", () => {
  it("refuses an asset not on the list", async () => {
    const v = await inspectAuthorization(quoteOf(MERCHANT, ONE_USDC), await signAuth(MERCHANT, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { assets: [OTHER_TOKEN] },
    });
    expect(codes(v)).toEqual(["X402-502"]);
  });

  it("refuses a payee not on the list, and allows one that is", async () => {
    const refused = await inspectAuthorization(quoteOf(ATTACKER, ONE_USDC), await signAuth(ATTACKER, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { payees: [MERCHANT] },
    });
    expect(codes(refused)).toEqual(["X402-503"]);
    const allowed = await inspectAuthorization(quoteOf(MERCHANT, ONE_USDC), await signAuth(MERCHANT, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { payees: [MERCHANT], assets: [BASE_USDC] },
    });
    expect(allowed.decision).toBe("allow");
  });

  it("an empty list allows nothing", async () => {
    const v = await inspectAuthorization(quoteOf(MERCHANT, ONE_USDC), await signAuth(MERCHANT, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { payees: [] },
    });
    expect(codes(v)).toEqual(["X402-503"]);
  });
});

describe("EVM: a policy that cannot be read is an abstain, never a skipped rule", () => {
  const cases: [string, unknown][] = [
    ["a misspelt key", { maxPerPaymnet: { [BASE_USDC]: "1" } }],
    ["a fractional amount", { maxPerPayment: { [BASE_USDC]: "1.5" } }],
    ["a negative amount", { maxPerPayment: { [BASE_USDC]: -1 } }],
    ["an unsafe float", { maxPerPayment: { [BASE_USDC]: 1e30 } }],
    ["a key that is not an address", { maxPerPayment: { USDC: "1" } }],
    ["two spellings, two caps", { maxPerPayment: { [BASE_USDC]: "1", [BASE_USDC.toLowerCase()]: "2" } }],
    ["caps that are an array", { maxPerPayment: [BASE_USDC] }],
    ["payees that are a string", { payees: MERCHANT }],
    ["a payee that is not an address", { payees: ["merchant"] }],
    ["a policy that is a string", "cap everything"],
    ["a policy that is null", null],
  ];
  for (const [name, policy] of cases) {
    it(name, async () => {
      const v = await inspectAuthorization(quoteOf(MERCHANT, ONE_USDC), await signAuth(MERCHANT, ONE_USDC), {
        nowSeconds: NOW,
        spendPolicy: policy as never,
      });
      expect(v.decision).toBe("abstain");
      expect(v.reason).toMatch(/spendPolicy/);
    });
  }

  it("a __proto__ key in the caps abstains rather than reaching the prototype", async () => {
    const caps = JSON.parse(`{"__proto__": {"x": 1}, "${BASE_USDC}": "1000000"}`);
    const v = await inspectAuthorization(quoteOf(MERCHANT, ONE_USDC), await signAuth(MERCHANT, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { maxPerPayment: caps },
    });
    expect(v.decision).toBe("abstain");
  });
});

describe("EVM: before signing (inspectTypedDataRequest)", () => {
  it("refuses the whole-balance quote with the same code as the signed path", () => {
    const v = inspectTypedDataRequest(quoteOf(ATTACKER, BALANCE), typedRequest(ATTACKER, BALANCE), {
      nowSeconds: NOW,
      spendPolicy: { maxPerPayment: { [BASE_USDC]: "1000000" } },
    });
    expect(codes(v)).toEqual(["X402-501"]);
  });

  it("abstains on an unreadable policy", () => {
    const v = inspectTypedDataRequest(quoteOf(MERCHANT, ONE_USDC), typedRequest(MERCHANT, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { maxTotl: {} } as never,
    });
    expect(v.decision).toBe("abstain");
  });
});

describe("guardEvmSigner: the cap before the wallet, and a lifetime total (X402-504)", () => {
  function fakeSigner(fail = () => false) {
    const calls: string[] = [];
    return {
      calls,
      async signTypedData(_p: unknown) {
        calls.push("signTypedData");
        if (fail()) throw new Error("the wallet refused");
        return "0xsigned";
      },
    };
  }

  it("refuses the whole-balance quote before the wallet is asked", async () => {
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quoteOf(ATTACKER, BALANCE), {
      nowSeconds: NOW,
      spendPolicy: { maxPerPayment: { [BASE_USDC]: "1000000" } },
    });
    await expect(guarded.signTypedData(typedRequest(ATTACKER, BALANCE))).rejects.toThrow(/X402-501/);
    expect(s.calls).toEqual([]);
  });

  it("signs until the lifetime total is reached, then refuses", async () => {
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quoteOf(MERCHANT, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { maxTotal: { [BASE_USDC]: "2000000" } },
    });
    await guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC));
    await guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC));
    await expect(guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC))).rejects.toThrow(/X402-504/);
    expect(s.calls).toEqual(["signTypedData", "signTypedData"]);
  });

  it("a payment the wallet refuses does not count", async () => {
    let failNext = true;
    const s = fakeSigner(() => {
      const f = failNext;
      failNext = false;
      return f;
    });
    const guarded = guardEvmSigner(s, () => quoteOf(MERCHANT, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { maxTotal: { [BASE_USDC]: "1000000" } },
    });
    await expect(guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC))).rejects.toThrow(/the wallet refused/);
    await expect(guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC))).resolves.toBe("0xsigned");
    await expect(guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC))).rejects.toThrow(/X402-504/);
  });

  it("two concurrent payments cannot both fit a total that holds one", async () => {
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quoteOf(MERCHANT, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { maxTotal: { [BASE_USDC]: "1000000" } },
    });
    const results = await Promise.allSettled([
      guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC)),
      guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC)),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(s.calls).toEqual(["signTypedData"]);
  });

  it("refuses an asset the totals do not name", async () => {
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quoteOf(MERCHANT, ONE_USDC), {
      nowSeconds: NOW,
      spendPolicy: { maxTotal: { [OTHER_TOKEN]: "9999999999" } },
    });
    await expect(guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC))).rejects.toThrow(/X402-504/);
  });

  it("totals are per guard: a second guard starts from zero", async () => {
    const policy = { maxTotal: { [BASE_USDC]: "1000000" } };
    const a = guardEvmSigner(fakeSigner(), () => quoteOf(MERCHANT, ONE_USDC), { nowSeconds: NOW, spendPolicy: policy });
    const b = guardEvmSigner(fakeSigner(), () => quoteOf(MERCHANT, ONE_USDC), { nowSeconds: NOW, spendPolicy: policy });
    await a.signTypedData(typedRequest(MERCHANT, ONE_USDC));
    await expect(b.signTypedData(typedRequest(MERCHANT, ONE_USDC))).resolves.toBe("0xsigned");
  });
});

// --- the Solana lane ---------------------------------------------------------

const USDC = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const payer = Keypair.generate();
const merchant = Keypair.generate();
const attacker = Keypair.generate();
const payerAta = getAssociatedTokenAddressSync(USDC, payer.publicKey);

function build(dest: PublicKey, amount: bigint): VersionedTransaction {
  const ata = getAssociatedTokenAddressSync(USDC, dest);
  const msg = new TransactionMessage({
    payerKey: payer.publicKey,
    recentBlockhash: PublicKey.default.toBase58(),
    instructions: [createTransferCheckedInstruction(payerAta, USDC, ata, payer.publicKey, amount, 6)],
  }).compileToV0Message();
  return new VersionedTransaction(msg);
}

const svmQuote = (payTo: PublicKey, amount: bigint): PaymentQuote => ({
  payTo: payTo.toBase58(),
  asset: USDC.toBase58(),
  amount: amount.toString(),
});

describe("Solana: inspectPayment with a policy", () => {
  it("no policy: the whole-balance quote is allowed, as before", () => {
    const v = inspectPayment(build(attacker.publicKey, BALANCE).serialize(), svmQuote(attacker.publicKey, BALANCE));
    expect(v.decision).toBe("allow");
  });

  it("refuses the whole-balance quote over the cap (X402-501), allows one at the cap", () => {
    const policy = { maxPerPayment: { [USDC.toBase58()]: "1000000" } };
    const refused = inspectPayment(build(attacker.publicKey, BALANCE).serialize(), svmQuote(attacker.publicKey, BALANCE), { spendPolicy: policy });
    expect(codes(refused)).toEqual(["X402-501"]);
    const allowed = inspectPayment(build(merchant.publicKey, ONE_USDC).serialize(), svmQuote(merchant.publicKey, ONE_USDC), { spendPolicy: policy });
    expect(allowed.decision).toBe("allow");
  });

  it("refuses a payee not on the list (X402-503) and a mint not on it (X402-502)", () => {
    const payee = inspectPayment(build(attacker.publicKey, ONE_USDC).serialize(), svmQuote(attacker.publicKey, ONE_USDC), {
      spendPolicy: { payees: [merchant.publicKey.toBase58()] },
    });
    expect(codes(payee)).toEqual(["X402-503"]);
    const mint = inspectPayment(build(merchant.publicKey, ONE_USDC).serialize(), svmQuote(merchant.publicKey, ONE_USDC), {
      spendPolicy: { assets: [Keypair.generate().publicKey.toBase58()] },
    });
    expect(codes(mint)).toEqual(["X402-502"]);
  });

  it("abstains on a policy whose mint does not parse", () => {
    const v = inspectPayment(build(merchant.publicKey, ONE_USDC).serialize(), svmQuote(merchant.publicKey, ONE_USDC), {
      spendPolicy: { maxPerPayment: { "not-a-mint": "1" } },
    });
    expect(v.decision).toBe("abstain");
  });
});

describe("guardSigner: a lifetime total on Solana (X402-504)", () => {
  function fakeWallet() {
    const calls: string[] = [];
    return {
      calls,
      async signTransaction(tx: VersionedTransaction) {
        calls.push("signTransaction");
        return tx;
      },
      async signAllTransactions(txs: VersionedTransaction[]) {
        calls.push(`signAllTransactions:${txs.length}`);
        return txs;
      },
    };
  }

  it("signs until the total is reached, then refuses", async () => {
    const w = fakeWallet();
    const guarded = guardSigner(w, () => svmQuote(merchant.publicKey, ONE_USDC), {
      spendPolicy: { maxTotal: { [USDC.toBase58()]: "2000000" } },
    });
    await guarded.signTransaction(build(merchant.publicKey, ONE_USDC));
    await guarded.signTransaction(build(merchant.publicKey, ONE_USDC));
    await expect(guarded.signTransaction(build(merchant.publicKey, ONE_USDC))).rejects.toThrow(/X402-504/);
    expect(w.calls).toEqual(["signTransaction", "signTransaction"]);
  });

  it("a batch that does not fit is refused whole, and holds nothing back", async () => {
    const w = fakeWallet();
    const guarded = guardSigner(w, () => svmQuote(merchant.publicKey, ONE_USDC), {
      spendPolicy: { maxTotal: { [USDC.toBase58()]: "2000000" } },
    });
    const three = [1, 2, 3].map(() => build(merchant.publicKey, ONE_USDC));
    await expect(guarded.signAllTransactions(three)).rejects.toThrow(/X402-504/);
    expect(w.calls).toEqual([]);
    // Nothing of the refused batch was kept, so two still fit.
    const two = [1, 2].map(() => build(merchant.publicKey, ONE_USDC));
    await expect(guarded.signAllTransactions(two)).resolves.toHaveLength(2);
  });

  it("the per-payment cap refuses before the wallet is asked", async () => {
    const w = fakeWallet();
    const guarded = guardSigner(w, () => svmQuote(attacker.publicKey, BALANCE), {
      spendPolicy: { maxPerPayment: { [USDC.toBase58()]: "1000000" } },
    });
    await expect(guarded.signTransaction(build(attacker.publicKey, BALANCE))).rejects.toThrow(/X402-501/);
    expect(w.calls).toEqual([]);
  });
});

// --- verify() and its digest -------------------------------------------------

describe("verify(): a policy on the wire", () => {
  const ctx = { quoteProvenance: "facilitator_held" as const, issuedAt: "2033-05-18T03:33:20.000Z" };

  it("refuses the whole-balance quote when the request carries a cap", async () => {
    const req: VerifyRequest = {
      network: "eip155:8453",
      quote: quoteOf(ATTACKER, BALANCE),
      payload: await signAuth(ATTACKER, BALANCE),
      options: { spendPolicy: { maxPerPayment: { [BASE_USDC]: "1000000" } } } as never,
    };
    const r = await verify(req, ctx);
    expect(r.decision).toBe("refuse");
    expect(r.findings.map((f) => f.code)).toContain("X402-501");
  });

  it("abstains on a policy it cannot read", async () => {
    const req: VerifyRequest = {
      network: "eip155:8453",
      quote: quoteOf(MERCHANT, ONE_USDC),
      payload: await signAuth(MERCHANT, ONE_USDC),
      options: { spendPolicy: { cap: 1 } } as never,
    };
    const r = await verify(req, ctx);
    expect(r.decision).toBe("abstain");
  });

  it("the digest covers the policy: with and without, different caps, different digests", async () => {
    const payload = await signAuth(MERCHANT, ONE_USDC);
    const base: VerifyRequest = { network: "eip155:8453", quote: quoteOf(MERCHANT, ONE_USDC), payload };
    const capped = (cap: string) => ({ ...base, options: { spendPolicy: { maxPerPayment: { [BASE_USDC]: cap } } } as never });
    const d0 = requestDigest(base);
    const d1 = requestDigest(capped("1000000"));
    const d2 = requestDigest(capped("2000000"));
    expect(new Set([d0, d1, d2]).size).toBe(3);
  });

  it("two spellings of one policy share a digest", async () => {
    const payload = await signAuth(MERCHANT, ONE_USDC);
    const base: VerifyRequest = { network: "eip155:8453", quote: quoteOf(MERCHANT, ONE_USDC), payload };
    const a = requestDigest({
      ...base,
      options: { spendPolicy: { payees: [MERCHANT], maxPerPayment: { [BASE_USDC]: "1000000" } } } as never,
    });
    const b = requestDigest({
      ...base,
      options: { spendPolicy: { maxPerPayment: { [BASE_USDC.toLowerCase()]: 1_000_000n }, payees: [MERCHANT.toLowerCase()] } } as never,
    });
    expect(a).toBe(b);
  });
});

// --- the digest's form of a policy, and reading it never throws (AWG-010-04, -05, -07)

describe("the digest hashes a policy as the request's lane reads it", () => {
  const ctx = { quoteProvenance: "facilitator_held" as const, issuedAt: "2033-05-18T03:33:20.000Z" };
  const mint = USDC.toBase58();
  const svmRequest = (options?: Record<string, unknown>): VerifyRequest => ({
    network: "solana",
    quote: svmQuote(merchant.publicKey, ONE_USDC),
    payload: Buffer.from(build(merchant.publicKey, ONE_USDC).serialize()).toString("base64"),
    ...(options === undefined ? {} : { options: options as never }),
  });

  it.each([
    ["a cap inside an array beside the same cap as a string", { maxPerPayment: { [mint]: "1000000" } }, { maxPerPayment: { [mint]: ["1000000"] } }],
    ["an own __proto__ key beside an empty policy", {}, JSON.parse('{"__proto__":{"assets":[]}}')],
    ["an own __proto__ key in the caps beside empty caps", { maxPerPayment: {} }, { maxPerPayment: JSON.parse('{"__proto__":"10"}') }],
  ])("a policy the lane cannot read never shares a digest with one it can: %s", async (_name, good, bad) => {
    const a = svmRequest({ spendPolicy: good });
    const b = svmRequest({ spendPolicy: bad });
    const va = await verify(a, ctx);
    expect(va.decision).not.toBe("abstain");
    expect((await verify(b, ctx)).decision).toBe("abstain");
    expect(requestDigest(a)).not.toBe(requestDigest(b));
    expect(replayMatches(va.receipt!, b)).toBe(false);
  });

  it("two spellings of one asset with different caps abstain, and do not hash like the cap that reads", async () => {
    const payload = await signAuth(MERCHANT, ONE_USDC);
    const base = { network: "eip155:8453", quote: quoteOf(MERCHANT, ONE_USDC), payload };
    const good: VerifyRequest = { ...base, options: { spendPolicy: { maxPerPayment: { [BASE_USDC.toLowerCase()]: "1000000" } } } as never };
    const bad: VerifyRequest = {
      ...base,
      options: { spendPolicy: { maxPerPayment: { [BASE_USDC]: "0", [BASE_USDC.toLowerCase()]: "1000000" } } } as never,
    };
    const a = await verify(good, ctx);
    expect(a.decision).toBe("allow");
    expect((await verify(bad, ctx)).decision).toBe("abstain");
    expect(replayMatches(a.receipt!, bad)).toBe(false);
  });

  it("two unreadable policies hash apart too", () => {
    const a = requestDigest(svmRequest({ spendPolicy: { maxPerPayment: { [mint]: ["10"] } } }));
    const b = requestDigest(svmRequest({ spendPolicy: { maxPerPayment: { [mint]: ["11"] } } }));
    expect(a).not.toBe(b);
  });

  it.each([["0010"], [" 10 "], ["\n0010\t"], [10], ["10"]])("a cap written %j hashes like the cap 10", async (cap) => {
    const a = svmRequest({ spendPolicy: { maxPerPayment: { [mint]: 10n } } });
    const b = svmRequest({ spendPolicy: { maxPerPayment: { [mint]: cap } } });
    expect((await verify(b, ctx)).decision).toBe((await verify(a, ctx)).decision);
    expect(requestDigest(b)).toBe(requestDigest(a));
  });

  it("repeated assets and payees hash like the set they make", async () => {
    const payee = merchant.publicKey.toBase58();
    const a = svmRequest({ spendPolicy: { assets: [mint], payees: [payee] } });
    const b = svmRequest({ spendPolicy: { assets: [mint, mint], payees: [payee, payee] } });
    expect((await verify(b, ctx)).decision).toBe("allow");
    expect(requestDigest(b)).toBe(requestDigest(a));
  });

  it("spaces around a mint or a payee hash as the lane reads them", async () => {
    const payee = merchant.publicKey.toBase58();
    const a = svmRequest({ spendPolicy: { maxPerPayment: { [mint]: "1000000" }, payees: [payee] } });
    const b = svmRequest({ spendPolicy: { maxPerPayment: { [` ${mint} `]: "1000000" }, payees: [` ${payee} `] } });
    expect((await verify(b, ctx)).decision).toBe("allow");
    expect(requestDigest(b)).toBe(requestDigest(a));
  });

  it("lifetime totals are read and hashed the same way", () => {
    const evm = (maxTotal: Record<string, unknown>): VerifyRequest => ({
      network: "eip155:8453",
      quote: quoteOf(MERCHANT, ONE_USDC),
      payload: { signature: "0x00", authorization: {} },
      options: { spendPolicy: { maxTotal } } as never,
    });
    expect(requestDigest(evm({ [BASE_USDC]: "0010" }))).toBe(requestDigest(evm({ [BASE_USDC.toLowerCase()]: 10n })));
    expect(requestDigest(evm({ [BASE_USDC]: "10" }))).not.toBe(requestDigest(evm({ [BASE_USDC]: "11" })));
  });

  it("an undefined policy hashes as no policy, which is how both lanes read it", () => {
    expect(requestDigest(svmRequest({ spendPolicy: undefined }))).toBe(requestDigest(svmRequest()));
  });

  it("a cyclic unreadable policy still hashes, and in bounded time", () => {
    const loop: unknown[] = [];
    for (let i = 0; i < 64; i++) loop.push(loop);
    const started = performance.now();
    expect(() => requestDigest(svmRequest({ spendPolicy: { assets: loop } }))).not.toThrow();
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it("an EVM address in a Solana request is unreadable there, and hashes apart from the same policy on EVM", () => {
    const policy = { payees: [MERCHANT] };
    const svm = svmRequest({ spendPolicy: policy });
    const evm: VerifyRequest = { ...svm, network: "eip155:8453" };
    expect(inspectPayment(build(merchant.publicKey, ONE_USDC).serialize(), svmQuote(merchant.publicKey, ONE_USDC), { spendPolicy: policy }).decision).toBe("abstain");
    expect(requestDigest(svm)).not.toBe(requestDigest(evm));
  });
});

describe("a policy whose reading throws is an abstain, never an exception", () => {
  const throwingGetter = () =>
    Object.defineProperty({}, "assets", {
      enumerable: true,
      get() {
        throw new Error("unreadable");
      },
    });
  const revoked = () => {
    const p = Proxy.revocable({}, {});
    p.revoke();
    return p.proxy;
  };
  const throwingCaps = () => ({
    maxPerPayment: Object.defineProperty({}, BASE_USDC, {
      enumerable: true,
      get() {
        throw new Error("unreadable");
      },
    }),
  });

  it("a bigint in an address list: the signed, pre-signing and Solana checks all abstain", async () => {
    const opts = { nowSeconds: NOW, spendPolicy: { assets: [1n] } } as never;
    expect((await inspectAuthorization(quoteOf(MERCHANT, ONE_USDC), await signAuth(MERCHANT, ONE_USDC), opts)).decision).toBe("abstain");
    expect(inspectTypedDataRequest(quoteOf(MERCHANT, ONE_USDC), typedRequest(MERCHANT, ONE_USDC), opts).decision).toBe("abstain");
    expect(inspectPayment(build(merchant.publicKey, ONE_USDC).serialize(), svmQuote(merchant.publicKey, ONE_USDC), opts).decision).toBe("abstain");
  });

  it.each([
    ["a getter that throws", throwingGetter],
    ["a revoked proxy", revoked],
    ["a getter that throws inside the caps", throwingCaps],
  ])("%s abstains", async (_name, make) => {
    const opts = { nowSeconds: NOW, spendPolicy: make() } as never;
    expect(inspectTypedDataRequest(quoteOf(MERCHANT, ONE_USDC), typedRequest(MERCHANT, ONE_USDC), opts).decision).toBe("abstain");
    expect((await inspectAuthorization(quoteOf(MERCHANT, ONE_USDC), await signAuth(MERCHANT, ONE_USDC), opts)).decision).toBe("abstain");
  });

  it("the digest of such a request is computed, not thrown, and a guard refuses before the wallet is asked", async () => {
    for (const policy of [{ assets: [1n] }, throwingGetter(), revoked()]) {
      const req: VerifyRequest = { network: "eip155:8453", quote: quoteOf(MERCHANT, ONE_USDC), payload: {}, options: { spendPolicy: policy } as never };
      expect(() => requestDigest(req)).not.toThrow();
      const calls: string[] = [];
      const wallet = {
        async signTransaction(tx: VersionedTransaction) {
          calls.push("signTransaction");
          return tx;
        },
      };
      const guarded = guardSigner(wallet, () => svmQuote(merchant.publicKey, ONE_USDC), { spendPolicy: policy as never });
      await expect(guarded.signTransaction(build(merchant.publicKey, ONE_USDC))).rejects.toThrow(/abstain/);
      expect(calls).toEqual([]);
    }
  });
});

describe("a guard reads its policy once per signing", () => {
  const counting = (key: string, value: unknown) => {
    const counter = { reads: 0 };
    const policy = Object.defineProperty({}, key, {
      enumerable: true,
      get() {
        counter.reads++;
        return value;
      },
    });
    return { counter, policy };
  };

  it("guardSigner: the check and the lifetime total see one reading", async () => {
    const { counter, policy } = counting("maxTotal", { [USDC.toBase58()]: "5000000" });
    const wallet = { async signTransaction(tx: VersionedTransaction) { return tx; } };
    const guarded = guardSigner(wallet, () => svmQuote(merchant.publicKey, ONE_USDC), { spendPolicy: policy as never });
    await guarded.signTransaction(build(merchant.publicKey, ONE_USDC));
    expect(counter.reads).toBe(1);
  });

  it("guardSigner: a batch is checked and counted on one reading too", async () => {
    const { counter, policy } = counting("maxTotal", { [USDC.toBase58()]: "5000000" });
    const wallet = {
      async signTransaction(tx: VersionedTransaction) { return tx; },
      async signAllTransactions(txs: VersionedTransaction[]) { return txs; },
    };
    const guarded = guardSigner(wallet, () => svmQuote(merchant.publicKey, ONE_USDC), { spendPolicy: policy as never });
    await guarded.signAllTransactions([1, 2].map(() => build(merchant.publicKey, ONE_USDC)));
    expect(counter.reads).toBe(1);
  });

  it("guardEvmSigner: the check and the lifetime total see one reading", async () => {
    const { counter, policy } = counting("maxTotal", { [BASE_USDC]: "5000000" });
    const signer = { async signTypedData(_r: unknown) { return "0xsigned"; } };
    const guarded = guardEvmSigner(signer, () => quoteOf(MERCHANT, ONE_USDC), { spendPolicy: policy as never });
    await guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC));
    expect(counter.reads).toBe(1);
  });
});

// --- one reading of a request, hidden keys, releases (AWG-010-08, -10, -11, -12, -14, -15)

describe("verify() reads a request once, for its verdict and its receipt", () => {
  const ctx = { quoteProvenance: "facilitator_held" as const, issuedAt: "2033-05-18T03:33:20.000Z" };
  const mint = USDC.toBase58();
  const lanes = async () => [
    {
      name: "evm",
      asset: BASE_USDC,
      base: { network: "eip155:8453", quote: quoteOf(MERCHANT, ONE_USDC), payload: await signAuth(MERCHANT, ONE_USDC) },
    },
    {
      name: "solana",
      asset: mint,
      base: {
        network: "solana",
        quote: svmQuote(merchant.publicKey, ONE_USDC),
        payload: Buffer.from(build(merchant.publicKey, ONE_USDC).serialize()).toString("base64"),
      },
    },
  ];

  it("a policy that changes between reads: the receipt hashes the reading its verdict used", async () => {
    for (const { name, asset, base } of await lanes()) {
      let reads = 0;
      const policy = {
        get maxPerPayment() {
          return { [asset]: ++reads === 1 ? "1000000" : "0" };
        },
      };
      const changing = { ...base, options: { spendPolicy: policy } } as VerifyRequest;
      const asChecked = { ...base, options: { spendPolicy: { maxPerPayment: { [asset]: "1000000" } } } } as VerifyRequest;
      const other = { ...base, options: { spendPolicy: { maxPerPayment: { [asset]: "0" } } } } as VerifyRequest;
      const r = await verify(changing, ctx);
      expect(r.decision, name).toBe("allow");
      expect(reads, name).toBe(1);
      expect(r.receipt!.request_digest, name).toBe(requestDigest(asChecked));
      expect(replayMatches(r.receipt!, other), name).toBe(false);
    }
  });

  it("a non-enumerable spendPolicy option is applied, and hashed, like any other", async () => {
    for (const { name, asset, base } of await lanes()) {
      const unreadable = { ...base, options: Object.defineProperty({}, "spendPolicy", { value: { assets: [1n] } }) } as VerifyRequest;
      expect((await verify(unreadable, ctx)).decision, name).toBe("abstain");
      const capped = { ...base, options: Object.defineProperty({}, "spendPolicy", { value: { maxPerPayment: { [asset]: "0" } } }) } as VerifyRequest;
      const r = await verify(capped, ctx);
      expect(r.decision, name).toBe("refuse");
      expect(codes(r), name).toContain("X402-501");
      expect(r.receipt!.request_digest, name).toBe(requestDigest({ ...base, options: { spendPolicy: { maxPerPayment: { [asset]: "0" } } } } as VerifyRequest));
    }
  });

  it("a spendPolicy option whose getter throws: verify abstains and the digest is computed", async () => {
    for (const { name, base } of await lanes()) {
      const options = Object.defineProperty({}, "spendPolicy", {
        enumerable: true,
        get() {
          throw new Error("unreadable");
        },
      });
      const req = { ...base, options } as VerifyRequest;
      expect((await verify(req, ctx)).decision, name).toBe("abstain");
      expect(() => requestDigest(req), name).not.toThrow();
    }
  });
});

describe("the checks read the spendPolicy option once and never throw on it", () => {
  const throwing = () =>
    Object.defineProperty({}, "spendPolicy", {
      enumerable: true,
      get() {
        throw new Error("unreadable");
      },
    }) as never;

  it("inspectAuthorization, inspectTypedDataRequest and inspectPayment abstain", async () => {
    expect((await inspectAuthorization(quoteOf(MERCHANT, ONE_USDC), await signAuth(MERCHANT, ONE_USDC), throwing())).decision).toBe("abstain");
    expect(inspectTypedDataRequest(quoteOf(MERCHANT, ONE_USDC), typedRequest(MERCHANT, ONE_USDC), throwing()).decision).toBe("abstain");
    expect(inspectPayment(build(merchant.publicKey, ONE_USDC).serialize(), svmQuote(merchant.publicKey, ONE_USDC), throwing()).decision).toBe("abstain");
  });

  it("both guards refuse with abstain, and no wallet is asked", async () => {
    const calls: string[] = [];
    const evm = guardEvmSigner({ async signTypedData(_r: unknown) { calls.push("evm"); return "0x"; } }, () => quoteOf(MERCHANT, ONE_USDC), throwing());
    await expect(evm.signTypedData(typedRequest(MERCHANT, ONE_USDC))).rejects.toThrow(/abstain/);
    const svm = guardSigner({ async signTransaction(tx: VersionedTransaction) { calls.push("svm"); return tx; } }, () => svmQuote(merchant.publicKey, ONE_USDC), throwing());
    await expect(svm.signTransaction(build(merchant.publicKey, ONE_USDC))).rejects.toThrow(/abstain/);
    expect(calls).toEqual([]);
  });

  it("a guard reads the option once per signing, whether or not it holds a policy", async () => {
    for (const value of [undefined, {}, { maxPerPayment: { [BASE_USDC]: "1000000" } }]) {
      let reads = 0;
      const opts = {
        get spendPolicy() {
          reads++;
          return value;
        },
      };
      const guarded = guardEvmSigner({ async signTypedData(_r: unknown) { return "0xsigned"; } }, () => quoteOf(MERCHANT, ONE_USDC), opts as never);
      await guarded.signTypedData(typedRequest(MERCHANT, ONE_USDC));
      expect(reads).toBe(1);
    }
    let reads = 0;
    const opts = {
      get spendPolicy() {
        reads++;
        return undefined;
      },
    };
    const svm = guardSigner({ async signTransaction(tx: VersionedTransaction) { return tx; } }, () => svmQuote(merchant.publicKey, ONE_USDC), opts as never);
    await svm.signTransaction(build(merchant.publicKey, ONE_USDC));
    expect(reads).toBe(1);
  });
});

describe("keys a policy cannot hide", () => {
  const check = (spendPolicy: unknown) =>
    inspectTypedDataRequest(quoteOf(MERCHANT, ONE_USDC), typedRequest(MERCHANT, ONE_USDC), { spendPolicy } as never);

  it("an unknown key that is not enumerable abstains", () => {
    expect(check(Object.defineProperty({}, "maxPerPaymnet", { value: { [BASE_USDC]: "0" } })).decision).toBe("abstain");
  });

  it("a symbol key abstains, in the policy or in its caps", () => {
    expect(check({ [Symbol("maxPerPayment")]: { [BASE_USDC]: "0" } }).decision).toBe("abstain");
    expect(check({ maxPerPayment: { [BASE_USDC]: "1000000", [Symbol("cap")]: "0" } }).decision).toBe("abstain");
  });

  it("a known rule that is not enumerable is applied", () => {
    const v = check(Object.defineProperty({}, "maxPerPayment", { value: { [BASE_USDC]: "0" } }));
    expect(codes(v)).toEqual(["X402-501"]);
  });

  it("a list that is not a plain array abstains: its own iterator, a named property, another prototype", () => {
    const iterating = Object.assign([], {
      [Symbol.iterator]() {
        throw new Error("unreadable");
      },
    });
    const named = Object.assign([MERCHANT], { extra: MERCHANT });
    class Payees extends Array<string> {}
    const subclass = Payees.from([MERCHANT]);
    for (const payees of [iterating, named, subclass]) expect(check({ payees }).decision).toBe("abstain");
    expect(check({ payees: [MERCHANT] }).decision).toBe("allow");
  });
});

describe("a lifetime total releases only what a call held", () => {
  it("a failed call made while no total was set refunds nothing, in either guard", async () => {
    for (const lane of ["evm", "solana"]) {
      const asset = lane === "evm" ? BASE_USDC : USDC.toBase58();
      const policy: { maxTotal?: Record<string, string> } = { maxTotal: { [asset]: "1000000" } };
      let fail = false;
      let signed = 0;
      const sign = async (x: unknown) => {
        if (fail) throw new Error("wallet refused");
        signed++;
        return x;
      };
      const evm = guardEvmSigner({ signTypedData: sign }, () => quoteOf(MERCHANT, ONE_USDC), { spendPolicy: policy });
      const svm = guardSigner({ signTransaction: sign }, () => svmQuote(merchant.publicKey, ONE_USDC), { spendPolicy: policy });
      const pay = () => (lane === "evm" ? evm.signTypedData(typedRequest(MERCHANT, ONE_USDC)) : svm.signTransaction(build(merchant.publicKey, ONE_USDC)));
      await pay();
      delete policy.maxTotal;
      fail = true;
      await expect(pay()).rejects.toThrow("wallet refused");
      policy.maxTotal = { [asset]: "1000000" };
      fail = false;
      await expect(pay(), lane).rejects.toThrow(/X402-504/);
      expect(signed, lane).toBe(1);
    }
  });
});

// --- the caller's own options, and shared objects read once (AWG-010-16, -17) ---

describe("a guard reads the caller's other options as the caller's own", () => {
  it("an expectedPayer getter keyed by the options object still binds the payer, with no policy", async () => {
    const values = new WeakMap<object, string>();
    const evmOptions = {
      get expectedPayer() {
        return values.get(this);
      },
    };
    values.set(evmOptions, ATTACKER);
    expect(inspectTypedDataRequest(quoteOf(MERCHANT, ONE_USDC), typedRequest(MERCHANT, ONE_USDC), evmOptions as never).decision).toBe("refuse");
    let evmCalls = 0;
    const evm = guardEvmSigner({ async signTypedData(_r: unknown) { evmCalls++; return "0x"; } }, () => quoteOf(MERCHANT, ONE_USDC), evmOptions as never);
    await expect(evm.signTypedData(typedRequest(MERCHANT, ONE_USDC))).rejects.toThrow(/refus/);
    expect(evmCalls).toBe(0);

    const svmOptions = {
      get expectedPayer() {
        return values.get(this);
      },
    };
    values.set(svmOptions, attacker.publicKey.toBase58());
    const tx = build(merchant.publicKey, ONE_USDC);
    expect(inspectPayment(tx.serialize(), svmQuote(merchant.publicKey, ONE_USDC), svmOptions as never).decision).toBe("refuse");
    let svmCalls = 0;
    const svm = guardSigner({ async signTransaction(t: VersionedTransaction) { svmCalls++; return t; } }, () => svmQuote(merchant.publicKey, ONE_USDC), svmOptions as never);
    await expect(svm.signTransaction(tx)).rejects.toThrow(/refus/);
    expect(svmCalls).toBe(0);
  });

  it("a nonce set made lazily on the options keeps its state across signings, with or without a policy", async () => {
    for (const withPolicy of [false, true]) {
      const options = {
        ...(withPolicy ? { spendPolicy: {} } : {}),
        nonceCache: undefined as Set<string> | undefined,
        get seenNonces() {
          return (this.nonceCache ??= new Set<string>());
        },
      };
      let calls = 0;
      const guarded = guardEvmSigner({ async signTypedData(_r: unknown) { calls++; return "0x"; } }, () => quoteOf(MERCHANT, ONE_USDC), options as never);
      const signed = await signAuth(MERCHANT, ONE_USDC);
      await guarded.signTypedData(signed);
      await expect(guarded.signTypedData(signed), String(withPolicy)).rejects.toThrow(/X402-107/);
      expect(options.nonceCache?.size, String(withPolicy)).toBe(1);
      expect(calls, String(withPolicy)).toBe(1);
    }
  });
});

describe("one object shared by two rules is read once", () => {
  const ctx = { quoteProvenance: "facilitator_held" as const, issuedAt: "2033-05-18T03:33:20.000Z" };

  it("a shared cap map's getter runs once per signing, in either guard", async () => {
    for (const lane of ["evm", "solana"]) {
      const asset = lane === "evm" ? BASE_USDC : USDC.toBase58();
      let reads = 0;
      const caps = {
        get [asset]() {
          if (++reads > 1) throw new Error("second read");
          return "5000000";
        },
      };
      const options = { spendPolicy: { maxPerPayment: caps, maxTotal: caps } };
      let calls = 0;
      const sign = async (x: unknown) => {
        calls++;
        return x;
      };
      if (lane === "evm") {
        await guardEvmSigner({ signTypedData: sign }, () => quoteOf(MERCHANT, ONE_USDC), options).signTypedData(typedRequest(MERCHANT, ONE_USDC));
      } else {
        await guardSigner({ signTransaction: sign }, () => svmQuote(merchant.publicKey, ONE_USDC), options).signTransaction(build(merchant.publicKey, ONE_USDC));
      }
      expect(reads, lane).toBe(1);
      expect(calls, lane).toBe(1);
    }
  });

  it("verify() and its digest use one reading of a shared cap", async () => {
    const lanes = [
      { asset: BASE_USDC, base: { network: "eip155:8453", quote: quoteOf(MERCHANT, ONE_USDC), payload: await signAuth(MERCHANT, ONE_USDC) } },
      {
        asset: USDC.toBase58(),
        base: { network: "solana", quote: svmQuote(merchant.publicKey, ONE_USDC), payload: Buffer.from(build(merchant.publicKey, ONE_USDC).serialize()).toString("base64") },
      },
    ];
    for (const { asset, base } of lanes) {
      let reads = 0;
      const caps = {
        get [asset]() {
          return ++reads === 1 ? "1000000" : "2000000";
        },
      };
      const r = await verify({ ...base, options: { spendPolicy: { maxPerPayment: caps, maxTotal: caps } } } as VerifyRequest, ctx);
      expect(r.decision).toBe("allow");
      expect(reads).toBe(1);
      const once = { maxPerPayment: { [asset]: "1000000" }, maxTotal: { [asset]: "1000000" } };
      expect(r.receipt!.request_digest).toBe(requestDigest({ ...base, options: { spendPolicy: once } } as VerifyRequest));
    }
  });

  it("a shared cap whose getter throws runs once, and the policy abstains", () => {
    let reads = 0;
    const caps = {
      get [BASE_USDC]() {
        reads++;
        throw new Error("unreadable");
      },
    };
    const v = inspectTypedDataRequest(quoteOf(MERCHANT, ONE_USDC), typedRequest(MERCHANT, ONE_USDC), {
      spendPolicy: { maxPerPayment: caps, maxTotal: caps },
    } as never);
    expect(v.decision).toBe("abstain");
    expect(reads).toBe(1);
  });

  it("a Solana batch applies the one reading to both rules", async () => {
    let reads = 0;
    const caps = {
      get [USDC.toBase58()]() {
        return ++reads === 1 ? "1000000" : "2000000";
      },
    };
    let calls = 0;
    const guarded = guardSigner(
      {
        async signTransaction(t: VersionedTransaction) { return t; },
        async signAllTransactions(txs: VersionedTransaction[]) { calls++; return txs; },
      },
      () => svmQuote(merchant.publicKey, ONE_USDC),
      { spendPolicy: { maxPerPayment: caps, maxTotal: caps } },
    );
    await expect(guarded.signAllTransactions([1, 2].map(() => build(merchant.publicKey, ONE_USDC)))).rejects.toThrow(/X402-504/);
    expect(reads).toBe(1);
    expect(calls).toBe(0);
  });
});

