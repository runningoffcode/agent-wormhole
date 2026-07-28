/**
 * These build real EIP-3009 TransferWithAuthorization signatures with viem and
 * run the EVM verifier over them, because the only claim worth testing is the
 * end-to-end one: given a quote and a signed authorization, does it recover the
 * right signer and catch a substituted destination, an inflated value, a
 * cross-chain replay, or a standing-authority grant disguised as a payment.
 */

import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import {
  inspectAuthorization,
  evmQuoteFromRequirements,
  parseNetwork,
  TRUSTED_DOMAINS,
  EIP3009,
  type EvmPaymentQuote,
  type EvmPayload,
} from "../src/evm.js";

// A fixed test key — deterministic signer address across runs.
const PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const account = privateKeyToAccount(PK);
const SIGNER = account.address; // this is `from`

// Base mainnet USDC — the on-chain-verified table entry.
const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const BASE_CHAIN = 8453;

const MERCHANT = "0x1111111111111111111111111111111111111111";
const ATTACKER = "0x2222222222222222222222222222222222222222";

const NONCE_A =
  "0x00000000000000000000000000000000000000000000000000000000000000aa" as Hex;

/** The quote as it would arrive in the server's 402 response. */
const quote: EvmPaymentQuote = {
  network: "eip155:8453",
  asset: BASE_USDC,
  payTo: MERCHANT,
  amount: "1000000", // 1 USDC (6 decimals)
};

interface AuthFields {
  to?: string;
  value?: bigint;
  validAfter?: bigint;
  validBefore?: bigint;
  nonce?: Hex;
  chainId?: number;
  verifyingContract?: string;
  name?: string;
  version?: string;
}

/**
 * Build a real EIP-3009 authorization + signature. Domain defaults to the
 * verified Base USDC domain; overrides let a test sign for a different chain,
 * token, or domain string to prove the recovery catches it.
 */
async function signAuth(f: AuthFields = {}): Promise<EvmPayload & { authorization: any }> {
  const to = f.to ?? MERCHANT;
  const value = f.value ?? 1_000_000n;
  const validAfter = f.validAfter ?? 0n;
  const validBefore = f.validBefore ?? 0n; // 0 = no expiry
  const nonce = f.nonce ?? NONCE_A;

  const domain = {
    name: f.name ?? "USD Coin",
    version: f.version ?? "2",
    chainId: f.chainId ?? BASE_CHAIN,
    verifyingContract: (f.verifyingContract ?? BASE_USDC) as Hex,
  } as const;

  const message = {
    from: SIGNER as Hex,
    to: to as Hex,
    value,
    validAfter,
    validBefore,
    nonce,
  };

  const signature = await account.signTypedData({
    domain,
    types: EIP3009.TYPES,
    primaryType: EIP3009.PRIMARY_TYPE,
    message,
  });

  return {
    signature,
    assetTransferMethod: "eip3009",
    authorization: {
      from: SIGNER,
      to,
      value: value.toString(),
      validAfter: validAfter.toString(),
      validBefore: validBefore.toString(),
      nonce,
    },
  };
}

// A clock pinned well inside any test window.
const FIXED_NOW = 2_000_000_000n; // year 2033

describe("network parsing", () => {
  it("resolves eip155:<id>", () => {
    expect(parseNetwork("eip155:8453")).toBe(8453);
    expect(parseNetwork("eip155:1")).toBe(1);
  });
  it("resolves known v1 bare names", () => {
    expect(parseNetwork("base")).toBe(8453);
    expect(parseNetwork("base-sepolia")).toBe(84532);
    expect(parseNetwork("ethereum")).toBe(1);
  });
  it("returns null for unknown networks", () => {
    expect(parseNetwork("solana")).toBeNull();
    expect(parseNetwork("eip155:")).toBeNull();
    expect(parseNetwork("eip155:0x10")).toBeNull();
    expect(parseNetwork("")).toBeNull();
    expect(parseNetwork(42 as any)).toBeNull();
  });
});

describe("the domain table is the source of truth, not the quote", () => {
  it("has Base USDC verified with the on-chain name/version", () => {
    const e = TRUSTED_DOMAINS[`8453:${BASE_USDC.toLowerCase()}`];
    expect(e).toBeTruthy();
    expect(e.name).toBe("USD Coin");
    expect(e.version).toBe("2");
    expect(e.verified).toBe(true);
  });
});

describe("a conforming EIP-3009 authorization", () => {
  it("ALLOWS a payment that matches the quote", async () => {
    const v = await inspectAuthorization(quote, await signAuth(), {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).toBe("allow");
    expect(v.findings).toHaveLength(0);
  });

  it("still ALLOWS when the quote's extra.name lies and says \"USDC\" (table wins)", async () => {
    // The signature is made against the REAL domain "USD Coin". The attacker
    // sets extra.name to "USDC" hoping the verifier recovers against that. It
    // must ignore extra entirely and use the table -> still recovers `from`.
    const attackerQuote = { ...quote } as EvmPaymentQuote & { extra?: any };
    (attackerQuote as any).extra = { name: "USDC", version: "1", assetTransferMethod: "eip3009" };
    const v = await inspectAuthorization(attackerQuote, await signAuth(), {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).toBe("allow");
    expect(v.findings).toHaveLength(0);
  });
});

describe("X402-101 substituted destination", () => {
  it("REFUSES an authorization paying the attacker", async () => {
    const v = await inspectAuthorization(quote, await signAuth({ to: ATTACKER }), {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).toBe("refuse");
    const f = v.findings.find((x) => x.code === "X402-101");
    expect(f?.severity).toBe("critical");
    expect(f?.expected?.toLowerCase()).toBe(MERCHANT.toLowerCase());
    expect(f?.actual?.toLowerCase()).toBe(ATTACKER.toLowerCase());
  });
  it("ALLOWS the benign twin paying the merchant", async () => {
    const v = await inspectAuthorization(quote, await signAuth({ to: MERCHANT }), {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).toBe("allow");
  });
});

describe("X402-102 wrong value", () => {
  it("REFUSES an inflated value", async () => {
    const v = await inspectAuthorization(quote, await signAuth({ value: 900_000_000n }), {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-102")).toBe(true);
  });
  it("ALLOWS the exact quoted value", async () => {
    const v = await inspectAuthorization(quote, await signAuth({ value: 1_000_000n }), {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).toBe("allow");
  });
});

describe("X402-103 / cross-chain & cross-token replay", () => {
  it("REFUSES a signature made for a different chain (recovery fails -> X402-104)", async () => {
    // Signed with chainId 1 in the domain, but the quote is Base 8453. The
    // verifier builds the domain from the Base table entry, so the recovered
    // signer will NOT equal `from`.
    const payload = await signAuth({ chainId: 1 });
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-104")).toBe(true);
  });

  it("REFUSES a signature made for a different verifyingContract", async () => {
    const payload = await signAuth({
      verifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    });
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-104")).toBe(true);
  });

  it("REFUSES an explicit payload asset that disagrees with the quote (X402-103)", async () => {
    const payload = await signAuth();
    (payload as any).asset = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    // The signature is still valid for Base USDC, so 104 passes; the mismatched
    // payload asset must surface as 103.
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-103")).toBe(true);
  });
});

describe("X402-104 signature recovery", () => {
  it("REFUSES when from is swapped to a different address than the signer", async () => {
    const payload = await signAuth();
    payload.authorization.from = ATTACKER; // claim someone else signed
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-104")).toBe(true);
  });
  it("ALLOWS when from matches the recovered signer", async () => {
    const v = await inspectAuthorization(quote, await signAuth(), { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("allow");
  });
});

describe("X402-105 validity window", () => {
  it("REFUSES an authorization not yet valid", async () => {
    const payload = await signAuth({ validAfter: FIXED_NOW + 1000n });
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-105")).toBe(true);
  });
  it("REFUSES an expired authorization", async () => {
    const payload = await signAuth({ validBefore: FIXED_NOW - 1000n });
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-105")).toBe(true);
  });
  it("ALLOWS inside the window", async () => {
    const payload = await signAuth({
      validAfter: FIXED_NOW - 1000n,
      validBefore: FIXED_NOW + 1000n,
    });
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("allow");
  });
  it("treats validBefore 0 as no-expiry and ALLOWS", async () => {
    const payload = await signAuth({ validBefore: 0n });
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("allow");
  });
});

describe("X402-106 standing authority", () => {
  it("REFUSES an EIP-2612 Permit shape", async () => {
    // No valid EIP-3009 signature needed — the shape alone is refused before
    // recovery is attempted.
    const payload: any = {
      assetTransferMethod: "eip3009",
      primaryType: "Permit",
      authorization: {},
    };
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-106")).toBe(true);
  });

  it("REFUSES an unbounded (max uint256) permit value", async () => {
    const payload: any = {
      permit: { value: ((1n << 256n) - 1n).toString() },
      authorization: {},
    };
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-106")).toBe(true);
  });

  it("REFUSES a setApprovalForAll shape", async () => {
    const payload: any = { primaryType: "setApprovalForAll", authorization: {} };
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-106")).toBe(true);
  });

  it("REFUSES a witness-less Permit2 PermitTransferFrom (blanket), method permit2", async () => {
    const payload: any = {
      assetTransferMethod: "permit2",
      primaryType: "PermitTransferFrom",
      authorization: {},
    };
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-106")).toBe(true);
  });

  it("ABSTAINS (not allow) on a scoped Permit2 PermitWitnessTransferFrom — positive verify is out of scope", async () => {
    const payload: any = {
      assetTransferMethod: "permit2",
      primaryType: "PermitWitnessTransferFrom",
      authorization: {},
    };
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("abstain");
    expect(v.decision).not.toBe("allow");
  });

  it("ALLOWS the benign twin: a real EIP-3009 transfer (no standing authority)", async () => {
    const v = await inspectAuthorization(quote, await signAuth(), { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("allow");
  });
});

describe("X402-107 session replay", () => {
  it("REFUSES a nonce already seen this session", async () => {
    const seen = new Set<string>();
    const v1 = await inspectAuthorization(quote, await signAuth(), {
      nowSeconds: FIXED_NOW,
      seenNonces: seen,
    });
    expect(v1.decision).toBe("allow");
    const v2 = await inspectAuthorization(quote, await signAuth(), {
      nowSeconds: FIXED_NOW,
      seenNonces: seen,
    });
    expect(v2.decision).toBe("refuse");
    expect(v2.findings.some((f) => f.code === "X402-107")).toBe(true);
  });

  it("ALLOWS a fresh nonce (benign twin)", async () => {
    const seen = new Set<string>();
    const nonceB =
      "0x00000000000000000000000000000000000000000000000000000000000000bb" as Hex;
    await inspectAuthorization(quote, await signAuth(), {
      nowSeconds: FIXED_NOW,
      seenNonces: seen,
    });
    const v = await inspectAuthorization(quote, await signAuth({ nonce: nonceB }), {
      nowSeconds: FIXED_NOW,
      seenNonces: seen,
    });
    expect(v.decision).toBe("allow");
  });
});

describe("X402-110 erc7710", () => {
  it("ABSTAINS on erc7710 (opaque permissionContext)", async () => {
    const payload: any = { assetTransferMethod: "erc7710", authorization: {} };
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("abstain");
    expect(v.findings.some((f) => f.code === "X402-110")).toBe(true);
  });
});

describe("table-miss ABSTAIN", () => {
  it("ABSTAINS when (chainId, asset) is not in the trusted table", async () => {
    const unknownQuote: EvmPaymentQuote = {
      network: "eip155:8453",
      asset: "0x9999999999999999999999999999999999999999",
      payTo: MERCHANT,
      amount: "1000000",
    };
    // Sign against the unknown token's own domain so a signature exists.
    const payload = await signAuth({
      verifyingContract: "0x9999999999999999999999999999999999999999",
    });
    const v = await inspectAuthorization(unknownQuote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("abstain");
    expect(v.reason).toMatch(/no trusted EIP-712 domain/);
  });

  it("ABSTAINS on an unresolvable network", async () => {
    const q = { ...quote, network: "solana" };
    const v = await inspectAuthorization(q, await signAuth(), { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("abstain");
  });
});

describe("signature hygiene", () => {
  it("ABSTAINS on a malformed signature (bad length)", async () => {
    const payload = await signAuth();
    payload.signature = "0xdeadbeef";
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("abstain");
    expect(v.reason).toMatch(/malformed/);
  });

  it("ABSTAINS when the signature is not a hex string", async () => {
    const payload = await signAuth();
    (payload as any).signature = 12345;
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("abstain");
  });

  it("REJECTS (ABSTAINS on) a high-s malleated signature", async () => {
    // Take a valid signature, flip s to n - s (the malleable counterpart) and
    // flip v. This is a valid ECDSA signature for the SAME message but with
    // high s; the verifier must refuse to recover from it.
    const SECP_N =
      0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const payload = await signAuth();
    const sig = (payload.signature as string).slice(2);
    const r = sig.slice(0, 64);
    const s = BigInt("0x" + sig.slice(64, 128));
    const v = parseInt(sig.slice(128, 130), 16);
    const highS = SECP_N - s;
    // sanity: our original was low-s
    expect(s <= SECP_N >> 1n).toBe(true);
    expect(highS > SECP_N >> 1n).toBe(true);
    const flippedV = v === 27 ? 28 : 27;
    const malleated =
      "0x" +
      r +
      highS.toString(16).padStart(64, "0") +
      flippedV.toString(16).padStart(2, "0");
    payload.signature = malleated as Hex;
    const res = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(res.decision).toBe("abstain");
    expect(res.reason).toMatch(/malformed|high-s|malleab/i);
  });

  it("accepts a 64-byte EIP-2098 compact signature that recovers correctly", async () => {
    // Build the compact form from the 65-byte signature and confirm ALLOW.
    const payload = await signAuth();
    const sig = (payload.signature as string).slice(2);
    const r = sig.slice(0, 64);
    const s = BigInt("0x" + sig.slice(64, 128));
    const v = parseInt(sig.slice(128, 130), 16);
    const yParity = BigInt(v - 27);
    const yParityAndS = (yParity << 255n) | s;
    const compact = "0x" + r + yParityAndS.toString(16).padStart(64, "0");
    payload.signature = compact as Hex;
    const res = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(res.decision).toBe("allow");
  });
});

describe("malformed authorization fields ABSTAIN rather than allow", () => {
  it("ABSTAINS on a nonce that is not bytes32", async () => {
    const payload = await signAuth();
    payload.authorization.nonce = "0x1234";
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("abstain");
  });

  it("ABSTAINS on a non-integer value", async () => {
    const payload = await signAuth();
    payload.authorization.value = "1.5";
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("abstain");
  });

  it("ABSTAINS on a non-address to", async () => {
    const payload = await signAuth();
    payload.authorization.to = "not-an-address";
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("abstain");
  });

  it("ABSTAINS on a non-integer quote amount", async () => {
    const v = await inspectAuthorization({ ...quote, amount: "1.5" }, await signAuth(), {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).toBe("abstain");
  });
});

describe("evmQuoteFromRequirements", () => {
  it("maps a v2 accepts entry to a quote", () => {
    const q = evmQuoteFromRequirements({
      scheme: "exact",
      network: "eip155:8453",
      payTo: MERCHANT,
      asset: BASE_USDC,
      amount: "1000000",
      extra: { assetTransferMethod: "eip3009" },
    });
    expect(q.network).toBe("eip155:8453");
    expect(q.payTo).toBe(MERCHANT);
    expect(q.asset).toBe(BASE_USDC);
    expect(q.amount).toBe("1000000");
  });

  it("falls back to maxAmountRequired (v1)", () => {
    const q = evmQuoteFromRequirements({
      scheme: "exact",
      network: "base",
      payTo: MERCHANT,
      asset: BASE_USDC,
      maxAmountRequired: "500000",
    });
    expect(q.amount).toBe("500000");
    expect(q.network).toBe("base");
  });

  it("throws when mandatory fields are missing", () => {
    expect(() =>
      evmQuoteFromRequirements({ scheme: "exact", network: "base" } as any),
    ).toThrow();
  });

  it("produces a quote that ALLOWS a real signature end-to-end", async () => {
    const q = evmQuoteFromRequirements({
      scheme: "exact",
      network: "eip155:8453",
      payTo: MERCHANT,
      asset: BASE_USDC,
      amount: "1000000",
      extra: { assetTransferMethod: "eip3009" },
    });
    const v = await inspectAuthorization(q, await signAuth(), { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("allow");
  });
});

describe("fail closed on undecodable input", () => {
  it("ABSTAINS on a null payload", async () => {
    const v = await inspectAuthorization(quote, null, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("abstain");
  });
  it("ABSTAINS on a payload with no authorization object", async () => {
    const v = await inspectAuthorization(
      quote,
      { signature: "0x" + "11".repeat(65), assetTransferMethod: "eip3009" },
      { nowSeconds: FIXED_NOW },
    );
    expect(v.decision).toBe("abstain");
  });
  it("never ALLOWS an unknown assetTransferMethod", async () => {
    const payload = await signAuth();
    (payload as any).assetTransferMethod = "some-future-method";
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).not.toBe("allow");
  });

  it("the payload cannot override the server quote's declared method", async () => {
    // The server (trusted 402 channel) says this payment is permit2 — which is
    // out of scope and should not be greenlit here. An attacker-adjacent
    // payload that self-declares eip3009 must NOT be able to steer itself into
    // the permissive EIP-3009 branch. The quote wins; the mismatch is refused.
    const quotePermit2: any = {
      network: "eip155:8453",
      asset: BASE_USDC,
      payTo: MERCHANT,
      amount: "1000000",
    };
    Object.defineProperty(quotePermit2, "extra", {
      value: { assetTransferMethod: "permit2" },
      enumerable: true,
    });
    const payload = await signAuth();
    (payload as any).assetTransferMethod = "eip3009";
    const v = await inspectAuthorization(quotePermit2, payload, {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-103")).toBe(true);
  });
});

describe("unreadable classification fields must not fall through to allow", () => {
  // A prior audit found every gate written `typeof x === "string" ? x : null`,
  // which conflates ABSENT with UNREADABLE. Control flow is "classify ->
  // refuse/abstain, else allow", so an unclassifiable value selected the most
  // permissive branch: primaryType ["Permit"] returned allow with zero findings
  // where "Permit" refused X402-106. Reachable from a plain JSON body -- no
  // boxed primitives, no Proxy.
  const NON_STRINGS: [string, unknown][] = [
    ["array", ["Permit"]],
    ["array naming a permit2 type", ["PermitBatchTransferFrom"]],
    ["number", 123],
    ["boolean", true],
    ["object", {}],
  ];

  for (const [label, value] of NON_STRINGS) {
    it(`does not allow when primaryType is a ${label}`, async () => {
      const wire = JSON.parse(
        JSON.stringify({ ...(await signAuth()), primaryType: value }),
      );
      const v = await inspectAuthorization(quote, wire, {
        nowSeconds: FIXED_NOW,
      });
      expect(v.decision).not.toBe("allow");
    });
  }

  it("does not allow when a permit value cannot be parsed", async () => {
    const MAX = (2n ** 256n - 1n).toString();
    const wire = JSON.parse(
      JSON.stringify({ ...(await signAuth()), permit: { value: [MAX] } }),
    );
    const v = await inspectAuthorization(quote, wire, {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).not.toBe("allow");
  });

  it("does not allow when assetTransferMethod is not a string", async () => {
    const wire = JSON.parse(
      JSON.stringify({ ...(await signAuth()), assetTransferMethod: ["eip3009"] }),
    );
    const v = await inspectAuthorization(quote, wire, {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).not.toBe("allow");
  });

  it("still allows an honest authorization with no primaryType", async () => {
    const v = await inspectAuthorization(quote, await signAuth(), {
      nowSeconds: FIXED_NOW,
    });
    expect(v.decision).toBe("allow");
  });

  it("still allows the correct primaryType", async () => {
    const v = await inspectAuthorization(
      quote,
      { ...(await signAuth()), primaryType: "TransferWithAuthorization" },
      { nowSeconds: FIXED_NOW },
    );
    expect(v.decision).toBe("allow");
  });
});
