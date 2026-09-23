/**
 * These build real EIP-3009 TransferWithAuthorization signatures with viem and
 * run the EVM verifier over them, because the only claim worth testing is the
 * end-to-end one: given a quote and a signed authorization, does it recover the
 * right signer and catch a substituted destination, an inflated value, a
 * cross-chain replay, or a standing-authority grant disguised as a payment.
 */

import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { keccak256, encodeAbiParameters, toBytes, type Hex } from "viem";
import {
  inspectAuthorization,
  evmQuoteFromRequirements,
  guardEvmSigner,
  inspectTypedDataRequest,
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
  // Not 0. The contract's check is `require(block.timestamp < validBefore)`
  // with no zero case, so 0 is the one value that can never pass it — an
  // honest fixture has to carry a real window.
  const validBefore = f.validBefore ?? 99999999999n;
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
  it("has Arc Testnet USDC verified with the on-chain name/version, and no Arc mainnet guess", () => {
    const e = TRUSTED_DOMAINS["5042002:0x3600000000000000000000000000000000000000"];
    expect(e).toBeTruthy();
    expect(e.name).toBe("USDC");
    expect(e.version).toBe("2");
    expect(e.verified).toBe(true);
  });

  it("has Arc mainnet verified against the deployed contract, not against a launch date", () => {
    const e = TRUSTED_DOMAINS["5042:0x3600000000000000000000000000000000000000"];
    expect(e).toBeTruthy();
    expect(e.name).toBe("USDC");
    expect(e.version).toBe("2");
    expect(e.verified).toBe(true);
  });

  it("has Robinhood Chain USDG on both networks, pinned to the on-chain separator", () => {
    const MAIN = "4663:0x5fc5360d0400a0fd4f2af552add042d716f1d168";
    const TEST = "46630:0x7e955252e15c84f5768b83c41a71f9eba181802f";
    for (const k of [MAIN, TEST]) {
      const e = TRUSTED_DOMAINS[k];
      expect(e).toBeTruthy();
      expect(e.name).toBe("Global Dollar");
      expect(e.version).toBe("1");
      expect(e.verified).toBe(true);
    }
    // The separator each contract actually returns. `version()` reverts on
    // this token, so the pinned "1" is only defensible while these match —
    // if a future edit changes name or version, recovery would silently
    // start returning the WRONG signer rather than failing.
    const sep = (chainId: bigint, contract: string, name: string) =>
      keccak256(
        encodeAbiParameters(
          [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
          [
            keccak256(toBytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
            keccak256(toBytes(name)),
            keccak256(toBytes("1")),
            chainId,
            contract as `0x${string}`,
          ],
        ),
      );
    expect(sep(4663n, "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", TRUSTED_DOMAINS[MAIN].name)).toBe(
      "0x7a3d7400b27830f4f91c2c16a082486d67c1befecaec2f53b33f1f35d5b62036",
    );
    expect(sep(46630n, "0x7E955252E15c84f5768B83c41a71F9eba181802F", TRUSTED_DOMAINS[TEST].name)).toBe(
      "0xb1debe91e09d82163fd9cddaab89359061c0671664e1611258a3c3de7c2d950b",
    );
  });

  it("recovers an Arc mainnet signer against the on-chain domain separator", async () => {
    // The separator below was read from the deployed contract on four
    // independent providers. If this entry's name/version ever drift from it,
    // recovery silently returns the WRONG signer, so pin the arithmetic.
    const ARC_USDC = "0x3600000000000000000000000000000000000000";
    const e = TRUSTED_DOMAINS[`5042:${ARC_USDC}`];
    const separator = keccak256(
      encodeAbiParameters(
        [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
        [
          keccak256(toBytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
          keccak256(toBytes(e.name)),
          keccak256(toBytes(e.version)),
          5042n,
          ARC_USDC as `0x${string}`,
        ],
      ),
    );
    expect(separator).toBe("0x940506929bba468048a19b567f4f0d534714bc06604b5c3017e5d16785ccdf84");
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
  it("REFUSES validBefore 0 — the contract can never accept it", async () => {
    // This asserted the opposite, on the belief that 0 meant "no expiry".
    // The contract's check is `require(block.timestamp < validBefore)` with
    // no zero case, so 0 is the one value that always fails it — and the old
    // exemption made it the one value that was never reported.
    const payload = await signAuth({ validBefore: 0n });
    const v = await inspectAuthorization(quote, payload, { nowSeconds: FIXED_NOW });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-105")).toBe(true);
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

/**
 * The EVM transaction firewall.
 *
 * `guardEvmSigner` is the difference between a check an agent may call and one it
 * cannot skip. These tests are about the SKIPPING, not the arithmetic —
 * `inspectAuthorization` is covered above. What matters here is that every route
 * to a signature goes through it and that an unrecognised route is refused.
 */
describe("guardEvmSigner — the firewall", () => {
  /** A signer that records what it was asked to do. */
  function fakeSigner() {
    const calls: string[] = [];
    return {
      calls,
      async signTypedData(p: unknown) {
        calls.push("signTypedData");
        return "0xsigned";
      },
      async _signTypedData(p: unknown) {
        calls.push("_signTypedData");
        return "0xsigned";
      },
      async signMessage(p: unknown) {
        calls.push("signMessage");
        return "0xsigned";
      },
      async sendTransaction(p: unknown) {
        calls.push("sendTransaction");
        return "0xhash";
      },
      async getAddress() {
        calls.push("getAddress");
        return SIGNER;
      },
    };
  }

  it("passes a conforming authorization through and calls the real signer", async () => {
    const payload = await signAuth();
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(guarded.signTypedData(payload)).resolves.toBe("0xsigned");
    expect(s.calls).toEqual(["signTypedData"]);
  });

  it("refuses when the amount does not match the quote, and never reaches the signer", async () => {
    // The whole product in one assertion: the signer is not called, so no
    // signature exists to be submitted.
    const payload = await signAuth({ value: 5_000_000n });
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(guarded.signTypedData(payload)).rejects.toThrow(/refusing to authorise/);
    expect(s.calls).toEqual([]);
  });

  it("refuses a payment redirected to another address", async () => {
    const payload = await signAuth({ to: ATTACKER });
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(guarded.signTypedData(payload)).rejects.toThrow(/refusing to authorise/);
    expect(s.calls).toEqual([]);
  });

  it("fails closed with no quote", async () => {
    // Every optional security parameter with a permissive default ends up unset
    // in production. Absent quote is a refusal, not a pass.
    const payload = await signAuth();
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => null);
    await expect(guarded.signTypedData(payload)).rejects.toThrow(/no payment quote/);
    expect(s.calls).toEqual([]);
  });

  it("guards EVERY signing route, not just signTypedData", async () => {
    // A guard on one method is a door with a doorman standing beside it. An
    // agent told to "just sign this" reaches for whatever the wallet offers.
    const bad = await signAuth({ value: 9_000_000n });
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quote) as any;
    for (const m of ["signTypedData", "_signTypedData", "signMessage", "sendTransaction"]) {
      await expect(guarded[m](bad), m).rejects.toThrow(/refusing to authorise/);
    }
    expect(s.calls).toEqual([]);
  });

  it("refuses an unrecognised signing request rather than passing it through", async () => {
    // "We did not recognise the call so we allowed it" is how every bypass is
    // written up afterwards.
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(guarded.signTypedData({ nonsense: true } as any)).rejects.toThrow(
      /could not read an x402 payment/,
    );
    expect(s.calls).toEqual([]);
  });

  it("leaves non-signing methods alone", async () => {
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(guarded.getAddress()).resolves.toBe(SIGNER);
    expect(s.calls).toEqual(["getAddress"]);
  });

  it("honours an explicit allow, so an unmodelled method stays usable", async () => {
    // The escape hatch is an allowlist with a name on it rather than a silent
    // pass-through.
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quote, { allow: ["signMessage"] });
    await expect(guarded.signMessage({ nonsense: true } as any)).resolves.toBe("0xsigned");
    expect(s.calls).toEqual(["signMessage"]);
  });

  it("accepts a REAL viem/ethers pre-signing typed-data call (AW-10)", async () => {
    // AW-10. The old fixture here passed { primaryType, message, signature } —
    // a shape no viem or ethers caller produces, because `signTypedData` is the
    // call that CREATES the signature. The wrapper tried to carry a
    // `signature` across that never exists, so `normalizeSignature(undefined)`
    // abstained and EVERY correct payment was refused, on all four methods it
    // intercepted. Measured against a real createWalletClient: 4 wrapped, 26
    // raw, and `g.account === wc.account`.
    //
    // This is the shape viem actually sends. It must pass.
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(
      guarded.signTypedData({
        domain: {
          name: "USD Coin",
          version: "2",
          chainId: 8453,
          verifyingContract: BASE_USDC,
        },
        types: EIP3009.TYPES,
        primaryType: EIP3009.PRIMARY_TYPE,
        message: {
          from: SIGNER,
          to: MERCHANT,
          value: 1_000_000n,
          validAfter: 0n,
          validBefore: 99999999999n,
          nonce: NONCE_A,
        },
      } as any),
    ).resolves.toBe("0xsigned");
    expect(s.calls).toEqual(["signTypedData"]);
  });

  it("refuses the same pre-signing call when it pays someone else", async () => {
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(
      guarded.signTypedData({
        domain: {
          name: "USD Coin",
          version: "2",
          chainId: 8453,
          verifyingContract: BASE_USDC,
        },
        types: EIP3009.TYPES,
        primaryType: EIP3009.PRIMARY_TYPE,
        message: {
          from: SIGNER,
          to: ATTACKER,
          value: 1_000_000n,
          validAfter: 0n,
          validBefore: 99999999999n,
          nonce: NONCE_A,
        },
      } as any),
    ).rejects.toThrow(/X402-101/);
    expect(s.calls).toEqual([]);
  });

  it("refuses an unbounded Permit dressed as a typed-data call", async () => {
    // Base USDC implements both EIP-3009 and EIP-2612 against the IDENTICAL
    // domain, so the primaryType is the only offline discriminator.
    const s = fakeSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(
      guarded.signTypedData({
        domain: {
          name: "USD Coin",
          version: "2",
          chainId: 8453,
          verifyingContract: BASE_USDC,
        },
        types: { Permit: [] },
        primaryType: "Permit",
        message: {
          owner: SIGNER,
          spender: ATTACKER,
          value: 2n ** 256n - 1n,
          nonce: 0n,
          deadline: 2n ** 256n - 1n,
        },
      } as any),
    ).rejects.toThrow(/not TransferWithAuthorization/);
    expect(s.calls).toEqual([]);
  });
});

/**
 * AW-10, the structural half — pinned against a REAL viem WalletClient.
 *
 * The old suite could not see this defect because `fakeSigner()` defines
 * exactly the six modelled names, so "guards EVERY signing route" iterated the
 * guarded set and asserted the guarded set was guarded. Measured against a real
 * `createWalletClient`: 30 functions, 4 wrapped, 26 raw passthrough, and
 * `g.account === wc.account` — so `g.account.signTypedData` signed an unbounded
 * Permit to an attacker spender with no error, no log and no abstain, while
 * `g.sendTransaction` threw and made the firewall look like it was working.
 *
 * These build the fixture from viem itself, so it cannot drift from what
 * callers actually pass.
 */
describe("guardEvmSigner — default-deny against a real viem client (AW-10)", () => {
  async function realClient() {
    const { createWalletClient, http } = await import("viem");
    const { base } = await import("viem/chains");
    const wc = createWalletClient({
      account,
      chain: base,
      transport: http("http://127.0.0.1:1"),
    });
    return wc as unknown as Record<string, unknown>;
  }

  it("wraps EVERY function property — no raw passthrough at all", async () => {
    const wc = await realClient();
    const g = guardEvmSigner(wc, () => quote) as Record<string, unknown>;
    const fns: string[] = [];
    for (const k in wc) if (typeof wc[k] === "function") fns.push(k);
    // Sanity: the fixture is the real thing, not a stub with six names.
    expect(fns.length).toBeGreaterThan(20);
    const raw = fns.filter((k) => g[k] === wc[k]);
    expect(raw).toEqual([]);
  });

  it("does not hand back the raw `account`, whose signing methods were unguarded", async () => {
    const wc = await realClient();
    const g = guardEvmSigner(wc, () => quote) as Record<string, unknown>;
    expect(g.account).not.toBe(wc.account);
  });

  it("refuses an unbounded Permit through the account object", async () => {
    const wc = await realClient();
    const g = guardEvmSigner(wc, () => quote) as any;
    await expect(
      g.account.signTypedData({
        domain: {
          name: "USD Coin",
          version: "2",
          chainId: 8453,
          verifyingContract: BASE_USDC,
        },
        types: { Permit: [] },
        primaryType: "Permit",
        message: {
          owner: SIGNER,
          spender: ATTACKER,
          value: 2n ** 256n - 1n,
          nonce: 0n,
          deadline: 2n ** 256n - 1n,
        },
      }),
    ).rejects.toThrow(/x402-guard/);
  });

  it("refuses writeContract and signAuthorization, which were identity-equal originals", async () => {
    const wc = await realClient();
    const g = guardEvmSigner(wc, () => quote) as any;
    // writeContract is the ordinary ERC-20 transfer path; signAuthorization
    // signs an EIP-7702 delegation of the whole EOA.
    await expect(g.writeContract({})).rejects.toThrow(/x402-guard/);
    await expect(g.signAuthorization({})).rejects.toThrow(/x402-guard/);
  });

  it("a correct payment still signs — the guard is not a brick", async () => {
    const wc = await realClient();
    const g = guardEvmSigner(wc, () => quote) as any;
    const sig = await g.signTypedData({
      account,
      domain: {
        name: "USD Coin",
        version: "2",
        chainId: 8453,
        verifyingContract: BASE_USDC,
      },
      types: EIP3009.TYPES,
      primaryType: EIP3009.PRIMARY_TYPE,
      message: {
        from: SIGNER,
        to: MERCHANT,
        value: 1_000_000n,
        validAfter: 0n,
        validBefore: 99999999999n,
        nonce: NONCE_A,
      },
    });
    expect(typeof sig).toBe("string");
    expect(sig.startsWith("0x")).toBe(true);
  });
});

/**
 * The wrapper wraps EVERY object, not objects that look like signers.
 *
 * The first default-deny pass gated nested wrapping on an `exposesSigning`
 * name check — which was the AW-10 inversion surviving one level down: a
 * nested method named `signDigest`, a signer at depth 3, and `accounts[0]`
 * were all handed back raw because none matched the modelled names. Wrapping
 * is lazy (a Proxy materialises only on access), so there is no cost to
 * dropping the shape test and the depth cap.
 */
describe("guardEvmSigner — no object is handed back unwrapped", () => {
  it("guards a nested method the wrapper does not model by name", async () => {
    const s = { signTypedData: async () => "0x", _signer: { signDigest: async () => "0xBAD" } };
    const g = guardEvmSigner(s, () => quote) as any;
    await expect(g._signer.signDigest()).rejects.toThrow(/x402-guard/);
  });

  it("guards a signer three levels down", async () => {
    const s = {
      signTypedData: async () => "0x",
      provider: { signer: { wallet: { sign: async () => "0xBAD" } } },
    };
    const g = guardEvmSigner(s, () => quote) as any;
    await expect(g.provider.signer.wallet.sign()).rejects.toThrow(/x402-guard/);
  });

  it("guards signers inside an array — `accounts` is a real viem shape", async () => {
    const s = {
      signTypedData: async () => "0x",
      accounts: [{ signTypedData: async () => "0xBAD" }],
    };
    const g = guardEvmSigner(s, () => quote) as any;
    await expect(g.accounts[0].signTypedData()).rejects.toThrow(/x402-guard/);
  });

  it("a cyclic object graph is traversable and does not hang", () => {
    const cyclic: any = { signTypedData: async () => "0x", p: {} };
    cyclic.p.self = cyclic;
    const g = guardEvmSigner(cyclic, () => quote) as any;
    expect(g.p.self.p).toBeDefined();
  });

  it("plain data still reads through unchanged", () => {
    const s = {
      signTypedData: async () => "0x",
      chain: { id: 8453, name: "Base" },
      uid: "abc",
    };
    const g = guardEvmSigner(s, () => quote) as any;
    expect(g.chain.id).toBe(8453);
    expect(g.chain.name).toBe("Base");
    expect(g.uid).toBe("abc");
  });
});

/**
 * AW-66(d). The session nonce set had two defects that compound.
 *
 * The key omitted the AUTHORIZER, so a nonce was global to (chain, asset)
 * rather than to the wallet that signed it. And it was committed BEFORE the
 * verdict, so a payload `inspectAuthorization` was about to REFUSE still burned
 * the nonce.
 *
 * Together: a denial of service on a victim's own payment. Reproduced — an
 * attacker's redirected payload refused with X402-101 and committed the
 * victim's nonce, and the victim's honest retry then refused as a replay.
 */
describe("the session nonce set cannot be poisoned (AW-66)", () => {
  const NONCE_B =
    "0x00000000000000000000000000000000000000000000000000000000000000cd" as Hex;
  const other = privateKeyToAccount(("0x" + "22".repeat(32)) as Hex);

  async function authFor(
    signer: typeof account,
    to: string,
    nonce: Hex,
  ): Promise<EvmPayload> {
    const signature = await signer.signTypedData({
      domain: {
        name: "USD Coin",
        version: "2",
        chainId: 8453,
        verifyingContract: BASE_USDC as Hex,
      },
      types: EIP3009.TYPES,
      primaryType: EIP3009.PRIMARY_TYPE,
      message: {
        from: signer.address,
        to: to as Hex,
        value: 1_000_000n,
        validAfter: 0n,
        validBefore: 99999999999n,
        nonce,
      },
    });
    return {
      signature,
      assetTransferMethod: "eip3009",
      authorization: {
        from: signer.address,
        to,
        value: "1000000",
        validAfter: "0",
        validBefore: "99999999999",
        nonce,
      },
    } as EvmPayload;
  }

  it("a REFUSED payload does not burn the victim's nonce", async () => {
    const seenNonces = new Set<string>();
    const attack = await authFor(account, ATTACKER, NONCE_A);
    expect((await inspectAuthorization(quote, attack, { seenNonces })).decision)
      .toBe("refuse");

    // The victim's own, honest payment on the same nonce must still clear.
    const honest = await authFor(account, MERCHANT, NONCE_A);
    expect((await inspectAuthorization(quote, honest, { seenNonces })).decision)
      .toBe("allow");
  });

  it("but a GENUINE replay is still caught", async () => {
    // The whole point of the set. Committing only on allow must not cost this.
    const seenNonces = new Set<string>();
    const honest = await authFor(account, MERCHANT, NONCE_B);
    expect((await inspectAuthorization(quote, honest, { seenNonces })).decision)
      .toBe("allow");
    const again = await inspectAuthorization(quote, honest, { seenNonces });
    expect(again.decision).toBe("refuse");
    expect(again.findings.some((f) => f.code === "X402-107")).toBe(true);
  });

  it("two different payers may use the same nonce bytes", async () => {
    // A nonce belongs to the wallet that signed it, not to the token.
    const seenNonces = new Set<string>();
    const a = await authFor(account, MERCHANT, NONCE_A);
    const b = await authFor(other, MERCHANT, NONCE_A);
    expect((await inspectAuthorization(quote, a, { seenNonces })).decision)
      .toBe("allow");
    expect((await inspectAuthorization(quote, b, { seenNonces })).decision)
      .toBe("allow");
  });
});

/**
 * AW-75. `extra` was attached NON-ENUMERABLE, for the stated reason of keeping
 * "the quote shape clean for equality checks in tests" — and the cost was that
 * `JSON.stringify`, spread, `Object.assign`, `structuredClone` and
 * `postMessage` all silently dropped it.
 *
 * That is the field `inspectAuthorization` treats as authoritative for the
 * transfer method, precisely so a caller cannot lie about it. An agent that
 * serialised the quote anywhere lost the routing signal and got a different
 * verdict on the other side, with nothing to indicate anything had changed.
 */
describe("a quote survives being serialised (AW-75)", () => {
  const req = {
    network: "eip155:8453",
    payTo: "0x1111111111111111111111111111111111111111",
    asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    maxAmountRequired: "1000000",
    extra: { assetTransferMethod: "permit2" },
  };

  it("extra survives JSON, spread and structuredClone", () => {
    const q = evmQuoteFromRequirements(req as never) as any;
    expect(q.extra?.assetTransferMethod).toBe("permit2");
    expect(JSON.parse(JSON.stringify(q)).extra?.assetTransferMethod).toBe("permit2");
    expect({ ...q }.extra?.assetTransferMethod).toBe("permit2");
    expect(structuredClone(q).extra?.assetTransferMethod).toBe("permit2");
  });

  it("a quote with no extra stays clean", () => {
    const { extra, ...bare } = req;
    const q = evmQuoteFromRequirements(bare as never);
    expect(JSON.stringify(q)).not.toContain("extra");
  });
});

/**
 * ETHERS SENDS THREE POSITIONAL ARGUMENTS, and the wrapper only read viem's
 * single-object call.
 *
 * `signTypedData(domain, types, value)` is how ethers has always spelled this;
 * viem spells it `signTypedData({domain, types, primaryType, message})`. The
 * argument sniffer looked for one object carrying both `domain` and `message`,
 * found nothing in the ethers form, and fell through to the fail-closed
 * refusal — so every payment from an ethers signer was rejected with "could
 * not read an x402 payment from the arguments".
 *
 * It failed CLOSED, so no funds were ever at risk. What was broken is the
 * integration this package documents, which is its own kind of bad: a guard
 * that refuses every honest payment gets removed.
 *
 * The reconstruction is the part that needs the adversarial tests. Rebuilding
 * a typed-data request out of loose arguments is exactly the sort of helpful
 * repair that turns a firewall into a rubber stamp, so the cases below drive
 * every refusal path through the positional form and assert the real signer is
 * never reached.
 */
describe("guardEvmSigner accepts ethers' positional signTypedData", () => {
  const DOMAIN = {
    name: "USD Coin",
    version: "2",
    chainId: 8453,
    verifyingContract: BASE_USDC,
  };
  const TYPES = {
    TransferWithAuthorization: [
      { name: "from", type: "address" },
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" },
      { name: "validBefore", type: "uint256" },
      { name: "nonce", type: "bytes32" },
    ],
  };
  const message = () => ({
    from: SIGNER,
    to: MERCHANT,
    value: "1000000",
    validAfter: "0",
    validBefore: String(Math.floor(Date.now() / 1000) + 600),
    nonce: `0x${"11".repeat(32)}`,
  });

  function recordingSigner() {
    const calls: string[] = [];
    return {
      calls,
      async signTypedData(..._args: unknown[]) {
        calls.push("signTypedData");
        return "0xsigned";
      },
    };
  }

  it("CONTROL: a conforming ethers call reaches the real signer", async () => {
    // Without this every assertion below is satisfied by a wrapper that
    // refuses everything, which is what the broken version did.
    const s = recordingSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(
      guarded.signTypedData(DOMAIN, TYPES, message()),
    ).resolves.toBe("0xsigned");
    expect(s.calls).toEqual(["signTypedData"]);
  });

  it.each([
    [
      "a payee the quote does not name",
      () => [DOMAIN, TYPES, { ...message(), to: `0x${"99".repeat(20)}` }],
    ],
    [
      "an amount larger than the quote",
      () => [DOMAIN, TYPES, { ...message(), value: "999999999" }],
    ],
    [
      "a domain on the wrong chain",
      () => [{ ...DOMAIN, chainId: 1 }, TYPES, message()],
    ],
    [
      "a domain naming a different contract",
      () => [
        { ...DOMAIN, verifyingContract: `0x${"99".repeat(20)}` },
        TYPES,
        message(),
      ],
    ],
    [
      "a Permit rather than a single transfer",
      () => [
        DOMAIN,
        {
          Permit: [
            { name: "owner", type: "address" },
            { name: "spender", type: "address" },
          ],
        },
        { owner: SIGNER, spender: MERCHANT },
      ],
    ],
    [
      "an ambiguous types map with two root structs",
      () => [
        DOMAIN,
        { A: [{ name: "x", type: "uint256" }], B: [{ name: "y", type: "uint256" }] },
        message(),
      ],
    ],
    ["arguments that are not a signing request", () => ["nope", 42, null]],
    [
      // The hostile case for the reconstruction itself, and the reason
      // `roots.length !== 1` is a refusal rather than "take the first".
      // TransferWithAuthorization is listed FIRST so a first-root heuristic
      // names it, while the struct actually being signed is the Permit — a
      // standing allowance vouched for as a single transfer. Verified: with
      // the ambiguity check relaxed to take roots[0], this signs.
      "a types map that names a transfer but also declares a Permit",
      () => [
        DOMAIN,
        {
          TransferWithAuthorization: TYPES.TransferWithAuthorization,
          Permit: [
            { name: "owner", type: "address" },
            { name: "spender", type: "address" },
            { name: "value", type: "uint256" },
          ],
        },
        message(),
      ],
    ],
  ])("refuses %s, and never reaches the signer", async (_label, build) => {
    const s = recordingSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(
      (guarded.signTypedData as (...a: unknown[]) => Promise<string>)(
        ...(build() as unknown[]),
      ),
    ).rejects.toThrow();
    expect(s.calls).toEqual([]);
  });

  it("still accepts viem's single-object form", async () => {
    // The shape that already worked must keep working: this fix adds a form,
    // it does not swap one for another.
    const s = recordingSigner();
    const guarded = guardEvmSigner(s, () => quote);
    await expect(
      guarded.signTypedData({
        domain: DOMAIN,
        types: TYPES,
        primaryType: "TransferWithAuthorization",
        message: message(),
      }),
    ).resolves.toBe("0xsigned");
    expect(s.calls).toEqual(["signTypedData"]);
  });
});


describe("AW-66 / AW-32: the pre-signing path checks what the signed path checks", () => {
  // inspectTypedDataRequest compared `to` and `value` and nothing else, so a
  // request that could never succeed on chain — validBefore of 0, a
  // validAfter in the future, a nonce that is not bytes32 — returned a clean
  // allow, and a truncated or renamed TransferWithAuthorization struct did
  // too. The signed path checks all of these; the two lanes now agree.
  const domain = { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: BASE_USDC };
  const message = () => ({
    from: SIGNER,
    to: MERCHANT,
    value: "1000000",
    validAfter: "0",
    validBefore: "99999999999",
    nonce: `0x${"11".repeat(32)}`,
  });
  const req = (m: Record<string, unknown>, types: unknown = EIP3009.TYPES) => ({
    domain,
    types,
    primaryType: EIP3009.PRIMARY_TYPE,
    message: m,
  });

  it("CONTROL: a conforming request allows with no findings", () => {
    const v = inspectTypedDataRequest(quote, req(message()));
    expect(v.decision).toBe("allow");
    expect(v.findings).toEqual([]);
  });

  it.each([
    ["a validBefore of 0", { validBefore: "0" }],
    ["a validAfter in the future", { validAfter: "99999999999" }],
    ["a validBefore in the past", { validBefore: "1" }],
  ])("reports %s as X402-105", (_label, over) => {
    const v = inspectTypedDataRequest(quote, req({ ...message(), ...over }));
    expect(v.findings.some((f) => f.code === "X402-105")).toBe(true);
  });

  it("abstains on a nonce that is not bytes32", () => {
    const v = inspectTypedDataRequest(quote, req({ ...message(), nonce: `0x${"11".repeat(16)}` }));
    expect(v.decision).toBe("abstain");
  });

  it("abstains on a truncated type list (AW-32)", () => {
    const v = inspectTypedDataRequest(
      quote,
      req(message(), { TransferWithAuthorization: EIP3009.TYPES.TransferWithAuthorization.slice(0, 3) }),
    );
    expect(v.decision).toBe("abstain");
  });

  it("abstains on a renamed field (AW-32)", () => {
    // Same length, one field renamed: the typeHash — and so the signature —
    // commits to a different struct.
    const renamed = EIP3009.TYPES.TransferWithAuthorization.map((f, i) =>
      i === 2 ? { ...f, name: "amount" } : f,
    );
    const v = inspectTypedDataRequest(quote, req(message(), { TransferWithAuthorization: renamed }));
    expect(v.decision).toBe("abstain");
  });
});
