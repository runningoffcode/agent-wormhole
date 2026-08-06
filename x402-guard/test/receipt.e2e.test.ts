/**
 * THE KILL CRITERION, end to end, on BOTH rails.
 *
 * A receipt is worthless unless a stranger can check it with nothing but our
 * published public key — no server, no database, no plaintext of the quote or
 * payment. These tests take the receipt `verify()` actually mints, sign it with
 * a fixed ed25519 test key, and then do exactly what an independent replayer
 * does offline:
 *
 *   1. verifyReceipt(receipt, sig, PUBLIC key).valid === true for a genuine sig.
 *   2. Flip a receipt field (decision / codes / amount_bucket) => valid === false.
 *   3. replayMatches(receipt, sameRequest) === true; a different request => false.
 *   4. The receipt JSON carries no quote text, no raw payee, no exact amount.
 *
 * The EVM payload is a real EIP-3009 TransferWithAuthorization signature built
 * with viem (recovery is genuinely exercised). The SVM payload is a real Solana
 * transaction built with @solana/web3.js and run through the SVM lane. Nothing
 * here touches a network, a socket, or a server; every input is fixed so the
 * receipt is a pure function of its request and replays identically.
 */

import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import {
  generateKeyPairSync,
  sign as edSign,
  createPublicKey,
} from "node:crypto";
import {
  Keypair,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  createTransferCheckedInstruction,
} from "@solana/spl-token";
import { EIP3009, type EvmPayload, type EvmPaymentQuote } from "../src/evm.js";
import {
  verify,
  canonicalReceipt,
  type VerifyRequest,
  type Receipt,
} from "../src/verify.js";
import { verifyReceipt, replayMatches } from "../src/receipt.js";
import type { PaymentQuote } from "../src/index.js";

// ---------------------------------------------------------------------------
// Fixed ed25519 signing key. Only the public half is ever handed to the
// replayer. Ed25519 hashes internally, so it is the one-shot sign(null, ...)
// form — createSign() throws for this curve.
// ---------------------------------------------------------------------------
const { publicKey: ED_PUBLIC, privateKey: ED_PRIVATE } =
  generateKeyPairSync("ed25519");
const sign = (canonical: string): string =>
  edSign(null, Buffer.from(canonical, "utf8"), ED_PRIVATE).toString("base64");
// PEM form of the public key — verifyReceipt accepts PEM or a KeyObject.
const ED_PUBLIC_PEM = ED_PUBLIC.export({ type: "spki", format: "pem" }).toString();

// A fixed clock. The core never reads Date.now(); issuedAt is an input.
const ISSUED_AT = "2033-05-18T03:33:20.000Z";
function ctx() {
  return { quoteProvenance: "merchant_signed" as const, issuedAt: ISSUED_AT, sign };
}

// ---------------------------------------------------------------------------
// EVM fixtures — real EIP-3009 signatures (reuses evm.test.ts signAuth shape).
// ---------------------------------------------------------------------------
const PK =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const evmAccount = privateKeyToAccount(PK);
const EVM_SIGNER = evmAccount.address;

const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const BASE_CHAIN = 8453;
const EVM_MERCHANT = "0x1111111111111111111111111111111111111111";
const EVM_ATTACKER = "0x2222222222222222222222222222222222222222";
const NONCE_A =
  "0x00000000000000000000000000000000000000000000000000000000000000aa" as Hex;

const EVM_SENSITIVE = "SENSITIVE-MERCHANT-NOTE-should-not-appear-evm";

const evmQuote: EvmPaymentQuote = {
  network: "eip155:8453",
  asset: BASE_USDC,
  payTo: EVM_MERCHANT,
  amount: "1000000", // 1 USDC (6 decimals)
};

async function signAuth(
  f: { to?: string; value?: bigint } = {},
): Promise<EvmPayload> {
  const to = f.to ?? EVM_MERCHANT;
  const value = f.value ?? 1_000_000n;
  const domain = {
    name: "USD Coin",
    version: "2",
    chainId: BASE_CHAIN,
    verifyingContract: BASE_USDC as Hex,
  } as const;
  const message = {
    from: EVM_SIGNER as Hex,
    to: to as Hex,
    value,
    validAfter: 0n,
    validBefore: 0n,
    nonce: NONCE_A,
  };
  const signature = await evmAccount.signTypedData({
    domain,
    types: EIP3009.TYPES,
    primaryType: EIP3009.PRIMARY_TYPE,
    message,
  });
  return {
    signature,
    assetTransferMethod: "eip3009",
    authorization: {
      from: EVM_SIGNER,
      to,
      value: value.toString(),
      validAfter: "0",
      validBefore: "0",
      nonce: NONCE_A,
    },
  } as EvmPayload;
}

// ---------------------------------------------------------------------------
// SVM fixtures — real Solana transactions (reuses guard.test.ts build shape).
// Keys are fixed via a deterministic seed so the request digest is stable and
// the "no raw payee" assertion targets a known address.
// ---------------------------------------------------------------------------
const USDC = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const svmPayer = Keypair.fromSeed(new Uint8Array(32).fill(7));
const svmMerchant = Keypair.fromSeed(new Uint8Array(32).fill(9));
const svmAttacker = Keypair.fromSeed(new Uint8Array(32).fill(11));

const svmPayerAta = getAssociatedTokenAddressSync(USDC, svmPayer.publicKey);
const svmMerchantAta = getAssociatedTokenAddressSync(USDC, svmMerchant.publicKey);
const svmAttackerAta = getAssociatedTokenAddressSync(USDC, svmAttacker.publicKey);

const SVM_MERCHANT = svmMerchant.publicKey.toBase58();

const svmQuote: PaymentQuote = {
  payTo: SVM_MERCHANT,
  asset: USDC.toBase58(),
  amount: "1000000", // 1 USDC
};

function svmBuild(dest: PublicKey, amount: bigint): string {
  const ix = createTransferCheckedInstruction(
    svmPayerAta,
    USDC,
    dest,
    svmPayer.publicKey,
    amount,
    6,
  );
  const msg = new TransactionMessage({
    payerKey: svmPayer.publicKey,
    recentBlockhash: PublicKey.default.toBase58(),
    instructions: [ix],
  }).compileToV0Message();
  const bytes = new VersionedTransaction(msg).serialize();
  // The SVM lane reads a base64 string (or raw bytes). Ship the header form.
  return Buffer.from(bytes).toString("base64");
}

// ===========================================================================
// EVM — the kill criterion on the EVM rail
// ===========================================================================
describe("EVM kill criterion: a real EIP-3009 receipt replays offline", () => {
  it("INVARIANT: verify() on a conforming EVM payment yields an allow receipt on the evm lane", async () => {
    const req: VerifyRequest = {
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
    };
    const r = await verify(req, ctx());
    expect(r.decision).toBe("allow");
    expect(r.receipt).toBeDefined();
    expect(r.receipt!.lane).toBe("evm");
    expect(r.receipt!.chain_id).toBe(BASE_CHAIN);
    expect(r.receipt!.decision).not.toBe("abstain");
  });

  it("INVARIANT: a genuine ed25519 signature over the EVM receipt verifies against the PUBLIC key alone", async () => {
    const req: VerifyRequest = {
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
    };
    const r = await verify(req, ctx());
    const receipt = r.receipt!;
    const sig = sign(canonicalReceipt(receipt));

    // The replayer holds only the receipt, the sig, and our public key.
    expect(verifyReceipt(receipt, sig, ED_PUBLIC_PEM).valid).toBe(true);
    // And identically against a KeyObject form of the same key.
    expect(verifyReceipt(receipt, sig, createPublicKey(ED_PUBLIC_PEM)).valid).toBe(true);
  });

  it("INVARIANT: flipping the EVM receipt decision breaks the signature (tamper-evident)", async () => {
    const req: VerifyRequest = {
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
    };
    const r = await verify(req, ctx());
    const receipt = r.receipt!;
    const sig = sign(canonicalReceipt(receipt)); // signature over the GENUINE receipt

    const forgedDecision: Receipt = { ...receipt, decision: "refuse" };
    expect(verifyReceipt(forgedDecision, sig, ED_PUBLIC_PEM).valid).toBe(false);

    const forgedCodes: Receipt = { ...receipt, codes: [...receipt.codes, "X402-999"] };
    expect(verifyReceipt(forgedCodes, sig, ED_PUBLIC_PEM).valid).toBe(false);

    const forgedBucket: Receipt = { ...receipt, amount_bucket: "tampered-bucket" };
    expect(verifyReceipt(forgedBucket, sig, ED_PUBLIC_PEM).valid).toBe(false);
  });

  it("INVARIANT: a wrong public key never validates the EVM receipt", async () => {
    const req: VerifyRequest = {
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
    };
    const r = await verify(req, ctx());
    const receipt = r.receipt!;
    const sig = sign(canonicalReceipt(receipt));

    const other = generateKeyPairSync("ed25519").publicKey.export({
      type: "spki",
      format: "pem",
    }).toString();
    expect(verifyReceipt(receipt, sig, other).valid).toBe(false);
  });

  it("INVARIANT: replayMatches binds the EVM receipt to its request and rejects a different one", async () => {
    const sameReq: VerifyRequest = {
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
    };
    const r = await verify(sameReq, ctx());
    const receipt = r.receipt!;

    // Same inputs => digest matches => binding holds.
    expect(replayMatches(receipt, sameReq)).toBe(true);
    // Reconstructing the request from scratch still binds (pure function of inputs).
    const rebuilt: VerifyRequest = {
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
    };
    expect(replayMatches(receipt, rebuilt)).toBe(true);

    // A different quoted amount does not bind: canonicalizeQuote folds
    // {payTo, asset, amount} into the digest, so a changed amount changes it.
    const differentAmount: VerifyRequest = {
      network: evmQuote.network,
      quote: { ...evmQuote, amount: "2000000" },
      payload: await signAuth(),
    };
    expect(replayMatches(receipt, differentAmount)).toBe(false);

    // A different quoted payee also does not bind.
    const differentPayee: VerifyRequest = {
      network: evmQuote.network,
      quote: { ...evmQuote, payTo: EVM_ATTACKER },
      payload: await signAuth(),
    };
    expect(replayMatches(receipt, differentPayee)).toBe(false);

    // A different network does not bind either.
    const differentNetwork: VerifyRequest = {
      network: "eip155:1",
      quote: evmQuote,
      payload: await signAuth(),
    };
    expect(replayMatches(receipt, differentNetwork)).toBe(false);
  });

  it("INVARIANT: the EVM receipt carries no quote text, no raw payee, no exact amount", async () => {
    const withText = { ...evmQuote, description: EVM_SENSITIVE };
    const req: VerifyRequest = {
      network: evmQuote.network,
      quote: withText,
      payload: await signAuth(),
    };
    const r = await verify(req, ctx());
    const serialized = JSON.stringify(r.receipt);
    expect(serialized).not.toContain(EVM_SENSITIVE);
    expect(serialized).not.toContain(EVM_MERCHANT); // raw destination
    expect(serialized).not.toContain(EVM_SIGNER); // raw payer
    expect(serialized).not.toContain("1000000"); // the exact figure
    // What it MAY carry: a coarse bucket, rule ids, chain id, digest — no plaintext.
    expect(r.receipt!.request_digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("INVARIANT: a refused EVM payment still mints a signed, replayable receipt", async () => {
    // A refuse is a billable, useful verdict — not a silence. It must replay too.
    const req: VerifyRequest = {
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth({ to: EVM_ATTACKER }),
    };
    const r = await verify(req, ctx());
    expect(r.decision).toBe("refuse");
    const receipt = r.receipt!;
    expect(receipt.decision).toBe("refuse");
    expect(receipt.codes.length).toBeGreaterThan(0);
    const sig = sign(canonicalReceipt(receipt));
    expect(verifyReceipt(receipt, sig, ED_PUBLIC_PEM).valid).toBe(true);
    expect(replayMatches(receipt, req)).toBe(true);
  });
});

// ===========================================================================
// SVM — the same kill criterion on the SVM rail, with a real Solana tx
// ===========================================================================
describe("SVM kill criterion: a real Solana-tx receipt replays offline", () => {
  it("INVARIANT: verify() on a conforming SVM payment yields an allow receipt on the svm lane", async () => {
    const req: VerifyRequest = {
      network: "solana",
      quote: svmQuote,
      payload: svmBuild(svmMerchantAta, 1_000_000n),
    };
    const r = await verify(req, ctx());
    expect(r.decision).toBe("allow");
    expect(r.receipt).toBeDefined();
    expect(r.receipt!.lane).toBe("svm");
    expect(r.receipt!.chain_id).toBeNull(); // Solana has no EVM chain id
    expect(r.receipt!.decision).not.toBe("abstain");
  });

  it("INVARIANT: a genuine ed25519 signature over the SVM receipt verifies against the PUBLIC key alone", async () => {
    const req: VerifyRequest = {
      network: "solana",
      quote: svmQuote,
      payload: svmBuild(svmMerchantAta, 1_000_000n),
    };
    const r = await verify(req, ctx());
    const receipt = r.receipt!;
    const sig = sign(canonicalReceipt(receipt));
    expect(verifyReceipt(receipt, sig, ED_PUBLIC_PEM).valid).toBe(true);
  });

  it("INVARIANT: flipping the SVM receipt decision / codes / amount_bucket breaks the signature", async () => {
    const req: VerifyRequest = {
      network: "solana",
      quote: svmQuote,
      payload: svmBuild(svmMerchantAta, 1_000_000n),
    };
    const r = await verify(req, ctx());
    const receipt = r.receipt!;
    const sig = sign(canonicalReceipt(receipt));

    expect(verifyReceipt({ ...receipt, decision: "refuse" }, sig, ED_PUBLIC_PEM).valid).toBe(false);
    expect(verifyReceipt({ ...receipt, codes: ["X402-000"] }, sig, ED_PUBLIC_PEM).valid).toBe(false);
    expect(verifyReceipt({ ...receipt, amount_bucket: "x" }, sig, ED_PUBLIC_PEM).valid).toBe(false);
  });

  it("INVARIANT: replayMatches binds the SVM receipt to its exact transaction and rejects a different one", async () => {
    const payload = svmBuild(svmMerchantAta, 1_000_000n);
    const sameReq: VerifyRequest = { network: "solana", quote: svmQuote, payload };
    const r = await verify(sameReq, ctx());
    const receipt = r.receipt!;

    expect(replayMatches(receipt, sameReq)).toBe(true);
    // Same base64 bytes rebuilt into a fresh request object still binds.
    expect(replayMatches(receipt, { network: "solana", quote: svmQuote, payload })).toBe(true);

    // A transaction paying the attacker is a different request — no binding.
    const differentReq: VerifyRequest = {
      network: "solana",
      quote: svmQuote,
      payload: svmBuild(svmAttackerAta, 1_000_000n),
    };
    expect(replayMatches(receipt, differentReq)).toBe(false);
  });

  it("INVARIANT: the SVM receipt carries no quote text, no raw payee, no exact amount", async () => {
    const SVM_SENSITIVE = "SENSITIVE-MERCHANT-NOTE-should-not-appear-svm";
    const withText = { ...svmQuote, memo: SVM_SENSITIVE };
    const req: VerifyRequest = {
      network: "solana",
      quote: withText,
      payload: svmBuild(svmMerchantAta, 1_000_000n),
    };
    const r = await verify(req, ctx());
    const serialized = JSON.stringify(r.receipt);
    expect(serialized).not.toContain(SVM_SENSITIVE);
    expect(serialized).not.toContain(SVM_MERCHANT); // raw payee base58
    expect(serialized).not.toContain("1000000"); // the exact figure
    expect(r.receipt!.request_digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("INVARIANT: a refused SVM payment (substituted destination) still mints a signed, replayable receipt", async () => {
    const req: VerifyRequest = {
      network: "solana",
      quote: svmQuote,
      payload: svmBuild(svmAttackerAta, 1_000_000n),
    };
    const r = await verify(req, ctx());
    expect(r.decision).toBe("refuse");
    const receipt = r.receipt!;
    expect(receipt.decision).toBe("refuse");
    const sig = sign(canonicalReceipt(receipt));
    expect(verifyReceipt(receipt, sig, ED_PUBLIC_PEM).valid).toBe(true);
    expect(replayMatches(receipt, req)).toBe(true);
  });
});

// ===========================================================================
// abstain never mints a receipt — and thus can never be replayed as an allow
// ===========================================================================
describe("abstain has no receipt on either rail (never replayable, never an allow)", () => {
  it("INVARIANT: an unresolved network abstains with no receipt", async () => {
    const req: VerifyRequest = {
      network: "dogechain-mainnet-???",
      quote: evmQuote,
      payload: await signAuth(),
    };
    const r = await verify(req, ctx());
    expect(r.decision).toBe("abstain");
    expect(r.receipt).toBeUndefined();
    expect(r.decision).not.toBe("allow");
  });

  it("INVARIANT: an undecodable SVM payload does not yield an allow receipt", async () => {
    const req: VerifyRequest = {
      network: "solana",
      quote: svmQuote,
      payload: Buffer.from(new Uint8Array([1, 2, 3, 4])).toString("base64"),
    };
    const r = await verify(req, ctx());
    expect(r.decision).not.toBe("allow");
    if (r.decision === "abstain") expect(r.receipt).toBeUndefined();
  });

  it("INVARIANT: replayMatches is false against a receipt-less abstain result", async () => {
    // There is no receipt to bind, so a caller cannot forge a match.
    const req: VerifyRequest = {
      network: "dogechain-mainnet-???",
      quote: evmQuote,
      payload: await signAuth(),
    };
    const r = await verify(req, ctx());
    expect(r.receipt).toBeUndefined();
    // Guard: replayMatches on an undefined receipt is defined-false, not a throw.
    expect(replayMatches(r.receipt as unknown as Receipt, req)).toBe(false);
  });
});
