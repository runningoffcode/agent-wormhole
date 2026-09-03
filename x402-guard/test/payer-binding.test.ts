/**
 * Payer binding — X402-011 (Solana) and X402-108 (EVM).
 *
 * The defect these close: quote conformance alone answers "does this payment
 * match the quote?", and a THIRD PARTY's funds moving to the quoted merchant
 * answers yes. Without `expectedPayer`, the guard structurally cannot answer
 * "did MY agent pay, from MY wallet?" — so the default (option unset) is
 * tested to allow, and the option is tested to refuse both halves: a wrong
 * authority and a wrong source account.
 */

import { describe, it, expect } from "vitest";
import {
  Keypair,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  createTransferCheckedInstruction,
  createTransferInstruction,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import { inspectPayment, type PaymentQuote } from "../src/index.js";
import {
  inspectAuthorization,
  EIP3009,
  type EvmPayload,
  type EvmPaymentQuote,
} from "../src/evm.js";
import { verify } from "../src/verify.js";

// --- Solana fixtures --------------------------------------------------------

const USDC = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const agent = Keypair.generate();
const merchant = Keypair.generate();
const stranger = Keypair.generate();

const agentAta = getAssociatedTokenAddressSync(USDC, agent.publicKey);
const merchantAta = getAssociatedTokenAddressSync(USDC, merchant.publicKey);
const strangerAta = getAssociatedTokenAddressSync(USDC, stranger.publicKey);

const svmQuote: PaymentQuote = {
  payTo: merchant.publicKey.toBase58(),
  asset: USDC.toBase58(),
  amount: "1000000",
};

function build(instructions: any[]): Uint8Array {
  const msg = new TransactionMessage({
    payerKey: agent.publicKey,
    recentBlockhash: PublicKey.default.toBase58(),
    instructions,
  }).compileToV0Message();
  return new VersionedTransaction(msg).serialize();
}

describe("Solana payer binding (X402-011)", () => {
  it("allows the agent's own conforming payment when expectedPayer names it", () => {
    const tx = build([
      createTransferCheckedInstruction(
        agentAta,
        USDC,
        merchantAta,
        agent.publicKey,
        1_000_000n,
        6,
      ),
    ]);
    const v = inspectPayment(tx, svmQuote, {
      expectedPayer: agent.publicKey.toBase58(),
    });
    expect(v.decision).toBe("allow");
    expect(v.findings).toHaveLength(0);
  });

  it("documents the default: a stranger's conforming payment allows when no payer is named", () => {
    const tx = build([
      createTransferCheckedInstruction(
        strangerAta,
        USDC,
        merchantAta,
        stranger.publicKey,
        1_000_000n,
        6,
      ),
    ]);
    expect(inspectPayment(tx, svmQuote).decision).toBe("allow");
  });

  it("refuses a stranger's conforming payment when the agent is the expected payer", () => {
    const tx = build([
      createTransferCheckedInstruction(
        strangerAta,
        USDC,
        merchantAta,
        stranger.publicKey,
        1_000_000n,
        6,
      ),
    ]);
    const v = inspectPayment(tx, svmQuote, {
      expectedPayer: agent.publicKey.toBase58(),
    });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-011")).toBe(true);
  });

  it("refuses when the authority is right but the source is not the payer's account", () => {
    // A delegate spend: the agent authorizes, a stranger's account drains.
    const tx = build([
      createTransferCheckedInstruction(
        strangerAta,
        USDC,
        merchantAta,
        agent.publicKey,
        1_000_000n,
        6,
      ),
    ]);
    const v = inspectPayment(tx, svmQuote, {
      expectedPayer: agent.publicKey.toBase58(),
    });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-011")).toBe(true);
  });

  it("binds the plain Transfer form too, not just TransferChecked", () => {
    const tx = build([
      createTransferInstruction(
        strangerAta,
        merchantAta,
        stranger.publicKey,
        1_000_000n,
      ),
    ]);
    const v = inspectPayment(tx, svmQuote, {
      expectedPayer: agent.publicKey.toBase58(),
    });
    expect(v.decision).toBe("refuse");
    expect(v.findings.some((f) => f.code === "X402-011")).toBe(true);
  });

  it("abstains on an unreadable expectedPayer rather than skipping the check", () => {
    const tx = build([
      createTransferCheckedInstruction(
        agentAta,
        USDC,
        merchantAta,
        agent.publicKey,
        1_000_000n,
        6,
      ),
    ]);
    const v = inspectPayment(tx, svmQuote, { expectedPayer: "not-a-pubkey" });
    expect(v.decision).toBe("abstain");
  });
});

// --- EVM fixtures -----------------------------------------------------------

const PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const account = privateKeyToAccount(PK);
const SIGNER = account.address;
const OTHER_WALLET = "0x9999999999999999999999999999999999999999";

const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MERCHANT = "0x1111111111111111111111111111111111111111";
const NONCE = "0x00000000000000000000000000000000000000000000000000000000000000bb" as Hex;

const evmQuote: EvmPaymentQuote = {
  network: "eip155:8453",
  asset: BASE_USDC,
  payTo: MERCHANT,
  amount: "1000000",
};

async function signAuth(): Promise<EvmPayload> {
  const domain = {
    name: "USD Coin",
    version: "2",
    chainId: 8453,
    verifyingContract: BASE_USDC as Hex,
  } as const;
  const message = {
    from: SIGNER as Hex,
    to: MERCHANT as Hex,
    value: 1_000_000n,
    validAfter: 0n,
    validBefore: 0n,
    nonce: NONCE,
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
      to: MERCHANT,
      value: "1000000",
      validAfter: "0",
      validBefore: "0",
      nonce: NONCE,
    },
  };
}

describe("EVM payer binding (X402-108)", () => {
  it("allows when the proven signer is the expected payer", async () => {
    const v = await inspectAuthorization(evmQuote, await signAuth(), {
      expectedPayer: SIGNER,
    });
    expect(v.decision).toBe("allow");
    expect(v.findings).toHaveLength(0);
  });

  it("refuses a valid authorization moving someone else's funds", async () => {
    const v = await inspectAuthorization(evmQuote, await signAuth(), {
      expectedPayer: OTHER_WALLET,
    });
    expect(v.decision).toBe("refuse");
    const hit = v.findings.find((f) => f.code === "X402-108");
    expect(hit).toBeDefined();
    expect(hit!.expected!.toLowerCase()).toBe(OTHER_WALLET.toLowerCase());
    expect(hit!.actual!.toLowerCase()).toBe(SIGNER.toLowerCase());
  });

  it("abstains on an unreadable expectedPayer rather than skipping the check", async () => {
    const v = await inspectAuthorization(evmQuote, await signAuth(), {
      expectedPayer: "0xnope",
    });
    expect(v.decision).toBe("abstain");
  });

  it("flows through verify() from the wire options", async () => {
    const result = await verify(
      {
        network: "eip155:8453",
        quote: evmQuote,
        payload: await signAuth(),
        options: { expectedPayer: OTHER_WALLET } as any,
      },
      { quoteProvenance: "caller_asserted", issuedAt: "2026-09-02T00:00:00Z" },
    );
    expect(result.decision).toBe("refuse");
    expect(result.receipt?.codes).toContain("X402-108");
  });
});
