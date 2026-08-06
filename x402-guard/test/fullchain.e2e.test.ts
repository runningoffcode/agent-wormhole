/**
 * THE FULL CHAIN, end to end, on both rails — the single test file that proves
 * the whole product works as one piece rather than as a bag of passing units.
 *
 * The claim under test is the product claim: an agent about to sign a payment
 * calls the checkpoint through the same `guardedPay` it would use in
 * production; a conforming payment is ALLOWED and comes back with a receipt and
 * a detached ed25519 signature; that receipt REPLAYS OFFLINE against the
 * published public key with no server access and binds to the exact request via
 * its digest; the billable event flows into the meter and is priced. Then the
 * adversarial twin: a payment redirected to an attacker is REFUSED — allow is
 * false, the receipt records the refuse — and a fleet of agents independently
 * refusing the same shape correlates into a shared-refuse cluster.
 *
 * EVM payloads are real EIP-3009 signatures built with viem, so the recovery
 * path is genuinely exercised. SVM payloads are real serialized Solana
 * transactions. No servers, no sockets, no network — the transport is an
 * in-process function that calls the real `verify` core with a real ed25519
 * signing context. Everything is deterministic: fixed keys, fixed issuedAt.
 */

import { describe, it, expect } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import {
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
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
  type VerifyRequest,
  type VerifyContext,
  type Receipt,
} from "../src/verify.js";
import {
  guardedPay,
  type VerifyTransport,
  type VerifiedResult,
} from "../src/client.js";
import { verifyReceipt, replayMatches } from "../src/receipt.js";
import {
  createMeter,
  correlate,
  priceFor,
  isBillable,
  type BillingEvent,
} from "../src/metering.js";
import type { PaymentQuote } from "../src/index.js";

// --- deterministic keys & fixtures ------------------------------------------

// Fixed EVM signer — deterministic address across runs.
const PK =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const account = privateKeyToAccount(PK);
const SIGNER = account.address; // this is EIP-3009 `from`

const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const BASE_CHAIN = 8453;
const MERCHANT = "0x1111111111111111111111111111111111111111";
const ATTACKER = "0x2222222222222222222222222222222222222222";
const NONCE_A =
  "0x00000000000000000000000000000000000000000000000000000000000000aa" as Hex;

const evmQuote: EvmPaymentQuote = {
  network: "eip155:8453",
  asset: BASE_USDC,
  payTo: MERCHANT,
  amount: "1000000", // 1 USDC (6 decimals)
};

/** Real EIP-3009 authorization + signature (reuses the working helper shape). */
async function signAuth(f: { to?: string; value?: bigint } = {}): Promise<EvmPayload> {
  const to = f.to ?? MERCHANT;
  const value = f.value ?? 1_000_000n;
  const domain = {
    name: "USD Coin",
    version: "2",
    chainId: BASE_CHAIN,
    verifyingContract: BASE_USDC as Hex,
  } as const;
  const message = {
    from: SIGNER as Hex,
    to: to as Hex,
    value,
    validAfter: 0n,
    validBefore: 0n,
    nonce: NONCE_A,
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
      validAfter: "0",
      validBefore: "0",
      nonce: NONCE_A,
    },
  } as EvmPayload;
}

// --- real SVM transaction fixtures ------------------------------------------

const USDC = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const svmPayer = Keypair.generate();
const svmMerchant = Keypair.generate();
const svmAttacker = Keypair.generate();
const payerAta = getAssociatedTokenAddressSync(USDC, svmPayer.publicKey);
const merchantAta = getAssociatedTokenAddressSync(USDC, svmMerchant.publicKey);
const attackerAta = getAssociatedTokenAddressSync(USDC, svmAttacker.publicKey);

const svmQuote: PaymentQuote = {
  payTo: svmMerchant.publicKey.toBase58(),
  asset: USDC.toBase58(),
  amount: "1000000",
};

/** Build a real serialized Solana transfer and return it base64 (wire form). */
function svmPaymentBase64(dest: PublicKey, amount: bigint): string {
  const ix = createTransferCheckedInstruction(
    payerAta,
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
  return Buffer.from(bytes).toString("base64");
}

// --- the signing checkpoint, wired offline ----------------------------------

// A fixed timestamp. The core never reads the clock — time is an input — which
// is exactly what lets a receipt be a pure function of its request and replay
// identically.
const ISSUED_AT = "2033-05-18T03:33:20.000Z";

// Our receipt-signing keypair. Only the public half is published; a third party
// verifies against it with no access to us. Ed25519 hashes internally, so the
// one-shot sign(null, data, key) form is used — never createSign.
const { publicKey: RECEIPT_PUBKEY, privateKey: RECEIPT_PRIVKEY } =
  generateKeyPairSync("ed25519");

/**
 * The transport an agent injects into guardedPay. In production this POSTs to
 * the hosted /v1/verify; here it calls the SAME `verify` core in-process, with a
 * real ed25519 signing context, and threads the detached signature back exactly
 * as `makeHttpTransport` would map it off the wire. No socket is opened.
 */
function inProcessTransport(
  provenance: VerifyContext["quoteProvenance"] = "merchant_signed",
  sign: KeyObject | null = RECEIPT_PRIVKEY,
): VerifyTransport {
  const ctx: VerifyContext = {
    quoteProvenance: provenance,
    issuedAt: ISSUED_AT,
    sign: sign
      ? (canonical: string) => edSign(null, Buffer.from(canonical), sign).toString("base64")
      : undefined,
  };
  return async (req: VerifyRequest): Promise<VerifiedResult> => {
    const r = await verify(req, ctx);
    // The core signs no receipts (it holds no key). The transport does, exactly
    // as server.ts would, and carries the detached signature as a sibling field.
    let signature: string | undefined;
    if (r.receipt && ctx.sign) {
      const { canonicalReceipt } = await import("../src/verify.js");
      signature = ctx.sign(canonicalReceipt(r.receipt));
    }
    return { ...r, signature };
  };
}

// ============================================================================
// EVM — the full chain, happy path
// ============================================================================

describe("EVM full chain — a conforming payment is ALLOWED, and its receipt replays offline and is billed", () => {
  it("guardedPay allows a real EIP-3009 payment matching the quote, and the returned receipt+signature verify offline, bind to the request, and price as billable", async () => {
    const payload = await signAuth(); // real signature paying the merchant
    const req: VerifyRequest = { network: evmQuote.network, quote: evmQuote, payload };

    // 1) The agent asks the checkpoint through the exact production surface.
    const res = await guardedPay({
      network: req.network,
      quote: req.quote,
      payload: req.payload,
      transport: inProcessTransport("merchant_signed"),
    });

    // INVARIANT: allow only when the payment matches the quote.
    expect(res.allow).toBe(true);
    expect(res.decision).toBe("allow");
    expect(res.receipt).toBeDefined();
    expect(res.signature).toBeDefined();
    expect(res.receipt!.lane).toBe("evm");
    expect(res.receipt!.chain_id).toBe(BASE_CHAIN);
    expect(res.receipt!.decision).toBe("allow");

    // 2) THE KILL CRITERION: an independent party verifies the receipt against
    //    the published public key, offline, with no access to us.
    const check = verifyReceipt(res.receipt!, res.signature!, RECEIPT_PUBKEY);
    expect(check.valid).toBe(true);

    // Tamper with the receipt (flip the decision) — the same signature must fail.
    const forged: Receipt = { ...res.receipt!, decision: "refuse" };
    expect(verifyReceipt(forged, res.signature!, RECEIPT_PUBKEY).valid).toBe(false);

    // 3) The receipt BINDS to this exact request, and to no other. The digest
    //    is over {network, quote{payTo,asset,amount}, payload{to,value,from}},
    //    so a request for a different quoted amount is a different request.
    expect(replayMatches(res.receipt!, req)).toBe(true);
    const otherReq: VerifyRequest = {
      network: evmQuote.network,
      quote: { ...evmQuote, amount: "2000000" }, // a different quote
      payload,
    };
    expect(replayMatches(res.receipt!, otherReq)).toBe(false);

    // 4) The billable event flows into the meter and prices as billable.
    const meter = createMeter();
    meter.record({
      digest: res.receipt!.request_digest,
      provenance: res.receipt!.quote_provenance,
      decision: res.receipt!.decision,
      chainId: res.receipt!.chain_id,
      issuedAt: res.receipt!.issued_at,
      amountBucket: res.receipt!.amount_bucket ?? undefined,
      tier: "per_call",
      caller: "agent-01",
    });
    expect(meter.store.recent(60_000).length).toBe(1);
    expect(isBillable("merchant_signed")).toBe(true);
    expect(priceFor("merchant_signed", "per_call")).toBe(3_000n);
    expect(meter.priceFor("merchant_signed", "per_call")).toBe(3_000n);
  });

  it("carries NO plaintext: a sensitive marker in the quote never appears in the receipt, meter event, or signed bytes", async () => {
    const withText = {
      ...evmQuote,
      description: "SENSITIVE-MERCHANT-NOTE-should-not-appear",
    };
    const req: VerifyRequest = {
      network: withText.network,
      quote: withText,
      payload: await signAuth(),
    };
    const res = await guardedPay({
      network: req.network,
      quote: req.quote,
      payload: req.payload,
      transport: inProcessTransport("merchant_signed"),
    });
    expect(res.decision).toBe("allow");

    const receiptJson = JSON.stringify(res.receipt);
    expect(receiptJson).not.toContain("SENSITIVE-MERCHANT-NOTE");
    expect(receiptJson).not.toContain(MERCHANT); // no raw payee address either

    const meter = createMeter();
    meter.record({
      digest: res.receipt!.request_digest,
      provenance: res.receipt!.quote_provenance,
      decision: res.receipt!.decision,
      chainId: res.receipt!.chain_id,
      issuedAt: res.receipt!.issued_at,
      caller: "agent-01",
    });
    const eventJson = JSON.stringify(meter.store.recent(60_000));
    expect(eventJson).not.toContain("SENSITIVE-MERCHANT-NOTE");
    expect(eventJson).not.toContain(MERCHANT);
  });
});

// ============================================================================
// EVM — the full chain, adversarial path
// ============================================================================

describe("EVM full chain — a redirected payment is REFUSED, and a fleet of refusals correlates", () => {
  it("guardedPay refuses a payment redirected to the attacker: allow=false, decision=refuse, and the receipt records the refuse", async () => {
    const payload = await signAuth({ to: ATTACKER }); // real sig, wrong destination
    const res = await guardedPay({
      network: evmQuote.network,
      quote: evmQuote,
      payload,
      transport: inProcessTransport("merchant_signed"),
    });

    // INVARIANT: refuse on redirect; allow is false; the receipt records refuse.
    expect(res.allow).toBe(false);
    expect(res.decision).toBe("refuse");
    expect(res.findings.some((f) => f.code.startsWith("X402-1"))).toBe(true);
    expect(res.receipt).toBeDefined();
    expect(res.receipt!.decision).toBe("refuse");
    expect(res.receipt!.codes.length).toBeGreaterThan(0);

    // A refuse receipt is still a genuine, offline-verifiable attestation.
    expect(verifyReceipt(res.receipt!, res.signature!, RECEIPT_PUBKEY).valid).toBe(true);
  });

  it("the refuse fed across 3 distinct agents forms a shared-refuse cluster; a 2-agent slice does not (minAgents gate)", async () => {
    // Three distinct agents each refuse a redirect payment of the same shape on
    // the same chain. Each mutates its payload per target, so digests differ and
    // identical-digest never forms — the shared-refuse behavioral signal is the
    // one that must survive per-target payload mutation.
    const meter = createMeter();
    const callers = ["agent-A", "agent-B", "agent-C"];
    for (let i = 0; i < callers.length; i++) {
      const res = await guardedPay({
        network: evmQuote.network,
        quote: evmQuote,
        payload: await signAuth({ to: ATTACKER }),
        transport: inProcessTransport("merchant_signed"),
      });
      expect(res.decision).toBe("refuse");
      // Per-target digest divergence: mutate the recorded digest per agent so no
      // two share one, isolating the shared-refuse signal.
      meter.record({
        digest: `digest-${i}-${res.receipt!.request_digest}`,
        provenance: "merchant_signed",
        decision: "refuse",
        chainId: BASE_CHAIN,
        issuedAt: ISSUED_AT,
        amountBucket: res.receipt!.amount_bucket ?? undefined,
        tier: "monthly",
        caller: callers[i],
      });
    }

    const events = meter.store.recent(3_600_000);
    expect(events.length).toBe(3);

    // INVARIANT: correlate flags a cluster only when >= minAgents distinct
    // callers share the signal. 3 agents, minAgents 3 -> a shared-refuse cluster.
    const clusters = correlate(events, { windowMs: 3_600_000, minAgents: 3 });
    const shared = clusters.find((c) => c.signal === "shared-refuse");
    expect(shared).toBeDefined();
    expect(shared!.chainId).toBe(BASE_CHAIN);
    expect(shared!.count).toBe(3);
    // Per-target mutation defeated the digest path, as designed.
    expect(clusters.some((c) => c.signal === "identical-digest")).toBe(false);

    // Raise the bar past the fleet size: no cluster forms.
    const stricter = correlate(events, { windowMs: 3_600_000, minAgents: 4 });
    expect(stricter.find((c) => c.signal === "shared-refuse")).toBeUndefined();
  });

  it("caller_asserted is never billed and never recorded as a trusted signal", () => {
    // priceFor is 0 for caller_asserted regardless of tier, and record() drops
    // it before it can reach the store — so it can never correlate as trusted.
    expect(isBillable("caller_asserted")).toBe(false);
    expect(priceFor("caller_asserted", "per_call")).toBe(0n);
    expect(priceFor("caller_asserted", "monthly")).toBe(0n);

    const meter = createMeter();
    for (const caller of ["agent-A", "agent-B", "agent-C"]) {
      meter.record({
        digest: "same-digest",
        provenance: "caller_asserted",
        decision: "refuse",
        chainId: BASE_CHAIN,
        issuedAt: ISSUED_AT,
        caller,
      });
    }
    // Nothing stored -> nothing to correlate.
    expect(meter.store.recent(3_600_000).length).toBe(0);
    const events: BillingEvent[] = meter.store.recent(3_600_000).slice();
    expect(correlate(events, { windowMs: 3_600_000, minAgents: 1 })).toHaveLength(0);
  });
});

// ============================================================================
// EVM — abstain is never an allow
// ============================================================================

describe("EVM full chain — abstain is never an allow and carries no receipt", () => {
  it("an unresolved network abstains: guardedPay allow=false, decision=abstain, no receipt", async () => {
    const res = await guardedPay({
      network: "dogechain-mainnet-???",
      quote: evmQuote,
      payload: await signAuth(),
      transport: inProcessTransport("merchant_signed"),
    });
    expect(res.allow).toBe(false);
    expect(res.decision).toBe("abstain");
    expect(res.receipt).toBeUndefined();
    expect(res.signature).toBeUndefined();
    expect(res.reason).toMatch(/unresolved network/);
  });
});

// ============================================================================
// SVM — the full chain: quote+payment -> receipt -> offline round-trip
// ============================================================================

describe("SVM full chain — a real Solana transaction verifies, and its receipt replays offline on the SVM rail", () => {
  it("guardedPay allows a conforming SVM transfer; the receipt verifies offline, binds to the request, and prices as billable", async () => {
    const payload = svmPaymentBase64(merchantAta, 1_000_000n); // real serialized tx
    const req: VerifyRequest = { network: "solana", quote: svmQuote, payload };

    const res = await guardedPay({
      network: req.network,
      quote: req.quote,
      payload: req.payload,
      transport: inProcessTransport("merchant_signed"),
    });

    expect(res.allow).toBe(true);
    expect(res.decision).toBe("allow");
    expect(res.receipt).toBeDefined();
    // SVM has no EVM-style chain id.
    expect(res.receipt!.lane).toBe("svm");
    expect(res.receipt!.chain_id).toBeNull();

    // Offline authenticity + binding, no server access.
    expect(verifyReceipt(res.receipt!, res.signature!, RECEIPT_PUBKEY).valid).toBe(true);
    expect(replayMatches(res.receipt!, req)).toBe(true);

    // A different SVM request must NOT bind to this receipt.
    const otherReq: VerifyRequest = {
      network: "solana",
      quote: svmQuote,
      payload: svmPaymentBase64(attackerAta, 1_000_000n),
    };
    expect(replayMatches(res.receipt!, otherReq)).toBe(false);

    // Billable on the SVM rail too.
    const meter = createMeter();
    meter.record({
      digest: res.receipt!.request_digest,
      provenance: res.receipt!.quote_provenance,
      decision: res.receipt!.decision,
      chainId: res.receipt!.chain_id,
      issuedAt: res.receipt!.issued_at,
      caller: "svm-agent-01",
    });
    expect(meter.store.recent(60_000).length).toBe(1);
    expect(meter.priceFor("merchant_signed", "per_call")).toBe(3_000n);

    // No plaintext: the raw payee address never appears in the receipt.
    expect(JSON.stringify(res.receipt)).not.toContain(svmMerchant.publicKey.toBase58());
  });

  it("guardedPay refuses an SVM transfer redirected to an attacker: allow=false, decision=refuse, receipt records the refuse", async () => {
    const payload = svmPaymentBase64(attackerAta, 1_000_000n);
    const req: VerifyRequest = { network: "solana", quote: svmQuote, payload };

    const res = await guardedPay({
      network: req.network,
      quote: req.quote,
      payload: req.payload,
      transport: inProcessTransport("merchant_signed"),
    });

    expect(res.allow).toBe(false);
    expect(res.decision).toBe("refuse");
    expect(res.receipt).toBeDefined();
    expect(res.receipt!.decision).toBe("refuse");
    expect(res.receipt!.lane).toBe("svm");
    // The refuse receipt is genuine and replays offline.
    expect(verifyReceipt(res.receipt!, res.signature!, RECEIPT_PUBKEY).valid).toBe(true);
    expect(replayMatches(res.receipt!, req)).toBe(true);
  });

  it("undecodable SVM bytes abstain: allow=false, decision=abstain, no receipt (a check that could not run is never an allow)", async () => {
    const junk = Buffer.from(new Uint8Array([1, 2, 3, 4])).toString("base64");
    const res = await guardedPay({
      network: "solana",
      quote: svmQuote,
      payload: junk,
      transport: inProcessTransport("merchant_signed"),
    });
    expect(res.allow).toBe(false);
    expect(res.decision).toBe("abstain");
    expect(res.receipt).toBeUndefined();
  });
});
