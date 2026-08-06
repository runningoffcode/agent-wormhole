/**
 * End-to-end tests for the CLIENT side of the checkpoint — `guardedPay`,
 * `makeHttpTransport`, and `guardedFetch` — over an INJECTED transport.
 *
 * The client never inspects a payment itself; it shapes a request, hands it to
 * a transport, and interprets the verdict. So the claims worth pinning here are
 * about that interpretation, not the arithmetic (covered in verify/evm/guard):
 *
 *   1. `guardedPay` allows ONLY on a decisive `allow`; a `refuse` and an
 *      `abstain` both yield `allow: false`, and an abstain is never an allow.
 *   2. The detached ed25519 `signature` the transport produced is threaded all
 *      the way through to `GuardedPayResult.signature`, and the receipt it
 *      covers still replays offline against the published public key.
 *   3. A transport that throws (verifier unreachable) becomes an abstain, never
 *      an allow.
 *   4. `makeHttpTransport` returns a function and opens no socket at build time;
 *      exercised only against a STUBBED global fetch, restored after.
 *   5. `guardedFetch` guards the 402 path against a stubbed fetch and lets a
 *      non-402 response through untouched.
 *
 * The transport is either a hand-written fake OR the real in-process `verify`
 * wrapped as a transport, so real EIP-3009 (EVM) and real Solana bytes (SVM)
 * are exercised, not mocked. No network, no server, no sockets: every fetch is
 * a vi.fn stub, restored in afterEach.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
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
import {
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import { EIP3009, type EvmPayload, type EvmPaymentQuote } from "../src/evm.js";
import {
  verify,
  canonicalReceipt,
  type VerifyRequest,
  type VerifyContext,
} from "../src/verify.js";
import {
  guardedPay,
  makeHttpTransport,
  guardedFetch,
  type VerifyTransport,
  type VerifiedResult,
} from "../src/client.js";

// --- EVM fixtures: a real EIP-3009 signer (reuses verify.test.ts's shape) ----

const PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const account = privateKeyToAccount(PK);
const SIGNER = account.address;

const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const BASE_CHAIN = 8453;
const MERCHANT = "0x1111111111111111111111111111111111111111";
const ATTACKER = "0x2222222222222222222222222222222222222222";
const NONCE_A = "0x00000000000000000000000000000000000000000000000000000000000000aa" as Hex;

const evmQuote: EvmPaymentQuote = {
  network: "eip155:8453",
  asset: BASE_USDC,
  payTo: MERCHANT,
  amount: "1000000",
};

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

// --- SVM fixtures: real serialized Solana transaction bytes ------------------

const USDC = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const svmPayer = Keypair.generate();
const svmMerchant = Keypair.generate();
const svmAttacker = Keypair.generate();
const svmPayerAta = getAssociatedTokenAddressSync(USDC, svmPayer.publicKey);
const svmMerchantAta = getAssociatedTokenAddressSync(USDC, svmMerchant.publicKey);
const svmAttackerAta = getAssociatedTokenAddressSync(USDC, svmAttacker.publicKey);

const svmQuote = {
  payTo: svmMerchant.publicKey.toBase58(),
  asset: USDC.toBase58(),
  amount: "1000000",
};

function svmBuild(dest: PublicKey, amount: bigint): Uint8Array {
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
  return new VersionedTransaction(msg).serialize();
}

// --- Deterministic context: fixed clock + fixed ed25519 signing key ----------

const ISSUED_AT = "2033-05-18T03:33:20.000Z";
const { publicKey: RECEIPT_PUB, privateKey: RECEIPT_PRIV } =
  generateKeyPairSync("ed25519");
const signReceipt = (canonical: string) =>
  edSign(null, Buffer.from(canonical), RECEIPT_PRIV).toString("base64");

function ctx(sign?: (c: string) => string): VerifyContext {
  return { quoteProvenance: "merchant_signed", issuedAt: ISSUED_AT, sign };
}

/**
 * The real in-process verifier, wrapped as a `VerifyTransport`. This is the
 * "same code, no socket" path: `guardedPay` runs against genuine EIP-3009 /
 * Solana logic and a real ed25519 signature over the canonical receipt, exactly
 * as a hosted endpoint would return it — but entirely offline.
 */
function localTransport(sign = signReceipt): VerifyTransport {
  return async (req: VerifyRequest): Promise<VerifiedResult> => {
    const r = await verify(req, ctx(sign));
    return {
      ...r,
      signature: r.receipt ? sign(canonicalReceipt(r.receipt)) : undefined,
    };
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------

describe("guardedPay: allow ONLY on a decisive allow (EVM rail, real signature)", () => {
  it("allows when the underlying verify allows a conforming EIP-3009 payment", async () => {
    const res = await guardedPay({
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
      transport: localTransport(),
    });
    expect(res.decision).toBe("allow");
    expect(res.allow).toBe(true);
    expect(res.receipt).toBeDefined();
    expect(res.receipt!.lane).toBe("evm");
    expect(res.receipt!.chain_id).toBe(BASE_CHAIN);
  });

  it("allow=false on refuse: a payment redirected to an attacker is not cleared", async () => {
    const res = await guardedPay({
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth({ to: ATTACKER }),
      transport: localTransport(),
    });
    expect(res.decision).toBe("refuse");
    expect(res.allow).toBe(false);
    // A refuse is still a decisive, billable verdict — it carries a receipt.
    expect(res.receipt).toBeDefined();
    expect(res.receipt!.decision).toBe("refuse");
  });

  it("allow=false on refuse: an overpayment above the quoted amount is not cleared", async () => {
    const res = await guardedPay({
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth({ value: 900_000_000n }),
      transport: localTransport(),
    });
    expect(res.decision).toBe("refuse");
    expect(res.allow).toBe(false);
  });
});

describe("guardedPay: abstain is NEVER an allow and carries NO receipt", () => {
  it("allow=false on abstain: an unresolved network abstains, no receipt", async () => {
    const res = await guardedPay({
      network: "dogechain-mainnet-???",
      quote: evmQuote,
      payload: await signAuth(),
      transport: localTransport(),
    });
    expect(res.decision).toBe("abstain");
    expect(res.allow).toBe(false);
    expect(res.receipt).toBeUndefined();
    expect(res.signature).toBeUndefined();
  });

  it("allow=false on abstain: an undecodable payload never becomes a signed allow", async () => {
    const res = await guardedPay({
      network: evmQuote.network,
      quote: evmQuote,
      payload: { not: "a payload" },
      transport: localTransport(),
    });
    expect(res.allow).toBe(false);
    expect(res.decision).not.toBe("allow");
    if (res.decision === "abstain") {
      expect(res.receipt).toBeUndefined();
      expect(res.signature).toBeUndefined();
    }
  });

  it("allow=false on abstain: a transport that THROWS is an abstain, never an allow", async () => {
    const throwing: VerifyTransport = async () => {
      throw new Error("verifier unreachable");
    };
    const res = await guardedPay({
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
      transport: throwing,
    });
    expect(res.allow).toBe(false);
    expect(res.decision).toBe("abstain");
    expect(res.receipt).toBeUndefined();
    expect(res.reason).toMatch(/transport_error/);
  });
});

describe("guardedPay: the detached signature is threaded through to the caller", () => {
  it("EVM: signature propagates and the receipt it covers replays offline", async () => {
    const res = await guardedPay({
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
      transport: localTransport(),
    });
    expect(res.decision).toBe("allow");
    expect(res.signature).toBeTypeOf("string");
    expect(res.receipt).toBeDefined();

    // --- everything below is what a third party does, offline, no server ---
    const canonical = canonicalReceipt(res.receipt!);
    const ok = edVerify(
      null,
      Buffer.from(canonical),
      RECEIPT_PUB,
      Buffer.from(res.signature!, "base64"),
    );
    expect(ok).toBe(true);

    // Tamper with the receipt: the propagated signature must fail to verify.
    const forged = canonicalReceipt({ ...res.receipt!, decision: "refuse" });
    const bad = edVerify(
      null,
      Buffer.from(forged),
      RECEIPT_PUB,
      Buffer.from(res.signature!, "base64"),
    );
    expect(bad).toBe(false);
  });

  it("EVM: a refuse verdict is also signed and replays offline", async () => {
    const res = await guardedPay({
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth({ to: ATTACKER }),
      transport: localTransport(),
    });
    expect(res.decision).toBe("refuse");
    expect(res.signature).toBeTypeOf("string");
    const ok = edVerify(
      null,
      Buffer.from(canonicalReceipt(res.receipt!)),
      RECEIPT_PUB,
      Buffer.from(res.signature!, "base64"),
    );
    expect(ok).toBe(true);
  });

  it("an unsigned transport (offline, no key) yields a receipt but no signature", async () => {
    const unsigned: VerifyTransport = async (req) => {
      const r = await verify(req, ctx()); // no sign fn
      return { ...r }; // signature intentionally omitted
    };
    const res = await guardedPay({
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
      transport: unsigned,
    });
    expect(res.decision).toBe("allow");
    expect(res.allow).toBe(true);
    expect(res.receipt).toBeDefined();
    expect(res.signature).toBeUndefined();
  });
});

describe("guardedPay: the SVM rail is exercised end-to-end (real Solana bytes)", () => {
  it("allows a conforming Solana payment and signs a replayable receipt", async () => {
    const payload = Buffer.from(svmBuild(svmMerchantAta, 1_000_000n)).toString("base64");
    const res = await guardedPay({
      network: "solana",
      quote: svmQuote,
      payload,
      transport: localTransport(),
    });
    expect(res.decision).toBe("allow");
    expect(res.allow).toBe(true);
    expect(res.receipt!.lane).toBe("svm");
    // The SVM receipt replays offline through the propagated signature too.
    const ok = edVerify(
      null,
      Buffer.from(canonicalReceipt(res.receipt!)),
      RECEIPT_PUB,
      Buffer.from(res.signature!, "base64"),
    );
    expect(ok).toBe(true);
  });

  it("allow=false on refuse: a substituted Solana destination is not cleared", async () => {
    const payload = Buffer.from(svmBuild(svmAttackerAta, 1_000_000n)).toString("base64");
    const res = await guardedPay({
      network: "solana",
      quote: svmQuote,
      payload,
      transport: localTransport(),
    });
    expect(res.decision).toBe("refuse");
    expect(res.allow).toBe(false);
  });
});

describe("guardedPay: no plaintext quote text or raw payee crosses to the caller", () => {
  it("a sensitive marker in the quote never appears in the serialized result", async () => {
    const poisonMarker = "SENSITIVE-MERCHANT-NOTE-should-not-appear";
    const res = await guardedPay({
      network: evmQuote.network,
      quote: { ...evmQuote, description: `benign note ${poisonMarker}` },
      payload: await signAuth(),
      transport: localTransport(),
    });
    // The receipt/finding surface must carry codes and buckets, not plaintext.
    const serialized = JSON.stringify({
      receipt: res.receipt,
      findings: res.findings,
      reason: res.reason,
    });
    expect(serialized).not.toContain("SENSITIVE-MERCHANT-NOTE");
    expect(serialized).not.toContain(MERCHANT); // no raw destination either
  });
});

describe("makeHttpTransport: builds a function and opens no socket until called", () => {
  it("returns a function and touches no fetch merely by being constructed", () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const transport = makeHttpTransport("https://verify.example.test");
    expect(transport).toBeTypeOf("function");
    // Constructing the transport must not have reached for the socket.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("POSTs to <baseUrl>/v1/verify and threads the wire signature through (stubbed fetch)", async () => {
    // A canned wire response as the hosted /v1/verify would return it, including
    // the detached ed25519 signature over the canonical receipt.
    const req: VerifyRequest = {
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
    };
    const real = await verify(req, ctx(signReceipt));
    const wireSignature = signReceipt(canonicalReceipt(real.receipt!));
    const wireBody = {
      decision: real.decision,
      findings: real.findings,
      receipt: real.receipt,
      signature: wireSignature,
      billable: true,
    };

    const fetchSpy = vi.fn(async (url: any, init: any) => {
      expect(String(url)).toBe("https://verify.example.test/v1/verify");
      expect(init.method).toBe("POST");
      expect(init.headers["x-quote-provenance"]).toBe("merchant_signed");
      return new Response(JSON.stringify(wireBody), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchSpy);

    const transport = makeHttpTransport("https://verify.example.test", {
      provenanceHeader: "merchant_signed",
    });
    const res = await guardedPay({
      network: req.network,
      quote: req.quote,
      payload: req.payload,
      transport,
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(res.decision).toBe("allow");
    expect(res.allow).toBe(true);
    expect(res.signature).toBe(wireSignature);
    // The signature threaded off the wire still verifies against the public key.
    const ok = edVerify(
      null,
      Buffer.from(canonicalReceipt(res.receipt!)),
      RECEIPT_PUB,
      Buffer.from(res.signature!, "base64"),
    );
    expect(ok).toBe(true);
  });

  it("a non-2xx from the endpoint is an abstain via guardedPay, never an allow (stubbed fetch)", async () => {
    const fetchSpy = vi.fn(async () => new Response("nope", { status: 500 }));
    vi.stubGlobal("fetch", fetchSpy);
    const transport = makeHttpTransport("https://verify.example.test");
    const res = await guardedPay({
      network: evmQuote.network,
      quote: evmQuote,
      payload: await signAuth(),
      transport,
    });
    expect(res.allow).toBe(false);
    expect(res.decision).toBe("abstain");
    expect(res.reason).toMatch(/transport_error/);
  });
});

describe("guardedFetch: guards the 402 path and passes non-402 through (stubbed fetch)", () => {
  it("a non-402 response is allowed untouched, no verifier consulted", async () => {
    const fetchSpy = vi.fn(async () => new Response("ok", { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    const transport = vi.fn() as unknown as VerifyTransport;
    const out = await guardedFetch(
      "https://merchant.example.test/resource",
      undefined,
      {
        quote: evmQuote,
        extractPayment: () => ({ network: evmQuote.network, payload: {} }),
        transport,
      },
    );
    expect(out.allow).toBe(true);
    expect(out.guard).toBeUndefined();
    expect(transport).not.toHaveBeenCalled();
  });

  it("on a 402, a conforming constructed payment is verified and allowed", async () => {
    const payload = await signAuth();
    const fetchSpy = vi.fn(async () => new Response("pay", { status: 402 }));
    vi.stubGlobal("fetch", fetchSpy);
    const out = await guardedFetch(
      "https://merchant.example.test/resource",
      undefined,
      {
        quote: evmQuote,
        extractPayment: () => ({ network: evmQuote.network, payload }),
        transport: localTransport(),
      },
    );
    expect(out.response.status).toBe(402);
    expect(out.allow).toBe(true);
    expect(out.guard!.decision).toBe("allow");
    expect(out.guard!.signature).toBeTypeOf("string");
  });

  it("on a 402, a redirected constructed payment is refused (allow=false)", async () => {
    const payload = await signAuth({ to: ATTACKER });
    const fetchSpy = vi.fn(async () => new Response("pay", { status: 402 }));
    vi.stubGlobal("fetch", fetchSpy);
    const out = await guardedFetch(
      "https://merchant.example.test/resource",
      undefined,
      {
        quote: evmQuote,
        extractPayment: () => ({ network: evmQuote.network, payload }),
        transport: localTransport(),
      },
    );
    expect(out.allow).toBe(false);
    expect(out.guard!.decision).toBe("refuse");
  });

  it("on a 402, a payment that cannot be constructed abstains, never allows", async () => {
    const fetchSpy = vi.fn(async () => new Response("pay", { status: 402 }));
    vi.stubGlobal("fetch", fetchSpy);
    const transport = vi.fn() as unknown as VerifyTransport;
    const out = await guardedFetch(
      "https://merchant.example.test/resource",
      undefined,
      {
        quote: evmQuote,
        extractPayment: () => undefined, // could not build the payment
        transport,
      },
    );
    expect(out.allow).toBe(false);
    expect(out.guard!.decision).toBe("abstain");
    expect(out.guard!.reason).toMatch(/could_not_construct_payment/);
    // Abstained before ever consulting the verifier.
    expect(transport).not.toHaveBeenCalled();
  });
});
