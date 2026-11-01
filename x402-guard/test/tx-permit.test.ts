/**
 * Permit2 allowance signatures held to the agent's intent (0.11.0).
 *
 * A Permit2 PermitSingle lets its spender pull the token later, so it is
 * standing authority: the token, spender and amount must be the intent's
 * exactly, the expiration and the signature deadline within bounds, and the
 * domain Permit2's own on the intent's chain. The guarded signers here sign
 * with a real key, and each test reads back what was signed.
 */

import { describe, it, expect } from "vitest";
import { createWalletClient, custom, recoverTypedDataAddress, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import { inspectPermit, presets, PERMIT2, type PermitIntent } from "../src/tx.js";
import { guardEvmSigner } from "../src/evm.js";

const account = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex);
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const ROUTER = "0x204FAca1764B154221e35c0d20aBb3c525710498";
const OTHER = "0x2222222222222222222222222222222222222222";
const MAX160 = (1n << 160n) - 1n;

const TYPES = {
  PermitSingle: [
    { name: "details", type: "PermitDetails" },
    { name: "spender", type: "address" },
    { name: "sigDeadline", type: "uint256" },
  ],
  PermitDetails: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint160" },
    { name: "expiration", type: "uint48" },
    { name: "nonce", type: "uint48" },
  ],
};

/** What a router client asks the wallet to sign: Permit2's own domain and struct. */
const request = (o: { token?: string; amount?: bigint; expiration?: number; spender?: string; sigDeadline?: bigint; chainId?: number; verifyingContract?: string } = {}) => ({
  domain: { name: "Permit2", chainId: o.chainId ?? 8453, verifyingContract: o.verifyingContract ?? PERMIT2 },
  types: TYPES,
  primaryType: "PermitSingle",
  message: {
    details: { token: o.token ?? USDC, amount: o.amount ?? 5_000_000n, expiration: o.expiration ?? 1_900_000_000, nonce: 0 },
    spender: o.spender ?? ROUTER,
    sigDeadline: o.sigDeadline ?? 1_800_000_000n,
  },
});

const intent: PermitIntent = presets.permit2.permit({
  chainId: 8453,
  token: USDC,
  spender: ROUTER,
  amount: 5_000_000n,
  expiration: { lte: 1_900_000_000n },
  sigDeadline: { lte: 1_800_000_000n },
});
const codes = (v: { findings: { code: string }[] }) => v.findings.map((f) => f.code);

describe("inspectPermit", () => {
  it("allows the intended allowance", () => {
    expect(inspectPermit(intent, request()).decision).toBe("allow");
  });

  it("refuses another token, spender or amount as standing authority the intent does not grant", () => {
    expect(codes(inspectPermit(intent, request({ token: OTHER })))).toEqual(["X402-705"]);
    expect(codes(inspectPermit(intent, request({ spender: OTHER })))).toEqual(["X402-705"]);
    expect(codes(inspectPermit(intent, request({ amount: 5_000_001n })))).toEqual(["X402-705"]);
    expect(codes(inspectPermit(intent, request({ amount: MAX160 })))).toEqual(["X402-705"]);
    expect(inspectPermit({ ...intent, amount: "unlimited" }, request({ amount: MAX160 })).decision).toBe("allow");
  });

  it("refuses a later expiration or signature deadline", () => {
    expect(codes(inspectPermit(intent, request({ expiration: 1_900_000_001 })))).toEqual(["X402-703"]);
    expect(codes(inspectPermit(intent, request({ sigDeadline: 1_800_000_001n })))).toEqual(["X402-703"]);
  });

  it("refuses a domain that is not Permit2 on the intent's chain", () => {
    expect(codes(inspectPermit(intent, request({ chainId: 1 })))).toEqual(["X402-701"]);
    expect(codes(inspectPermit(intent, request({ verifyingContract: OTHER })))).toEqual(["X402-701"]);
    const versioned = { ...request(), domain: { ...request().domain, version: "1" } };
    expect(codes(inspectPermit(intent, versioned))).toEqual(["X402-701"]);
  });

  it("refuses another struct, and abstains on fields it does not model", () => {
    expect(codes(inspectPermit(intent, { ...request(), primaryType: "PermitDetails" }))).toContain("X402-702");
    const widened = { ...request(), types: { ...TYPES, PermitSingle: [...TYPES.PermitSingle, { name: "note", type: "string" }] } };
    expect(codes(inspectPermit(intent, widened))).toContain("X402-702");
    const extra = request();
    const v = inspectPermit(intent, { ...extra, message: { ...extra.message, note: "x" } });
    expect(v.decision).toBe("abstain");
    expect(codes(v)).toEqual(["X402-709"]);
  });

  it("holds the allowance to the spending policy", () => {
    expect(codes(inspectPermit(intent, request(), { spendPolicy: { maxPerPayment: { [USDC]: 1_000_000n } } }))).toEqual(["X402-706"]);
    expect(inspectPermit(intent, request(), { spendPolicy: { maxPerPayment: { [USDC]: 5_000_000n } } }).decision).toBe("allow");
  });

  it("abstains on an intent that is not a permit", () => {
    const tx = { kind: "native.transfer", chainId: 8453, to: OTHER, amount: 1 } as unknown as PermitIntent;
    expect(codes(inspectPermit(tx, request()))).toEqual(["X402-707"]);
  });
});

describe("guardEvmSigner signs a Permit2 allowance only under its intent", () => {
  /** A local account: signs whatever typed data it is handed, viem's way. */
  function viemSigner() {
    const handed: unknown[] = [];
    return {
      handed,
      async signTypedData(r: unknown) {
        handed.push(r);
        return account.signTypedData(r as never);
      },
    };
  }

  it("signs the intended permit, and what it signs is the request it checked", async () => {
    const s = viemSigner();
    const g = guardEvmSigner(s, () => null, { intentFor: (r) => (r.primaryType === "PermitSingle" ? intent : null) });
    const sig = (await g.signTypedData(request())) as Hex;
    expect(await recoverTypedDataAddress({ ...(request() as never), signature: sig })).toBe(account.address);
    expect(s.handed[0]).toEqual(request());
    expect(Object.isFrozen(s.handed[0])).toBe(true);
  });

  it("refuses a permit to another spender without reaching the wallet", async () => {
    const s = viemSigner();
    const g = guardEvmSigner(s, () => null, { intentFor: () => intent });
    await expect(g.signTypedData(request({ spender: OTHER }))).rejects.toThrow(/X402-705/);
    expect(s.handed).toEqual([]);
  });

  it("keeps refusing permits without intentFor, as before", async () => {
    const quote = () => ({ network: "eip155:8453", asset: USDC, payTo: OTHER, amount: "5000000" });
    await expect(guardEvmSigner(viemSigner(), quote).signTypedData(request())).rejects.toThrow(/refusing/);
  });

  it("signs ethers' positional call with the domain, types and value it checked", async () => {
    const handed: unknown[][] = [];
    const ethersLike = {
      async signTypedData(d: unknown, t: unknown, v: unknown) {
        handed.push([d, t, v]);
        return account.signTypedData({ domain: d, types: t, primaryType: "PermitSingle", message: v } as never);
      },
    };
    const g = guardEvmSigner(ethersLike, () => null, { intentFor: () => intent });
    const r = request();
    const sig = (await g.signTypedData(r.domain, r.types, r.message)) as Hex;
    expect(await recoverTypedDataAddress({ ...(r as never), signature: sig })).toBe(account.address);
    expect(handed[0]).toEqual([r.domain, r.types, r.message]);
  });

  it("passes viem's account on, and holds the allowance against the lifetime total", async () => {
    const client = createWalletClient({ account, chain: base, transport: custom({ request: async () => { throw new Error("no node needed"); } }) });
    const g = guardEvmSigner(client, () => null, { intentFor: () => intent, spendPolicy: { maxTotal: { [USDC]: 6_000_000n } } });
    const sig = (await g.signTypedData({ account, ...request() } as never)) as Hex;
    expect(await recoverTypedDataAddress({ ...(request() as never), signature: sig })).toBe(account.address);
    await expect(g.signTypedData({ account, ...request() } as never)).rejects.toThrow(/X402-706.*X402-504/);
  });

  it("refuses a permit whose intent names a transaction", async () => {
    const g = guardEvmSigner(viemSigner(), () => null, { intentFor: () => ({ kind: "native.transfer", chainId: 8453, to: OTHER, amount: 1 }) });
    await expect(g.signTypedData(request())).rejects.toThrow(/permit2\.permit/);
  });
});
