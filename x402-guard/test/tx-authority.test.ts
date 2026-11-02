/**
 * Standing authority, delegatecalls, chain binding and strict reading in the
 * transaction check (0.11.0).
 *
 * Each case pairs a transaction that should pass with the one change that
 * should stop it: an unlimited grant written as a number, a delegatecall
 * packed inside a wrapper, an account-control grant left open, a node that
 * names another chain when the wallet signs, a key no rule reads.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { createWalletClient, custom, encodeAbiParameters, encodeFunctionData, encodePacked, parseAbiItem, parseAbiParameters, parseTransaction, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { inspectTransaction, inspectPermit, presets, PERMIT2, type TxIntent, type PermitIntent } from "../src/tx.js";
import { guardEvmSigner } from "../src/evm.js";

const account = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex);
const CHAIN = 8453;
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const ROUTER = "0x204FAca1764B154221e35c0d20aBb3c525710498";
const SAFE = "0x3333333333333333333333333333333333333333";
const OTHER = "0x2222222222222222222222222222222222222222";
const MAX256 = (1n << 256n) - 1n;
const MAX160 = (1n << 160n) - 1n;
const fn = (sig: string) => parseAbiItem(`function ${sig}`);
const call = (sig: string, args: readonly unknown[]): Hex =>
  encodeFunctionData({ abi: [fn(sig)], functionName: fn(sig).name, args: args as unknown[] } as never);
const codes = (v: { findings: { code: string }[] }) => v.findings.map((f) => f.code);

describe("an unlimited grant needs the word for it", () => {
  it("refuses a maximum approval written as a number, and allows it written unlimited", () => {
    const data = call("approve(address,uint256)", [PERMIT2, MAX256]);
    const numeric: TxIntent = { kind: "erc20.approve", chainId: CHAIN, token: USDC, spender: PERMIT2, amount: MAX256 };
    expect(codes(inspectTransaction(numeric, { to: USDC, data }))).toEqual(["X402-705"]);
    expect(inspectTransaction({ ...numeric, amount: "unlimited" }, { to: USDC, data }).decision).toBe("allow");
  });

  it("refuses a maximum Permit2 permit written as a number", () => {
    const req = {
      domain: { name: "Permit2", chainId: CHAIN, verifyingContract: PERMIT2 },
      types: {
        PermitSingle: [{ name: "details", type: "PermitDetails" }, { name: "spender", type: "address" }, { name: "sigDeadline", type: "uint256" }],
        PermitDetails: [{ name: "token", type: "address" }, { name: "amount", type: "uint160" }, { name: "expiration", type: "uint48" }, { name: "nonce", type: "uint48" }],
      },
      primaryType: "PermitSingle",
      message: { details: { token: USDC, amount: MAX160, expiration: 100, nonce: 0 }, spender: ROUTER, sigDeadline: 100n },
    };
    const intent: PermitIntent = { kind: "permit2.permit", chainId: CHAIN, token: USDC, spender: ROUTER, amount: MAX160, expiration: { lte: 100n }, sigDeadline: { lte: 100n } };
    expect(codes(inspectPermit(intent, req))).toEqual(["X402-705"]);
    expect(inspectPermit({ ...intent, amount: "unlimited" }, req).decision).toBe("allow");
  });

  it("refuses Permit2's on-chain permit at its maximum unless the intent says unlimited", () => {
    const SIG = "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)";
    const data = call(SIG, [account.address, [[USDC, MAX160, 100, 0], ROUTER, 100n], `0x${"11".repeat(65)}`]);
    const intent: TxIntent = {
      kind: "call",
      chainId: CHAIN,
      target: PERMIT2,
      signature: SIG,
      args: [{ eq: account.address }, { eq: [[USDC, MAX160, 100, 0], ROUTER, 100n] }, { signature: true }],
    };
    expect(codes(inspectTransaction(intent, { to: PERMIT2, data }))).toEqual(["X402-705"]);
    expect(inspectTransaction({ ...intent, unlimited: true }, { to: PERMIT2, data }).decision).toBe("allow");
  });

  it("refuses an unlimited permit inside a router call unless the intent says unlimited", () => {
    const base = { chainId: 4663, router: ROUTER, fields: 6 as const, zeroForOne: true, amountIn: 5n, minAmountOut: 1n, deadline: { lte: 10n } };
    const poolKey = { currency0: USDC, currency1: OTHER, fee: 3000, tickSpacing: 60, hooks: "0x0000000000000000000000000000000000000000" };
    const permit = encodeAbiParameters(parseAbiParameters("((address,uint160,uint48,uint48),address,uint256), bytes"), [[[USDC, MAX160, 9, 0], ROUTER, 9n], `0x${"22".repeat(65)}`] as never);
    const swap = encodeAbiParameters(parseAbiParameters("((address,address,uint24,int24,address),bool,uint128,uint128,uint256,bytes)"), [[[USDC, OTHER, 3000, 60, poolKey.hooks], true, 5n, 1n, 0n, "0x"]] as never);
    const leg = (cur: string, n: bigint) => encodeAbiParameters(parseAbiParameters("address, uint256"), [cur as Hex, n]);
    const v4 = encodeAbiParameters(parseAbiParameters("bytes, bytes[]"), ["0x060c0f", [swap, leg(USDC, 5n), leg(OTHER, 1n)]]);
    const data = call("execute(bytes,bytes[],uint256)", ["0x0a10", [permit, v4], 9n]);
    const numeric = presets.uniswapV4.swapExactInSingle({ ...base, poolKey, permit: { amount: MAX160, expiration: { lte: 9n }, sigDeadline: { lte: 9n } } });
    expect(codes(inspectTransaction(numeric, { to: ROUTER, data }))).toEqual(["X402-705"]);
    const named = presets.uniswapV4.swapExactInSingle({ ...base, poolKey, permit: { amount: "unlimited", expiration: { lte: 9n }, sigDeadline: { lte: 9n } } });
    expect(inspectTransaction(named, { to: ROUTER, data }).decision).toBe("allow");
  });
});

describe("a delegatecall packed inside a wrapper", () => {
  const inner = encodePacked(["address", "uint256", "bytes"], [USDC, 0n, call("transfer(address,uint256)", [OTHER, 1n])]);
  const mode = (callType: string) => `0x${callType}${"00".repeat(31)}` as Hex;

  it("abstains on an ERC-7579 delegatecall mode, and on a mode the intent leaves open", () => {
    const SIG = "execute(bytes32,bytes)";
    const exactly = (m: Hex): TxIntent => ({ kind: "call", chainId: CHAIN, target: SAFE, signature: SIG, args: [{ eq: m }, { eq: inner }] });
    expect(inspectTransaction(exactly(mode("00")), { to: SAFE, data: call(SIG, [mode("00"), inner]) }).decision).toBe("allow");
    expect(codes(inspectTransaction(exactly(mode("ff")), { to: SAFE, data: call(SIG, [mode("ff"), inner]) }))).toEqual(["X402-709"]);
    const open: TxIntent = { kind: "call", chainId: CHAIN, target: SAFE, signature: SIG, args: [{ any: true }, { eq: inner }] };
    expect(codes(inspectTransaction(open, { to: SAFE, data: call(SIG, [mode("00"), inner]) }))).toEqual(["X402-709"]);
  });

  it("abstains on a MultiSend record that is a delegatecall", () => {
    const record = (op: number) =>
      encodePacked(["uint8", "address", "uint256", "uint256", "bytes"], [op, USDC, 0n, BigInt((inner.length - 2) / 2), inner]);
    const intent = (records: Hex): TxIntent => ({ kind: "call", chainId: CHAIN, target: SAFE, signature: "multiSend(bytes)", args: [{ eq: records }] });
    expect(inspectTransaction(intent(record(0)), { to: SAFE, data: call("multiSend(bytes)", [record(0)]) }).decision).toBe("allow");
    const mixed = `${record(0)}${record(1).slice(2)}` as Hex;
    expect(codes(inspectTransaction(intent(mixed), { to: SAFE, data: call("multiSend(bytes)", [mixed]) }))).toEqual(["X402-709"]);
  });
});

describe("account-control grants and bundler wrappers", () => {
  it("needs exact terms and unlimited: true to enable a Safe module", () => {
    const data = call("enableModule(address)", [OTHER]);
    const open: TxIntent = { kind: "call", chainId: CHAIN, target: SAFE, signature: "enableModule(address)", args: [{ any: true }] };
    expect(codes(inspectTransaction(open, { to: SAFE, data }))).toContain("X402-705");
    const exactly: TxIntent = { ...open, args: [{ eq: OTHER }] } as TxIntent;
    expect(codes(inspectTransaction(exactly, { to: SAFE, data }))).toEqual(["X402-705"]);
    expect(inspectTransaction({ ...exactly, unlimited: true } as TxIntent, { to: SAFE, data }).decision).toBe("allow");
  });

  it("holds a new Safe owner and threshold to exact terms", () => {
    const SIG = "addOwnerWithThreshold(address,uint256)";
    const data = call(SIG, [OTHER, 2n]);
    expect(codes(inspectTransaction({ kind: "call", chainId: CHAIN, target: SAFE, signature: SIG, args: [{ any: true }, { eq: 2 }] }, { to: SAFE, data }))).toEqual(["X402-705"]);
    expect(inspectTransaction({ kind: "call", chainId: CHAIN, target: SAFE, signature: SIG, args: [{ eq: OTHER }, { eq: 2 }] }, { to: SAFE, data }).decision).toBe("allow");
  });

  it("abstains on aggregated user operations the intent leaves open", () => {
    const SIG = "handleAggregatedOps(((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address,bytes)[],address)";
    const data = call(SIG, [[], OTHER]);
    const intent: TxIntent = { kind: "call", chainId: CHAIN, target: SAFE, signature: SIG, args: [{ any: true }, { eq: OTHER }] };
    expect(codes(inspectTransaction(intent, { to: SAFE, data }))).toEqual(["X402-709"]);
  });
});

describe("strict reading", () => {
  const data = call("transfer(address,uint256)", [OTHER, 1n]);
  const base: TxIntent = { kind: "call", chainId: CHAIN, target: USDC, signature: "transfer(address,uint256)", args: [{ eq: OTHER }, { lte: 5 }] };

  it("abstains with X402-707 on an intent array that carries a key no rule reads", () => {
    const named = Object.assign([{ eq: OTHER }, { lte: 5 }], { note: "x" });
    expect(codes(inspectTransaction({ ...base, args: named } as TxIntent, { to: USDC, data }))).toEqual(["X402-707"]);
    const symbol = Object.assign([{ eq: OTHER }, { lte: 5 }], { [Symbol("rule")]: true });
    expect(codes(inspectTransaction({ ...base, args: symbol } as TxIntent, { to: USDC, data }))).toEqual(["X402-707"]);
    const throwing = [{ eq: OTHER }];
    Object.defineProperty(throwing, 1, { get: () => { throw new Error("boom"); }, enumerable: true });
    expect(codes(inspectTransaction({ ...base, args: throwing } as TxIntent, { to: USDC, data }))).toEqual(["X402-707"]);
  });

  it("abstains on a transaction field keyed by a symbol", () => {
    expect(codes(inspectTransaction(base, { to: USDC, data, [Symbol("extra")]: 1 }))).toEqual(["X402-709"]);
  });
});

describe("the chain a viem wallet client signs for", () => {
  /** A node that names one chain to the guard and, from the next question on, another. */
  function shiftingNode(first: number, later: number) {
    let asked = 0;
    return custom({
      async request({ method }: { method: string }) {
        if (method === "eth_chainId") return `0x${(asked++ === 0 ? first : later).toString(16)}`;
        throw new Error(`unexpected ${method}`);
      },
    });
  }
  const intent: TxIntent = { kind: "native.transfer", chainId: 1, to: OTHER, amount: { lte: 10n } };
  const tx = { to: OTHER, value: 1n, gas: 21_000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, nonce: 0 };

  it("refuses when the node names another chain as the client signs, with no chain configured", async () => {
    const client = createWalletClient({ account, chain: null, transport: shiftingNode(1, 2) });
    const g = guardEvmSigner(client, () => null, { intentFor: () => intent });
    await expect(g.signTransaction(tx as never)).rejects.toThrow();
  });

  it("CONTROL: signs for the intent's chain when the node stays on it", async () => {
    const client = createWalletClient({ account, chain: null, transport: shiftingNode(1, 1) });
    const g = guardEvmSigner(client, () => null, { intentFor: () => intent });
    expect(parseTransaction((await g.signTransaction(tx as never)) as Hex).chainId).toBe(1);
  });
});

describe("release metadata", () => {
  it("names one version in the manifest and the lockfile", () => {
    const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
    expect(lock.version).toBe(manifest.version);
    expect(lock.packages[""].version).toBe(manifest.version);
  });

  it("refuses a standing allowance by name on the payment path", async () => {
    const quote = () => ({ network: "eip155:8453", asset: USDC, payTo: OTHER, amount: "1" });
    const s = { calls: 0, async signTypedData() { s.calls++; return "0x"; } };
    const req = { domain: { name: "Permit2", chainId: CHAIN, verifyingContract: PERMIT2 }, types: {}, primaryType: "PermitSingle", message: {} };
    await expect(guardEvmSigner(s, quote).signTypedData(req)).rejects.toThrow(/X402-106/);
    expect(s.calls).toBe(0);
  });
});
