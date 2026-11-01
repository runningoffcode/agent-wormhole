/**
 * Presets for Orbio's contracts, a UniversalRouter swap that carries its own
 * Permit2 allowance, and Orbio's wallet-key line (0.11.0).
 *
 * Orbio's calls are encoded from the ABIs it publishes (/protocol/abi), the
 * way its API or SDK would hand them to an agent, then changed in one place.
 */

import { describe, it, expect } from "vitest";
import { encodeAbiParameters, encodeFunctionData, parseAbiItem, parseAbiParameters, verifyMessage, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { inspectTransaction, presets, ORBIO, PERMIT2, type TxIntent } from "../src/tx.js";
import { inspectSignIn } from "../src/signin.js";
import { guardEvmSigner } from "../src/evm.js";

const account = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex);
const ME = account.address;
const OTHER = "0x2222222222222222222222222222222222222222";
const ROUTER = "0x204FAca1764B154221e35c0d20aBb3c525710498";
const fn = (sig: string) => parseAbiItem(`function ${sig}`);
const call = (sig: string, args: readonly unknown[]): Hex =>
  encodeFunctionData({ abi: [fn(sig)], functionName: fn(sig).name, args: args as unknown[] } as never);
const pad = (a: string) => `0x${a.slice(2).toLowerCase().padStart(64, "0")}` as Hex;
const codes = (v: { findings: { code: string }[] }) => v.findings.map((f) => f.code);
const tx = (to: string, data: Hex, value = 0n) => ({ to, data, value, chainId: 4663 });

describe("Orbio: buying CREDIT", () => {
  const buy = presets.orbio.buy({ usdgIn: { lte: 25_000_000n }, minCreditOut: 24_000_000n, recipient: ME });
  const BUY = "buy(uint256,uint256,address,uint256)";

  it("allows the intended buy and the exact USDG approval before it", () => {
    expect(inspectTransaction(buy, tx(ORBIO.exchange, call(BUY, [25_000_000n, 24_500_000n, ME, 10n]))).decision).toBe("allow");
    const approve = presets.orbio.approveUsdg({ amount: 25_000_000n });
    expect(inspectTransaction(approve, tx(ORBIO.usdg, call("approve(address,uint256)", [ORBIO.exchange, 25_000_000n]))).decision).toBe("allow");
    expect(codes(inspectTransaction(approve, tx(ORBIO.usdg, call("approve(address,uint256)", [ORBIO.exchange, 10n ** 12n]))))).toEqual(["X402-705"]);
  });

  it("refuses more USDG, a lower floor, or CREDIT paid to someone else", () => {
    expect(codes(inspectTransaction(buy, tx(ORBIO.exchange, call(BUY, [25_000_001n, 24_500_000n, ME, 10n]))))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(buy, tx(ORBIO.exchange, call(BUY, [25_000_000n, 1n, ME, 10n]))))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(buy, tx(ORBIO.exchange, call(BUY, [25_000_000n, 24_500_000n, OTHER, 10n]))))).toEqual(["X402-703"]);
  });

  it("will not build a buy without a USDG bound or with a zero floor", () => {
    expect(() => presets.orbio.buy({ usdgIn: { gte: 1n }, minCreditOut: 1n, recipient: ME })).toThrow(/upper bound/);
    expect(() => presets.orbio.buy({ usdgIn: 10n, minCreditOut: 0n, recipient: ME })).toThrow(/positive/);
  });
});

describe("Orbio: activation, which burns CREDIT for good", () => {
  it("activates for the agent, and refuses an activation that funds someone else", () => {
    const own = presets.orbio.activate({ amount: { lte: 25_000_000n } });
    expect(inspectTransaction(own, tx(ORBIO.credit, call("activate(uint256)", [25_000_000n]))).decision).toBe("allow");
    // The two-argument overload credits a beneficiary: another function than the intent's.
    expect(codes(inspectTransaction(own, tx(ORBIO.credit, call("activate(uint256,bytes32)", [25_000_000n, pad(OTHER)]))))).toEqual(["X402-702"]);
    const named = presets.orbio.activate({ amount: 25_000_000n, beneficiary: ME });
    expect(inspectTransaction(named, tx(ORBIO.credit, call("activate(uint256,bytes32)", [25_000_000n, pad(ME)]))).decision).toBe("allow");
    expect(codes(inspectTransaction(named, tx(ORBIO.credit, call("activate(uint256,bytes32)", [25_000_000n, pad(OTHER)]))))).toEqual(["X402-703"]);
  });

  it("holds buyAndActivate's beneficiary to the intent", () => {
    const intent = presets.orbio.buyAndActivate({ usdgIn: 25_000_000n, minCreditOut: 24_000_000n, beneficiary: ME });
    const SIG = "buyAndActivate(uint256,uint256,bytes32,uint256)";
    expect(inspectTransaction(intent, tx(ORBIO.exchange, call(SIG, [25_000_000n, 24_000_000n, pad(ME), 5n]))).decision).toBe("allow");
    expect(codes(inspectTransaction(intent, tx(ORBIO.exchange, call(SIG, [25_000_000n, 24_000_000n, pad(OTHER), 5n]))))).toEqual(["X402-703"]);
  });
});

describe("Orbio: bridging CREDIT through LayerZero", () => {
  const SEND = "send((uint32,bytes32,uint256,uint256,bytes,bytes,bytes),(uint256,uint256),address)";
  const send = (o: { eid?: number; to?: string; amount?: bigint; min?: bigint; options?: Hex; compose?: Hex; fee?: bigint }) =>
    call(SEND, [[o.eid ?? 30101, pad(o.to ?? ME), o.amount ?? 10_000_000n, o.min ?? 10_000_000n, o.options ?? "0x", o.compose ?? "0x", "0x"], [o.fee ?? 10n ** 14n, 0n], ME]);
  const intent = presets.orbio.bridge({ to: "ethereum", recipient: ME, amount: 10_000_000n, minAmount: 10_000_000n, nativeFee: { lte: 10n ** 15n }, refundAddress: ME });
  const adapter = ORBIO.bridges.ethereum.oft;

  it("allows the intended send to the agent's own address on Ethereum", () => {
    expect(inspectTransaction(intent, tx(adapter, send({}), 10n ** 14n)).decision).toBe("allow");
  });

  it("refuses another chain, recipient, a compose message, other executor options, or more fee", () => {
    expect(codes(inspectTransaction(intent, tx(adapter, send({ eid: 30168 }), 10n ** 14n)))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(intent, tx(adapter, send({ to: OTHER }), 10n ** 14n)))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(intent, tx(adapter, send({ compose: "0x01" }), 10n ** 14n)))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(intent, tx(adapter, send({ options: "0x0003" }), 10n ** 14n)))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(intent, tx(adapter, send({}), 2n * 10n ** 15n)))).toEqual(["X402-704"]);
    expect(codes(inspectTransaction(intent, tx(ORBIO.bridges.solana.oft, send({}), 10n ** 14n)))).toEqual(["X402-701"]);
  });
});

describe("a UniversalRouter swap that carries its own Permit2 allowance", () => {
  const USDG = ORBIO.usdg;
  const WORM = "0x5555555555555555555555555555555555555555";
  const poolKey = { currency0: USDG, currency1: WORM, fee: 19_000, tickSpacing: 60, hooks: "0x49d8000000000000000000000000000000aaec00" };
  const intent: TxIntent = presets.uniswapV4.swapExactInSingle({
    chainId: 4663,
    router: ROUTER,
    fields: 6,
    poolKey,
    zeroForOne: true,
    amountIn: 5_000_000n,
    minAmountOut: 1_000n,
    deadline: { lte: 2_000_000_000n },
    permit: { expiration: { lte: 1_900_000_000n }, sigDeadline: { lte: 1_800_000_000n } },
  });
  const PERMIT = parseAbiParameters("((address,uint160,uint48,uint48),address,uint256), bytes");
  const SWAP6 = parseAbiParameters("((address,address,uint24,int24,address),bool,uint128,uint128,uint256,bytes)");
  const build = (o: { spender?: string; permitAmount?: bigint; sig?: Hex; commands?: Hex } = {}) => {
    const permit = encodeAbiParameters(PERMIT, [[[USDG, o.permitAmount ?? 5_000_000n, 1_899_999_999, 0], (o.spender ?? ROUTER) as Hex, 1_799_999_999n], o.sig ?? (`0x${"ab".repeat(65)}` as Hex)] as never);
    const key = [poolKey.currency0, poolKey.currency1, poolKey.fee, poolKey.tickSpacing, poolKey.hooks];
    const swap = encodeAbiParameters(SWAP6, [[key, true, 5_000_000n, 1_000n, 0n, "0x"]] as never);
    const settle = encodeAbiParameters(parseAbiParameters("address, uint256"), [USDG as Hex, 5_000_000n]);
    const take = encodeAbiParameters(parseAbiParameters("address, uint256"), [WORM as Hex, 1_000n]);
    const v4 = encodeAbiParameters(parseAbiParameters("bytes, bytes[]"), ["0x060c0f", [swap, settle, take]]);
    return call("execute(bytes,bytes[],uint256)", [o.commands ?? "0x0a10", (o.commands ?? "0x0a10") === "0x10" ? [v4] : [permit, v4], 1_999_999_999n]);
  };

  it("allows the intended swap with its permit", () => {
    expect(inspectTransaction(intent, tx(ROUTER, build())).decision).toBe("allow");
  });

  it("refuses a permit to another spender, for another amount, with an odd signature, or a missing permit", () => {
    expect(codes(inspectTransaction(intent, tx(ROUTER, build({ spender: OTHER }))))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(intent, tx(ROUTER, build({ permitAmount: 10n ** 12n }))))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(intent, tx(ROUTER, build({ sig: `0x${"ab".repeat(97)}` as Hex }))))).toEqual(["X402-703"]);
    expect(inspectTransaction(intent, tx(ROUTER, build({ commands: "0x10" }))).decision).toBe("refuse");
  });

  it("will not add a permit to a native-coin swap, and reads a signature rule only on bytes", () => {
    expect(() =>
      presets.uniswapV4.swapExactInSingle({
        chainId: 4663, router: ROUTER, fields: 6, poolKey: { ...poolKey, currency0: "0x0000000000000000000000000000000000000000" }, zeroForOne: true,
        amountIn: 1n, minAmountOut: 1n, deadline: { lte: 1n }, permit: { expiration: { lte: 1n }, sigDeadline: { lte: 1n } },
      }),
    ).toThrow(/native coin/);
    const bad = { kind: "call", chainId: 4663, target: PERMIT2, signature: "lockdown((address,address)[])", args: [{ signature: true }] } as unknown as TxIntent;
    expect(codes(inspectTransaction(bad, tx(PERMIT2, "0x")))).toEqual(["X402-707"]);
  });
});

describe("Orbio's wallet-key line is signed only for Orbio", () => {
  const LINE = "Orbio API key · chain 4663 · epoch 0";

  it.each([["https://api.orbio.so"], ["https://www.orbio.so"], ["https://orbio.so/developers"]])("signs it for %s", (origin) => {
    expect(inspectSignIn({ message: LINE }, origin).decision).toBe("allow");
  });

  it.each([
    ["another site", "https://tools.example", "X402-601"],
    ["plain http", "http://api.orbio.so", "X402-601"],
    ["a name that only ends like it", "https://notorbio.so", "X402-601"],
    ["a name that only starts like it", "https://orbio.so.tools.example", "X402-601"],
  ])("refuses it for %s", (_name, origin, code) => {
    const v = inspectSignIn({ message: LINE }, origin);
    expect(v.decision).toBe("refuse");
    expect(v.findings[0]!.code).toBe(code);
  });

  it("refuses it with no site known, and with invisible characters inside", () => {
    expect(inspectSignIn({ message: LINE }, undefined).findings[0]!.code).toBe("X402-602");
    expect(inspectSignIn({ message: "Orb​io API key · chain 4663 · epoch 0" }, "https://tools.example").decision).toBe("refuse");
  });

  it("still holds a sign-in request that carries it to the request's own site", () => {
    const siwe = [
      "tools.example wants you to sign in with your Ethereum account:",
      ME,
      "",
      "Orbio API key · chain 4663 · epoch 0",
      "",
      "URI: https://tools.example",
      "Version: 1",
      "Chain ID: 4663",
      "Nonce: abcdef12",
      "Issued At: 2026-11-01T00:00:00Z",
    ].join("\n");
    expect(inspectSignIn({ message: siwe }, "https://api.orbio.so").findings[0]!.code).toBe("X402-601");
  });

  it("lets a guarded wallet make its Orbio key while talking to Orbio, and no one else's", async () => {
    const forOrbio = guardEvmSigner(account, () => null, { allow: ["signMessage"], origin: "https://api.orbio.so" });
    const sig = (await forOrbio.signMessage({ message: LINE })) as Hex;
    expect(await verifyMessage({ address: ME, message: LINE, signature: sig })).toBe(true);
    const elsewhere = guardEvmSigner(account, () => null, { allow: ["signMessage"], origin: "https://tools.example" });
    await expect(elsewhere.signMessage({ message: LINE })).rejects.toThrow(/X402-601.*Orbio wallet key/);
  });
});
