/**
 * inspectTransaction holds a transaction to the agent's intent (0.11.0).
 *
 * Every transaction here is encoded with viem the way a counterparty would
 * hand it over, then changed in one place, so each refusal is tied to the one
 * difference that causes it.
 */

import { describe, it, expect } from "vitest";
import { encodeAbiParameters, encodeFunctionData, parseAbiItem, parseAbiParameters, type Hex } from "viem";
import { inspectTransaction, presets, NATIVE_ASSET, PERMIT2, type TxIntent } from "../src/tx.js";

const CHAIN = 8453;
const AGENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const MERCHANT = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MORPHO = "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb";
const ROUTER = "0x204FAca1764B154221e35c0d20aBb3c525710498";
const MAX = (1n << 256n) - 1n;

const fn = (sig: string) => parseAbiItem(`function ${sig}`);
const call = (sig: string, args: readonly unknown[]): Hex =>
  encodeFunctionData({ abi: [fn(sig)], functionName: fn(sig).name, args: args as unknown[] } as never);

const codes = (v: { findings: { code: string }[] }) => v.findings.map((f) => f.code);

describe("native transfers", () => {
  const intent: TxIntent = { kind: "native.transfer", chainId: CHAIN, to: MERCHANT, amount: { lte: 10n ** 16n } };

  it("allows the intended transfer, with or without a chainId on the transaction", () => {
    expect(inspectTransaction(intent, { to: MERCHANT, value: 10n ** 15n }).decision).toBe("allow");
    expect(inspectTransaction(intent, { to: MERCHANT, value: 10n ** 15n, chainId: CHAIN }).decision).toBe("allow");
  });

  it("refuses another recipient, more value, calldata, or another chain", () => {
    expect(codes(inspectTransaction(intent, { to: OTHER, value: 1n }))).toEqual(["X402-701"]);
    expect(codes(inspectTransaction(intent, { to: MERCHANT, value: 10n ** 16n + 1n }))).toEqual(["X402-704"]);
    expect(codes(inspectTransaction(intent, { to: MERCHANT, value: 1n, data: "0x00" }))).toEqual(["X402-702"]);
    expect(codes(inspectTransaction(intent, { to: MERCHANT, value: 1n, chainId: 1 }))).toEqual(["X402-701"]);
    expect(codes(inspectTransaction(intent, { to: MERCHANT, value: 1n, chain: { id: 1 } }))).toEqual(["X402-701"]);
  });

  it("reads value the ways signers accept it, and nothing else", () => {
    expect(inspectTransaction(intent, { to: MERCHANT, value: "0x38d7ea4c68000" }).decision).toBe("allow");
    expect(inspectTransaction(intent, { to: MERCHANT, value: { _isBigNumber: true, _hex: "0x38d7ea4c68000" } }).decision).toBe("allow");
    // ethers v5's BigNumber is a frozen class instance.
    class BigNumberLike {
      readonly _hex = "0x38d7ea4c68000";
      readonly _isBigNumber = true;
    }
    expect(inspectTransaction(intent, { to: MERCHANT, value: Object.freeze(new BigNumberLike()) }).decision).toBe("allow");
    expect(inspectTransaction(intent, { to: MERCHANT, value: "1e15" }).decision).toBe("abstain");
    expect(inspectTransaction(intent, { to: MERCHANT, value: -1 }).decision).toBe("abstain");
  });
});

describe("token transfers and approvals", () => {
  const transfer: TxIntent = { kind: "erc20.transfer", chainId: CHAIN, token: USDC, to: [MERCHANT, AGENT], amount: { lte: 5_000_000n } };

  it("allows a transfer to a listed recipient within the bound", () => {
    expect(inspectTransaction(transfer, { to: USDC, data: call("transfer(address,uint256)", [MERCHANT, 5_000_000n]) }).decision).toBe("allow");
    expect(inspectTransaction(transfer, { to: USDC, data: call("transfer(address,uint256)", [AGENT, 1n]) }).decision).toBe("allow");
  });

  it("refuses another recipient, a larger amount, another token, another function, or value", () => {
    const ok = call("transfer(address,uint256)", [MERCHANT, 1n]);
    expect(codes(inspectTransaction(transfer, { to: USDC, data: call("transfer(address,uint256)", [OTHER, 1n]) }))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(transfer, { to: USDC, data: call("transfer(address,uint256)", [MERCHANT, 5_000_001n]) }))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(transfer, { to: OTHER, data: ok }))).toEqual(["X402-701"]);
    expect(codes(inspectTransaction(transfer, { to: USDC, data: call("approve(address,uint256)", [MERCHANT, 1n]) }))).toEqual(["X402-702"]);
    expect(codes(inspectTransaction(transfer, { to: USDC, data: ok, value: 1n }))).toEqual(["X402-704"]);
  });

  it("holds an approval to its exact spender and amount, and an unlimited one to the word", () => {
    const exact: TxIntent = { kind: "erc20.approve", chainId: CHAIN, token: USDC, spender: PERMIT2, amount: 1_000_000n };
    expect(inspectTransaction(exact, { to: USDC, data: call("approve(address,uint256)", [PERMIT2, 1_000_000n]) }).decision).toBe("allow");
    expect(codes(inspectTransaction(exact, { to: USDC, data: call("approve(address,uint256)", [OTHER, 1_000_000n]) }))).toEqual(["X402-705"]);
    expect(codes(inspectTransaction(exact, { to: USDC, data: call("approve(address,uint256)", [PERMIT2, MAX]) }))).toEqual(["X402-705"]);
    const unlimited: TxIntent = { ...exact, amount: "unlimited" };
    expect(inspectTransaction(unlimited, { to: USDC, data: call("approve(address,uint256)", [PERMIT2, MAX]) }).decision).toBe("allow");
  });
});

describe("calls held argument by argument", () => {
  const market = {
    loanToken: USDC,
    collateralToken: "0x4200000000000000000000000000000000000006",
    oracle: "0x3333333333333333333333333333333333333333",
    irm: "0x4444444444444444444444444444444444444444",
    lltv: 860000000000000000n,
  };
  const borrow = presets.morpho.borrow({ chainId: CHAIN, morpho: MORPHO, market, assets: { lte: 100_000_000n }, onBehalf: AGENT, receiver: AGENT });
  const SIG = "borrow((address,address,address,address,uint256),uint256,uint256,address,address)";
  const tuple = [market.loanToken, market.collateralToken, market.oracle, market.irm, market.lltv];

  it("allows the intended Morpho borrow", () => {
    expect(inspectTransaction(borrow, { to: MORPHO, data: call(SIG, [tuple, 50_000_000n, 0n, AGENT, AGENT]) }).decision).toBe("allow");
  });

  it("refuses another receiver, more assets, shares, or another market", () => {
    const v = inspectTransaction(borrow, { to: MORPHO, data: call(SIG, [tuple, 50_000_000n, 0n, AGENT, OTHER]) });
    expect(codes(v)).toEqual(["X402-703"]);
    expect(v.findings[0]!.message).toMatch(/argument 5/);
    expect(codes(inspectTransaction(borrow, { to: MORPHO, data: call(SIG, [tuple, 100_000_001n, 0n, AGENT, AGENT]) }))).toEqual(["X402-703"]);
    expect(codes(inspectTransaction(borrow, { to: MORPHO, data: call(SIG, [tuple, 0n, 5n, AGENT, AGENT]) }))).toEqual(["X402-703"]);
    const riskier = [...tuple.slice(0, 4), 945000000000000000n];
    const m = inspectTransaction(borrow, { to: MORPHO, data: call(SIG, [riskier, 50_000_000n, 0n, AGENT, AGENT]) });
    expect(codes(m)).toEqual(["X402-703"]);
    expect(m.findings[0]!.message).toMatch(/argument 1 \(tuple\), component 5/);
  });

  it("abstains on calldata that decodes but is not its canonical encoding", () => {
    const data = call(SIG, [tuple, 50_000_000n, 0n, AGENT, AGENT]);
    expect(inspectTransaction(borrow, { to: MORPHO, data: `${data}00000000` }).decision).toBe("abstain");
    // A receiver word with non-zero high bytes still decodes to the same address in a lenient decoder.
    const dirty = `${data.slice(0, data.length - 64)}ff${data.slice(data.length - 62)}` as Hex;
    const v = inspectTransaction(borrow, { to: MORPHO, data: dirty });
    expect(v.decision).toBe("abstain");
    expect(codes(v)).toEqual(["X402-709"]);
  });

  it("names every argument it leaves open: any is written, never assumed", () => {
    const open = { kind: "call", chainId: CHAIN, target: MORPHO, signature: SIG, args: [{ any: true }, { any: true }, { any: true }, { any: true }] } as const;
    const v = inspectTransaction(open as unknown as TxIntent, { to: MORPHO, data: call(SIG, [tuple, 1n, 0n, AGENT, AGENT]) });
    expect(v.decision).toBe("abstain");
    expect(codes(v)).toEqual(["X402-707"]);
  });
});

describe("standing authority", () => {
  const approveAny: TxIntent = { kind: "call", chainId: CHAIN, target: USDC, signature: "approve(address,uint256)", args: [{ eq: ROUTER }, { lte: 10n ** 9n }] };

  it("refuses an approval whose terms the intent leaves loose", () => {
    const v = inspectTransaction(approveAny, { to: USDC, data: call("approve(address,uint256)", [ROUTER, 1n]) });
    expect(codes(v)).toEqual(["X402-705"]);
  });

  it("refuses an unlimited grant unless the intent says unlimited", () => {
    const exactMax: TxIntent = { kind: "call", chainId: CHAIN, target: USDC, signature: "approve(address,uint256)", args: [{ eq: ROUTER }, { eq: MAX }] };
    const data = call("approve(address,uint256)", [ROUTER, MAX]);
    expect(codes(inspectTransaction(exactMax, { to: USDC, data }))).toEqual(["X402-705"]);
    expect(inspectTransaction({ ...exactMax, unlimited: true }, { to: USDC, data }).decision).toBe("allow");
    const all: TxIntent = { kind: "call", chainId: CHAIN, target: USDC, signature: "setApprovalForAll(address,bool)", args: [{ eq: ROUTER }, { eq: true }] };
    expect(codes(inspectTransaction(all, { to: USDC, data: call("setApprovalForAll(address,bool)", [ROUTER, true]) }))).toEqual(["X402-705"]);
  });

  it("allows Permit2's approve with its terms exact and its expiration bounded", () => {
    const intent = presets.permit2.approve({ chainId: CHAIN, token: USDC, spender: ROUTER, amount: 1_000_000n, expiration: { lte: 2_000_000_000n } });
    const data = call("approve(address,address,uint160,uint48)", [USDC, ROUTER, 1_000_000n, 1_999_999_999]);
    expect(inspectTransaction(intent, { to: PERMIT2, data }).decision).toBe("allow");
    const later = call("approve(address,address,uint160,uint48)", [USDC, ROUTER, 1_000_000n, 2_000_000_001]);
    expect(codes(inspectTransaction(intent, { to: PERMIT2, data: later }))).toEqual(["X402-703"]);
    const open: TxIntent = { ...intent, args: [{ eq: USDC }, { eq: ROUTER }, { eq: 1_000_000n }, { any: true }] } as TxIntent;
    expect(codes(inspectTransaction(open, { to: PERMIT2, data }))).toEqual(["X402-705"]);
  });

  it("refuses an EIP-7702 delegation whatever the intent", () => {
    const intent: TxIntent = { kind: "native.transfer", chainId: CHAIN, to: MERCHANT, amount: 0n };
    const auth = [{ address: OTHER, chainId: CHAIN, nonce: 0, r: "0x01", s: "0x01", yParity: 0 }];
    expect(codes(inspectTransaction(intent, { to: MERCHANT, authorizationList: auth }))).toContain("X402-705");
    expect(codes(inspectTransaction(intent, { to: MERCHANT, type: "eip7702" }))).toContain("X402-705");
    expect(inspectTransaction(intent, { to: MERCHANT, authorizationList: [] }).decision).toBe("allow");
  });
});

describe("calls that carry other calls", () => {
  const inner = call("transfer(address,uint256)", [MERCHANT, 1n]);
  const SIG = "multicall(bytes[])";

  it("abstains when the intent leaves the inner calls open", () => {
    const intent: TxIntent = { kind: "call", chainId: CHAIN, target: ROUTER, signature: SIG, args: [{ any: true }] };
    const v = inspectTransaction(intent, { to: ROUTER, data: call(SIG, [[inner]]) });
    expect(v.decision).toBe("abstain");
    expect(codes(v)).toEqual(["X402-709"]);
  });

  it("allows them when the intent decodes and fixes each one", () => {
    const intent: TxIntent = {
      kind: "call",
      chainId: CHAIN,
      target: ROUTER,
      signature: SIG,
      args: [{ items: [{ eq: inner }] }],
    };
    expect(inspectTransaction(intent, { to: ROUTER, data: call(SIG, [[inner]]) }).decision).toBe("allow");
    expect(codes(inspectTransaction(intent, { to: ROUTER, data: call(SIG, [[inner, inner]]) }))).toEqual(["X402-703"]);
  });

  it("abstains on a Safe transaction that can choose a delegatecall", () => {
    const SAFE = "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)";
    const args = (op: number) => [USDC, 0n, inner, op, 0n, 0n, 0n, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", "0x"];
    const fixed = (op: unknown) => [{ eq: USDC }, { eq: 0 }, { eq: inner }, op, { eq: 0 }, { eq: 0 }, { eq: 0 }, { any: true }, { any: true }, { eq: "0x" }];
    const open = { kind: "call", chainId: CHAIN, target: OTHER, signature: SAFE, args: fixed({ any: true }) } as unknown as TxIntent;
    expect(inspectTransaction(open, { to: OTHER, data: call(SAFE, args(0)) }).decision).toBe("abstain");
    const delegate = { kind: "call", chainId: CHAIN, target: OTHER, signature: SAFE, args: fixed({ eq: 1 }) } as unknown as TxIntent;
    expect(inspectTransaction(delegate, { to: OTHER, data: call(SAFE, args(1)) }).decision).toBe("abstain");
    const plain = { kind: "call", chainId: CHAIN, target: OTHER, signature: SAFE, args: fixed({ eq: 0 }) } as unknown as TxIntent;
    expect(inspectTransaction(plain, { to: OTHER, data: call(SAFE, args(0)) }).decision).toBe("allow");
  });
});

describe("a Uniswap v4 swap through the UniversalRouter", () => {
  const WORM = "0x5555555555555555555555555555555555555555";
  const poolKey = { currency0: "0x0000000000000000000000000000000000000000", currency1: WORM, fee: 19_000, tickSpacing: 60, hooks: "0x49d8000000000000000000000000000000aaec00" };
  const DEADLINE = 2_000_000_000n;
  const SWAP6 = parseAbiParameters("((address,address,uint24,int24,address),bool,uint128,uint128,uint256,bytes)");
  const SWAP5 = parseAbiParameters("((address,address,uint24,int24,address),bool,uint128,uint128,bytes)");
  const key = [poolKey.currency0, poolKey.currency1, poolKey.fee, poolKey.tickSpacing, poolKey.hooks] as const;

  /** What a router client builds: V4_SWAP with SWAP_EXACT_IN_SINGLE, SETTLE_ALL and TAKE_ALL. */
  const build = (o: { amountIn: bigint; minOut: bigint; fields?: 5 | 6; actions?: Hex; extra?: Hex[]; currencyIn?: string; deadline?: bigint; fee?: number }) => {
    const k = [poolKey.currency0, poolKey.currency1, o.fee ?? poolKey.fee, poolKey.tickSpacing, poolKey.hooks] as const;
    const swap =
      (o.fields ?? 6) === 6
        ? encodeAbiParameters(SWAP6, [[k, true, o.amountIn, o.minOut, 0n, "0x"]] as never)
        : encodeAbiParameters(SWAP5, [[k, true, o.amountIn, o.minOut, "0x"]] as never);
    const settle = encodeAbiParameters(parseAbiParameters("address, uint256"), [(o.currencyIn ?? poolKey.currency0) as Hex, o.amountIn]);
    const take = encodeAbiParameters(parseAbiParameters("address, uint256"), [WORM, o.minOut]);
    const input = encodeAbiParameters(parseAbiParameters("bytes, bytes[]"), [o.actions ?? "0x060c0f", [swap, settle, take, ...(o.extra ?? [])]]);
    return call("execute(bytes,bytes[],uint256)", ["0x10", [input], o.deadline ?? DEADLINE - 1n]);
  };
  const intent = (fields: 5 | 6) =>
    presets.uniswapV4.swapExactInSingle({
      chainId: 4663,
      router: ROUTER,
      fields,
      poolKey,
      zeroForOne: true,
      amountIn: 10n ** 15n,
      minAmountOut: 1_000n,
      deadline: { lte: DEADLINE },
    });
  const tx = (data: Hex, value = 10n ** 15n) => ({ to: ROUTER, data, value, chainId: 4663 });

  it("allows the intended swap, with the value it spends", () => {
    expect(inspectTransaction(intent(6), tx(build({ amountIn: 10n ** 15n, minOut: 1_000n }))).decision).toBe("allow");
    expect(inspectTransaction(intent(5), tx(build({ amountIn: 10n ** 15n, minOut: 1_000n, fields: 5 }))).decision).toBe("allow");
  });

  it("refuses a lower floor, another pool, a later deadline, more value, or an extra action", () => {
    const r = (data: Hex, value?: bigint) => inspectTransaction(intent(6), tx(data, value));
    expect(codes(r(build({ amountIn: 10n ** 15n, minOut: 999n })))).toContain("X402-703");
    expect(codes(r(build({ amountIn: 10n ** 15n, minOut: 1_000n, fee: 3_000 })))).toEqual(["X402-703"]);
    expect(codes(r(build({ amountIn: 10n ** 15n, minOut: 1_000n, deadline: DEADLINE + 1n })))).toEqual(["X402-703"]);
    expect(codes(r(build({ amountIn: 10n ** 15n, minOut: 1_000n }), 2n * 10n ** 15n))).toEqual(["X402-704"]);
    const sweep = encodeAbiParameters(parseAbiParameters("address, address, uint256"), [WORM, OTHER, 0n]);
    const swept = r(build({ amountIn: 10n ** 15n, minOut: 1_000n, actions: "0x060c0f14", extra: [sweep] }));
    expect(swept.decision).toBe("refuse");
    expect(codes(swept)).toEqual(["X402-703", "X402-703"]);
  });

  it("does not read one router's layout as the other's", () => {
    for (const v of [
      inspectTransaction(intent(6), tx(build({ amountIn: 10n ** 15n, minOut: 1_000n, fields: 5 }))),
      inspectTransaction(intent(5), tx(build({ amountIn: 10n ** 15n, minOut: 1_000n }))),
    ]) {
      expect(v.decision).toBe("abstain");
      expect(codes(v)).toEqual(["X402-709"]);
    }
  });

  it("will not build a native-input swap without an exact amount", () => {
    expect(() =>
      presets.uniswapV4.swapExactInSingle({ chainId: 4663, router: ROUTER, fields: 6, poolKey, zeroForOne: true, amountIn: { lte: 10n }, minAmountOut: 1n, deadline: { lte: DEADLINE } }),
    ).toThrow(/exact/);
  });
});

describe("what the check cannot read, it does not allow", () => {
  const intent: TxIntent = { kind: "native.transfer", chainId: CHAIN, to: MERCHANT, amount: { lte: 10n } };

  it.each([
    ["a field it does not model", { to: MERCHANT, value: 1n, customData: { paymasterParams: {} } }],
    ["a dataSuffix viem would append", { to: MERCHANT, value: 1n, dataSuffix: "0xdeadbeef" }],
    ["blobs", { to: MERCHANT, value: 1n, blobs: ["0x00"] }],
    ["a name the signer would resolve", { to: "merchant.eth", value: 1n }],
    ["input that differs from data", { to: MERCHANT, value: 1n, input: "0x01" }],
    ["a class instance", Object.assign(Object.create({ to: MERCHANT }), { value: 1n })],
  ])("abstains on %s", (_name, tx) => {
    expect(inspectTransaction(intent, tx).decision).toBe("abstain");
  });

  it("refuses a contract creation", () => {
    expect(codes(inspectTransaction(intent, { value: 1n, data: "0x60" }))).toContain("X402-701");
  });

  it.each([
    ["an unknown key", { ...intent, note: "x" }],
    ["a bad address", { ...intent, to: "0x123" }],
    ["a bound on an address", { kind: "call", chainId: CHAIN, target: USDC, signature: "transfer(address,uint256)", args: [{ lte: 5 }, { any: true }] }],
    ["an empty constraint", { kind: "call", chainId: CHAIN, target: USDC, signature: "transfer(address,uint256)", args: [{}, { any: true }] }],
    ["a constraint with two rules", { kind: "call", chainId: CHAIN, target: USDC, signature: "transfer(address,uint256)", args: [{ eq: MERCHANT, any: true }, { any: true }] }],
    ["an empty range", { kind: "native.transfer", chainId: CHAIN, to: MERCHANT, amount: { lte: 1, gte: 2 } }],
    ["a symbol key", { ...intent, [Symbol("rule")]: 1 }],
    ["no chain", { kind: "native.transfer", to: MERCHANT, amount: 1 }],
  ])("abstains on an intent with %s", (_name, bad) => {
    const v = inspectTransaction(bad as unknown as TxIntent, { to: MERCHANT, value: 1n });
    expect(v.decision).toBe("abstain");
    expect(codes(v)).toEqual(["X402-707"]);
  });
});

describe("the spending policy on the movements it can read", () => {
  const transfer: TxIntent = { kind: "erc20.transfer", chainId: CHAIN, token: USDC, to: MERCHANT, amount: { lte: 10n ** 9n } };
  const data = call("transfer(address,uint256)", [MERCHANT, 5_000_000n]);

  it("refuses a transfer over the per-payment cap, and allows one within it", () => {
    expect(codes(inspectTransaction(transfer, { to: USDC, data }, { spendPolicy: { maxPerPayment: { [USDC]: 1_000_000n } } }))).toEqual(["X402-706"]);
    expect(inspectTransaction(transfer, { to: USDC, data }, { spendPolicy: { maxPerPayment: { [USDC]: 5_000_000n } } }).decision).toBe("allow");
  });

  it("refuses native value the policy does not name, and allows it named as the native asset", () => {
    const pay: TxIntent = { kind: "native.transfer", chainId: CHAIN, to: MERCHANT, amount: { lte: 10n ** 18n } };
    expect(codes(inspectTransaction(pay, { to: MERCHANT, value: 10n }, { spendPolicy: { assets: [USDC] } }))).toEqual(["X402-706"]);
    expect(inspectTransaction(pay, { to: MERCHANT, value: 10n }, { spendPolicy: { assets: [USDC, NATIVE_ASSET] } }).decision).toBe("allow");
  });

  it("holds an approval's allowance to the cap, and abstains on a policy it cannot read", () => {
    const approve: TxIntent = { kind: "erc20.approve", chainId: CHAIN, token: USDC, spender: PERMIT2, amount: "unlimited" };
    const unlimited = call("approve(address,uint256)", [PERMIT2, MAX]);
    expect(codes(inspectTransaction(approve, { to: USDC, data: unlimited }, { spendPolicy: { maxPerPayment: { [USDC]: 10n ** 9n } } }))).toEqual(["X402-706"]);
    expect(inspectTransaction(transfer, { to: USDC, data }, { spendPolicy: { maxPerPaymnet: {} } as never }).decision).toBe("abstain");
  });
});
