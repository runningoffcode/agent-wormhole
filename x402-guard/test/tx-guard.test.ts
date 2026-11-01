/**
 * guardEvmSigner signs a transaction only when it matches the caller's intent
 * (0.11.0), and signs exactly the transaction it checked.
 *
 * The signers here are viem's own, a local account and a wallet client with a
 * local transport, signing with a real key. Each test reads back what was
 * signed, so a check that passed one transaction while the wallet signed
 * another would show in the signed bytes.
 */

import { describe, it, expect } from "vitest";
import { createWalletClient, custom, encodeFunctionData, parseAbiItem, parseTransaction, recoverTransactionAddress, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import { guardEvmSigner, type TxIntent } from "../src/evm.js";

const account = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex);
const MERCHANT = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const transfer = (to: string, amount: bigint): Hex =>
  encodeFunctionData({ abi: [parseAbiItem("function transfer(address,uint256)")], functionName: "transfer", args: [to as Hex, amount] });

const pay: TxIntent = { kind: "erc20.transfer", chainId: 8453, token: USDC, to: MERCHANT, amount: { lte: 10_000_000n } };
const fees = { gas: 60_000n, maxFeePerGas: 10n ** 9n, maxPriorityFeePerGas: 1n, nonce: 0 };

/** A local account, as an agent holds one: signTransaction signs whatever it is handed. */
function localSigner() {
  const handed: unknown[] = [];
  return {
    handed,
    address: account.address,
    async signTransaction(tx: Record<string, unknown>) {
      handed.push(tx);
      return account.signTransaction(tx as never);
    },
  };
}

describe("signTransaction with an intent", () => {
  it("signs the intended transfer, for the intent's chain even when the transaction names none", async () => {
    const s = localSigner();
    const g = guardEvmSigner(s, () => null, { intentFor: () => pay });
    const raw = (await g.signTransaction({ to: USDC, data: transfer(MERCHANT, 5_000_000n), ...fees })) as Hex;
    const signed = parseTransaction(raw);
    expect(signed.chainId).toBe(8453);
    expect(signed.to?.toLowerCase()).toBe(USDC.toLowerCase());
    expect(signed.data).toBe(transfer(MERCHANT, 5_000_000n));
    expect(await recoverTransactionAddress({ serializedTransaction: raw as never })).toBe(account.address);
  });

  it("refuses a transfer to someone else without reaching the wallet", async () => {
    const s = localSigner();
    const g = guardEvmSigner(s, () => null, { intentFor: () => pay });
    await expect(g.signTransaction({ to: USDC, data: transfer(OTHER, 5_000_000n), ...fees })).rejects.toThrow(/X402-703/);
    await expect(g.signTransaction({ to: USDC, data: transfer(MERCHANT, 5_000_000n), chainId: 1, ...fees })).rejects.toThrow(/X402-701/);
    expect(s.handed).toEqual([]);
  });

  it("refuses as before without intentFor, and when it names no intent or throws", async () => {
    const tx = { to: USDC, data: transfer(MERCHANT, 1n), ...fees };
    await expect(guardEvmSigner(localSigner(), () => null).signTransaction(tx)).rejects.toThrow(/refusing/);
    await expect(guardEvmSigner(localSigner(), () => null, { intentFor: () => null }).signTransaction(tx)).rejects.toThrow(/named no intent/);
    await expect(
      guardEvmSigner(localSigner(), () => null, {
        intentFor: () => {
          throw new Error("no such market");
        },
      }).signTransaction(tx),
    ).rejects.toThrow(/intentFor threw \(no such market\)/);
  });

  it("asks intentFor with the transaction as read, frozen, and waits for an async answer", async () => {
    const s = localSigner();
    let seen: Readonly<Record<string, unknown>> | undefined;
    const g = guardEvmSigner(s, () => null, {
      intentFor: async (tx) => {
        seen = tx;
        return tx.to === USDC ? pay : null;
      },
    });
    await g.signTransaction({ to: USDC, data: transfer(MERCHANT, 1n), ...fees });
    expect(Object.isFrozen(seen)).toBe(true);
    expect(seen!.data).toBe(transfer(MERCHANT, 1n));
  });

  it("hands the wallet what it checked, not the caller's object read again", async () => {
    const s = localSigner();
    const g = guardEvmSigner(s, () => null, { intentFor: () => pay });
    let reads = 0;
    const tx = {
      get data() {
        reads++;
        return reads === 1 ? transfer(MERCHANT, 1n) : transfer(OTHER, 10n ** 12n);
      },
      to: USDC,
      ...fees,
    };
    const raw = (await g.signTransaction(tx)) as Hex;
    expect(parseTransaction(raw).data).toBe(transfer(MERCHANT, 1n));
    expect(reads).toBe(1);
    expect(s.handed[0]).not.toBe(tx);
  });
});

describe("the chain the signer is on", () => {
  it("refuses when the signer says it is on another chain, and signs when it agrees", async () => {
    const on = (id: number) => Object.assign(localSigner(), { getChainId: async () => id });
    const tx = { to: USDC, data: transfer(MERCHANT, 1n), ...fees };
    await expect(guardEvmSigner(on(1), () => null, { intentFor: () => pay }).signTransaction(tx)).rejects.toThrow(/X402-701.*another chain/);
    await expect(guardEvmSigner(on(8453), () => null, { intentFor: () => pay }).signTransaction(tx)).resolves.toMatch(/^0x02/);
  });

  it("reads an ethers signer's chain from its provider", async () => {
    const ethersLike = Object.assign(localSigner(), { provider: { getNetwork: async () => ({ chainId: 1n }) } });
    const tx = { to: USDC, data: transfer(MERCHANT, 1n), ...fees };
    await expect(guardEvmSigner(ethersLike, () => null, { intentFor: () => pay }).signTransaction(tx)).rejects.toThrow(/X402-701/);
  });
});

describe("sendTransaction through a viem wallet client", () => {
  /** A local node: answers what viem asks before sending, and keeps what is sent. */
  function node(chainId: number) {
    const sent: Hex[] = [];
    const transport = custom({
      async request({ method, params }: { method: string; params?: unknown }) {
        switch (method) {
          case "eth_chainId":
            return `0x${chainId.toString(16)}`;
          case "eth_getTransactionCount":
            return "0x0";
          case "eth_estimateGas":
            return "0xea60";
          case "eth_maxPriorityFeePerGas":
            return "0x1";
          case "eth_gasPrice":
            return "0x3b9aca00";
          case "eth_getBlockByNumber":
            return { number: "0x1", hash: `0x${"11".repeat(32)}`, timestamp: "0x1", baseFeePerGas: "0x1", gasLimit: "0x1c9c380", gasUsed: "0x0", transactions: [] };
          case "eth_sendRawTransaction":
            sent.push((params as Hex[])[0]!);
            return `0x${"22".repeat(32)}`;
          default:
            throw new Error(`unexpected ${method}`);
        }
      },
    });
    return { sent, client: createWalletClient({ account, chain: base, transport }) };
  }

  it("sends the intended transaction, signed for the intent's chain", async () => {
    const { sent, client } = node(8453);
    const g = guardEvmSigner(client, () => null, { intentFor: () => pay });
    await g.sendTransaction({ to: USDC, data: transfer(MERCHANT, 5_000_000n) } as never);
    expect(sent).toHaveLength(1);
    const tx = parseTransaction(sent[0]!);
    expect(tx.chainId).toBe(8453);
    expect(tx.data).toBe(transfer(MERCHANT, 5_000_000n));
  });

  it("refuses before signing when the client's node is on another chain", async () => {
    const { sent, client } = node(1);
    const g = guardEvmSigner(client, () => null, { intentFor: () => pay });
    await expect(g.sendTransaction({ to: USDC, data: transfer(MERCHANT, 5_000_000n) } as never)).rejects.toThrow(/X402-701/);
    expect(sent).toEqual([]);
  });

  it("refuses bytes viem would append after the checked calldata", async () => {
    const { sent, client } = node(8453);
    const g = guardEvmSigner(client, () => null, { intentFor: () => pay });
    await expect(g.sendTransaction({ to: USDC, data: transfer(MERCHANT, 1n), dataSuffix: "0xdeadbeef" } as never)).rejects.toThrow(/\(abstain\).*dataSuffix/);
    expect(sent).toEqual([]);
  });
});

describe("lifetime totals count transactions too", () => {
  it("holds each movement before signing and gives it back when the wallet fails", async () => {
    let fail = true;
    const s = {
      async signTransaction(tx: Record<string, unknown>) {
        if (fail) {
          fail = false;
          throw new Error("wallet locked");
        }
        return account.signTransaction(tx as never);
      },
    };
    const g = guardEvmSigner(s, () => null, { intentFor: () => pay, spendPolicy: { maxTotal: { [USDC]: 10_000_000n } } });
    const tx = (n: bigint) => ({ to: USDC, data: transfer(MERCHANT, n), ...fees });
    await expect(g.signTransaction(tx(6_000_000n))).rejects.toThrow(/wallet locked/);
    await expect(g.signTransaction(tx(6_000_000n))).resolves.toMatch(/^0x/);
    await expect(g.signTransaction(tx(4_000_000n))).resolves.toMatch(/^0x/);
    await expect(g.signTransaction(tx(1n))).rejects.toThrow(/X402-706.*X402-504/);
  });
});
