import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import {
  EIP3009, inspectAuthorization, inspectTypedDataRequest,
} from "../src/evm.js";

const account = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);
const domain = {
  name: "USD Coin", version: "2", chainId: 8453,
  verifyingContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const,
};
const message = {
  from: account.address,
  to: "0x1111111111111111111111111111111111111111" as const,
  value: 1_000_000n, validAfter: 100n, validBefore: 200n,
  nonce: `0x${"11".repeat(32)}` as `0x${string}`,
};
const request = {
  domain, types: EIP3009.TYPES, primaryType: EIP3009.PRIMARY_TYPE, message,
};
const quote = {
  network: "eip155:8453", asset: domain.verifyingContract,
  payTo: message.to, amount: "1000000",
};

// ERC-3009 requires validAfter < now < validBefore, with strict endpoints.
const cases = [
  { label: "before opening", now: 99n, skew: 0n, invalid: true },
  { label: "at opening", now: 100n, skew: 0n, invalid: true },
  { label: "after opening", now: 101n, skew: 0n, invalid: false },
  { label: "before expiry", now: 199n, skew: 0n, invalid: false },
  { label: "at expiry", now: 200n, skew: 0n, invalid: true },
  { label: "after expiry", now: 201n, skew: 0n, invalid: true },
  { label: "at opening with tolerance", now: 95n, skew: 5n, invalid: true },
  { label: "inside opening tolerance", now: 96n, skew: 5n, invalid: false },
  { label: "at expiry with tolerance", now: 205n, skew: 5n, invalid: true },
  { label: "inside expiry tolerance", now: 204n, skew: 5n, invalid: false },
];

describe.each(["signed", "unsigned"])("%s authorization window", (lane) => {
  it.each(cases)("$label", async ({ now, skew, invalid }) => {
    const opts = { nowSeconds: now, clockSkewSeconds: skew };
    const verdict = lane === "signed"
      ? await inspectAuthorization(quote, {
          signature: await account.signTypedData(request),
          assetTransferMethod: "eip3009",
          authorization: {
            ...message, value: String(message.value),
            validAfter: String(message.validAfter),
            validBefore: String(message.validBefore),
          },
        }, opts)
      : inspectTypedDataRequest(quote, request, opts);
    expect(verdict.findings.some((f) => f.code === "X402-105")).toBe(invalid);
    expect(verdict.decision).toBe(invalid && lane === "signed" ? "refuse" : "allow");
  });
});
