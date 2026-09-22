/**
 * Kite mainnet (chain 2366) bridged USDC, the token Kite documents for x402
 * settlement.
 *
 * The EIP-712 domain in TRUSTED_DOMAINS decides which signer is recovered, so
 * an entry taken from a document rather than the contract silently recovers
 * the wrong address. These values were read off the deployed contract over
 * RPC and the domain recomputed and compared to DOMAIN_SEPARATOR(); this test
 * pins the result so a later edit cannot quietly change what we recover
 * against.
 *
 * Offline by construction: the expected separator is a constant here, not a
 * live call. The package never reaches the network to verify a payment.
 */
import { describe, expect, it } from "vitest";
import { encodeAbiParameters, keccak256, parseAbiParameters, toHex } from "viem";
import { TRUSTED_DOMAINS } from "../src/evm.js";

const KITE_USDCE = "0x7ab6f3ed87c42ef0adb67ed95090f8bf5240149e";
const KITE_CHAIN = 2366n;

/** Read from the deployed contract on 2026-09-22 via rpc.gokite.ai. */
const ON_CHAIN_DOMAIN_SEPARATOR =
  "0x5d955afb663de40bd0780e115f3d5fa9ad612419f55c0c4a177f40b4f0f69a6d";

describe("Kite mainnet USDC.e domain", () => {
  const entry = TRUSTED_DOMAINS[`${KITE_CHAIN}:${KITE_USDCE}`];

  it("is present and marked verified", () => {
    expect(entry).toBeDefined();
    // `verified: false` makes the verifier abstain, so this flag is the
    // difference between checking a Kite payment and declining to.
    expect(entry?.verified).toBe(true);
  });

  it("carries the contract's own name, not the symbol or a guess", () => {
    // name() is "Bridged USDC (Kite AI)". It is NOT "USD Coin" (what every
    // other USDC entry here uses) and NOT "USDC.e" (the symbol). Either
    // substitution recovers a different signer and fails every honest payment.
    expect(entry?.name).toBe("Bridged USDC (Kite AI)");
    expect(entry?.version).toBe("2");
  });

  it("reproduces the deployed contract's DOMAIN_SEPARATOR", () => {
    // The real check: these two fields, this chain id and this address must
    // hash to what the contract reports. If they do not, the signer we recover
    // is not the signer who signed.
    const typeHash = keccak256(
      toHex(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
      ),
    );
    const computed = keccak256(
      encodeAbiParameters(
        parseAbiParameters("bytes32, bytes32, bytes32, uint256, address"),
        [
          typeHash,
          keccak256(toHex(entry!.name)),
          keccak256(toHex(entry!.version)),
          KITE_CHAIN,
          KITE_USDCE as `0x${string}`,
        ],
      ),
    );
    expect(computed).toBe(ON_CHAIN_DOMAIN_SEPARATOR);
  });

  it("has no Kite testnet entry, because there is no USDC.e to verify", () => {
    // Kite testnet (2368) carries PYUSD, not the bridged USDC it settles x402
    // with on mainnet. An unverified guess here would abstain anyway; leaving
    // it out says so honestly.
    const testnet = Object.keys(TRUSTED_DOMAINS).filter((k) => k.startsWith("2368:"));
    expect(testnet).toEqual([]);
  });
});
