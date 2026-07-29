/**
 * wormhole-x402/evm — EIP-3009 authorization guard, end to end.
 *
 * Signs REAL EIP-712 TransferWithAuthorization messages with viem and puts
 * them through inspectAuthorization(): one that conforms to the quote, one
 * redirected to an attacker, one with an inflated value, and one on a chain
 * the trusted-domain table does not cover.
 *
 * Everything is offline. Signature recovery is pure computation — no RPC, no
 * chain reads. The private key below is a well-known throwaway test key from
 * viem's own docs; it holds nothing and must never be used for anything.
 */

import { privateKeyToAccount } from "viem/accounts";
import { inspectAuthorization, TRUSTED_DOMAINS, parseNetwork, EIP3009 } from "wormhole-x402/evm";

// viem's canonical test account. Public, funded on nothing, safe to publish.
const PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const payer = privateKeyToAccount(PRIVATE_KEY);

const MERCHANT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const ATTACKER = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

// Base mainnet USDC — chainId 8453. This pair MUST be in TRUSTED_DOMAINS or
// the guard abstains, which is the whole point of case 4.
const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const OPTIMISM_USDC = "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85";

/**
 * The quote from the merchant's 402 response. `extra.assetTransferMethod`
 * declares the scheme; the server quote is authoritative and a payload that
 * contradicts it is refused outright (X402-103).
 */
const quote = {
  network: "base",
  asset: BASE_USDC,
  payTo: MERCHANT,
  amount: "1000000", // 1.000000 USDC
  extra: { assetTransferMethod: "eip3009" },
};

const NONCE = "0x" + "11".repeat(32);

// Fixed clock so validAfter/validBefore and the printed output are stable.
const NOW = 1_800_000_000n;

/**
 * Build and actually SIGN an EIP-3009 authorization.
 *
 * The domain must match what the guard will use, and the guard builds its
 * domain FROM ITS OWN TABLE, never from the quote. For Base USDC that is
 * name "USD Coin", version "2" — sign with anything else and recovery yields
 * a different address, which surfaces as X402-104 rather than a silent pass.
 */
async function signAuthorization({ to, value, asset = BASE_USDC, chainId = 8453 }) {
  const authorization = {
    from: payer.address,
    to,
    value,
    validAfter: 0n,
    validBefore: NOW + 3600n,
    nonce: NONCE,
  };

  const entry = TRUSTED_DOMAINS[`${chainId}:${asset.toLowerCase()}`];
  const signature = await payer.signTypedData({
    domain: {
      // Fall back to the mainnet USDC names for the untrusted-chain case so
      // the signature itself is well-formed; the guard should abstain on the
      // domain lookup, not on a malformed signature.
      name: entry?.name ?? "USD Coin",
      version: entry?.version ?? "2",
      chainId,
      verifyingContract: asset,
    },
    types: EIP3009.TYPES,
    primaryType: EIP3009.PRIMARY_TYPE,
    message: authorization,
  });

  return { authorization, signature, assetTransferMethod: "eip3009" };
}

function show(title, note) {
  console.log("\n" + "=".repeat(72));
  console.log(title);
  if (note) console.log(note);
  console.log("=".repeat(72));
}

/** inspectAuthorization is ASYNC — it must be awaited. */
async function check(q, payload) {
  const verdict = await inspectAuthorization(q, payload, { nowSeconds: NOW });
  console.log(JSON.stringify(verdict, null, 2));
  return verdict;
}

console.log("payer (signer)", payer.address);
console.log("merchant      ", MERCHANT);
console.log("attacker      ", ATTACKER);
console.log("quote         ", JSON.stringify({ ...quote }));
console.log("parseNetwork('base') ->", parseNetwork("base"));

// =========================================================================
// 1. Conforming authorization — ALLOW
// =========================================================================
show(
  "1. Conforming authorization — expect ALLOW",
  "Pays the quoted merchant the quoted amount, signed by the payer.",
);
await check(quote, await signAuthorization({ to: MERCHANT, value: 1_000_000n }));

// =========================================================================
// 2. Redirected payee — REFUSE X402-101
// =========================================================================
show(
  "2. Redirected payee — expect REFUSE X402-101",
  "A validly signed authorization for the right amount, to the wrong address.\n" +
    "The signature is genuine — the payer really did sign this — so signature\n" +
    "checking alone would pass it. Only comparison against the quote catches it.",
);
await check(quote, await signAuthorization({ to: ATTACKER, value: 1_000_000n }));

// =========================================================================
// 3. Inflated amount — REFUSE X402-102
// =========================================================================
show(
  "3. Inflated amount — expect REFUSE X402-102",
  "Right merchant, but 1000 USDC instead of the quoted 1.",
);
await check(quote, await signAuthorization({ to: MERCHANT, value: 1_000_000_000n }));

// =========================================================================
// 4. Chain/asset outside the trusted-domain table — ABSTAIN
// =========================================================================
show(
  "4. Optimism USDC — expect ABSTAIN, not allow and not refuse",
  "Optimism is a real chain and this is real USDC, but the pair is not in the\n" +
    "5-entry trusted-domain table, so there is no confirmed (name, version) to\n" +
    "recover against. Recovering against a guessed domain would produce a\n" +
    "confident wrong answer, so the guard declines to answer at all.\n" +
    "ABSTAIN IS NOT AN ALL-CLEAR. Nothing was verified. Do not treat it as a pass.",
);
await check(
  { ...quote, network: "eip155:10", asset: OPTIMISM_USDC },
  await signAuthorization({
    to: MERCHANT,
    value: 1_000_000n,
    asset: OPTIMISM_USDC,
    chainId: 10,
  }),
);

console.log("\ntrusted domains (the complete table):");
for (const key of Object.keys(TRUSTED_DOMAINS)) {
  console.log("  ", key, "->", TRUSTED_DOMAINS[key].label);
}
console.log("\nDone. No network calls were made.");
