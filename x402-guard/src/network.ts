/**
 * x402 network-string parsing. Pure string work, zero dependencies.
 *
 * WHY THIS IS ITS OWN MODULE
 * ==========================
 * It used to live in ./evm, and ./sink imported it from there. That single
 * import dragged the entire EVM runtime -- and therefore `viem` -- into every
 * consumer of the package root, because ./index re-exports the sink.
 *
 * viem is an OPTIONAL peer dependency. The Solana path is supposed to work
 * without it. In practice a Solana-only install crashed at import:
 *
 *     Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'viem'
 *       imported from .../wormhole-x402/dist/evm.js
 *
 * Nothing here needs viem. It is a lookup table and a regex, so it belongs in
 * a leaf module that both ./evm and ./sink can depend on without either
 * depending on the other.
 */

/**
 * v1 bare network names -> chainId, for the pre-CAIP-2 envelope. Only names we
 * can pin to a specific chain are listed; anything else returns null and the
 * caller ABSTAINs (a network we cannot resolve is not one we can check a
 * domain against).
 */
const V1_NETWORK_CHAIN_IDS: Readonly<Record<string, number>> = {
  base: 8453,
  "base-sepolia": 84532,
  ethereum: 1,
  mainnet: 1,
  "ethereum-mainnet": 1,
  arbitrum: 42161,
  "arbitrum-one": 42161,
  polygon: 137,
  "polygon-mainnet": 137,
};

/**
 * Resolve an x402 network string to a chainId. Accepts CAIP-2 `eip155:<id>`
 * (v2) and the known bare v1 names. Returns null when it cannot be resolved,
 * which the verifier treats as ABSTAIN — never as a default chain.
 */
export function parseNetwork(network: unknown): number | null {
  if (typeof network !== "string") return null;
  const n = network.trim().toLowerCase();
  if (n.length === 0) return null;

  if (n.startsWith("eip155:")) {
    const idPart = n.slice("eip155:".length);
    if (!/^[0-9]+$/.test(idPart)) return null;
    const id = Number(idPart);
    if (!Number.isSafeInteger(id) || id <= 0) return null;
    return id;
  }

  if (Object.prototype.hasOwnProperty.call(V1_NETWORK_CHAIN_IDS, n)) {
    return V1_NETWORK_CHAIN_IDS[n];
  }
  return null;
}
