/**
 * wormhole-x402/evm — refuse an EVM x402 payment authorization that does not
 * match what the agent was quoted. Offline, no RPC.
 *
 * The Solana core (./index) answers "is this the transaction that was asked
 * for?" by walking a serialized transaction. On EVM the `exact` scheme ships
 * no transaction at all: the client signs a typed-data authorization (EIP-3009
 * TransferWithAuthorization) and the facilitator submits it. So the object to
 * check is a signature over structured fields, and the check is the same in
 * spirit — recover the signer, compare (to, value, chain, validity window)
 * against the server's quote, and refuse anything that does not match.
 *
 * THE THREAT THAT SHAPES THIS FILE. Base USDC implements *both* EIP-3009 and
 * EIP-2612. A malicious unbounded `Permit(value=max)` and a legitimate
 * `TransferWithAuthorization` validate against the *identical* EIP-712 domain.
 * A domain check alone cannot tell them apart. The only offline discriminator
 * is the primaryType / typehash of what was signed. This build therefore
 * ALLOWLISTS exactly one primary type — TransferWithAuthorization — and treats
 * every other shape as either a standing-authority grant to REFUSE or an
 * unknown to ABSTAIN on. Never allow on doubt.
 *
 * SCOPE (Steps 1+2). EIP-3009 full verification, signature hygiene, EIP-2612 /
 * Permit2 / approve standing-authority detection (refuse path), erc7710
 * abstain, and structural/session-only replay checks. Positive verification of
 * a *scoped* Permit2 PermitWitnessTransferFrom is deferred — such payloads
 * abstain loudly (and flag X402-106 if they carry standing-authority shape)
 * rather than being green-lit.
 *
 * This file deliberately re-declares the Verdict / Finding / Decision shapes
 * rather than importing them from ./index, so that importing `wormhole-x402/evm`
 * pulls in viem only and never the Solana runtime. The shapes are kept
 * structurally identical to ./index on purpose.
 */

import {
  recoverTypedDataAddress,
  isAddress,
  getAddress,
  keccak256,
  toBytes,
  type Hex,
} from "viem";

// --- verdict shapes (structurally identical to ./index) --------------------

export type Decision = "allow" | "refuse" | "abstain";

export interface Finding {
  code: string;
  severity: "critical" | "high" | "medium";
  message: string;
  expected?: string;
  actual?: string;
}

export interface Verdict {
  decision: Decision;
  findings: Finding[];
  /** Why an abstain happened, so it is never mistaken for an allow. */
  reason?: string;
}

// --- the quote, parsed from the server's 402 response ----------------------

/**
 * The EVM quote. Never agent-authored: it arrives as structured JSON in the
 * server's 402 `accepts` entry, on a channel separate from the model's
 * context. `network` is the raw x402 network string (`eip155:8453` in v2, or a
 * bare name like `base` in v1); it is resolved to a chainId here.
 */
export interface EvmPaymentQuote {
  /** Server-declared network: `eip155:<id>` (v2) or a bare v1 name. */
  network: string;
  /** Token contract address (the ERC-20 the EIP-3009 authorization targets). */
  asset: string;
  /** Address the server says to pay (the authorization's `to`). */
  payTo: string;
  /** Exact amount in the token's base units, as a decimal string. */
  amount: string;
}

// --- EIP-3009 constants ----------------------------------------------------

/**
 * The one primary type this build allows, its typehash, and the sibling
 * ReceiveWithAuthorization typehash (recognized only to REFUSE — it binds the
 * caller to msg.sender and is not the `exact` scheme's transfer). Both
 * typehashes independently re-derived with keccak256 and asserted at module
 * load; a wrong typehash here is a live vulnerability.
 */
export const EIP3009 = {
  /** keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)") */
  TRANSFER_WITH_AUTHORIZATION_TYPEHASH:
    "0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267" as Hex,
  /** keccak256("ReceiveWithAuthorization(...)") — same fields, different binding. */
  RECEIVE_WITH_AUTHORIZATION_TYPEHASH:
    "0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8" as Hex,
  PRIMARY_TYPE: "TransferWithAuthorization" as const,
  /**
   * The EIP-712 field layout viem needs. EIP712Domain is intentionally NOT
   * listed — viem derives it from the domain object. Listing it would change
   * the struct hash and break recovery.
   */
  TYPES: {
    TransferWithAuthorization: [
      { name: "from", type: "address" },
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" },
      { name: "validBefore", type: "uint256" },
      { name: "nonce", type: "bytes32" },
    ],
  } as const,
} as const;

// A load-time self-check: if viem ever disagrees with the constant above, fail
// loudly at import rather than silently recover against the wrong struct.
{
  const derived = keccak256(
    toBytes(
      "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
    ),
  );
  if (
    derived.toLowerCase() !==
    EIP3009.TRANSFER_WITH_AUTHORIZATION_TYPEHASH.toLowerCase()
  ) {
    throw new Error(
      "wormhole-x402/evm: TransferWithAuthorization typehash mismatch — refusing to load with an incorrect struct definition",
    );
  }
}

// secp256k1 curve order and its halfway point (the low-s bound, EIP-2).
const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_N_HALF = SECP256K1_N >> 1n;

// --- the trusted domain table ----------------------------------------------

export interface DomainEntry {
  /** EIP-712 domain `name`. */
  name: string;
  /** EIP-712 domain `version`. */
  version: string;
  /** Human label for messages. */
  label: string;
  /**
   * true only when name/version were confirmed against the deployed contract's
   * DOMAIN_SEPARATOR / name()/version() getters. A false here means the entry
   * is a best-guess and the verifier should ABSTAIN rather than trust it.
   */
  verified: boolean;
}

/**
 * The trusted (chainId, verifyingContract) -> EIP-712 domain table.
 *
 * The domain name/version used to recover the signer MUST come from here and
 * NEVER from the quote's `extra.name`/`extra.version`, which are
 * attacker-influenceable. Any (chainId, asset) not present -> ABSTAIN. An
 * entry present but `verified: false` -> ABSTAIN (we will not recover against
 * an unconfirmed domain).
 *
 * Keys are `${chainId}:${lowercased contract}`.
 */
export const TRUSTED_DOMAINS: Readonly<Record<string, DomainEntry>> = {
  // Base mainnet USDC. On-chain verified: name() = "USD Coin", version = "2".
  // (The x402 spec example wrongly says name "USDC" for this contract.)
  "8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": {
    name: "USD Coin",
    version: "2",
    label: "Base USDC",
    verified: true,
  },

  // Ethereum mainnet USDC (Circle). name() = "USD Coin", version() = "2".
  // On-chain verified against the FiatTokenV2_1 proxy getters.
  "1:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {
    name: "USD Coin",
    version: "2",
    label: "Ethereum USDC",
    verified: true,
  },

  // Arbitrum One native USDC (Circle). name() = "USD Coin", version() = "2".
  "42161:0xaf88d065e77c8cc2239327c5edb3a432268e5831": {
    name: "USD Coin",
    version: "2",
    label: "Arbitrum USDC",
    verified: true,
  },

  // Polygon PoS native USDC (Circle, "USDC" not bridged "USDC.e").
  // name() = "USD Coin", version() = "2". On-chain verified.
  "137:0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": {
    name: "USD Coin",
    version: "2",
    label: "Polygon USDC",
    verified: true,
  },

  // Base Sepolia testnet USDC (Circle test token). The deployed test token's
  // name() is "USDC" (NOT "USD Coin") and version "2" — confirmed against the
  // testnet contract getters. Kept as a distinct entry precisely because the
  // testnet name differs from mainnet; using the mainnet "USD Coin" here would
  // recover the wrong signer and could false-refuse a legitimate testnet
  // payment (or, worse, be worked around by an attacker).
  "84532:0x036cbd53842c5426634e7929541ec2318f3dcf7e": {
    name: "USDC",
    version: "2",
    label: "Base Sepolia USDC",
    verified: true,
  },
} as const;

// --- network parsing -------------------------------------------------------

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

// --- envelope types (shape only; every field is validated before use) ------

export interface EvmAcceptedEntry {
  scheme?: unknown;
  network?: unknown;
  amount?: unknown;
  asset?: unknown;
  payTo?: unknown;
  maxAmountRequired?: unknown;
  maxTimeoutSeconds?: unknown;
  extra?: {
    assetTransferMethod?: unknown;
    name?: unknown;
    version?: unknown;
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

export interface EvmAuthorization {
  from?: unknown;
  to?: unknown;
  value?: unknown;
  validAfter?: unknown;
  validBefore?: unknown;
  nonce?: unknown;
}

export interface EvmPayload {
  signature?: unknown;
  authorization?: EvmAuthorization;
  /** Present on Permit2 / permit-style payloads; used only for X402-106 shape. */
  permit?: unknown;
  primaryType?: unknown;
  [k: string]: unknown;
}

export interface InspectAuthorizationOptions {
  /**
   * A caller-owned set of nonces seen this session. If supplied, a nonce
   * already in it produces X402-107 (structural/session replay only — NOT
   * on-chain replay protection, which needs RPC). The verifier adds the nonce
   * to the set on a well-formed authorization.
   */
  seenNonces?: Set<string>;
  /**
   * Clock for the validity-window check, unix seconds. Defaults to now. Lets
   * tests pin time deterministically.
   */
  nowSeconds?: bigint;
  /**
   * Slack in seconds allowed on the validity window before X402-105 fires, to
   * absorb clock skew between the agent and the facilitator. Default 0.
   */
  clockSkewSeconds?: bigint;
}

// --- small parse helpers ---------------------------------------------------

function abstain(reason: string, findings: Finding[] = []): Verdict {
  return { decision: "abstain", findings, reason };
}

/** A uint256-ish value: decimal string, 0x-hex string, number, or bigint. */
function toBig(v: unknown): bigint | null {
  try {
    if (typeof v === "bigint") return v;
    if (typeof v === "number") {
      if (!Number.isSafeInteger(v) || v < 0) return null;
      return BigInt(v);
    }
    if (typeof v === "string") {
      const s = v.trim();
      if (s.length === 0) return null;
      if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
      if (/^[0-9]+$/.test(s)) return BigInt(s);
      return null;
    }
    return null;
  } catch {
    return null;
  }
}

/** Normalize an address to checksum form, or null if not a valid address. */
function normAddress(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!isAddress(s)) return null;
  try {
    return getAddress(s);
  } catch {
    return null;
  }
}

function isHexString(v: unknown): v is Hex {
  return typeof v === "string" && /^0x[0-9a-fA-F]*$/.test(v);
}

// --- signature hygiene -----------------------------------------------------

interface NormalizedSig {
  sig: Hex;
  r: bigint;
  s: bigint;
  v: number;
}

/**
 * Accept a 65-byte r||s||v signature or a 64-byte EIP-2098 compact signature;
 * expand the compact form; enforce low-s (s <= n/2) and canonical v (27/28).
 * Any malformed length or non-canonical field returns null -> the caller
 * ABSTAINs (a signature we cannot canonicalize is not one to recover from).
 */
function normalizeSignature(raw: unknown): NormalizedSig | null {
  if (!isHexString(raw)) return null;
  let hex = raw.slice(2);
  if (hex.length % 2 !== 0) return null;
  const bytes = hex.length / 2;

  let r: bigint;
  let s: bigint;
  let v: number;

  if (bytes === 65) {
    r = BigInt("0x" + hex.slice(0, 64));
    s = BigInt("0x" + hex.slice(64, 128));
    v = parseInt(hex.slice(128, 130), 16);
    if (v === 0 || v === 1) v += 27;
  } else if (bytes === 64) {
    // EIP-2098 compact: r (32) || yParityAndS (32). The top bit of the second
    // word is the y-parity; the rest is s.
    r = BigInt("0x" + hex.slice(0, 64));
    const yParityAndS = BigInt("0x" + hex.slice(64, 128));
    const yParity = (yParityAndS >> 255n) & 1n;
    s = yParityAndS & ((1n << 255n) - 1n);
    v = 27 + Number(yParity);
  } else {
    return null;
  }

  if (v !== 27 && v !== 28) return null;
  if (r === 0n || r >= SECP256K1_N) return null;
  if (s === 0n || s >= SECP256K1_N) return null;
  // Low-s: reject the malleable high-s counterpart outright.
  if (s > SECP256K1_N_HALF) return null;

  const rHex = r.toString(16).padStart(64, "0");
  const sHex = s.toString(16).padStart(64, "0");
  const vHex = v.toString(16).padStart(2, "0");
  return { sig: ("0x" + rHex + sHex + vHex) as Hex, r, s, v };
}

// --- standing-authority (X402-106) shape detection -------------------------

const STANDING_AUTHORITY_TYPES = new Set([
  // EIP-2612 — an unbounded Permit is a blanket allowance, not a payment.
  "permit",
  // Permit2 AllowanceTransfer family.
  "permitsingle",
  "permitbatch",
  "permitdetails",
  "tokenpermissions",
  // Permit2 witness-less transfer (no scoping witness) — blanket.
  "permittransferfrom",
  "permitbatchtransferfrom",
  // ERC-20 raw grants (if ever surfaced as a typed shape).
  "approve",
  "increaseallowance",
  "setapprovalforall",
]);

/**
 * Classify by STANDING AUTHORITY, not by "is it Permit2". Returns a finding
 * when the payload carries a shape that grants ongoing spend authority rather
 * than moving a single, quote-bound amount. A *scoped* Permit2
 * PermitWitnessTransferFrom is NOT flagged here — but this build does not
 * positively verify it either (out of scope), so the caller still ABSTAINs on
 * any permit-family payload it did not allow via EIP-3009.
 */
function detectStandingAuthority(
  payload: EvmPayload,
  method: string | null,
): Finding | null {
  const pt =
    typeof payload.primaryType === "string"
      ? payload.primaryType.trim().toLowerCase()
      : null;

  // A scoped witness transfer is the one permit shape that is a real payment.
  if (pt === "permitwitnesstransferfrom") return null;

  if (pt && STANDING_AUTHORITY_TYPES.has(pt)) {
    return {
      code: "X402-106",
      severity: "critical",
      message:
        `payload signs "${payload.primaryType}", a standing-authority grant — ` +
        "it hands over ongoing spend authority rather than moving the quoted amount",
      actual: String(payload.primaryType),
    };
  }

  // EIP-2612 Permit with value === max uint256 is the canonical unbounded
  // allowance disguised as a one-off — flag even without an explicit type.
  const permit = payload.permit as { value?: unknown; amount?: unknown } | undefined;
  if (permit && typeof permit === "object") {
    const val = toBig(permit.value) ?? toBig(permit.amount);
    const MAX_UINT256 = (1n << 256n) - 1n;
    if (val !== null && val === MAX_UINT256) {
      return {
        code: "X402-106",
        severity: "critical",
        message:
          "payload carries an unbounded (max uint256) permit value — a blanket allowance, not a payment",
        actual: "value = 2^256 - 1",
      };
    }
  }

  return null;
}

// --- the verifier ----------------------------------------------------------

/**
 * Verify an x402 EVM `exact` EIP-3009 authorization against the quote.
 *
 * Fail-closed by construction. The only path to `allow` is: a resolvable
 * network with a `verified` domain in the trusted table, an `eip3009` transfer
 * method, a well-formed low-s signature, a recovered signer that equals
 * `authorization.from`, and destination/value/validity all matching the quote.
 * Every other outcome is `refuse` (a positive mismatch we understand) or
 * `abstain` (something we could not fully check). Nothing is ever allowed on
 * doubt.
 */
export async function inspectAuthorization(
  quote: EvmPaymentQuote,
  payload: EvmPayload | unknown,
  opts: InspectAuthorizationOptions = {},
): Promise<Verdict> {
  const findings: Finding[] = [];

  // --- 0. parse the quote --------------------------------------------------
  if (typeof quote !== "object" || quote === null) {
    return abstain("quote is not an object — nothing to check against");
  }
  const chainId = parseNetwork(quote.network);
  if (chainId === null) {
    return abstain(
      `quote network (${String(
        (quote as EvmPaymentQuote).network,
      )}) could not be resolved to a chainId — refusing to report the payment as checked`,
    );
  }
  const quoteAsset = normAddress(quote.asset);
  if (quoteAsset === null) {
    return abstain("quote asset is not a valid address");
  }
  const quotePayTo = normAddress(quote.payTo);
  if (quotePayTo === null) {
    return abstain("quote payTo is not a valid address");
  }
  const quotedValue = toBig(quote.amount);
  if (quotedValue === null) {
    return abstain(
      `quote amount is not an integer (${String(
        quote.amount,
      )}) — refusing to report the payment as checked`,
    );
  }

  // --- 1. parse the payload envelope --------------------------------------
  if (typeof payload !== "object" || payload === null) {
    return abstain("payment payload is not an object");
  }
  const p = payload as EvmPayload;

  // Determine the asset-transfer method. The SERVER QUOTE's `extra` is the
  // authoritative source — it arrives on the trusted 402 channel the model
  // never touches. The payload's self-declared method is attacker-adjacent and
  // must NOT be able to steer verification into a more permissive branch, so
  // the quote wins whenever it declares a method. The payload method is used
  // only as a fallback when the quote is silent, and a payload that CONTRADICTS
  // a quote-declared method is refused outright — a conforming client never
  // disagrees with the server about which scheme it is paying under.
  const quoteExtra = (quote as unknown as { extra?: EvmAcceptedEntry["extra"] })
    .extra as EvmAcceptedEntry["extra"] | undefined;
  const quoteMethod =
    typeof quoteExtra?.assetTransferMethod === "string"
      ? quoteExtra.assetTransferMethod.trim().toLowerCase()
      : null;
  const payloadMethod =
    typeof (p as { assetTransferMethod?: unknown }).assetTransferMethod ===
    "string"
      ? ((p as { assetTransferMethod?: unknown }).assetTransferMethod as string)
          .trim()
          .toLowerCase()
      : null;
  if (quoteMethod && payloadMethod && quoteMethod !== payloadMethod) {
    return {
      decision: "refuse",
      findings: [
        {
          code: "X402-103",
          severity: "critical",
          message:
            "payload declares a different asset-transfer method than the server quote — a conforming client does not disagree with the server about the payment scheme",
          expected: quoteMethod,
          actual: payloadMethod,
        },
      ],
    };
  }
  const method = quoteMethod ?? payloadMethod;

  // --- 1a. erc7710 -> ABSTAIN (X402-110) ----------------------------------
  // A redelegatable permissionContext is opaque: there is no offline
  // destination+amount to compare. Do not attempt to allow it.
  if (method === "erc7710") {
    return abstain(
      "assetTransferMethod is erc7710 — the redelegatable permissionContext is opaque and carries no offline destination or amount to check",
      [
        {
          code: "X402-110",
          severity: "high",
          message:
            "erc7710 authorization cannot be verified offline (opaque permissionContext)",
          actual: "erc7710",
        },
      ],
    );
  }

  // --- 1b. standing-authority shapes -> REFUSE (X402-106) -----------------
  // Checked before the eip3009 gate so a permit-family payload that mislabels
  // its method still gets refused rather than merely abstained.
  const standing = detectStandingAuthority(p, method);
  if (standing) {
    return { decision: "refuse", findings: [standing] };
  }

  // --- 1c. permit2 (scoped-witness positive verify is OUT OF SCOPE) -------
  if (method === "permit2") {
    return abstain(
      "assetTransferMethod is permit2 — positive verification of a scoped PermitWitnessTransferFrom is out of scope for this build; refusing to report it as safe",
      [
        {
          code: "X402-106",
          severity: "high",
          message:
            "permit2 payload not positively verified in this build — abstaining rather than allowing",
          actual: "permit2",
        },
      ],
    );
  }

  // --- 1d. allowlist: only eip3009 is verified here -----------------------
  // An absent method is tolerated only if the payload otherwise looks like a
  // bare EIP-3009 authorization; any *named* method other than eip3009 that
  // reached here is unknown -> ABSTAIN.
  if (method !== null && method !== "eip3009") {
    return abstain(
      `assetTransferMethod (${String(
        method,
      )}) is not eip3009 — only EIP-3009 TransferWithAuthorization is verified in this build`,
    );
  }

  // If the payload declares a primaryType, it must be the one we allow.
  if (
    typeof p.primaryType === "string" &&
    p.primaryType.trim() !== EIP3009.PRIMARY_TYPE
  ) {
    return abstain(
      `payload primaryType (${p.primaryType}) is not ${EIP3009.PRIMARY_TYPE} — only TransferWithAuthorization is allowed`,
    );
  }

  // --- 2. domain table lookup (ABSTAIN on miss) ---------------------------
  // The domain used to recover MUST come from the table, never from the quote.
  const key = `${chainId}:${quoteAsset.toLowerCase()}`;
  const domainEntry = TRUSTED_DOMAINS[key];
  if (!domainEntry) {
    return abstain(
      `no trusted EIP-712 domain for (chainId ${chainId}, asset ${quoteAsset}) — refusing to recover against an unknown domain`,
    );
  }
  if (!domainEntry.verified) {
    return abstain(
      `trusted-domain entry for (chainId ${chainId}, asset ${quoteAsset}) is unverified — refusing to recover against an unconfirmed domain`,
    );
  }

  // --- 3. parse the authorization fields ----------------------------------
  const auth = p.authorization;
  if (typeof auth !== "object" || auth === null) {
    return abstain("payload carries no authorization object to check");
  }
  const from = normAddress(auth.from);
  const to = normAddress(auth.to);
  const value = toBig(auth.value);
  const validAfter = toBig(auth.validAfter);
  const validBefore = toBig(auth.validBefore);

  if (from === null) {
    return abstain("authorization.from is not a valid address");
  }
  if (to === null) {
    return abstain("authorization.to is not a valid address");
  }
  if (value === null) {
    return abstain("authorization.value is not an integer");
  }
  if (validAfter === null || validBefore === null) {
    return abstain("authorization validity window is not readable");
  }
  // nonce must be a well-formed bytes32.
  const nonce = auth.nonce;
  if (!isHexString(nonce) || nonce.length !== 66) {
    return abstain(
      "authorization.nonce is not a well-formed bytes32 — refusing to report the payment as checked",
    );
  }

  // --- 4. signature hygiene (ABSTAIN on malformed) ------------------------
  const norm = normalizeSignature(p.signature);
  if (norm === null) {
    return abstain(
      "signature is malformed (bad length, non-canonical v, or high-s malleability) — refusing to recover from it",
    );
  }

  // --- 5. recover the signer (X402-104) -----------------------------------
  // Domain is built FROM THE TABLE. recoverTypedDataAddress is pure/offline.
  const domain = {
    name: domainEntry.name,
    version: domainEntry.version,
    chainId,
    verifyingContract: quoteAsset as Hex,
  } as const;

  let recovered: string;
  try {
    const addr = await recoverTypedDataAddress({
      domain,
      types: EIP3009.TYPES,
      primaryType: EIP3009.PRIMARY_TYPE,
      message: {
        from: from as Hex,
        to: to as Hex,
        value,
        validAfter,
        validBefore,
        nonce: nonce as Hex,
      },
      signature: norm.sig,
    });
    recovered = getAddress(addr);
  } catch (e) {
    return abstain(
      `signature recovery failed (${
        e instanceof Error ? e.message : String(e)
      }) — refusing to report the payment as checked`,
    );
  }

  if (recovered.toLowerCase() !== from.toLowerCase()) {
    findings.push({
      code: "X402-104",
      severity: "critical",
      message:
        "recovered signer does not match authorization.from — the signature does not authorize this transfer",
      expected: from,
      actual: recovered,
    });
    // A bad signature invalidates every downstream comparison; refuse now.
    return { decision: "refuse", findings };
  }

  // --- 6. destination must be the quoted payee (X402-101) -----------------
  if (to.toLowerCase() !== quotePayTo.toLowerCase()) {
    findings.push({
      code: "X402-101",
      severity: "critical",
      message:
        "authorization pays an address other than the quoted payee — this is the substituted-destination attack",
      expected: quotePayTo,
      actual: to,
    });
  }

  // --- 7. value must match the quote exactly (X402-102) -------------------
  if (value !== quotedValue) {
    findings.push({
      code: "X402-102",
      severity: "critical",
      message: "authorization value does not match the quoted amount",
      expected: quotedValue.toString(),
      actual: value.toString(),
    });
  }

  // --- 8. chain / domain consistency (X402-103) ---------------------------
  // The recovery already bound chainId + verifyingContract into the domain, so
  // a signature made for a different chain or a different token simply would
  // not have recovered to `from` (caught at X402-104). This explicit check
  // guards the remaining offline-checkable mismatch: the payload asset (if it
  // carries one) disagreeing with the quoted asset the domain was built from.
  const payloadAsset = normAddress(
    (p as { asset?: unknown }).asset ?? (auth as { asset?: unknown }).asset,
  );
  if (payloadAsset !== null && payloadAsset.toLowerCase() !== quoteAsset.toLowerCase()) {
    findings.push({
      code: "X402-103",
      severity: "critical",
      message:
        "payload asset does not match the quoted asset the EIP-712 domain was built from",
      expected: quoteAsset,
      actual: payloadAsset,
    });
  }

  // --- 9. validity window (X402-105) --------------------------------------
  const now = opts.nowSeconds ?? BigInt(Math.floor(Date.now() / 1000));
  const skew = opts.clockSkewSeconds ?? 0n;
  if (now + skew < validAfter) {
    findings.push({
      code: "X402-105",
      severity: "high",
      message:
        "authorization is not yet valid (validAfter is in the future) — the payment window has not opened",
      expected: `now (${now.toString()}) >= validAfter`,
      actual: `validAfter = ${validAfter.toString()}`,
    });
  }
  // validBefore == 0 is the EIP-3009 convention for "no expiry"; only enforce
  // an expiry when validBefore is set.
  if (validBefore !== 0n && now > validBefore + skew) {
    findings.push({
      code: "X402-105",
      severity: "high",
      message:
        "authorization has expired (validBefore is in the past) — the payment window has closed",
      expected: `now (${now.toString()}) <= validBefore`,
      actual: `validBefore = ${validBefore.toString()}`,
    });
  }

  // --- 10. structural / session replay (X402-107) -------------------------
  // NOT on-chain replay protection — that needs authorizationState via RPC.
  // This is bytes32 well-formedness (already checked) plus a within-session
  // seen-set, when the caller supplies one.
  if (opts.seenNonces) {
    const nkey = `${chainId}:${quoteAsset.toLowerCase()}:${(nonce as string).toLowerCase()}`;
    if (opts.seenNonces.has(nkey)) {
      findings.push({
        code: "X402-107",
        severity: "high",
        message:
          "authorization nonce was already seen this session — possible replay (session-scoped detection only; on-chain replay state is not checked offline)",
        actual: nonce,
      });
    } else {
      opts.seenNonces.add(nkey);
    }
  }

  const blocking = findings.some(
    (f) => f.severity === "critical" || f.severity === "high",
  );
  return { decision: blocking ? "refuse" : "allow", findings };
}

// --- facilitator-flow helper ----------------------------------------------

/**
 * The relevant fields of an x402 EVM `accepts` entry (PaymentRequirements)
 * from the server's 402 response. `maxAmountRequired` (v1) or `amount` (v2) is
 * the exact amount under the `exact` scheme.
 */
export interface EvmPaymentRequirements {
  scheme?: unknown;
  network?: unknown;
  payTo?: unknown;
  asset?: unknown;
  amount?: unknown;
  maxAmountRequired?: unknown;
  extra?: EvmAcceptedEntry["extra"];
  [k: string]: unknown;
}

/**
 * Map a 402 EVM `accepts` entry to the quote `inspectAuthorization` checks
 * against. Throws if the mandatory fields are missing — a quote we cannot read
 * is not one to silently default.
 */
export function evmQuoteFromRequirements(
  req: EvmPaymentRequirements,
): EvmPaymentQuote {
  const amount =
    typeof req?.amount === "string"
      ? req.amount
      : typeof req?.maxAmountRequired === "string"
        ? req.maxAmountRequired
        : null;
  if (
    typeof req?.network !== "string" ||
    typeof req?.payTo !== "string" ||
    typeof req?.asset !== "string" ||
    amount === null
  ) {
    throw new Error(
      "wormhole-x402/evm: payment requirements are missing network, payTo, asset, or amount/maxAmountRequired",
    );
  }
  const q: EvmPaymentQuote = {
    network: req.network,
    payTo: req.payTo,
    asset: req.asset,
    amount,
  };
  // Preserve extra so a caller that passes the quote straight through can still
  // surface an out-of-band assetTransferMethod. Non-enumerable to keep the
  // quote shape clean for equality checks in tests.
  if (req.extra) {
    Object.defineProperty(q, "extra", {
      value: req.extra,
      enumerable: false,
      writable: false,
    });
  }
  return q;
}
