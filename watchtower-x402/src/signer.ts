/**
 * The EIP-3009 signer that makes a control payload acceptable.
 *
 * ═══ WHY THIS EXISTS AND WHY IT IS SEPARATE ═══
 *
 * Without a real signature the facilitator refuses every probe on signature
 * grounds, so the control is never accepted and every verdict is honestly
 * `unknown`. That is correct but useless. This module produces signatures a
 * facilitator will accept, which is what turns `unknown` into a real `pass` or
 * `fail`.
 *
 * It is a separate file, and `viem` is an OPTIONAL peer, because the probers must
 * remain runnable and testable with no crypto dependency at all — the fake
 * facilitators in the test suite never need a real signature, and a package whose
 * core requires a signing library is a package that cannot be audited without
 * one.
 *
 * ═══ THE SAFETY POSITION, WHICH IS UNUSUAL AND WORTH STATING ═══
 *
 * This signs a REAL, VALID transfer authorization. If it were submitted to
 * `/settle`, value would move. Three things make that acceptable:
 *
 *   1. The rail in safety.ts makes `/settle` unreachable — `SafeOperation` cannot
 *      express it and the URL is re-checked on every request.
 *   2. Every amount passes `assertProbeSafeValue`, capped at 1000 base units
 *      (0.001 USDC). Even a total failure of (1) moves a rounding error.
 *   3. The wallet is testnet-only and funded with testnet USDC that has no value.
 *
 * The authorization is real precisely so the facilitator's answer is meaningful.
 * A probe that could not produce a valid signature could not tell a conforming
 * facilitator from a broken one — which is the failure this whole package exists
 * to correct.
 *
 * ═══ NONCES ARE RANDOM, NOT SEQUENTIAL ═══
 *
 * EIP-3009 nonces are arbitrary 32-byte values, not counters. Random nonces mean
 * two probe runs never collide, and — more importantly — a nonce we have used
 * before cannot be replayed against us by a facilitator that stored it.
 */

import { assertProbeSafeValue } from "./safety.js";
import type { PayloadParts } from "./probes.js";

/** The subset of a viem account this module needs. Structural, so any signer fits. */
export interface TypedDataSigner {
  address: string;
  signTypedData(args: {
    domain: Record<string, unknown>;
    types: Record<string, unknown>;
    primaryType: string;
    message: Record<string, unknown>;
  }): Promise<string>;
}

/** EIP-3009 `TransferWithAuthorization`, the type x402's `exact` scheme signs. */
export const TRANSFER_WITH_AUTHORIZATION = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/**
 * Build a signer function for `ProbeContext.sign`.
 *
 * The chain id is parsed from the CAIP-2 network string the probe context
 * already carries (`eip155:84532`), so the caller cannot accidentally sign for a
 * different chain than it is probing — a mismatch there would produce a signature
 * the facilitator rejects, and we would misread that as a conformance signal.
 */
export function createSigner(opts: {
  account: TypedDataSigner;
  /** CAIP-2, e.g. "eip155:84532". */
  network: string;
  /** The token contract the authorization is against. */
  asset: string;
  /** EIP-712 domain of the asset. Base Sepolia USDC is name "USDC", version "2". */
  assetName?: string;
  assetVersion?: string;
}): (parts: PayloadParts) => Promise<string> {
  const chainId = parseChainId(opts.network);

  return async (parts: PayloadParts): Promise<string> => {
    // Layer 3 of the rail, applied at the moment of signing rather than only at
    // payload construction: this is the last point before a real, spendable
    // authorization exists, so it is the most important place to check.
    const value = assertProbeSafeValue(parts.amount, "signing a probe authorization");

    return opts.account.signTypedData({
      domain: {
        name: opts.assetName ?? "USDC",
        version: opts.assetVersion ?? "2",
        chainId,
        verifyingContract: opts.asset,
      },
      types: TRANSFER_WITH_AUTHORIZATION as unknown as Record<string, unknown>,
      primaryType: "TransferWithAuthorization",
      message: {
        from: parts.from,
        to: parts.payTo,
        value,
        validAfter: 0n,
        // One hour. Long enough that a slow probe run does not expire mid-flight,
        // short enough that a signature which somehow escaped this process stops
        // being usable quickly.
        validBefore: BigInt(Math.floor(Date.now() / 1000) + 3600),
        nonce: parts.nonce,
      },
    });
  };
}

function parseChainId(network: string): number {
  const m = /^eip155:(\d+)$/.exec(network.trim());
  if (!m) {
    throw new Error(
      `signer: network must be CAIP-2 eip155 (got ${network.slice(0, 32)}) — ` +
        `refusing to guess a chain id, because signing for the wrong chain looks ` +
        `like a conformance failure`,
    );
  }
  return Number(m[1]);
}

/** A fresh random 32-byte nonce. See the header for why these are not counters. */
export function randomNonce(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
