/**
 * x402-guard — refuse a payment that does not match what the agent was quoted.
 *
 * Every transaction-security product on Solana answers the same question:
 * "what will this transaction do?" Simulation, asset diffs, address reputation.
 * All useful, none of it sufficient for an agent, because a payment to an
 * attacker's address simulates perfectly: correct balances, no revert, clean
 * verdict. The transaction is valid. It is simply not the one that was asked
 * for.
 *
 * Nobody answers "is this the transaction that was asked for?" -- and in the
 * leading provider's API it is not merely unimplemented, it is not
 * expressible: the request schema carries `origin` ("DApp domain proposing
 * these transactions") and has no field for the agent's instructions at all.
 * The whole stack is shaped around a human approving a website's request. A
 * headless agent has neither.
 *
 * THE DESIGN CONSTRAINT THAT MATTERS. Intent must never be something the agent
 * states. If it is a field the model fills in, a compromised model fills in
 * both sides of the comparison and validates its own forgery -- worse than no
 * check, because it manufactures confidence at the moment funds move.
 *
 * x402 is the case where this works, because no model is in the path. The
 * recipient, amount and mint arrive as structured JSON in the server's HTTP
 * 402 response, before the transaction exists, on a channel entirely separate
 * from the model's context. That is a genuinely independent second input, and
 * the comparison against it is pure offline math.
 *
 * SCOPE, STATED UP FRONT. This checks conformance to a quote. It is not a
 * simulator and does not replace one -- run both. It cannot help when intent
 * only ever existed as open-ended natural language ("pay the invoice Alice
 * emailed me"), because then there is no independent channel and the guard
 * would be diffing against text that lived in the poisoned context. That case
 * is refused rather than approximated.
 */

import { PublicKey, VersionedTransaction, Transaction } from "@solana/web3.js";
import { getAssociatedTokenAddressSync } from "@solana/spl-token";

/** The quote, parsed from the server's 402 response. Never agent-authored. */
export interface PaymentQuote {
  /** Base58 address the server says to pay. */
  payTo: string;
  /** Token mint. */
  asset: string;
  /** Exact amount, in the token's base units, as a decimal string. */
  amount: string;
}

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

// --- program ids -----------------------------------------------------------

const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPL_TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM = "11111111111111111111111111111111";
const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111";
const MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const LIGHTHOUSE = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95";
const ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/**
 * The x402 SVM `exact` scheme names the programs a conforming payment may
 * touch. Anything else is out of spec, and out of spec is the whole signal --
 * this is an allowlist, not a blocklist, so it holds against instructions
 * nobody has catalogued.
 */
const ALLOWED_PROGRAMS = new Set([
  SPL_TOKEN,
  SPL_TOKEN_2022,
  SYSTEM,
  COMPUTE_BUDGET,
  MEMO,
  LIGHTHOUSE,
  ATA_PROGRAM,
]);

/**
 * SPL Token instruction discriminants worth refusing outright. Each is a
 * single leading byte. These are the ones that hand over control rather than
 * move a balance, so they have no business in a payment.
 */
const DANGEROUS_TOKEN_IX: Record<number, string> = {
  4: "Approve — delegates spending authority over the account",
  6: "SetAuthority — transfers ownership of the token account",
  9: "CloseAccount — closes the account and sweeps its rent",
  13: "ApproveChecked — delegates spending authority over the account",
};

// --- helpers ---------------------------------------------------------------

function decodeTransaction(raw: Uint8Array | string): {
  tx: VersionedTransaction | null;
  err?: string;
} {
  const bytes =
    typeof raw === "string" ? Uint8Array.from(Buffer.from(raw, "base64")) : raw;
  try {
    return { tx: VersionedTransaction.deserialize(bytes) };
  } catch {
    // A legacy transaction is still a valid thing to be handed.
    try {
      const legacy = Transaction.from(Buffer.from(bytes));
      return { tx: new VersionedTransaction(legacy.compileMessage()) };
    } catch (e) {
      return { tx: null, err: e instanceof Error ? e.message : String(e) };
    }
  }
}

/** Little-endian u64 from an instruction's data, at a byte offset. */
function readU64LE(data: Uint8Array, offset: number): bigint | null {
  if (data.length < offset + 8) return null;
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(data[offset + i]);
  return v;
}

// --- the guard -------------------------------------------------------------

export function inspectPayment(
  raw: Uint8Array | string,
  quote: PaymentQuote,
): Verdict {
  const findings: Finding[] = [];
  const { tx, err } = decodeTransaction(raw);

  if (!tx) {
    return {
      decision: "abstain",
      findings: [],
      reason: `could not deserialize the transaction (${err}) — refusing to report it as safe`,
    };
  }

  const msg = tx.message;
  const keys = msg.staticAccountKeys.map((k) => k.toBase58());

  /**
   * A versioned transaction can hide accounts behind an address lookup table,
   * and the message carries only the table address plus integer indices -- the
   * actual pubkeys live in on-chain account data. That cannot be resolved
   * offline, so the honest answer is abstain. Never green: a guard that
   * reports safe on a transaction it could not fully read is worse than no
   * guard, because the operator believes it was checked.
   */
  if (msg.addressTableLookups && msg.addressTableLookups.length > 0) {
    return {
      decision: "abstain",
      findings: [],
      reason:
        "transaction uses address lookup tables; the referenced accounts are " +
        "not in the message and cannot be resolved without RPC",
    };
  }

  // --- 1. destination must be the ATA derived from the quote ---------------
  let expectedAta: string | null = null;
  try {
    const payTo = new PublicKey(quote.payTo);
    const mint = new PublicKey(quote.asset);
    expectedAta = getAssociatedTokenAddressSync(mint, payTo, true).toBase58();
  } catch (e) {
    return {
      decision: "abstain",
      findings: [],
      reason: `quote contains an unreadable address (${
        e instanceof Error ? e.message : String(e)
      })`,
    };
  }

  // --- 2. walk the instructions -------------------------------------------
  let sawTransferToExpected = false;
  let transferredAmount: bigint | null = null;
  const memos: string[] = [];

  for (const ix of msg.compiledInstructions) {
    const programId = keys[ix.programIdIndex];

    if (!ALLOWED_PROGRAMS.has(programId)) {
      findings.push({
        code: "X402-003",
        severity: "critical",
        message:
          "transaction invokes a program the x402 exact scheme does not permit",
        actual: programId,
      });
      continue;
    }

    if (programId === MEMO) {
      try {
        memos.push(new TextDecoder().decode(Uint8Array.from(ix.data)));
      } catch {
        /* a memo that will not decode is not a finding on its own */
      }
      continue;
    }

    if (programId === SPL_TOKEN || programId === SPL_TOKEN_2022) {
      const data = Uint8Array.from(ix.data);
      const disc = data[0];

      const danger = DANGEROUS_TOKEN_IX[disc];
      if (danger !== undefined) {
        findings.push({
          code: "X402-006",
          severity: "critical",
          message: `payment contains a control-transferring instruction: ${danger}`,
        });
        continue;
      }

      // TransferChecked = 12. Accounts: [source, mint, destination, authority]
      if (disc === 12 && ix.accountKeyIndexes.length >= 3) {
        const dest = keys[ix.accountKeyIndexes[2]];
        const amt = readU64LE(data, 1);

        if (dest === expectedAta) {
          sawTransferToExpected = true;
          transferredAmount = amt;
        } else {
          findings.push({
            code: "X402-001",
            severity: "critical",
            message:
              "payment destination is not the account derived from the quote",
            expected: expectedAta,
            actual: dest,
          });
        }
      }
    }
  }

  // --- 3. the payment must actually be present ----------------------------
  if (!sawTransferToExpected && findings.length === 0) {
    findings.push({
      code: "X402-001",
      severity: "critical",
      message:
        "transaction contains no transfer to the account derived from the quote",
      expected: expectedAta,
    });
  }

  // --- 4. the amount must match exactly -----------------------------------
  if (sawTransferToExpected && transferredAmount !== null) {
    let quoted: bigint | null = null;
    try {
      quoted = BigInt(quote.amount);
    } catch {
      quoted = null;
    }
    if (quoted !== null && transferredAmount !== quoted) {
      findings.push({
        code: "X402-002",
        severity: "critical",
        message: "payment amount does not match the quoted amount",
        expected: quoted.toString(),
        actual: transferredAmount.toString(),
      });
    }
  }

  // --- 5. memo directive scan ---------------------------------------------
  // Deliberately last and deliberately not load-bearing. This is shape
  // matching over attacker-controlled text; it is evadable by rewording, and
  // it is here to surface an obvious attempt, not to be relied on.
  for (const memo of memos) {
    if (looksLikeDirective(memo)) {
      findings.push({
        code: "X402-008",
        severity: "medium",
        message:
          "memo contains instruction-shaped text; a memo is data, and an " +
          "agent that reads it as an instruction is reading attacker input",
        actual: memo.slice(0, 160),
      });
    }
  }

  const blocking = findings.some((f) => f.severity === "critical");
  return { decision: blocking ? "refuse" : "allow", findings };
}

/** Imperative text aimed at a reader, in a field that should carry a reference. */
function looksLikeDirective(text: string): boolean {
  return (
    /\b(ignore|disregard|override)\s+(all\s+|any\s+)?(previous|prior|earlier)\b/i.test(text) ||
    /\b(instead\s+send|send\s+to|redirect|forward)\b.{0,60}\b(address|wallet|account)\b/i.test(text) ||
    /\b(do\s+not|don't)\s+(tell|mention|report|inform|notify)\b/i.test(text) ||
    /\b(copy|append|include|repeat)\s+this\b/i.test(text)
  );
}

/**
 * Wrap a signer so nothing is signed unless it matches the quote.
 *
 * Fails closed by design: no quote means refuse. Every optional security
 * parameter with a permissive default ends up unset in production, and then
 * the guard reports green on all traffic and nobody notices.
 */
export function guardSigner<T extends { signTransaction: Function }>(
  wallet: T,
  getQuote: () => PaymentQuote | null,
): T {
  const original = wallet.signTransaction.bind(wallet);
  return new Proxy(wallet, {
    get(target, prop, receiver) {
      if (prop !== "signTransaction") return Reflect.get(target, prop, receiver);
      return async (tx: VersionedTransaction) => {
        const quote = getQuote();
        if (!quote) {
          throw new Error(
            "x402-guard: refusing to sign — no payment quote was supplied, " +
              "so there is nothing to check this transaction against.",
          );
        }
        const verdict = inspectPayment(tx.serialize(), quote);
        if (verdict.decision !== "allow") {
          const detail = verdict.findings
            .map((f) => `${f.code}: ${f.message}`)
            .join("; ");
          throw new Error(
            `x402-guard: refusing to sign (${verdict.decision}). ` +
              (verdict.reason ?? detail),
          );
        }
        return original(tx);
      };
    },
  }) as T;
}
