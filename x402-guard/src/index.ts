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

import {
  PublicKey,
  VersionedTransaction,
  VersionedMessage,
  Transaction,
} from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
} from "@solana/spl-token";

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
  8: "Burn — destroys tokens from the payer's account",
  9: "CloseAccount — closes the account and sweeps its rent",
  13: "ApproveChecked — delegates spending authority over the account",
  15: "BurnChecked — destroys tokens from the payer's account",
};

/**
 * System program instruction tags, u32 LE. The only one a conforming payment
 * has any use for is AdvanceNonceAccount (durable-nonce transactions). All
 * lamport movement and every ownership handoff is refused — this is an
 * allowlist for the same reason the program list is: TransferWithSeed (11)
 * moves lamports exactly like Transfer (2) through a different opcode, and a
 * blocklist that names only the opcodes someone has already thought of is a
 * bypass catalogue.
 */
const SYSTEM_ALLOWED_TAGS = new Set([4 /* AdvanceNonceAccount */]);
const SYSTEM_LAMPORT_MOVERS = new Set([
  0 /* CreateAccount */, 2 /* Transfer */, 3 /* CreateAccountWithSeed */,
  5 /* WithdrawNonceAccount */, 11 /* TransferWithSeed */,
]);

/** Default cap on priority fees: 0.01 SOL. Override via InspectOptions. */
const DEFAULT_MAX_PRIORITY_FEE_LAMPORTS = 10_000_000n;
/** Runtime maximum compute units, assumed when a price is set with no limit. */
const MAX_COMPUTE_UNITS = 1_400_000n;

export interface InspectOptions {
  /**
   * Maximum total priority fee (compute unit price × limit) in lamports.
   * A "correct" payment carrying a 10 SOL priority fee simulates cleanly,
   * matches the quote, and drains the fee payer anyway.
   */
  maxPriorityFeeLamports?: bigint;
  /**
   * The wallet (base58 pubkey) whose funds this payment is supposed to move.
   * When set, the transfer's authority must BE this wallet and the source must
   * be this wallet's associated token account for the quoted asset — otherwise
   * X402-011 refuses. Without it, a conforming payment of a THIRD PARTY's
   * funds to the quoted merchant returns allow, and the guard cannot answer
   * the question it exists to answer: "did MY agent make this payment?"
   * "This payment matches the quote" and "my agent paid" are different claims.
   *
   * A multisig authority will not equal a wallet pubkey and therefore refuses;
   * that is fail-closed by design — a payment whose signer set cannot be read
   * offline is not something to report as payer-checked.
   */
  expectedPayer?: string;
}

// --- helpers ---------------------------------------------------------------

/** A Solana packet is 1232 bytes. Anything claiming more is not a transaction. */
const MAX_TX_BYTES = 1232;

function decodeTransaction(raw: Uint8Array | string): {
  tx: VersionedTransaction | null;
  err?: string;
} {
  // AW-05. The parameter is TYPED `Uint8Array | string`, but the value comes
  // from JSON as `unknown`, and a type is not a runtime check. A plain object
  // is neither, so it fell through to `Buffer.from(bytes)` below, which
  // honours an attacker-declared `.length`: `{ "length": 2e8 }` allocates
  // 200MB in 4.5s (measured), and a large enough value is a V8 fatal that no
  // try/catch can intercept — a 48-byte body killing the process.
  //
  // Refuse the shape here rather than deeper: `Buffer.from(arrayLike)` must
  // never be reachable from caller-controlled JSON.
  if (typeof raw !== "string" && !(raw instanceof Uint8Array))
    return { tx: null, err: "payload must be base64 or bytes" };

  const bytes =
    typeof raw === "string" ? Uint8Array.from(Buffer.from(raw, "base64")) : raw;

  // Bound the allocation before anything downstream spreads or copies it.
  if (bytes.length > MAX_TX_BYTES)
    return { tx: null, err: `transaction exceeds ${MAX_TX_BYTES} bytes` };
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

function readU32LE(data: Uint8Array, offset: number): number | null {
  if (data.length < offset + 4) return null;
  return (
    data[offset] |
    (data[offset + 1] << 8) |
    (data[offset + 2] << 16) |
    (data[offset + 3] << 24)
  );
}

// --- the guard -------------------------------------------------------------

export function inspectPayment(
  raw: Uint8Array | string,
  quote: PaymentQuote,
  opts: InspectOptions = {},
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
  // The ATA is derived from (owner, mint, token program). A Token-2022 mint
  // derives a different address than a legacy one, so deriving only the legacy
  // form would refuse every legitimate Token-2022 payment. Which program owns
  // the mint is on-chain state we deliberately do not fetch, so both are
  // derived and either is accepted as the destination.
  let expectedAta: string | null = null;
  let expectedAta2022: string | null = null;
  try {
    const payTo = new PublicKey(quote.payTo);
    const mint = new PublicKey(quote.asset);
    expectedAta = getAssociatedTokenAddressSync(
      mint,
      payTo,
      true,
      TOKEN_PROGRAM_ID,
    ).toBase58();
    expectedAta2022 = getAssociatedTokenAddressSync(
      mint,
      payTo,
      true,
      TOKEN_2022_PROGRAM_ID,
    ).toBase58();
  } catch (e) {
    return {
      decision: "abstain",
      findings: [],
      reason: `quote contains an unreadable address (${
        e instanceof Error ? e.message : String(e)
      })`,
    };
  }

  // --- 1b. payer binding, when the caller names one ------------------------
  // Derived up front for the same reason the merchant ATA is: an unreadable
  // option must abstain before any instruction is judged, never be skipped.
  let expectedAuthority: string | null = null;
  let payerAta: string | null = null;
  let payerAta2022: string | null = null;
  if (opts.expectedPayer !== undefined) {
    try {
      const payer = new PublicKey(opts.expectedPayer);
      const mint = new PublicKey(quote.asset);
      expectedAuthority = payer.toBase58();
      payerAta = getAssociatedTokenAddressSync(
        mint,
        payer,
        true,
        TOKEN_PROGRAM_ID,
      ).toBase58();
      payerAta2022 = getAssociatedTokenAddressSync(
        mint,
        payer,
        true,
        TOKEN_2022_PROGRAM_ID,
      ).toBase58();
    } catch (e) {
      return {
        decision: "abstain",
        findings: [],
        reason: `expectedPayer is not a readable address (${
          e instanceof Error ? e.message : String(e)
        }) — refusing to report the payer as checked`,
      };
    }
  }

  // --- 2. walk the instructions -------------------------------------------
  let sawTransferToExpected = false;
  let transferredAmount: bigint | null = null;
  const memos: string[] = [];
  // AW-12. A conforming payment creates at most the merchant's own token
  // account. More than one create is rent leaving the funder for accounts the
  // quote never named, whoever owns them.
  let ataCreates = 0;
  let cuLimit: bigint | null = null;
  let cuPrice: bigint | null = null;

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

      // Both transfer forms move tokens and both must be accounted for.
      // TransferChecked = 12, accounts [source, mint, destination, authority];
      // Transfer = 3, accounts [source, destination, authority]. Ignoring the
      // unchecked form would let a second, undeclared transfer ride along
      // beside the quoted one and still be reported as matching the quote.
      const isChecked = disc === 12;
      const isPlain = disc === 3;

      if (isChecked || isPlain) {
        const destIndex = isChecked ? 2 : 1;
        const minAccounts = isChecked ? 3 : 2;

        if (ix.accountKeyIndexes.length >= minAccounts) {
          const dest = keys[ix.accountKeyIndexes[destIndex]];
          const amt = readU64LE(data, 1);

          if (dest === expectedAta || dest === expectedAta2022) {
            if (sawTransferToExpected) {
              // A second transfer to the merchant is still money leaving the
              // payer that the quote never described.
              findings.push({
                code: "X402-002",
                severity: "critical",
                message:
                  "transaction contains more than one transfer to the quoted destination",
              });
            } else {
              sawTransferToExpected = true;
              transferredAmount = amt;
            }

            // Payer binding: the quoted transfer must move the EXPECTED
            // wallet's funds. TransferChecked accounts are [source, mint,
            // destination, authority]; Transfer is [source, destination,
            // authority]. Both the authority (who signs the movement) and the
            // source (whose account drains) are checked — authority alone
            // misses a delegate spending from a stranger's account, source
            // alone misses an authority that is not the wallet at all.
            if (expectedAuthority !== null) {
              const authIdx = isChecked ? 3 : 2;
              const authority =
                ix.accountKeyIndexes.length > authIdx
                  ? keys[ix.accountKeyIndexes[authIdx]]
                  : undefined;
              const source = keys[ix.accountKeyIndexes[0]];

              if (authority === undefined) {
                findings.push({
                  code: "X402-011",
                  severity: "critical",
                  message:
                    "transfer authority could not be read, so the payer cannot be confirmed",
                  expected: expectedAuthority,
                });
              } else if (authority !== expectedAuthority) {
                findings.push({
                  code: "X402-011",
                  severity: "critical",
                  message:
                    "payment is authorized by a wallet other than the expected payer — " +
                    "a conforming payment of someone else's funds is not this agent's payment",
                  expected: expectedAuthority,
                  actual: authority,
                });
              } else if (source !== payerAta && source !== payerAta2022) {
                findings.push({
                  code: "X402-011",
                  severity: "critical",
                  message:
                    "funds leave a token account that is not the expected payer's " +
                    "associated account for the quoted asset",
                  expected: payerAta ?? undefined,
                  actual: source,
                });
              }
            }
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
        } else {
          // A transfer we cannot read the destination of is not something to
          // report as matching the quote.
          findings.push({
            code: "X402-001",
            severity: "critical",
            message:
              "transaction contains a transfer whose destination could not be read",
          });
        }
      } else {
        // ALLOWLIST, not a blocklist. Anything that is not one of the two
        // transfer forms is refused here, including discriminants nobody has
        // enumerated.
        //
        // This was a blocklist and it was a wrong-allow bug that moved money.
        // Token-2022 namespaces its extensions: for TransferCheckedWithFee,
        // data[0] = 26 selects the TransferFee extension GROUP and data[1] = 1
        // selects the operation. A switch reading only data[0] therefore never
        // sees a genuine funds-moving transfer, and 33 leading bytes fell
        // through with no finding at all -- an attacker-destination transfer
        // built by the official @solana/spl-token helper rode alongside a
        // conforming payment and the verdict was allow with zero findings.
        //
        // Enumerating 26/27/36 into the dangerous table would repeat the
        // mistake one layer down. An extension group is refused unless a
        // specific (data[0], data[1]) pair is explicitly understood, and none
        // are yet.
        findings.push({
          code: "X402-006",
          severity: "critical",
          message:
            `token instruction ${disc}${data.length > 1 ? "/" + data[1] : ""} ` +
            "is not one of the transfer forms an exact-scheme payment uses, so " +
            "what it does to the payer's funds cannot be determined offline",
          actual: `discriminant ${disc}`,
        });
      }
    }

    // System program: strict allowlist. Only AdvanceNonceAccount has a place
    // in a payment; anything else either moves lamports the quote never
    // mentioned or hands over control of an account. An unreadable tag is
    // refused too — a System instruction we could not classify is not
    // something to wave through.
    if (programId === SYSTEM) {
      const data = Uint8Array.from(ix.data);
      const tag = data.length >= 4 ? readU32LE(data, 0) : null;

      if (tag === null || !SYSTEM_ALLOWED_TAGS.has(tag)) {
        if (tag !== null && SYSTEM_LAMPORT_MOVERS.has(tag)) {
          findings.push({
            code: "X402-007",
            severity: "critical",
            message:
              "transaction moves SOL alongside the payment — the quote covers the token transfer only",
            actual: `system instruction tag ${tag}`,
          });
        } else {
          findings.push({
            code: "X402-009",
            severity: "critical",
            message:
              "system instruction out of scope for a payment — assigns ownership, allocates, or could not be classified",
            actual: tag === null ? "unreadable tag" : `system instruction tag ${tag}`,
          });
        }
      }
    }

    // ATA program: Create (0 or empty data) and CreateIdempotent (1) fund the
    // merchant's account into existence and are part of the scheme.
    // RecoverNested (2) MOVES TOKENS out of a nested account — an in-allowlist
    // program with an instruction that behaves like a transfer.
    if (programId === ATA_PROGRAM) {
      const data = Uint8Array.from(ix.data);
      const disc = data.length === 0 ? 0 : data[0];
      if (disc === 2) {
        findings.push({
          code: "X402-006",
          severity: "critical",
          message:
            "payment contains a control-transferring instruction: RecoverNested — moves tokens out of a nested account",
        });
      } else if (disc !== 0 && disc !== 1) {
        findings.push({
          code: "X402-009",
          severity: "critical",
          message: "unrecognized associated-token-program instruction in a payment",
          actual: `discriminant ${disc}`,
        });
      } else {
        // AW-12. Create (0) and CreateIdempotent (1) used to be waved through
        // on the discriminant alone, with no look at WHICH account is being
        // created or WHO pays for it. Both CPI into
        // SystemProgram::CreateAccount, moving rent-exempt lamports out of the
        // funder — exactly the movement X402-007 exists to stop, one layer up
        // through a CPI this walk did not model.
        //
        // Measured: a 1-lamport SystemProgram.transfer rider refuses with
        // X402-007, while 11 ATA riders drain 0.0164 SOL (~$1.82, about 1.6x
        // the priority-fee ceiling the guard itself rates critical) and return
        // `allow` with zero findings. The attacker owns the created accounts
        // and can CloseAccount the rent back out to themselves.
        //
        // Account layout for both: [0] funder, [1] associatedAccount,
        // [2] owner, [3] mint. False-positive-free because a transaction using
        // address lookup tables has already abstained above, so every key here
        // is static.
        const idx = ix.accountKeyIndexes;
        if (idx.length < 4) {
          findings.push({
            code: "X402-009",
            severity: "critical",
            message:
              "associated-token-program create instruction has too few accounts to check",
            actual: `${idx.length} accounts`,
          });
        } else {
          ataCreates += 1;
          const created = keys[idx[1]];
          const owner = keys[idx[2]];
          const mint = keys[idx[3]];
          const funder = keys[idx[0]];

          // The only account a payment has any business creating is the
          // merchant's own token account for the quoted asset.
          const createdIsQuoted =
            (created === expectedAta || created === expectedAta2022) &&
            owner === quote.payTo &&
            mint === quote.asset;

          if (!createdIsQuoted) {
            findings.push({
              code: "X402-007",
              severity: "critical",
              message:
                "payment funds the creation of a token account that is not the " +
                "quoted merchant's: rent-exempt lamports leave the funder for an " +
                "account the quote never mentioned",
              expected: `${expectedAta} (owner ${quote.payTo}, mint ${quote.asset})`,
              actual: `${created} (owner ${owner}, mint ${mint})`,
            });
          }

          // When the caller named a payer, they are asking "did MY wallet fund
          // this?" — so a create funded by anyone else is not something to
          // report as checked.
          if (expectedAuthority !== null && funder !== expectedAuthority) {
            findings.push({
              code: "X402-007",
              severity: "critical",
              message:
                "token-account creation is funded by an account other than the " +
                "expected payer",
              expected: expectedAuthority,
              actual: funder,
            });
          }
        }
      }
    }

    // Compute budget: collect limit and price; the fee check runs after the
    // walk so the two instructions can appear in any order.
    if (programId === COMPUTE_BUDGET) {
      const data = Uint8Array.from(ix.data);
      const disc = data[0];
      if (disc === 2) {
        const v = readU32LE(data, 1);
        if (v !== null) cuLimit = BigInt(v >>> 0);
      } else if (disc === 3) {
        cuPrice = readU64LE(data, 1);
      }
    }
  }

  // --- 2b. priority-fee cap ------------------------------------------------
  // A transaction that pays the quoted merchant the quoted amount and sets a
  // 10 SOL priority fee simulates cleanly and drains the fee payer anyway.
  if (cuPrice !== null && cuPrice > 0n) {
    const limit = cuLimit ?? MAX_COMPUTE_UNITS;
    const feeLamports = (limit * cuPrice) / 1_000_000n;
    const cap = opts.maxPriorityFeeLamports ?? DEFAULT_MAX_PRIORITY_FEE_LAMPORTS;
    if (feeLamports > cap) {
      findings.push({
        code: "X402-010",
        severity: "critical",
        message:
          "priority fee exceeds the cap — fees are paid regardless of what the quote covers",
        expected: `<= ${cap.toString()} lamports`,
        actual: `${feeLamports.toString()} lamports`,
      });
    }
  }

  // AW-12. Even when every create names the quoted merchant, more than one is
  // not a payment shape: a conforming transaction creates the merchant's token
  // account if it does not exist, and that is one account. Capping here is the
  // belt to the per-instruction braces above — it bounds the rent a payment
  // can move even if some future create passes the per-account checks.
  if (ataCreates > 1) {
    findings.push({
      code: "X402-007",
      severity: "critical",
      message:
        "payment creates more than one token account: rent-exempt lamports " +
        "leave the funder once per create, and a conforming payment needs at " +
        "most the merchant's own account",
      expected: "at most 1",
      actual: `${ataCreates} creates`,
    });
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
  // Every path here that cannot complete the comparison abstains. Skipping a
  // check we could not perform and then allowing is the one failure mode this
  // package exists to avoid: it reports "checked" on a transaction nobody
  // checked, at the moment funds move irreversibly.
  if (sawTransferToExpected) {
    let quoted: bigint | null = null;
    try {
      quoted = BigInt(quote.amount);
    } catch {
      quoted = null;
    }

    if (quoted === null) {
      return {
        decision: "abstain",
        findings,
        reason: `quote amount is not an integer (${String(
          quote.amount,
        )}) — refusing to report the payment as checked`,
      };
    }

    if (transferredAmount === null) {
      return {
        decision: "abstain",
        findings,
        reason:
          "transfer amount could not be read from the instruction data — refusing to report the payment as checked",
      };
    }

    if (transferredAmount !== quoted) {
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
 * Every method through which a wallet can produce a signature. Wrapping only
 * `signTransaction` and leaving `signAllTransactions` bare is not a guard, it
 * is a door with a doorman standing beside it — an agent told to "batch the
 * payment" walks straight past the check.
 */
const SIGNING_METHODS = new Set([
  "signTransaction",
  "signAllTransactions",
  "signAndSendTransaction",
  "signAndSendAllTransactions",
  // AW-11. `sendTransaction` is the method a wallet-adapter agent reaches for
  // most often, and it was handed back raw: money moved with no quote check at
  // all. It takes a transaction as its first argument like the others, so the
  // same check applies unchanged.
  "sendTransaction",
  "sendAllTransactions",
]);


/**
 * Methods that sign arbitrary bytes rather than a transaction.
 *
 * These stay dangerous even when the caller names them in `allow`, because on
 * Solana the two are the same operation: a transaction signature is ed25519
 * over `message.serialize()`, with no domain separator to tell them apart.
 */
const MESSAGE_SIGNING_METHODS = new Set(["signMessage", "signMessages", "signIn"]);

/** Decode base64 without throwing; null when it is not base64. */
function tryDecodeBase64(s: string): Uint8Array | null {
  try {
    const b = Buffer.from(s, "base64");
    return b.length > 0 ? new Uint8Array(b) : null;
  } catch {
    return null;
  }
}

/**
 * Do these bytes parse as a Solana transaction message?
 *
 * Deliberately tries BOTH the bare message and the full transaction: an
 * attacker hands over whichever shape the victim's signer accepts, and the
 * signature is valid over the message bytes either way.
 */
function looksLikeTransaction(bytes: Uint8Array): boolean {
  if (bytes.length === 0 || bytes.length > MAX_TX_BYTES) return false;
  try {
    VersionedTransaction.deserialize(bytes);
    return true;
  } catch {
    /* not a full transaction — try the message alone */
  }
  try {
    VersionedMessage.deserialize(bytes);
    return true;
  } catch {
    return false;
  }
}

/** Reads that cannot move funds. Every name here is a decision. */
const SOLANA_SAFE_READS = new Set([
  "getAccounts",
  "getPublicKey",
  "connect",
  "disconnect",
  "on",
  "off",
  "removeListener",
]);

/**
 * Wrap a signer so nothing is signed unless it matches the quote — through
 * any signing method the wallet exposes.
 *
 * Fails closed by design: no quote means refuse. Every optional security
 * parameter with a permissive default ends up unset in production, and then
 * the guard reports green on all traffic and nobody notices.
 */
export function guardSigner<T extends { signTransaction: Function }>(
  wallet: T,
  getQuote: () => PaymentQuote | null,
  opts: InspectOptions & {
    /**
     * Members to leave UNGUARDED, named explicitly. Under default-deny this is
     * the only way anything reaches the wallet unchecked, so each entry is a
     * decision with a name on it. A nested member can be named with a dotted
     * path, e.g. `"provider.connect"`.
     */
    allow?: readonly string[];
  } = {},
): T {
  const allowed = new Set(opts.allow ?? []);

  const check = (tx: VersionedTransaction, method: string): Uint8Array => {
    const quote = getQuote();
    if (!quote) {
      throw new Error(
        `x402-guard: refusing to sign via ${method}() — no payment quote was ` +
          "supplied, so there is nothing to check this transaction against.",
      );
    }
    let serialized: Uint8Array;
    try {
      serialized = tx.serialize();
    } catch {
      // An argument that does not serialise is not a transaction this wrapper
      // can check, and an uncheckable signing request is refused.
      throw new Error(
        `x402-guard: refusing to sign via ${method}() — the argument is not a ` +
          "serializable transaction, so it cannot be checked against the quote.",
      );
    }
    const verdict = inspectPayment(serialized, quote, opts);
    if (verdict.decision !== "allow") {
      const detail = verdict.findings
        .map((f) => `${f.code}: ${f.message}`)
        .join("; ");
      throw new Error(
        `x402-guard: refusing to sign (${verdict.decision}). ` +
          (verdict.reason ?? detail),
      );
    }
    // AW-67. The bytes that were INSPECTED, handed back so the caller signs
    // exactly these. See guardFn.
    return serialized;
  };

  /**
   * Permit a message-signing method, but never let it sign a TRANSACTION.
   *
   * On Solana a transaction signature is ed25519 over `message.serialize()`
   * with no domain separator, so a message signer is a transaction signer for
   * anyone who passes it the right bytes. This is the check the audit asked
   * for: discriminate on whether the bytes deserialize, rather than refusing
   * the method outright (which makes it useless) or allowing it outright
   * (which re-opens the oracle).
   */
  const signMessageGuard = (fn: Function, method: string, self: unknown) =>
    async (first: unknown, ...rest: unknown[]) => {
      const bytes =
        first instanceof Uint8Array
          ? first
          : typeof first === "string"
            ? tryDecodeBase64(first)
            : null;
      if (bytes !== null && looksLikeTransaction(bytes)) {
        throw new Error(
          `x402-guard: refusing ${method}() — the bytes handed to it deserialize ` +
            "as a Solana transaction message, and a transaction signature IS " +
            "ed25519 over exactly those bytes. Signing them as a 'message' " +
            "produces a valid transaction signature that no quote was ever " +
            "checked against.",
        );
      }
      return fn.apply(self, [first, ...rest]);
    };

  /**
   * Rebuild a transaction from the bytes that were actually checked.
   *
   * AW-67. `check` serialised the caller's object and the wallet was then
   * invoked with THAT OBJECT, so nothing bound the inspected bytes to the
   * signed ones. A `message` getter that returns clean content on the guard's
   * read and hostile content on the wallet's read is signed unchecked:
   * reproduced here, the guard allowed a 1 USDC payment to the merchant and
   * the wallet signed 999 USDC to the attacker's ATA.
   *
   * Signing the reconstruction closes the window — there is no second read to
   * differ, because the bytes are the ones the verdict was computed over.
   */
  const rebind = (bytes: Uint8Array, method: string): VersionedTransaction => {
    try {
      return VersionedTransaction.deserialize(bytes);
    } catch {
      throw new Error(
        `x402-guard: refusing to sign via ${method}() — the inspected bytes ` +
          "could not be rebuilt into a transaction, so what the wallet would " +
          "sign cannot be proven identical to what was checked.",
      );
    }
  };

  const guardFn = (fn: Function, method: string, self: unknown) =>
    async (first: unknown, ...rest: unknown[]) => {
      // The wallet receives the REBUILT transaction, never the caller's
      // object: a guard that checks one thing and signs another is not a
      // guard.
      if (Array.isArray(first)) {
        const rebuilt = first.map((tx) =>
          rebind(check(tx as VersionedTransaction, method), method),
        );
        return fn.apply(self, [rebuilt, ...rest]);
      }
      const rebuilt = rebind(
        check(first as VersionedTransaction, method),
        method,
      );
      return fn.apply(self, [rebuilt, ...rest]);
    };


  const wrap = <O extends object>(obj: O, path: string, depth = 0): O =>
    new Proxy(obj, {
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver);
        if (typeof prop !== "string") return value;
        const qualified = path ? `${path}.${prop}` : prop;
        if (allowed.has(prop) || allowed.has(qualified)) {
          // `allow` names a method the caller says cannot move funds. On
          // Solana that claim is not the caller's alone to make for
          // message-signing: a transaction signature IS ed25519 over the
          // serialized message, with no domain separator, so
          // `signMessage(tx.message.serialize())` produces a signature that
          // validates on a real transaction. Allowing the method wholesale
          // restored the exact oracle this wrapper exists to close.
          //
          // So the escape hatch is scoped rather than total: the method is
          // permitted, but bytes that deserialize AS A TRANSACTION are still
          // refused. A caller signing genuine messages is unaffected.
          if (MESSAGE_SIGNING_METHODS.has(prop) && typeof value === "function") {
            return signMessageGuard(value as Function, qualified, target);
          }
          return value;
        }

        if (typeof value === "function") {
          // DEFAULT DENY. `sendTransaction` was the loud half of AW-11: it is
          // the method a wallet-adapter agent reaches for most, it moves money
          // without producing a detached signature, and it was handed back raw.
          if (SIGNING_METHODS.has(prop)) {
            return guardFn(value as Function, qualified, target);
          }
          if (SOLANA_SAFE_READS.has(prop)) return value.bind(target);
          return async () => {
            throw new Error(
              `x402-guard: refusing ${qualified}() — this wrapper does not know ` +
                `how to check it, and passing through an unmodelled method on a ` +
                `wallet is how a guard becomes a formality. If ${qualified} ` +
                `cannot move funds, name it in \`allow\` to pass it through.`,
            );
          };
        }

        // The inner `provider` / `adapter` was handed back whole, so
        // `wallet.provider.signTransaction` was the unguarded original.
        // EVERY object is wrapped, arrays included. Asking "does this object
        // look like a signer?" was a name allowlist one level down — the same
        // enumerate-instead-of-refuse inversion this wrapper exists to fix. A
        // nested `signDigest`, a signer at depth 3, or `accounts[0]` all
        // executed unguarded because none matched the modelled names.
        if (value !== null && typeof value === "object") {
          const v = value as Record<string, unknown>;
          // RAW KEY MATERIAL is not wrappable. anchor's NodeWallet exposes the
          // Keypair on `payer`; returning a Proxy over it changes nothing,
          // because `secretKey` is 64 bytes the caller simply reads. The only
          // safe answer is not to hand it over.
          if (v["secretKey"] !== undefined || v["_keypair"] !== undefined) {
            throw new Error(
              `x402-guard: refusing to expose ${qualified} — it carries raw key ` +
                `material, and a guard that hands back the secret key is not a ` +
                `guard. If you need the unwrapped object, name it in \`allow\`.`,
            );
          }
          // No depth cap and no shape test. Wrapping is lazy — the Proxy only
          // materialises on property access — so an arbitrarily deep or cyclic
          // graph costs nothing until something actually reaches into it, and
          // reaching in is exactly when the guard must be present.
          return wrap(value as object, qualified, depth + 1);
        }
        return value;
      },
    }) as O;

  return wrap(wallet, "", 0) as T;
}

// --- facilitator flow -------------------------------------------------------

/**
 * The relevant fields of an x402 `accepts` entry (PaymentRequirements) from
 * the server's 402 response. `maxAmountRequired` is the exact amount under
 * the `exact` scheme.
 */
export interface PaymentRequirements {
  scheme: string;
  network: string;
  payTo: string;
  asset: string;
  maxAmountRequired: string;
  [key: string]: unknown;
}

/**
 * Quote-text scanning, re-exported for convenience.
 *
 * The module itself has zero imports and is also published at
 * `wormhole-x402/quotetext`, so an EVM-only or bundle-conscious consumer can
 * take it without pulling in the Solana runtime. Re-exporting here is purely
 * so that `quoteFromRequirements` and `inspectQuoteText` — the two things you
 * do with a freshly-arrived 402 response — are reachable from one import.
 *
 * The pairing is the point. `quoteFromRequirements` extracts the three fields
 * that move money and DISCARDS everything else in the entry: description,
 * resource, mimeType, outputSchema, extra. That discarded remainder is exactly
 * the text the model goes on to read, and until now nothing in this package
 * looked at it.
 */
export {
  inspectQuoteText,
  assertQuoteTextClean,
  normalizeQuoteText,
  decodeUnicodeTags,
  type QuoteTextFinding,
  type QuoteTextVerdict,
  type InspectQuoteTextOptions,
} from "./quotetext.js";

/**
 * Opt-in local event sink (see sink.ts).
 *
 * OFF unless `configureEventSink` is called with a path. It writes six fields
 * per finding to a JSONL file on the operator's own disk and makes no network
 * call of any kind — the package's no-network guarantee is unchanged, and the
 * CI gate that enforces it still passes.
 */
export {
  configureEventSink,
  resetEventSink,
  recordVerdict,
  eventSinkStats,
  toEvents,
  amountBucket,
  resolveChainId,
  assertNoPlaintext,
  KNOWN_CODES,
  AMOUNT_BUCKETS,
  type PaymentEvent,
  type EventSinkOptions,
  type SinkContext,
  type SinkVerdictLike,
} from "./sink.js";

/** Map a 402 `accepts` entry to the quote the guard checks against. */
export function quoteFromRequirements(req: PaymentRequirements): PaymentQuote {
  if (
    typeof req?.payTo !== "string" ||
    typeof req?.asset !== "string" ||
    typeof req?.maxAmountRequired !== "string"
  ) {
    throw new Error(
      "x402-guard: payment requirements are missing payTo, asset, or maxAmountRequired",
    );
  }
  return { payTo: req.payTo, asset: req.asset, amount: req.maxAmountRequired };
}

/**
 * Inspect an X-PAYMENT payload — the facilitator flow.
 *
 * Most agents never submit a transaction themselves: they build and partially
 * sign one (the facilitator is the fee payer, which is what makes it feel
 * gasless), then ship it base64 inside the X-PAYMENT header. The client's key
 * still touches the bytes exactly once, and these are those bytes. Accepts
 * the decoded payload object or the base64/JSON header string.
 *
 * EVM authorization payloads (EIP-3009) carry no transaction to decode and
 * are abstained on, never allowed.
 */
export function inspectPaymentPayload(
  paymentHeader: unknown,
  quote: PaymentQuote,
  opts: InspectOptions = {},
): Verdict {
  let obj: unknown = paymentHeader;
  if (typeof paymentHeader === "string") {
    try {
      obj = JSON.parse(Buffer.from(paymentHeader, "base64").toString("utf8"));
    } catch {
      try {
        obj = JSON.parse(paymentHeader);
      } catch {
        return {
          decision: "abstain",
          findings: [],
          reason:
            "payment payload is neither base64-encoded JSON nor JSON — refusing to report it as safe",
        };
      }
    }
  }
  const p = obj as {
    x402Version?: unknown;
    scheme?: unknown;
    accepted?: { scheme?: unknown } | null;
    payload?: { transaction?: unknown };
  };
  if (typeof p !== "object" || p === null) {
    return {
      decision: "abstain",
      findings: [],
      reason: "payment payload is not an object",
    };
  }

  // The scheme moved between protocol versions.
  //
  //   v1: { x402Version: 1, scheme: "exact", network, payload: {...} }
  //   v2: { x402Version: 2, accepted: { scheme: "exact", network, ... },
  //         payload: {...}, resource: {...}, extensions: {} }
  //
  // Read from the v2 location first, falling back to the v1 one. Reading only
  // the top level meant every current-spec payload arrived with
  // `scheme === undefined` and abstained -- fail-closed, so no wrong-allow,
  // but a guard that abstains on 100% of live traffic is a guard nobody keeps
  // installed. Verified against specs/x402-specification-v2.md §5.2.1 in the
  // x402-foundation repository.
  //
  // Deliberately not keyed on `x402Version`: an envelope that declares v1 and
  // carries `accepted`, or vice versa, is still unambiguous about where its
  // scheme is, and refusing to read it would reintroduce the same blind spot
  // for anyone whose version field is wrong.
  const accepted =
    typeof p.accepted === "object" && p.accepted !== null ? p.accepted : null;
  const scheme = accepted?.scheme !== undefined ? accepted.scheme : p.scheme;

  if (scheme !== "exact") {
    return {
      decision: "abstain",
      findings: [],
      reason:
        scheme === undefined
          ? "payment payload declares no scheme in either the v2 (accepted.scheme) or v1 (scheme) location — refusing to guess"
          : `unsupported x402 scheme (${String(scheme)}) — only "exact" is checked`,
    };
  }
  const tx = p.payload?.transaction;
  if (typeof tx !== "string") {
    return {
      decision: "abstain",
      findings: [],
      reason:
        "payload carries no transaction to decode (EVM authorization payloads are not yet supported)",
    };
  }
  return inspectPayment(tx, quote, opts);
}
