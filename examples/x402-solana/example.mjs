/**
 * wormhole-x402 — Solana payment guard, end to end.
 *
 * Wraps a real Keypair in guardSigner() and puts four transactions through it:
 * one that conforms to the quote, one redirected to an attacker, one that
 * carries a Token-2022 extension instruction, and one signed with no quote.
 *
 * Everything here is offline. No RPC is contacted, no airdrop is requested,
 * and no transaction is ever submitted — the blockhash is a fixed dummy value.
 * The keypairs are generated fresh on every run and thrown away.
 */

import {
  Keypair,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  createTransferCheckedInstruction,
  createTransferCheckedWithFeeInstruction,
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
} from "@solana/spl-token";
import { guardSigner, inspectPayment } from "wormhole-x402";

// --- the cast -------------------------------------------------------------
// Deterministic seeds so the printed addresses are stable between runs. In a
// real integration `payer` is the agent's wallet and `merchant` comes from the
// 402 response; nothing here should be reused as an actual key.
const seed = (n) => Uint8Array.from({ length: 32 }, (_, i) => (i + n) & 0xff);
const payer = Keypair.fromSeed(seed(1));
const merchant = Keypair.fromSeed(seed(2));
const attacker = Keypair.fromSeed(seed(3));

// A stand-in USDC mint. The guard never fetches it; it only derives addresses.
const MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

/**
 * The quote is what the merchant's 402 response said the payment would be.
 * It is the ONLY thing the transaction gets compared against. In production
 * this comes off the trusted HTTP channel, not from anything the model wrote.
 */
const quote = {
  asset: MINT.toBase58(),
  payTo: merchant.publicKey.toBase58(),
  amount: "1000000", // 1.000000 USDC, in base units
};

// Associated token accounts. The guard re-derives the destination itself from
// (payTo, asset) — passing it the wrong one is the whole point of case 2.
const ata = (owner, program = TOKEN_PROGRAM_ID) =>
  getAssociatedTokenAddressSync(MINT, owner, true, program);

const DUMMY_BLOCKHASH = "11111111111111111111111111111111";

/** Build an unsigned v0 transaction. guardSigner REQUIRES VersionedTransaction. */
function buildTx(instructions) {
  const message = new TransactionMessage({
    payerKey: payer.publicKey,
    recentBlockhash: DUMMY_BLOCKHASH,
    instructions,
  }).compileToV0Message();
  return new VersionedTransaction(message);
}

// --- a wallet ------------------------------------------------------------
// Minimal stand-in for a wallet adapter. `signed` records whether the real
// signing path was reached, which is what we actually want to assert: a
// refusal must mean no signature was produced, not merely that an error was
// printed after the fact.
function makeWallet(keypair) {
  return {
    publicKey: keypair.publicKey,
    signed: 0,
    signTransaction(tx) {
      this.signed += 1;
      tx.sign([keypair]);
      return tx;
    },
  };
}

function show(title, note) {
  console.log("\n" + "=".repeat(72));
  console.log(title);
  if (note) console.log(note);
  console.log("=".repeat(72));
}

/**
 * Run a transaction through a guarded wallet and report what happened.
 *
 * IMPORTANT: the guarded method is ASYNC even when the underlying wallet's
 * signTransaction is synchronous — guardSigner's proxy always returns an async
 * function. You MUST await it (or .catch it). A plain synchronous try/catch
 * around a guarded call catches nothing: the refusal becomes an unhandled
 * rejection, the line after it runs as if signing succeeded, and the process
 * dies later with a stack trace pointing at the guard. That failure mode looks
 * exactly like the guard being broken, and it is the easiest way to
 * accidentally ship a guard that does not stop anything.
 */
async function attempt(label, tx, getQuote = () => quote) {
  const wallet = makeWallet(payer);
  const guarded = guardSigner(wallet, getQuote);
  try {
    await guarded.signTransaction(tx);
    console.log(`${label}: SIGNED (wallet.signTransaction calls: ${wallet.signed})`);
  } catch (err) {
    // guardSigner throws a PLAIN Error. There is no err.verdict — the detail
    // lives only in the message. Use inspectPayment directly if you need the
    // structured findings.
    console.log(`${label}: REFUSED, nothing was signed`);
    console.log(`  ${err.message}`);
    console.log(`  wallet.signTransaction calls: ${wallet.signed}`);
  }
}

console.log("payer    ", payer.publicKey.toBase58());
console.log("merchant ", merchant.publicKey.toBase58());
console.log("attacker ", attacker.publicKey.toBase58());
console.log("quote    ", JSON.stringify(quote));
console.log("merchant ATA (expected destination):", ata(merchant.publicKey).toBase58());

// =========================================================================
// 1. Conforming payment — ALLOW
// =========================================================================
show(
  "1. Conforming payment — expect ALLOW",
  "1 USDC to the merchant's ATA, exactly the quoted amount.",
);
const conforming = buildTx([
  createTransferCheckedInstruction(
    ata(payer.publicKey),
    MINT,
    ata(merchant.publicKey),
    payer.publicKey,
    1_000_000n,
    6,
  ),
]);
console.log("inspectPayment:", JSON.stringify(inspectPayment(conforming.serialize(), quote), null, 2));
await attempt("guardSigner", conforming);

// =========================================================================
// 2. Redirected payee — REFUSE X402-001
// =========================================================================
show(
  "2. Redirected destination — expect REFUSE X402-001",
  "Same amount, same mint, but the destination ATA belongs to the attacker.\n" +
    "This is the attack the package exists for: the quote the agent showed the\n" +
    "user is correct, and the bytes it is about to sign are not.",
);
const redirected = buildTx([
  createTransferCheckedInstruction(
    ata(payer.publicKey),
    MINT,
    ata(attacker.publicKey), // <-- swapped
    payer.publicKey,
    1_000_000n,
    6,
  ),
]);
console.log("inspectPayment:", JSON.stringify(inspectPayment(redirected.serialize(), quote), null, 2));
await attempt("guardSigner", redirected);

// =========================================================================
// 3. Token-2022 extension instruction — REFUSE X402-006
// =========================================================================
show(
  "3. Token-2022 TransferCheckedWithFee — expect REFUSE X402-006",
  "Built with the official @solana/spl-token helper, paying the CORRECT\n" +
    "merchant ATA the CORRECT amount. It is refused anyway, because the guard\n" +
    "allowlists the two plain transfer forms and will not guess at what an\n" +
    "extension instruction does to the payer's funds offline.\n" +
    "Note the instruction is 26/1 — a switch reading only data[0] never sees a\n" +
    "transfer here, which is exactly how this was once a wrong-allow bug.",
);
const t22 = buildTx([
  createTransferCheckedWithFeeInstruction(
    ata(payer.publicKey, TOKEN_2022_PROGRAM_ID),
    MINT,
    ata(merchant.publicKey, TOKEN_2022_PROGRAM_ID),
    payer.publicKey,
    1_000_000n,
    6,
    0n, // fee
    [],
    TOKEN_2022_PROGRAM_ID,
  ),
]);
console.log("inspectPayment:", JSON.stringify(inspectPayment(t22.serialize(), quote), null, 2));
await attempt("guardSigner", t22);

// =========================================================================
// 4. No quote — fails closed
// =========================================================================
show(
  "4. No quote available — expect a throw, not a pass",
  "A guard whose default is 'allow when unconfigured' reports green on all\n" +
    "traffic and nobody notices. Missing quote is a refusal.",
);
await attempt("guardSigner", buildTx([
  createTransferCheckedInstruction(
    ata(payer.publicKey),
    MINT,
    ata(merchant.publicKey),
    payer.publicKey,
    1_000_000n,
    6,
  ),
]), () => null);

console.log("\nDone. No network calls were made and no transaction was submitted.");
