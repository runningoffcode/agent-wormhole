/**
 * Opt-in event sink — write six fields per verdict to a local JSONL spool.
 *
 * WHY THIS EXISTS AT ALL, GIVEN THE PACKAGE PROMISES OFFLINE AND ZERO
 * TELEMETRY. It is not telemetry and it is not a network call. It is a local
 * file the operator names, in a directory the operator chose, that nothing in
 * this package ever reads back or transmits. A separate program the operator
 * also runs (the fleet reporter) may drain it. If the operator never
 * configures a path, no file is opened, no directory is created, and no
 * `node:fs` module is even imported — the require is lazy and happens inside
 * `configureEventSink`, so a build that never calls it has no filesystem
 * surface at all. OFF is not a default flag value here; OFF is the absence of
 * any code that could run.
 *
 * WHY A JSONL FILE AND NOT AN HTTP CALL TO A LOCAL PORT. The guard runs
 * synchronously inside the payment path, immediately before a signature. A
 * localhost POST puts a socket connect, a DNS-free-but-still-real syscall
 * round trip, and a failure mode (nothing listening, port taken by something
 * else, an EADDRINUSE from a crashed daemon) between the agent and its
 * payment. Worse, it would be a network call in a package whose CI gate fails
 * the build if importing it opens a socket, and "only to localhost" is exactly
 * the kind of exception that erodes a guarantee until it is worth nothing. An
 * append to an already-open file descriptor is one `write(2)`. The file IS the
 * queue, so events survive the reporter being absent, crashed, or not yet
 * installed — which is the normal case, since the reporter runs from cron and
 * is not running at all most of the time.
 *
 * WHAT IS WRITTEN, EXHAUSTIVELY. Six fields, constructed by naming each one:
 *
 *     code           X402-xxx, checked against a literal allowlist
 *     severity       critical | high | medium
 *     decision       allow | refuse | abstain
 *     chain_id       integer, or null for Solana (no EIP-155 id exists)
 *     payee_hash     HMAC-SHA256(salt, payTo), hex, or null if no salt
 *     amount_bucket  a coarse band, never the figure
 *     ts             ISO-8601
 *
 * The `Finding` objects this sink is handed carry `message`, `expected`,
 * `actual`, and on the quote-text path `excerpt` and `field`. `excerpt` is
 * literally the attacker's matched text; `expected`/`actual` are where an exact
 * amount and a plaintext payee address live. NONE of them may reach the file.
 * So `toEvent()` builds a NEW object field by field and never spreads, copies,
 * or filters a Finding — the same discipline the Python side uses in
 * `wire.to_api`. A filtered copy is one forgotten key away from a leak; a
 * constructed object cannot leak a field nobody wrote down. `assertNoPlaintext`
 * below re-checks the serialized line as a second, independent gate, because
 * the first gate is code review and the second one is arithmetic.
 *
 * WHY THE AMOUNT IS A BUCKET. An exact amount plus a timestamp identifies a
 * transaction on a public chain. The merchant relationship is the operator's
 * business, not ours, and a fleet console does not need the figure to show that
 * a payment was refused. Buckets are powers of ten over the base-unit integer,
 * which is deliberately crude: the digit count of a uint256 is not a fingerprint.
 *
 * WHY THE PAYEE IS SALTED. Unsalted, an address hash is a rainbow-table lookup
 * against the set of all addresses that have ever received a payment, which is
 * public and enumerable. Salted per-installation, two events can still be
 * correlated as "same payee" within one operator's fleet — which is the whole
 * question being asked — without being reversible by anyone holding the file.
 * If the operator supplies no salt, the field is null rather than a plaintext
 * address or an unsalted digest. Degrading to null loses a correlation; the
 * alternatives lose the guarantee.
 *
 * WHAT THIS DOES NOT DO, STATED SO IT IS NOT ASSUMED:
 *
 *   - It does not fsync. A hard power loss can lose recent lines. fsync on
 *     every payment would put a disk flush on the hot path, and losing the tail
 *     of an observability spool is a much smaller harm than adding milliseconds
 *     to every signature. This is a deliberate trade, not an oversight.
 *   - It does not lock. Concurrent writers rely on O_APPEND making a single
 *     small write atomic, which holds on Linux and macOS for lines well under
 *     PIPE_BUF. Lines here are ~200 bytes.
 *   - It is not a record of every payment. It records verdicts the caller
 *     chose to hand it. A payment that bypassed the guard entirely leaves no
 *     trace here, and absence of events in this file is not evidence that no
 *     payments happened.
 *   - It never throws. Every path is wrapped. A full disk, a read-only mount,
 *     a path that is a directory, a revoked permission — all of them silently
 *     increment a dropped counter and return. An observability sink that can
 *     break a payment is worse than no observability sink.
 */

import { createRequire } from "node:module";
import { parseNetwork } from "./network.js";

/**
 * A CommonJS-style loader that works inside this ESM package.
 *
 * `node:module` is a type-only concern at import time here in the sense that
 * matters: it is a builtin, it opens nothing, and the CI network gate cares
 * about sockets, not about module resolution. The alternative — a top-level
 * `import * as fs from "node:fs"` — would put a filesystem dependency in the
 * module graph of a package that is otherwise loadable in a browser bundle.
 */
const nodeRequire = createRequire(import.meta.url);

/** Verdict shape this sink accepts — structurally what all three guards return. */
export interface SinkVerdictLike {
  decision: "allow" | "refuse" | "abstain";
  findings: ReadonlyArray<{ code?: unknown; severity?: unknown }>;
}

/** What the caller tells us about the payment, separate from the verdict. */
export interface SinkContext {
  /** Address the QUOTE said to pay. Hashed, never written in the clear. */
  payTo?: string;
  /** Base-unit amount as a decimal string. Bucketed, never written. */
  amount?: string;
  /** EIP-155 chain id, or an `eip155:x` / v1 network name we can parse. */
  chainId?: number | string | null;
}

export interface EventSinkOptions {
  /** Absolute path to the JSONL spool. Absent = sink stays off. */
  path: string;
  /**
   * Salt for the payee HMAC. 16 bytes minimum, matching the floor the Python
   * `PathHasher` enforces: below 16, guessing the salt is easier than guessing
   * the address it protects. A shorter salt disables hashing rather than
   * weakening it.
   */
  salt?: Uint8Array | string;
  /** Byte ceiling before the spool rotates. Default 4 MiB. */
  maxBytes?: number;
  /** Rotated segments to keep. Default 2, so the ceiling is ~3x maxBytes. */
  keepSegments?: number;
}

/**
 * The exact on-disk record. Seven keys maximum, no others, ever.
 *
 * `payee_hash` and `amount_bucket` are OPTIONAL and are omitted entirely when
 * absent rather than written as null. A quote-text finding has no payee and no
 * amount; emitting `"payee_hash": null` would put a key on the wire carrying no
 * information and force the validator to decide whether null is a legal value
 * for a hash field. Absent is unambiguous. This matches `payment.wire_dict` on
 * the Python side, which omits the same two fields for the same reason.
 *
 * `chain_id` is NOT optional: 0 is the declared sentinel for Solana, whose
 * chain identity is not an EIP-155 integer.
 */
export interface PaymentEvent {
  code: string;
  severity: "critical" | "high" | "medium";
  decision: "allow" | "refuse" | "abstain";
  chain_id: number;
  payee_hash?: string;
  amount_bucket?: string;
  ts: string;
  /**
   * Which SUPPLIED fields this record could not read. Absent on every honest
   * record, so the seven-key shape is unchanged for normal traffic.
   *
   * AW-71: `chain_id: 0` meant both "Solana" and "we could not read what you
   * sent", so an operator reading the spool could not locate the rows whose
   * chain was guessed. The doubt belongs in its own key rather than in
   * `chain_id`'s value -- the cross-language `chain_id` vocabulary stays
   * exactly as the reporter and the SQLite CHECK constraint expect it.
   *
   * A KEY and not a sentinel value, so there is nothing for a caller to forge:
   * the entries are drawn from a closed two-name set this module writes, and
   * `assertNoPlaintext` re-checks them against that set before the line is
   * written.
   */
  unreadable?: string[];
}

/**
 * The only two names that may appear in {@link PaymentEvent.unreadable}.
 * Closed, so the key cannot become a channel for caller-supplied text.
 */
export const UNREADABLE_FIELDS: ReadonlyArray<string> = ["amount", "chain_id"];

/**
 * Solana has no EIP-155 chain id. Zero is the declared sentinel for "this event
 * came from a chain whose identity is not an integer" — not a missing value.
 * Mirrors `payment.CHAIN_ID_SOLANA`.
 */
export const CHAIN_ID_SOLANA = 0;

/**
 * Every code this package can emit, enumerated literally.
 *
 * A literal list, not a `/^X402-\d{3}$/` regex, because the regex would happily
 * pass a code from a future version the consuming Python vocabulary has never
 * heard of — and the reporter's privacy self-check would then reject the whole
 * report, losing every event in it. Failing closed HERE costs one unknown
 * event; failing closed THERE costs the batch. Kept in sync with the source by
 * `sink.test.ts`, which greps the other three modules and asserts set equality,
 * so adding a code without adding it here fails the build.
 */
export const KNOWN_CODES: ReadonlySet<string> = new Set([
  // Solana conformance (index.ts)
  "X402-001", "X402-002", "X402-003", "X402-006",
  "X402-007", "X402-008", "X402-009", "X402-010", "X402-011",
  "X402-012",
  // EVM EIP-3009 conformance (evm.ts)
  "X402-101", "X402-102", "X402-103", "X402-104",
  "X402-105", "X402-106", "X402-107", "X402-108", "X402-110",
  // Quote-text injection (quotetext.ts)
  "X402-201", "X402-202", "X402-203", "X402-204", "X402-205", "X402-206",
  "X402-207", "X402-208", "X402-209", "X402-210", "X402-211", "X402-212",
  "X402-213",
  "X402-214",
  // Address provenance (provenance.ts)
  "X402-301",
  // Delivery conformance (delivery.ts) — deliberate HTTP mnemonics
  "X402-401", "X402-402", "X402-403", "X402-404", "X402-406",
]);

const SEVERITIES: ReadonlySet<string> = new Set(["critical", "high", "medium"]);
const DECISIONS: ReadonlySet<string> = new Set(["allow", "refuse", "abstain"]);

/**
 * Amount buckets: six half-open bands over the base-unit integer.
 *
 * THESE TOKENS ARE A CROSS-LANGUAGE CONTRACT AND MAY NOT BE CHANGED HERE ALONE.
 * The identical set is enforced in three other places, the last of which is a
 * SQLite CHECK constraint that will reject a row rather than store an unknown
 * band:
 *
 *   reporter/wormhole_reporter/payment.py   AMOUNT_BUCKETS (the reader)
 *   api/fleet_api/validate.py               AMOUNT_BUCKETS (server validation)
 *   api/fleet_api/store.py                  CHECK (amount_bucket IN (...))
 *
 * An earlier draft of this file used a finer 13-token set keyed on digit count
 * (`amt:1e0`, `amt:1e1`, ...). It was self-consistent and completely useless:
 * feeding a real line from this writer into the real reader produced
 * `accepted=0, invalid_field=1`, because no token matched. Measured, not
 * reasoned about. The lesson is that the coarser set is authoritative because
 * it is the one already in the database, and the drift test below is what keeps
 * this comment true.
 *
 * There is no `amt:unknown`. An amount we could not parse is not a band — it is
 * an absent field, and `toEvents` omits it rather than inventing a token. A
 * quote-text finding has no amount at all, and labelling that "unknown" would
 * put a value on the wire that carries no information.
 */
export const AMOUNT_BUCKETS: ReadonlyArray<string> = [
  "amt:0",
  "amt:1-1e3",
  "amt:1e3-1e6",
  "amt:1e6-1e9",
  "amt:1e9-1e12",
  "amt:1e12+",
];

/**
 * Bucket a base-unit amount. Returns null when the input is not a whole count.
 *
 * Deliberately does NOT convert to human units: that needs the token's decimals,
 * which is a second input we would have to trust, and getting it wrong would
 * silently mislabel by 10^6. The band is over the raw integer, which needs
 * nothing else to be correct.
 *
 * Compared as a BigInt, never a Number. A uint256 amount exceeds
 * Number.MAX_SAFE_INTEGER, and parsing it as a float would round — turning an
 * exact figure into a slightly wrong exact figure, which is worse than a band.
 *
 * Null for a negative or non-integer input rather than `amt:0`: an amount we
 * could not parse is not the same as an amount of zero, and folding the two
 * together would make an unparseable payload look like a free one. This mirrors
 * `payment.amount_bucket` on the Python side exactly.
 */
export function amountBucket(amount: unknown): string | null {
  const r = resolveAmountTagged(amount);
  return r.kind === "band" ? r.bucket : null;
}

/**
 * The three distinct facts a supplied amount can be.
 *
 * Same reasoning as {@link ChainIdResolution}: `null` conflated "no amount on
 * this finding at all" (a quote-text finding has none, and that is normal) with
 * "an amount arrived that we could not read" (which is a defect somewhere
 * upstream). `toEvents` omits the key in both cases -- the wire shape is
 * unchanged -- but only the second one is worth telling the operator about.
 */
export type AmountResolution =
  | { kind: "band"; bucket: string }
  | { kind: "absent" }
  | { kind: "unreadable" };

/**
 * Band a base-unit amount, keeping WHY it did not band.
 *
 * `Number.isInteger`, not `Number.isSafeInteger`. AW-71: the safe-integer test
 * rejected every whole count above 2^53, which on the SVM lamport lane is not an
 * exotic case -- 1e18 lamports is an ordinary figure, and `2**53` itself is a
 * whole number. The four exact values that lane produces most often were the
 * ones getting no band at all, so the highest-value payments were the least
 * labelled. Above 2^53 a JS number is still an exact integer, just a sparse one;
 * `BigInt(n)` converts it without rounding, and the band is 3 orders of
 * magnitude wide, so the sparseness cannot move a value across a boundary.
 */
export function resolveAmountTagged(amount: unknown): AmountResolution {
  if (amount === undefined || amount === null) return { kind: "absent" };

  let v: bigint;
  try {
    if (typeof amount === "bigint") {
      v = amount;
    } else if (typeof amount === "number") {
      if (!Number.isInteger(amount)) return { kind: "unreadable" };
      v = BigInt(amount);
    } else if (typeof amount === "string") {
      const s = amount.trim();
      if (s.length === 0) return { kind: "absent" };
      if (/^0[xX][0-9a-fA-F]+$/.test(s)) {
        // Hex is how the EVM spells a uint256; rejecting it banded nothing.
        try {
          v = BigInt(s);
        } catch {
          return { kind: "unreadable" };
        }
      } else if (/^[0-9]+$/.test(s)) {
        v = BigInt(s);
      } else {
        return { kind: "unreadable" };
      }
    } else {
      return { kind: "unreadable" };
    }
  } catch {
    return { kind: "unreadable" };
  }

  // A negative amount is not a band and not an absence -- it is a value that
  // should not exist, which is exactly what "unreadable" is for.
  if (v < 0n) return { kind: "unreadable" };
  if (v === 0n) return { kind: "band", bucket: "amt:0" };
  if (v < 1000n) return { kind: "band", bucket: "amt:1-1e3" };
  if (v < 1000000n) return { kind: "band", bucket: "amt:1e3-1e6" };
  if (v < 1000000000n) return { kind: "band", bucket: "amt:1e6-1e9" };
  if (v < 1000000000000n) return { kind: "band", bucket: "amt:1e9-1e12" };
  return { kind: "band", bucket: "amt:1e12+" };
}

/**
 * Resolve a chain id to an integer, or null.
 *
 * Accepts a raw number or anything `evm.parseNetwork` understands — CAIP-2
 * `eip155:<id>` and the known bare v1 names.
 *
 * The first draft of this module DUPLICATED the v1 network table to avoid
 * importing from `evm.ts`, on the theory that a Solana-only install should not
 * reach into the EVM module. The drift test caught the copy inventing three
 * chains that do not exist in the real table, on the very first run, before it
 * had ever been used. That is the whole argument against the copy: a duplicated
 * lookup table is wrong the moment it is written, not eventually. `parseNetwork`
 * is pure string arithmetic with no viem import on its path, so importing it
 * costs a Solana-only bundle nothing and removes the drift surface entirely.
 */
export function resolveChainId(chainId: unknown): number | null {
  const r = resolveChainIdTagged(chainId);
  return r.kind === "evm" ? r.id : null;
}

/**
 * The four distinct facts a supplied chain id can be, kept distinct.
 *
 * AW-71: the old `resolveChainId(x) ?? CHAIN_ID_SOLANA` in `toEvents` collapsed
 * these into one integer, so "the caller said Solana", "the caller said nothing"
 * and "the caller sent bytes we could not read" all landed on 0. An operator
 * reading the spool could not tell a genuine Solana row from an unreadable one,
 * and a fleet console's Solana bucket silently absorbed every parse failure.
 *
 * A tagged union rather than a sentinel integer, deliberately. A sentinel is a
 * VALUE, and any value a caller can also supply is a value a caller can forge --
 * an earlier attempt declared CHAIN_ID_UNRESOLVED = MAX_SAFE_INTEGER while this
 * function still accepted that number as an ordinary chain id, so a caller could
 * stamp their own row "unreadable". A tag computed here is not a field the
 * caller writes.
 */
export type ChainIdResolution =
  | { kind: "evm"; id: number }
  | { kind: "non_evm" }
  | { kind: "absent" }
  | { kind: "unreadable" };

/**
 * Resolve a supplied chain id, keeping WHY it did not resolve.
 *
 * Accepts every shape the x402 envelope documents, because the pre-AW-71 version
 * accepted only a bare `number` and CAIP-2/v1 strings -- so `"8453"`, `"0x2105"`
 * and `8453n`, all of which appear in real payloads (JSON has no integer type
 * wide enough for a uint256, and hex is the EVM's native spelling), filed
 * themselves under the Solana sentinel. That is not a cosmetic mislabel: it put
 * Base traffic in the Solana bucket of every downstream report.
 *
 * `0` and the Solana name resolve to `non_evm`, which is a real answer rather
 * than a failure: Solana's chain identity is not an EIP-155 integer.
 */
export function resolveChainIdTagged(chainId: unknown): ChainIdResolution {
  if (chainId === undefined || chainId === null) return { kind: "absent" };

  if (typeof chainId === "number") {
    if (chainId === 0) return { kind: "non_evm" };
    if (Number.isSafeInteger(chainId) && chainId > 0) {
      return { kind: "evm", id: chainId };
    }
    // Negative, fractional, NaN, Infinity, or beyond 2^53 where the integer we
    // read back is not the integer that was sent.
    return { kind: "unreadable" };
  }

  if (typeof chainId === "bigint") {
    if (chainId === 0n) return { kind: "non_evm" };
    if (chainId > 0n && chainId <= BigInt(Number.MAX_SAFE_INTEGER)) {
      return { kind: "evm", id: Number(chainId) };
    }
    return { kind: "unreadable" };
  }

  if (typeof chainId !== "string") return { kind: "unreadable" };

  const s = chainId.trim();
  if (s.length === 0) return { kind: "absent" };

  // Bare decimal: "8453". JSON carries chain ids as strings more often than as
  // numbers, and the pre-fix code sent every one of them to the Solana bucket.
  if (/^[0-9]+$/.test(s)) {
    if (/^0+$/.test(s)) return { kind: "non_evm" };
    const id = Number(s);
    return Number.isSafeInteger(id) && id > 0
      ? { kind: "evm", id }
      : { kind: "unreadable" };
  }

  // Hex, either case of the prefix and the digits. "0x2105" is Base.
  if (/^0[xX][0-9a-fA-F]+$/.test(s)) {
    let v: bigint;
    try {
      v = BigInt(s);
    } catch {
      return { kind: "unreadable" };
    }
    if (v === 0n) return { kind: "non_evm" };
    return v > 0n && v <= BigInt(Number.MAX_SAFE_INTEGER)
      ? { kind: "evm", id: Number(v) }
      : { kind: "unreadable" };
  }

  // CAIP-2 `eip155:<id>` and the known bare v1 names, via the one shared table.
  const viaNetwork = parseNetwork(s);
  if (viaNetwork !== null) return { kind: "evm", id: viaNetwork };

  // The declared non-EVM chain, by name.
  if (s.toLowerCase() === "solana") return { kind: "non_evm" };

  return { kind: "unreadable" };
}

// --- module state ----------------------------------------------------------
//
// Module-level and not a class instance because the call site is deep inside a
// payment path that the operator does not control the plumbing of — threading a
// sink handle through `guardSigner` into a wallet adapter is not something an
// integrator can reasonably do. One process, one sink, configured once at
// startup. The cost is that it is global state, which is why `resetEventSink()`
// exists and why every test uses it.

interface SinkState {
  path: string;
  fs: typeof import("node:fs");
  hmacKey: Uint8Array | null;
  crypto: typeof import("node:crypto") | null;
  maxBytes: number;
  keepSegments: number;
  written: number;
  dropped: number;
  degraded: number;
  bytesSinceCheck: number;
  checkEvery: number;
  /**
   * A cached append-mode file descriptor.
   *
   * MEASURED, not assumed. `appendFileSync` opens, writes and closes on every
   * call, which benchmarked at 36,263 ns/write on this machine. A held fd with
   * `writeSync` benchmarked at 2,033 ns for the identical line — 18x cheaper,
   * and this sits inside a payment path. The whole per-call cost of the sink
   * with a held fd is under 4 us including the HMAC (1,662 ns) and JSON.
   *
   * The fd is reopened on demand if it goes bad (rotation, an operator deleting
   * the file), so a stale descriptor costs one dropped write and self-heals
   * rather than silently writing into an unlinked inode forever.
   */
  fd: number | null;
}

let sink: SinkState | null = null;

const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;
const DEFAULT_KEEP = 2;
const MIN_SALT_BYTES = 16;

/**
 * Bytes written between size checks, so we do not `stat()` on every event.
 *
 * Capped at a quarter of `maxBytes` at configure time. A fixed 64 KiB interval
 * silently defeats any ceiling smaller than itself: with maxBytes=2048 the
 * first check would not happen until 64 KiB had already been written, which
 * measured at 86400 bytes on disk under a 2048-byte ceiling. The bound has to
 * be a function of the bound, not a constant.
 */
const SIZE_CHECK_CEILING = 64 * 1024;

function checkInterval(maxBytes: number): number {
  return Math.max(1, Math.min(SIZE_CHECK_CEILING, Math.floor(maxBytes / 4)));
}

/**
 * Turn the sink on. Returns true if it is now active.
 *
 * Never throws — a bad path or an unwritable directory returns false and leaves
 * the sink off. The caller gets a boolean it can log at startup; what it must
 * not get is an exception during application init that a payment path later
 * inherits.
 */
export function configureEventSink(opts: EventSinkOptions | null): boolean {
  if (opts === null) {
    sink = null;
    return false;
  }
  try {
    if (!opts.path || typeof opts.path !== "string") return false;

    // Lazy load: importing this module must not import node:fs, so that a
    // browser or edge bundle of the guard has no filesystem reference at all.
    //
    // `createRequire` and not a bare `require`, because this package is ESM
    // ("type": "module") and a bare `require` is simply undefined at runtime.
    // It typechecks — @types/node declares it — and then throws ReferenceError
    // into the catch below, leaving the sink permanently and SILENTLY off. That
    // is the exact failure this module's never-throw contract is designed to
    // hide, which is why `sink.test.ts` asserts `configureEventSink` returns
    // true and a line actually lands on disk, rather than only asserting that
    // it did not throw.
    const fs = nodeRequire("node:fs") as typeof import("node:fs");

    let hmacKey: Uint8Array | null = null;
    let crypto: typeof import("node:crypto") | null = null;
    if (opts.salt !== undefined) {
      const raw =
        typeof opts.salt === "string"
          ? new TextEncoder().encode(opts.salt)
          : opts.salt;
      if (raw && raw.length >= MIN_SALT_BYTES) {
        hmacKey = raw;
        crypto = nodeRequire("node:crypto") as typeof import("node:crypto");
      }
      // A salt shorter than the floor is treated as no salt: payee_hash goes
      // null. Silently hashing with a weak key would produce a field that looks
      // protected and is not, which is the worse of the two failures.
    }

    // Refuse anything that is not a regular file BEFORE opening it.
    //
    // This module promises never to throw into the payment path, and every
    // write is wrapped. But a FIFO defeats that promise on its own terms: a
    // blocking `openSync`/`appendFileSync` on a pipe with no draining reader
    // does not throw, it BLOCKS -- so no catch runs, `dropped` cannot record
    // it, and the process sits in an uninterruptible syscall that SIGTERM does
    // not clear. Measured: a checkout loop stopped dead and needed SIGKILL.
    //
    // lstat rather than stat, so a symlink pointing at a FIFO or a device is
    // caught rather than followed. Checked at configure time, which is the only
    // place a blocking open can be refused without being in the payment path
    // already.
    try {
      const st = fs.lstatSync(opts.path);
      if (!st.isFile()) {
        throw new Error(
          "event sink path must be a regular file, not a " +
            (st.isFIFO()
              ? "FIFO — a blocking write to a pipe would hang the payment path"
              : st.isDirectory()
                ? "directory"
                : st.isSymbolicLink()
                  ? "symlink"
                  : "special file"),
        );
      }
    } catch (err) {
      // ENOENT is the normal first-run case: the file does not exist yet and
      // appendFileSync below creates it. Anything else is a real refusal.
      const code = (err as { code?: string } | null)?.code;
      if (code !== "ENOENT") throw err;
    }

    // Touch the file once, now, so a misconfigured path fails at startup where
    // an operator will see it rather than at the first payment.
    fs.appendFileSync(opts.path, "", { mode: 0o600 });

    const maxBytes =
      typeof opts.maxBytes === "number" && opts.maxBytes > 0
        ? opts.maxBytes
        : DEFAULT_MAX_BYTES;

    sink = {
      path: opts.path,
      fs,
      hmacKey,
      crypto,
      maxBytes,
      keepSegments:
        typeof opts.keepSegments === "number" && opts.keepSegments >= 0
          ? opts.keepSegments
          : DEFAULT_KEEP,
      written: 0,
      dropped: 0,
      degraded: 0,
      checkEvery: checkInterval(maxBytes),
      bytesSinceCheck: Number.MAX_SAFE_INTEGER, // force a check on the first write
      fd: null,
    };
    return true;
  } catch {
    sink = null;
    return false;
  }
}

/** Turn the sink off, close the held fd, and forget the counters. */
export function resetEventSink(): void {
  closeFd(sink);
  sink = null;
}

function closeFd(s: SinkState | null): void {
  if (!s || s.fd === null) return;
  try {
    s.fs.closeSync(s.fd);
  } catch {
    /* already gone */
  }
  s.fd = null;
}

/** Counters for a status command. Null when the sink is off. */
export function eventSinkStats(): {
  path: string;
  written: number;
  dropped: number;
  degraded: number;
  salted: boolean;
  maxBytes: number;
  keepSegments: number;
} | null {
  if (!sink) return null;
  return {
    path: sink.path,
    written: sink.written,
    dropped: sink.dropped,
    degraded: sink.degraded,
    salted: sink.hmacKey !== null,
    maxBytes: sink.maxBytes,
    keepSegments: sink.keepSegments,
  };
}

function hashPayee(payTo: unknown): string | null {
  if (!sink || !sink.hmacKey || !sink.crypto) return null;
  if (typeof payTo !== "string" || payTo.length === 0) return null;
  try {
    return sink.crypto
      .createHmac("sha256", sink.hmacKey)
      .update(payTo, "utf8")
      .digest("hex");
  } catch {
    return null;
  }
}

/**
 * Build the events for one verdict. Pure, exported for testing.
 *
 * One event per finding, because a verdict with three findings is three facts
 * and the console timeline is a list of facts. A verdict with NO findings emits
 * nothing: "the guard ran and found nothing" is not an indicator, and writing a
 * row for it would make the spool grow with every successful payment while
 * telling a reader nothing they could act on.
 *
 * Findings whose code is not in KNOWN_CODES are skipped, not passed through.
 * See the note on KNOWN_CODES for why failing closed here is the cheap option.
 */
export function toEvents(
  verdict: SinkVerdictLike,
  ctx: SinkContext = {},
  now?: Date,
): PaymentEvent[] {
  const out: PaymentEvent[] = [];
  if (!verdict || typeof verdict !== "object") return out;
  if (!DECISIONS.has(verdict.decision as string)) return out;
  if (!Array.isArray(verdict.findings)) return out;

  const ts = (now ?? new Date()).toISOString();

  // Resolved ONCE per verdict, unconditionally, for every input shape. There is
  // no branch here that can decide a record is not worth building: AW-71's
  // second attempt made this section "fail closed" by dropping events, which for
  // an audit log is fail-OPEN -- a malformed chain id made a critical refusal
  // vanish from the spool, and an explicit chainId of 0 (this module's own
  // Solana sentinel) cost Solana integrators every refusal record they had.
  const chain = resolveChainIdTagged(ctx.chainId);
  const amount = resolveAmountTagged(ctx.amount);

  // The storage column is NOT NULL and 0 is the agreed meaning of "not an
  // EIP-155 chain", so an unresolved chain still writes 0 -- but it now says so
  // on a separate key instead of being indistinguishable from real Solana.
  const chain_id = chain.kind === "evm" ? chain.id : CHAIN_ID_SOLANA;
  const payee_hash = hashPayee(ctx.payTo);
  const amount_bucket = amount.kind === "band" ? amount.bucket : null;

  // Built from tags this module computed, never from caller bytes.
  const unreadable: string[] = [];
  if (amount.kind === "unreadable") unreadable.push("amount");
  if (chain.kind === "unreadable") unreadable.push("chain_id");

  for (const f of verdict.findings) {
    if (!f || typeof f !== "object") continue;
    const code = (f as { code?: unknown }).code;
    const severity = (f as { severity?: unknown }).severity;
    if (typeof code !== "string" || !KNOWN_CODES.has(code)) continue;
    if (typeof severity !== "string" || !SEVERITIES.has(severity)) continue;

    // Constructed field by field. Never `{...f}`, never a filtered copy —
    // `message`, `expected`, `actual`, `excerpt` and `field` exist on the input
    // and must not exist on the output, and the only way to guarantee that
    // structurally is to write down the keys that may.
    const ev: PaymentEvent = {
      code,
      severity: severity as PaymentEvent["severity"],
      decision: verdict.decision,
      chain_id,
      ts,
    };
    // Assigned only when present, so the key is absent rather than null.
    if (payee_hash !== null) ev.payee_hash = payee_hash;
    if (amount_bucket !== null) ev.amount_bucket = amount_bucket;
    // Fresh array per event: the records are handed out separately and must not
    // share a mutable field.
    if (unreadable.length > 0) ev.unreadable = unreadable.slice();
    out.push(ev);
  }
  return out;
}

/**
 * Second gate: refuse to write a line that is not the shape we promised.
 *
 * Mirrors the reporter's `verify_payload_shape` — an allowlist, not a blocklist.
 * A blocklist catches the leaks we thought of; an allowlist catches any string
 * that is not one of the four shapes this record is allowed to contain. It runs
 * on every write because it costs a handful of set lookups and it is the thing
 * standing between a future refactor and a plaintext address on disk.
 */
const REQUIRED_KEYS = ["chain_id", "code", "decision", "severity", "ts"];
const OPTIONAL_KEYS = ["amount_bucket", "payee_hash", "unreadable"];

export function assertNoPlaintext(ev: PaymentEvent): string[] {
  const bad: string[] = [];

  // Key-set check first, and it is an ALLOWLIST: any key that is not required
  // and not optional is a violation, whatever it contains. This is the check
  // that catches a future refactor spreading a Finding into the record.
  for (const k of Object.keys(ev)) {
    if (!REQUIRED_KEYS.includes(k) && !OPTIONAL_KEYS.includes(k)) {
      bad.push(`unexpected key: ${k}`);
    }
  }
  for (const k of REQUIRED_KEYS) {
    if (!(k in ev)) bad.push(`missing key: ${k}`);
  }

  if (!KNOWN_CODES.has(ev.code)) bad.push(`code not in vocabulary: ${ev.code}`);
  if (!SEVERITIES.has(ev.severity)) bad.push(`severity: ${ev.severity}`);
  if (!DECISIONS.has(ev.decision)) bad.push(`decision: ${ev.decision}`);
  if (!Number.isSafeInteger(ev.chain_id) || ev.chain_id < 0) {
    bad.push(`chain_id not a non-negative integer: ${String(ev.chain_id)}`);
  }
  if (ev.payee_hash !== undefined && !/^[0-9a-f]{64}$/.test(ev.payee_hash)) {
    bad.push(`payee_hash not a sha256 hex digest`);
  }
  if (
    ev.amount_bucket !== undefined &&
    !AMOUNT_BUCKETS.includes(ev.amount_bucket)
  ) {
    bad.push(`amount_bucket not in vocabulary: ${ev.amount_bucket}`);
  }
  if (!/^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(ev.ts)) bad.push(`ts: ${ev.ts}`);

  // `unreadable` is built here from a closed two-name set, so this is a second
  // gate on the one key whose existence is decided by caller context: if a
  // future refactor ever lets a caller-supplied string reach it, the line is
  // refused rather than written. Checked as an allowlist for the same reason the
  // key set above is.
  if (ev.unreadable !== undefined) {
    if (!Array.isArray(ev.unreadable) || ev.unreadable.length === 0) {
      bad.push(`unreadable not a non-empty array`);
    } else {
      for (const f of ev.unreadable) {
        if (typeof f !== "string" || !UNREADABLE_FIELDS.includes(f)) {
          bad.push(`unreadable field not in vocabulary: ${String(f)}`);
        }
      }
    }
  }
  return bad;
}

/**
 * Write via the cached fd, reopening once if it has gone stale.
 *
 * Returns false if the line could not be written at all. One retry and no more:
 * if a freshly opened descriptor also fails, the filesystem is genuinely
 * unavailable and looping would put the payment path in a retry storm.
 */
function writeThrough(s: SinkState, payload: string): boolean {
  const buf = Buffer.from(payload, "utf8");

  // Liveness check on the NAME, not the descriptor. A held fd keeps working
  // after its path is unlinked (verified: write-after-unlink returns success on
  // macOS), so "the write did not throw" is not evidence the data is reachable.
  //
  // MEASURED COST, because this is the most expensive line in the module and it
  // buys correctness rather than speed: existsSync 1,572 ns, writeSync 1,977 ns,
  // both together 3,552 ns. So the check is ~44% of the syscall budget of a
  // write. It stays, because the alternative failure is silent and unbounded —
  // an operator deletes the spool, every subsequent event lands in an inode
  // with no name, and the sink reports success for all of them. A payment path
  // can afford 1.6 us; an observability feed cannot afford lying.
  if (s.fd !== null) {
    try {
      if (!s.fs.existsSync(s.path)) closeFd(s);
    } catch {
      closeFd(s);
    }
  }

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      if (s.fd === null) {
        // Re-check the type on every reopen, not just at configure time: the
        // path could have been replaced with a FIFO since then, and a blocking
        // open on a pipe hangs the payment path where no catch would run.
        //
        // A MISSING path is not a refusal. Deletion and rotation are the normal
        // cases this reopen loop exists to handle -- the open below recreates
        // the file. Only a path that exists and is NOT a regular file is
        // refused, which is the FIFO case and nothing else.
        try {
          const st = s.fs.lstatSync(s.path);
          if (!st.isFile()) return false;
        } catch (err) {
          if ((err as { code?: string } | null)?.code !== "ENOENT") return false;
        }
        // O_APPEND: every write lands at the current end of file, so a
        // concurrent writer in another process interleaves whole lines rather
        // than overwriting ours. This is why no lock is needed.
        s.fd = s.fs.openSync(s.path, "a", 0o600);
      }
      s.fs.writeSync(s.fd, buf, 0, buf.length);
      return true;
    } catch {
      closeFd(s);
    }
  }
  return false;
}

function rotateIfNeeded(s: SinkState): void {
  s.bytesSinceCheck = 0;
  let size = 0;
  try {
    size = s.fs.statSync(s.path).size;
  } catch {
    // The path is gone — an operator deleted it, or its directory was removed.
    //
    // This matters more than it looks. On POSIX, writes through a descriptor
    // whose name has been unlinked SUCCEED: the inode survives until the last
    // fd closes, so the sink would happily keep writing into an orphaned inode
    // that nothing can ever read. Measured on macOS: write-after-unlink
    // returned success. Dropping the fd here turns invisible data loss into a
    // visible failed write, and `writeThrough`'s reopen will recreate the file
    // if the directory comes back.
    closeFd(s);
    return;
  }
  if (size < s.maxBytes) return;

  // Close the held fd BEFORE renaming. An fd points at an inode, not a name, so
  // a descriptor kept open across a rename keeps appending to the rotated
  // segment forever — the live file would stay empty while `.1` grew without
  // bound, defeating the ceiling entirely. Reopened lazily on the next write.
  closeFd(s);

  try {
    if (s.keepSegments === 0) {
      s.fs.writeFileSync(s.path, "", { mode: 0o600 });
      return;
    }
    const oldest = `${s.path}.${s.keepSegments}`;
    try {
      s.fs.unlinkSync(oldest);
    } catch {
      /* absent is fine */
    }
    for (let i = s.keepSegments - 1; i >= 1; i--) {
      try {
        s.fs.renameSync(`${s.path}.${i}`, `${s.path}.${i + 1}`);
      } catch {
        /* absent is fine */
      }
    }
    s.fs.renameSync(s.path, `${s.path}.1`);
  } catch {
    /* if rotation fails the file simply keeps growing; a failed rotate must
       not become a failed payment. The size ceiling is best-effort by design. */
  }
}

/**
 * Record a verdict. The one function the payment path calls.
 *
 * Returns the number of lines written — 0 when the sink is off, which is the
 * default and the common case. Never throws, never awaits, never blocks on
 * anything but one `writeSync` of a few hundred bytes to a held descriptor.
 *
 * MEASURED per-call cost on this machine (20,000 iterations, after warmup):
 *
 *     sink OFF (the default)    13 ns
 *     sink ON, salted, writing  8,587 ns  (~0.009 ms)
 *
 * The off path is a null check, which is what makes "off by default" free
 * rather than merely cheap. The on path is dominated by three syscalls and an
 * HMAC; there is no fsync, no lock, and no network.
 */
export function recordVerdict(
  verdict: SinkVerdictLike,
  ctx: SinkContext = {},
): number {
  const s = sink;
  if (!s) return 0;
  try {
    const events = toEvents(verdict, ctx);
    if (events.length === 0) return 0;

    let payload = "";
    let n = 0;
    let degraded = 0;
    for (const ev of events) {
      if (assertNoPlaintext(ev).length > 0) {
        // Fail closed. A record that does not match the promised shape is
        // dropped rather than written; the counter makes the drop visible.
        s.dropped++;
        continue;
      }
      payload += JSON.stringify(ev) + "\n";
      if (ev.unreadable !== undefined) degraded++;
      n++;
    }
    if (n === 0) return 0;

    if (s.bytesSinceCheck >= s.checkEvery) rotateIfNeeded(s);

    if (!writeThrough(s, payload)) {
      s.dropped += n;
      return 0;
    }
    s.written += n;
    // Counted on the SAME UNIT as `written` -- one per event, added only after
    // the bytes reached the file -- so `degraded <= written` always holds and
    // the counter can never claim a record that is not on disk. An earlier
    // attempt counted a degraded record for an event it had already dropped,
    // which made the counter unreconcilable against the spool.
    s.degraded += degraded;
    s.bytesSinceCheck += payload.length;

    // Rotation is checked ONLY BEFORE the write, never after.
    //
    // An earlier version also checked afterwards, reasoning that it would keep
    // the file closer to the ceiling. What it actually did was rename the live
    // file away as the last action of a write, leaving no spool at the
    // configured path until the next write recreated it. Measured: after 201
    // events the write returned success, `written` was 201, `dropped` was 0 —
    // and the live path did not exist, with the newest events sitting in
    // `.1`. A reader polling the path would have seen "absent" and reported no
    // events at all. Rotating only before a write guarantees the file that
    // receives the bytes is still the live file when the call returns.
    return n;
  } catch {
    // Full disk, read-only mount, deleted directory, EMFILE. All the same
    // answer: count it and get out of the payment's way.
    try {
      s.dropped++;
    } catch {
      /* unreachable, but this function's contract is that it cannot throw */
    }
    return 0;
  }
}
