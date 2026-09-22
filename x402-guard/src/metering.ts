// src/metering.ts
/**
 * Metering + correlation — the billing spine that backs BOTH tiers.
 *
 * This module answers two questions and nothing else:
 *   1. "Was this verification billable, and for how much?" (per-call tier)
 *   2. "Do these billable events form a cross-agent pattern?" (monthly tier)
 *
 * It is dependency-free and holds no database. Persistence is the caller's
 * choice, injected as a `MeterStore` (`append` + `recent`). The module keeps no
 * clock: every pure function derives its time window from `issuedAt` values that
 * arrive ON the events, never from `Date.now()`. That is what lets a receipt —
 * and by extension a billing record — replay identically.
 *
 * WHERE TIER / CALLER IDENTITY COMES FROM, STATED SO IT IS NOT ASSUMED.
 * The verdict logic in `verify.ts` never sees a tier, a caller id, or a price.
 * It answers one question: does the payment match the quote? The TRANSPORT
 * (`server.ts`) owns the caller relationship — it knows which API key signed the
 * request, which plan that key is on, and which provenance the request path
 * proved. It passes `tier` and `caller` INTO this module per event. The
 * separation is load-bearing: a verdict that could see who is paying could, in
 * principle, be bought. It cannot see, so it cannot be.
 *
 * ZERO PLAINTEXT. A stored `BillingEvent` carries a digest, a provenance, a
 * decision, a chain id, a timestamp, and an optional amount bucket — never the
 * quote text, never the payment bytes, never an exact figure. The event is
 * constructed field by field (never spread from a receipt) for the same reason
 * `sink.ts` does: a constructed object cannot leak a key nobody wrote down.
 *
 * NEVER BILLS caller_asserted. It is answered, but it is not a relied-upon
 * attestation, so it is neither priced nor recorded. `record()` drops it before
 * it can reach the store; `priceFor` returns 0 for it. Both gates exist because
 * one of them is code review and the other is arithmetic.
 */

import type { QuoteProvenance } from "./verify.js";

// --- provenance billing gate -----------------------------------------------

/**
 * The three provenances that are billable attestations. Mirrors the set in
 * `server.ts` deliberately — kept as its own const here so the metering module
 * is self-contained and testable without the transport.
 */
export const BILLABLE_PROVENANCES: ReadonlySet<QuoteProvenance> = new Set([
  "independent_fetch",
  "merchant_signed",
  "facilitator_held",
]);

/** True for exactly the three trusted provenances. caller_asserted is false. */
export function isBillable(provenance: QuoteProvenance): boolean {
  return BILLABLE_PROVENANCES.has(provenance);
}

// --- pricing ----------------------------------------------------------------

/**
 * Micro-USDC: USDC has 6 decimals, so 1 USDC = 1_000_000 micro-units. All prices
 * are integer micro-USDC as `bigint`, never floats — a float price times a large
 * call count rounds, and a rounded invoice is a wrong invoice.
 */
export const MICRO_USDC = 1_000_000n;

/** The two ways a caller can be on the meter. */
export type BillingTier = "per_call" | "monthly";

/**
 * Per-call pricing, in micro-USDC. Default 0.003 USDC = 3_000 micro-USDC per
 * billable verification, within the settled $0.002–0.005 band. Configurable via
 * `PriceConfig.perCallMicroUsdc`.
 *
 * The three trusted provenances are all priced the same per call by default; the
 * table is a map so an operator can differentiate later (e.g. charge more for a
 * `merchant_signed` attestation that required a signature check) without changing
 * this signature.
 */
export const DEFAULT_PER_CALL_MICRO_USDC = 3_000n; // 0.003 USDC

/**
 * Monthly tier: a flat platform fee plus an included call volume. Overage above
 * the included volume falls back to the per-call rate. The flat fee is what the
 * monthly-tier signal (`correlate`) is really paying for — cross-agent pattern
 * detection is a fleet feature, not a per-call one.
 */
export interface MonthlyTierConfig {
  /** Flat monthly fee in micro-USDC. */
  flatMicroUsdc: bigint;
  /** Verifications included in the flat fee before overage applies. */
  includedVolume: number;
}

export const DEFAULT_MONTHLY_TIER: MonthlyTierConfig = {
  // 25 USDC/mo flat, 10k verifications included. Illustrative defaults; the
  // operator sets real numbers via PriceConfig.
  flatMicroUsdc: 25n * MICRO_USDC,
  includedVolume: 10_000,
};

export interface PriceConfig {
  /** Per-call rate in micro-USDC. Default {@link DEFAULT_PER_CALL_MICRO_USDC}. */
  perCallMicroUsdc?: bigint;
  /** Per-provenance overrides for the per-call rate, in micro-USDC. */
  perProvenanceMicroUsdc?: Partial<Record<QuoteProvenance, bigint>>;
  /** Monthly-tier shape. Default {@link DEFAULT_MONTHLY_TIER}. */
  monthly?: MonthlyTierConfig;
}

/**
 * Price a SINGLE verification, in integer micro-USDC.
 *
 *   - caller_asserted   => 0n, always, whatever the tier. It is unbillable.
 *   - per_call tier     => the per-call rate (per-provenance override, else the
 *                          flat per-call rate) for a trusted provenance.
 *   - monthly tier      => 0n per call. The monthly cost is the flat fee, charged
 *                          once per period by the caller's billing loop against
 *                          `monthlyInvoice`, NOT per verification. Returning the
 *                          per-call rate here would double-bill a monthly
 *                          customer for calls their flat fee already covers.
 *
 * Returning a per-call marginal price for the monthly tier only when a customer
 * exceeds their included volume is an INVOICE-level decision (it needs the
 * period's total count), so it lives in `monthlyInvoice`, not here. A single
 * verification cannot know whether it is the one that tipped a customer into
 * overage.
 */
export function priceFor(
  provenance: QuoteProvenance,
  tier: BillingTier,
  config: PriceConfig = {},
): bigint {
  if (!isBillable(provenance)) return 0n;
  if (tier === "monthly") return 0n;

  const override = config.perProvenanceMicroUsdc?.[provenance];
  if (override !== undefined) return override;
  return config.perCallMicroUsdc ?? DEFAULT_PER_CALL_MICRO_USDC;
}

/**
 * Roll a month of monthly-tier events into an invoice, in micro-USDC.
 *
 * Flat fee, plus per-call overage on any billable calls beyond the included
 * volume. `caller_asserted` events never reach here (they are dropped at
 * `record`), but this filters them again — the second, arithmetic gate.
 */
/**
 * One money field that could not be read as configured, and what was used.
 *
 * A LIST ON THE RETURN VALUE rather than a throw. AW-71: the pre-fix arithmetic
 * threw on two config shapes (a fractional `includedVolume`, a number-typed
 * price), which loses the whole period's invoice -- and a throw reachable from
 * config is a denial-of-billing primitive wherever config is not purely
 * operator-controlled. It is equally not acceptable to substitute a number
 * silently: the pre-fix code did that for a negative flat fee and produced a
 * NEGATIVE invoice that looked like a real one. A complete invoice plus a
 * visible defect list is the only shape that can be neither lost nor silently
 * wrong.
 */
export interface PriceFieldFault {
  /** Which config field could not be read. */
  field: "flatMicroUsdc" | "includedVolume" | "perCallMicroUsdc";
  /** Why, in a fixed vocabulary -- never an echo of the supplied value. */
  reason: "not-numeric" | "negative" | "out-of-range" | "fractional";
  /** The value used instead, as a decimal string. */
  usedInstead: string;
}

/**
 * Read a money field as non-negative integer micro-USDC.
 *
 * Accepts bigint, a whole number, and a numeric string. The string case is not
 * hypothetical: a price table that round-trips through JSON comes back with
 * `flatMicroUsdc: "25000000"`, and the pre-fix code fed that straight into
 * `+` -- where JS chose STRING CONCATENATION over addition, so a 25 USDC fee
 * plus 15000 micro-USDC of overage billed as "2500000015000", a 99,800-fold
 * overbill that threw nothing and typed as a string all the way to the invoice.
 */
function toMicroUsdc(
  value: unknown,
  field: PriceFieldFault["field"],
  fallback: bigint,
  faults: PriceFieldFault[],
): bigint {
  const fault = (reason: PriceFieldFault["reason"]): bigint => {
    faults.push({ field, reason, usedInstead: fallback.toString() });
    return fallback;
  };

  if (typeof value === "bigint") {
    return value < 0n ? fault("negative") : value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return fault("not-numeric");
    if (!Number.isInteger(value)) return fault("fractional");
    if (value < 0) return fault("negative");
    if (!Number.isSafeInteger(value)) return fault("out-of-range");
    return BigInt(value);
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (!/^[+-]?[0-9]+$/.test(s)) return fault("not-numeric");
    let v: bigint;
    try {
      v = BigInt(s);
    } catch {
      return fault("not-numeric");
    }
    return v < 0n ? fault("negative") : v;
  }
  return fault("not-numeric");
}

/**
 * Read `includedVolume` as a non-negative whole call count.
 *
 * NOT CLAMPED. An out-of-range value falls back to the default included volume
 * and is reported, because clamping 1e308 to Number.MAX_SAFE_INTEGER would mean
 * no call in any conceivable month is ever overage -- i.e. the month silently
 * becomes free, which is the same class of defect as the negative invoice, just
 * pointing the other way.
 */
function toIncludedVolume(
  value: unknown,
  fallback: number,
  faults: PriceFieldFault[],
): number {
  const fault = (reason: PriceFieldFault["reason"]): number => {
    faults.push({ field: "includedVolume", reason, usedInstead: String(fallback) });
    return fallback;
  };

  let n: number;
  if (typeof value === "bigint") {
    if (value < 0n) return fault("negative");
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) return fault("out-of-range");
    return Number(value);
  } else if (typeof value === "number") {
    n = value;
  } else if (typeof value === "string" && /^[+-]?[0-9]+$/.test(value.trim())) {
    n = Number(value.trim());
  } else {
    return fault("not-numeric");
  }

  if (!Number.isFinite(n)) return fault("not-numeric");
  if (n < 0) return fault("negative");
  if (!Number.isSafeInteger(n)) {
    // A fraction is a near-miss we can honour by flooring: 10.5 included calls
    // means 10 are included. Anything beyond 2^53 is not a call count at all.
    if (Number.isInteger(n)) return fault("out-of-range");
    const floored = Math.floor(n);
    faults.push({
      field: "includedVolume",
      reason: "fractional",
      usedInstead: String(floored),
    });
    return floored;
  }
  return n;
}

export function monthlyInvoice(
  events: ReadonlyArray<BillingEvent>,
  config: PriceConfig = {},
): {
  flatMicroUsdc: bigint;
  overageMicroUsdc: bigint;
  totalMicroUsdc: bigint;
  billableCalls: number;
  faults: PriceFieldFault[];
} {
  const monthly = config.monthly ?? DEFAULT_MONTHLY_TIER;

  // Every money field is read through a total function, so no supplied shape can
  // reach the arithmetic as something other than a non-negative bigint. Faults
  // are collected, never thrown: see PriceFieldFault.
  const faults: PriceFieldFault[] = [];
  const flatMicroUsdc = toMicroUsdc(
    monthly.flatMicroUsdc,
    "flatMicroUsdc",
    DEFAULT_MONTHLY_TIER.flatMicroUsdc,
    faults,
  );
  const perCall = toMicroUsdc(
    config.perCallMicroUsdc ?? DEFAULT_PER_CALL_MICRO_USDC,
    "perCallMicroUsdc",
    DEFAULT_PER_CALL_MICRO_USDC,
    faults,
  );
  const includedVolume = toIncludedVolume(
    monthly.includedVolume,
    DEFAULT_MONTHLY_TIER.includedVolume,
    faults,
  );

  let billableCalls = 0;
  for (const e of events) {
    if (isBillable(e.provenance)) billableCalls++;
  }

  const overageCalls = Math.max(0, billableCalls - includedVolume);
  const overageMicroUsdc = BigInt(overageCalls) * perCall;
  return {
    flatMicroUsdc,
    overageMicroUsdc,
    totalMicroUsdc: flatMicroUsdc + overageMicroUsdc,
    billableCalls,
    faults,
  };
}

// --- stored event & store interface ----------------------------------------

/**
 * The exact stored record. Plaintext-free by construction: a digest, coarse
 * decision/chain/bucket facts, a timestamp, and the transport-supplied tier /
 * caller identity. NO quote text, NO payment bytes, NO exact amount.
 *
 * `tier` and `caller` are set BY THE TRANSPORT and are meaningless to the verdict
 * logic (see the module header). `caller` is an opaque account id the operator
 * assigns to an API key — this module treats it as a correlation key only and
 * never interprets it.
 */
export interface BillingEvent {
  /** SHA-256 request digest from the receipt. The only correlation handle we keep. */
  digest: string;
  /** Which trusted provenance made this billable. Never caller_asserted here. */
  provenance: QuoteProvenance;
  /** allow | refuse | abstain. */
  decision: string;
  /** EIP-155 chain id, or null for Solana / unresolved. */
  chainId: number | null;
  /** Caller-supplied ISO-8601 timestamp, echoed from the receipt. */
  issuedAt: string;
  /** Coarse amount band (from sink.ts amountBucket), if the receipt carried one. */
  amount_bucket?: string;
  /** Billing tier, supplied by the transport. Verdict logic never sees this. */
  tier: BillingTier;
  /** Opaque caller/account id, supplied by the transport. A correlation key only. */
  caller: string;
}

/**
 * Persistence, injected. `append` records one event; `recent` returns events
 * whose `issuedAt` falls within the last `windowMs` relative to the newest event
 * the store holds. The module never opens a DB, a socket, or a file — the store
 * decides where bytes go.
 *
 * `recent` is deliberately window-relative-to-newest rather than
 * relative-to-now, because this module reads no clock: "recent" is defined by the
 * data, not by wall time.
 */
export interface MeterStore {
  append(event: BillingEvent): void;
  recent(windowMs: number): ReadonlyArray<BillingEvent>;
  /**
   * The last `limit` events by INSERTION ORDER, newest last. Optional.
   *
   * AW-71: `recent()` picks its window from `max(issuedAt)`, a caller-supplied
   * field, so ONE event bearing a far-future timestamp moves the right edge past
   * every honest row and `recent()` returns just that row -- measured, 40 rows
   * down to 1 -- which blinded `correlate` completely until the forged row aged
   * out of the ring. `correlate` therefore stopped reading `recent()`.
   *
   * Insertion order is the one ordering a caller cannot influence: a row cannot
   * arrive before rows that are already in the store. No field on the record is
   * consulted, so there is nothing here to forge.
   *
   * `recent()` itself is deliberately NOT widened. It is also the BILLING
   * surface -- `monthlyInvoice(store.recent(period))` is how a billing loop
   * drives it -- and returning a superset there re-bills last period's calls.
   * The two readers want different things from the same data, so they get
   * different methods.
   *
   * Optional so an existing custom store still satisfies the interface; see
   * `correlationFeed` for what a store without it falls back to.
   */
  tail?(limit: number): ReadonlyArray<BillingEvent>;
}

/**
 * How many events by arrival `correlate` looks at.
 *
 * A COUNT bound, and it is here for PERFORMANCE, not as a security boundary --
 * say so plainly. `buildCluster`'s sliding window is O(n^2) in the size of one
 * candidate group, today, with no fix applied: 20,000 honest rows in one window
 * take ~14 seconds on this machine. Feeding it the whole ring would turn a
 * routine call into a denial of service reachable from a single account.
 *
 * The bound therefore also PRICES the blinding attack rather than closing it: an
 * attacker who appends this many rows still pushes honest traffic out of the
 * feed. That raises the cost from one forged row to a few thousand; it does not
 * eliminate the class. Closing it needs `buildCluster`'s window made linear so
 * the whole ring can be read safely, which lives in correlate's own section.
 */
export const CORRELATE_TAIL = 2000;

/**
 * The events `correlate` reads. Never `recent()`; see {@link MeterStore.tail}.
 *
 * A store that does not implement `tail` falls back to `recent()` and keeps the
 * original exposure -- the alternative was a breaking change to a published
 * interface, and a durable store can close it by adding six lines.
 */
export function correlationFeed(
  store: MeterStore,
  windowMs: number,
  limit: number = CORRELATE_TAIL,
): ReadonlyArray<BillingEvent> {
  if (typeof store.tail === "function") {
    try {
      // `tail` is preferred because it slices by insertion order, so a single
      // future-dated row cannot blind the feed the way a timestamp-anchored
      // read can. But it carries no notion of time, and returning it unfiltered
      // drops recency entirely — a cluster formed once would be reported as
      // current forever, including groups years old. Anchor on the newest
      // event actually present and keep the window relative to it.
      const rows = store.tail(limit);
      if (rows.length === 0) return rows;
      // Anchor on the MEDIAN timestamp, not the newest. The newest is exactly
      // what an attacker controls — a single far-future row is what blinded
      // the timestamp-anchored read this branch exists to replace, and
      // anchoring on it here would reintroduce that blinding through the back
      // door. A median moves only if most of the window is forged, and by
      // then the feed has bigger problems than its cutoff.
      const times: number[] = [];
      for (const e of rows) {
        const t = Date.parse(e.issuedAt);
        if (Number.isFinite(t)) times.push(t);
      }
      if (times.length === 0) return rows;
      times.sort((a, b) => a - b);
      const anchor = times[Math.floor(times.length / 2)];
      // The window is one-sided from the median, widened to cover the rows
      // that legitimately sit on either side of it.
      const cutoff = anchor - windowMs;
      return rows.filter((e) => {
        const t = Date.parse(e.issuedAt);
        // An unparseable timestamp is kept: dropping it would let a malformed
        // row delete itself from the audit feed.
        return !Number.isFinite(t) || t >= cutoff;
      });
    } catch {
      // A store that throws must not take the correlation call down with it.
      return [];
    }
  }
  return store.recent(windowMs);
}

/**
 * A zero-dependency in-memory store, provided as the default so the meter works
 * out of the box. Ring-bounded so an unbounded process cannot grow without limit;
 * the operator swaps in a durable store for real billing.
 */
export function createMemoryStore(maxEvents = 100_000): MeterStore {
  const buf: BillingEvent[] = [];
  return {
    append(event: BillingEvent): void {
      buf.push(event);
      if (buf.length > maxEvents) buf.splice(0, buf.length - maxEvents);
    },
    tail(limit: number): ReadonlyArray<BillingEvent> {
      // The limit is sanitised here rather than trusted, so a caller that hands
      // in NaN or 1e9 gets the constant instead of an unbounded slice.
      const n =
        Number.isInteger(limit) && limit > 0 && limit <= CORRELATE_TAIL
          ? limit
          : CORRELATE_TAIL;
      return n >= buf.length ? buf.slice() : buf.slice(buf.length - n);
    },
    recent(windowMs: number): ReadonlyArray<BillingEvent> {
      if (buf.length === 0) return [];
      // Newest event by issuedAt defines the window's right edge — no clock read.
      let newest = -Infinity;
      for (const e of buf) {
        const t = Date.parse(e.issuedAt);
        if (Number.isFinite(t) && t > newest) newest = t;
      }
      if (!Number.isFinite(newest)) return [];
      const cutoff = newest - windowMs;
      return buf.filter((e) => {
        const t = Date.parse(e.issuedAt);
        return Number.isFinite(t) && t >= cutoff;
      });
    },
  };
}

// --- the meter ---------------------------------------------------------------

/**
 * The event shape the TRANSPORT hands the meter, matching (and widening) the
 * `Meter` type in `server.ts`. `server.ts` passes the first five fields; `tier`,
 * `caller`, and `amountBucket` are the metering additions the transport supplies
 * from the caller relationship and the receipt. All optional-with-defaults so an
 * existing `server.ts` call still compiles.
 */
export interface MeterEvent {
  digest: string;
  provenance: QuoteProvenance;
  decision: string;
  chainId: number | null;
  issuedAt: string;
  /** Coarse amount band from the receipt, if present. */
  amountBucket?: string;
  /** Billing tier, from the transport. Defaults to per_call. */
  tier?: BillingTier;
  /** Opaque caller id, from the transport. Defaults to "unknown". */
  caller?: string;
}

/** Matches the injected `Meter` type in server.ts: record one event, return void. */
export type Meter = (event: MeterEvent) => void;

export interface MeterOptions {
  /** Where billable events land. Defaults to an in-memory ring store. */
  store?: MeterStore;
  /** Pricing table, used by `priceFor`/`monthlyInvoice` helpers on the returned meter. */
  price?: PriceConfig;
}

export interface MeterHandle {
  /** The `Meter` function the transport passes to `createVerifyHandler`. */
  record: Meter;
  /** The backing store, exposed so a billing loop can drain it. */
  store: MeterStore;
  /** Price a single verification with this meter's configured table. */
  priceFor(provenance: QuoteProvenance, tier: BillingTier): bigint;
  /** Correlate the store's recent events into cross-agent clusters. */
  correlate(opts: CorrelateOptions): Cluster[];
}

/**
 * Build a meter. The returned `record` is the function the transport injects as
 * `opts.meter`. It:
 *   - DROPS caller_asserted before it can reach the store (never billed, never
 *     logged as a relied-upon allow);
 *   - constructs a plaintext-free `BillingEvent` field by field;
 *   - appends via the injected store.
 *
 * It never throws into the caller: a store failure is swallowed, because a
 * metering failure must never affect a verdict the transport already returned.
 */
export function createMeter(opts: MeterOptions = {}): MeterHandle {
  const store = opts.store ?? createMemoryStore();
  const price = opts.price ?? {};

  const record: Meter = (event: MeterEvent): void => {
    // Gate 1: caller_asserted is unbillable — drop it entirely. It is neither
    // priced nor stored, so it can never be replayed as a relied-upon allow.
    if (!isBillable(event.provenance)) return;

    // Constructed field by field. Never a spread of a receipt or a request —
    // that is the structural guarantee that no quote text or payment byte can
    // ride along on a key nobody wrote down here.
    const stored: BillingEvent = {
      digest: event.digest,
      provenance: event.provenance,
      decision: event.decision,
      chainId: event.chainId,
      issuedAt: event.issuedAt,
      tier: event.tier ?? "per_call",
      caller: event.caller ?? "unknown",
    };
    if (event.amountBucket !== undefined) stored.amount_bucket = event.amountBucket;

    try {
      store.append(stored);
    } catch {
      // A metering failure must never affect the verdict. Swallow.
    }
  };

  return {
    record,
    store,
    priceFor: (provenance, tier) => priceFor(provenance, tier, price),
    correlate: (o) => correlate(correlationFeed(store, o.windowMs), o),
  };
}

// --- correlation (the monthly-tier signal) ----------------------------------

export interface CorrelateOptions {
  /** Width of the correlation window, in milliseconds, over event.issuedAt. */
  windowMs: number;
  /** A cluster is only flagged when it spans at least this many distinct callers. */
  minAgents: number;
}

export type ClusterSignal = "shared-refuse" | "identical-digest";

export interface Cluster {
  /** Which of the two grouping signals produced this cluster. */
  signal: ClusterSignal;
  /** EIP-155 chain id, or null for Solana / unresolved. */
  chainId: number | null;
  /** Coarse amount band, present only for the shared-refuse signal. */
  amountBucket?: string;
  /** Total events in the cluster. */
  count: number;
  /** [start, end] of the cluster's issuedAt span, as ISO-8601 strings. */
  window: [string, string];
  /** A few finding-relevant codes seen in the cluster, deduped. Here: decisions/provenances. */
  sampleCodes: string[];
}

/**
 * Correlate billable events into cross-agent clusters — the signal the monthly
 * tier is really selling.
 *
 * TWO grouping keys, each flagged only when it spans >= minAgents distinct
 * callers within `windowMs`:
 *
 *   'identical-digest'  Events sharing the exact `request_digest`. The same quote
 *                       + payload verified by several agents in a short window is
 *                       a fan-out pattern — one crafted request replayed across a
 *                       fleet.
 *
 *   'shared-refuse'     REFUSE events sharing (chainId, amount_bucket). Several
 *                       distinct agents independently refusing payments of the
 *                       same shape on the same chain is a behavioral signal that
 *                       something is probing the fleet.
 *
 * KNOWN EVASION — read before trusting the digest path. A digest is a hash of the
 * canonical request, so an adversary who MUTATES THE PAYLOAD PER TARGET (a
 * different nonce, a different memo, a per-agent field) produces a distinct
 * digest for every victim and DEFEATS identical-digest clustering entirely: each
 * event looks unique, no group forms. That is not a bug to be patched here — it
 * is inherent to content-addressed correlation.
 *
 * The shared-refuse path is the BEHAVIORAL FALLBACK that survives per-target
 * payload mutation. It keys on the OUTCOME (a refusal) and the COARSE SHAPE
 * (chain + amount band), neither of which the attacker can vary without changing
 * the attack itself — mutating the payload to dodge the digest does not change
 * that the payments are still being refused on the same chain in the same band.
 * An adversary who also spreads across chains and amount bands to dodge
 * shared-refuse has been forced to give up the uniformity that made the campaign
 * efficient, which is the point.
 *
 * PURE. Reads no clock. The window edges are computed from the `issuedAt` values
 * on the events passed in; the caller selects which events to pass (e.g. via
 * `store.recent(windowMs)`).
 */
export function correlate(
  events: ReadonlyArray<BillingEvent>,
  { windowMs, minAgents }: CorrelateOptions,
): Cluster[] {
  const clusters: Cluster[] = [];
  if (!Array.isArray(events) || events.length === 0) return clusters;

  // Group 1: identical request_digest.
  const byDigest = new Map<string, BillingEvent[]>();
  // Group 2: refuse + chainId + amount_bucket.
  const byRefuseShape = new Map<string, BillingEvent[]>();

  for (const e of events) {
    if (!e || typeof e.digest !== "string") continue;

    const d = byDigest.get(e.digest);
    if (d) d.push(e);
    else byDigest.set(e.digest, [e]);

    if (e.decision === "refuse") {
      // amount_bucket may be absent; a literal token keeps the composite key
      // unambiguous vs. an empty string that a real bucket could collide with.
      const bucket = e.amount_bucket ?? " none";
      const key = `${e.chainId ?? "null"}|${bucket}`;
      const r = byRefuseShape.get(key);
      if (r) r.push(e);
      else byRefuseShape.set(key, [e]);
    }
  }

  for (const group of byDigest.values()) {
    const c = buildCluster(group, "identical-digest", windowMs, minAgents);
    if (c) clusters.push(c);
  }
  for (const group of byRefuseShape.values()) {
    const c = buildCluster(group, "shared-refuse", windowMs, minAgents);
    if (c) clusters.push(c);
  }

  return clusters;
}

/**
 * Turn one candidate group into a flagged cluster, or null.
 *
 * A group qualifies only if, WITHIN a `windowMs`-wide span, it holds events from
 * at least `minAgents` distinct callers. Events are sorted by `issuedAt` and a
 * sliding window finds the widest qualifying run — so a group whose members are
 * spread over a day but bunch into a burst still flags on the burst, and the
 * reported `window`/`count` describe that burst, not the whole day.
 */
function buildCluster(
  group: BillingEvent[],
  signal: ClusterSignal,
  windowMs: number,
  minAgents: number,
): Cluster | null {
  if (group.length < minAgents) return null;

  // Sort by parsed issuedAt; drop unparseable timestamps rather than let a NaN
  // corrupt the window arithmetic.
  const dated = group
    .map((e) => ({ e, t: Date.parse(e.issuedAt) }))
    .filter((x) => Number.isFinite(x.t))
    .sort((a, b) => a.t - b.t);
  if (dated.length < minAgents) return null;

  // Sliding window: for each left edge, extend right while within windowMs, and
  // keep the widest run that reaches minAgents distinct callers.
  let best: { start: number; end: number; members: BillingEvent[] } | null = null;
  for (let i = 0; i < dated.length; i++) {
    const callers = new Set<string>();
    let j = i;
    for (; j < dated.length && dated[j].t - dated[i].t <= windowMs; j++) {
      callers.add(dated[j].e.caller);
    }
    if (callers.size >= minAgents) {
      const members = dated.slice(i, j).map((x) => x.e);
      if (!best || members.length > best.members.length) {
        best = { start: dated[i].t, end: dated[j - 1].t, members };
      }
    }
  }
  if (!best) return null;

  const first = best.members[0];
  const sampleCodes = Array.from(
    new Set(best.members.map((e) => `${e.decision}:${e.provenance}`)),
  ).slice(0, 8);

  const cluster: Cluster = {
    signal,
    chainId: first.chainId,
    count: best.members.length,
    window: [new Date(best.start).toISOString(), new Date(best.end).toISOString()],
    sampleCodes,
  };
  // amountBucket is meaningful only for the shared-refuse shape, where every
  // member shares it by construction. The digest path may mix buckets, so it is
  // omitted there rather than reported misleadingly.
  if (signal === "shared-refuse" && first.amount_bucket !== undefined) {
    cluster.amountBucket = first.amount_bucket;
  }
  return cluster;
}