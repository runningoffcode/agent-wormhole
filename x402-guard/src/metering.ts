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
export function monthlyInvoice(
  events: ReadonlyArray<BillingEvent>,
  config: PriceConfig = {},
): { flatMicroUsdc: bigint; overageMicroUsdc: bigint; totalMicroUsdc: bigint; billableCalls: number } {
  const monthly = config.monthly ?? DEFAULT_MONTHLY_TIER;
  const perCall = config.perCallMicroUsdc ?? DEFAULT_PER_CALL_MICRO_USDC;

  let billableCalls = 0;
  for (const e of events) {
    if (isBillable(e.provenance)) billableCalls++;
  }

  const overageCalls = Math.max(0, billableCalls - monthly.includedVolume);
  const overageMicroUsdc = BigInt(overageCalls) * perCall;
  return {
    flatMicroUsdc: monthly.flatMicroUsdc,
    overageMicroUsdc,
    totalMicroUsdc: monthly.flatMicroUsdc + overageMicroUsdc,
    billableCalls,
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
    correlate: (o) => correlate(store.recent(o.windowMs), o),
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