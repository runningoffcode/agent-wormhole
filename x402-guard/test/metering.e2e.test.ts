/**
 * End-to-end tests for the metering + correlation spine — the billing half of
 * the product. verify.ts answers "does the payment match the quote?"; this
 * module answers "was that verification billable, for how much, and does it
 * form a cross-agent pattern?".
 *
 * The claims a buyer (and an auditor) relies on, each pinned by a test title:
 *   - priceFor: the three trusted provenances bill > 0n per call; caller_asserted
 *     is 0n always; the monthly tier bills 0n per call (the flat fee is charged
 *     once at invoice time, not per verification).
 *   - createMeter over createMemoryStore records billable events, DROPS every
 *     caller_asserted event, and stores NO plaintext (no quote text, no raw
 *     payee, no exact amount figure).
 *   - correlate: an identical-digest fan-out across >= minAgents distinct callers
 *     flags; the same fan-out below the threshold does not; a single agent
 *     repeating the same digest never flags; the shared-refuse behavioral
 *     fallback still clusters when per-target payload mutation defeats the digest.
 *
 * Fully offline and deterministic: fixed ISO timestamps, no clock read, no
 * network, no store but the in-memory ring.
 */

import { describe, it, expect } from "vitest";
import {
  priceFor,
  isBillable,
  createMeter,
  createMemoryStore,
  correlate,
  monthlyInvoice,
  BILLABLE_PROVENANCES,
  DEFAULT_PER_CALL_MICRO_USDC,
  type BillingEvent,
  type MeterEvent,
} from "../src/metering.js";
import type { QuoteProvenance } from "../src/verify.js";

// The three provenances a verdict is allowed to bill for. caller_asserted is
// deliberately excluded — it is answered but never relied upon.
const TRUSTED: QuoteProvenance[] = [
  "independent_fetch",
  "merchant_signed",
  "facilitator_held",
];

// A fixed instant and its neighbours, so every window computation is
// deterministic. The module reads no clock — time arrives on the events.
const T0 = Date.parse("2033-05-18T03:33:20.000Z"); // fixed epoch anchor
function at(msFromT0: number): string {
  return new Date(T0 + msFromT0).toISOString();
}

// A plaintext-free-by-construction billing event. A sensitive marker only ever
// appears in fields the store must NOT keep — never smuggled in.
function billing(over: Partial<BillingEvent> = {}): BillingEvent {
  return {
    digest: "a".repeat(64),
    provenance: "merchant_signed",
    decision: "allow",
    chainId: 8453,
    issuedAt: at(0),
    tier: "per_call",
    caller: "agent-1",
    ...over,
  };
}

describe("metering — pricing (priceFor pins who is billed and how much)", () => {
  it("invariant: each of the three trusted provenances bills > 0n on the per_call tier", () => {
    for (const p of TRUSTED) {
      expect(isBillable(p)).toBe(true);
      expect(priceFor(p, "per_call")).toBe(DEFAULT_PER_CALL_MICRO_USDC);
      expect(priceFor(p, "per_call")).toBeGreaterThan(0n);
    }
  });

  it("invariant: caller_asserted is unbillable — priceFor => 0n on every tier", () => {
    expect(isBillable("caller_asserted")).toBe(false);
    expect(BILLABLE_PROVENANCES.has("caller_asserted" as QuoteProvenance)).toBe(false);
    expect(priceFor("caller_asserted", "per_call")).toBe(0n);
    expect(priceFor("caller_asserted", "monthly")).toBe(0n);
  });

  it("invariant: the monthly tier bills 0n per call (flat fee charged at invoice time, not per verification)", () => {
    // Even a trusted provenance is 0n per call on monthly — otherwise a monthly
    // customer is double-billed for calls their flat fee already covers.
    for (const p of TRUSTED) {
      expect(priceFor(p, "monthly")).toBe(0n);
    }
  });

  it("invariant: a per-provenance override changes only its own per_call price, still integer micro-USDC", () => {
    const config = { perProvenanceMicroUsdc: { merchant_signed: 5_000n } };
    expect(priceFor("merchant_signed", "per_call", config)).toBe(5_000n);
    // The other trusted provenances keep the flat per-call rate.
    expect(priceFor("independent_fetch", "per_call", config)).toBe(DEFAULT_PER_CALL_MICRO_USDC);
    // caller_asserted is still 0n — an override cannot make it billable.
    expect(priceFor("caller_asserted", "per_call", config)).toBe(0n);
    // The override still returns a bigint, never a float.
    expect(typeof priceFor("merchant_signed", "per_call", config)).toBe("bigint");
  });

  it("invariant: monthlyInvoice charges the flat fee and only overages beyond included volume, never caller_asserted", () => {
    const config = { monthly: { flatMicroUsdc: 25_000_000n, includedVolume: 2 }, perCallMicroUsdc: 3_000n };
    const events: BillingEvent[] = [
      billing({ provenance: "merchant_signed", tier: "monthly" }),
      billing({ provenance: "independent_fetch", tier: "monthly" }),
      billing({ provenance: "facilitator_held", tier: "monthly" }),
      // caller_asserted must never count toward billable volume even if it
      // somehow reached the roll-up.
      billing({ provenance: "caller_asserted" as QuoteProvenance, tier: "monthly" }),
    ];
    const inv = monthlyInvoice(events, config);
    expect(inv.billableCalls).toBe(3); // caller_asserted excluded
    expect(inv.flatMicroUsdc).toBe(25_000_000n);
    // 3 billable calls, 2 included → 1 overage call at 3_000 micro-USDC.
    expect(inv.overageMicroUsdc).toBe(3_000n);
    expect(inv.totalMicroUsdc).toBe(25_003_000n);
  });
});

describe("metering — the meter (createMeter over createMemoryStore)", () => {
  it("invariant: a billable event is recorded to the store", () => {
    const store = createMemoryStore();
    const meter = createMeter({ store });
    const ev: MeterEvent = {
      digest: "b".repeat(64),
      provenance: "merchant_signed",
      decision: "allow",
      chainId: 8453,
      issuedAt: at(0),
      caller: "agent-1",
    };
    meter.record(ev);
    const kept = store.recent(60_000);
    expect(kept.length).toBe(1);
    expect(kept[0].digest).toBe("b".repeat(64));
    expect(kept[0].provenance).toBe("merchant_signed");
    // Defaults the transport did not supply are filled in, not left undefined.
    expect(kept[0].tier).toBe("per_call");
    expect(kept[0].caller).toBe("agent-1");
  });

  it("invariant: caller_asserted is DROPPED — it never reaches the store, so it is never billed", () => {
    const store = createMemoryStore();
    const meter = createMeter({ store });
    // Record one trusted event and one caller_asserted event.
    meter.record({
      digest: "c".repeat(64),
      provenance: "facilitator_held",
      decision: "allow",
      chainId: null,
      issuedAt: at(0),
      caller: "agent-1",
    });
    meter.record({
      digest: "d".repeat(64),
      provenance: "caller_asserted",
      decision: "allow",
      chainId: null,
      issuedAt: at(0),
      caller: "agent-1",
    });
    const kept = store.recent(60_000);
    expect(kept.length).toBe(1); // only the trusted one survived
    expect(kept.every((e) => e.provenance !== "caller_asserted")).toBe(true);
    expect(kept[0].provenance).toBe("facilitator_held");
  });

  it("invariant: a stored event carries NO plaintext — no quote text, no raw payee, no exact amount figure", () => {
    const store = createMemoryStore();
    const meter = createMeter({ store });
    // A transport that (wrongly) tried to smuggle plaintext through extra keys
    // would still not have them stored: the event is constructed field by field.
    const SENSITIVE_QUOTE = "SENSITIVE-MERCHANT-NOTE-should-not-appear";
    const RAW_PAYEE = "0x1111111111111111111111111111111111111111";
    const EXACT_AMOUNT = "1000000";
    meter.record({
      digest: "e".repeat(64),
      provenance: "merchant_signed",
      decision: "allow",
      chainId: 8453,
      issuedAt: at(0),
      amountBucket: "1e6-1e7", // coarse band only — this IS allowed
      caller: "agent-1",
      // Adversarial extra keys a sloppy transport might attach:
      ...( { description: SENSITIVE_QUOTE, payTo: RAW_PAYEE, amount: EXACT_AMOUNT } as unknown as object ),
    });
    const serialized = JSON.stringify(store.recent(60_000));
    expect(serialized).not.toContain(SENSITIVE_QUOTE);
    expect(serialized).not.toContain(RAW_PAYEE);
    // The exact figure must not appear; the coarse bucket may.
    expect(serialized).not.toContain(EXACT_AMOUNT);
    expect(serialized).toContain("1e6-1e7");
  });

  it("invariant: a store failure never throws into the caller (a metering failure must not affect a verdict)", () => {
    const throwingStore = {
      append() {
        throw new Error("store is down");
      },
      recent() {
        return [] as BillingEvent[];
      },
    };
    const meter = createMeter({ store: throwingStore });
    // record() swallows the store error — the verdict already returned.
    expect(() =>
      meter.record({
        digest: "f".repeat(64),
        provenance: "merchant_signed",
        decision: "allow",
        chainId: 8453,
        issuedAt: at(0),
        caller: "agent-1",
      }),
    ).not.toThrow();
  });

  it("invariant: meter.priceFor uses the configured table; caller_asserted stays 0n", () => {
    const meter = createMeter({ price: { perCallMicroUsdc: 4_000n } });
    expect(meter.priceFor("merchant_signed", "per_call")).toBe(4_000n);
    expect(meter.priceFor("caller_asserted", "per_call")).toBe(0n);
    expect(meter.priceFor("merchant_signed", "monthly")).toBe(0n);
  });
});

describe("metering — correlation (the monthly-tier cross-agent signal)", () => {
  const WINDOW = 60_000; // 60s
  const DIGEST = "1".repeat(64);

  it("invariant: an identical-digest fan-out across >= minAgents distinct callers flags a cluster", () => {
    // Three DISTINCT callers verifying the exact same request within the window
    // — one crafted request replayed across a fleet.
    const events: BillingEvent[] = [
      billing({ digest: DIGEST, caller: "agent-1", issuedAt: at(0) }),
      billing({ digest: DIGEST, caller: "agent-2", issuedAt: at(1_000) }),
      billing({ digest: DIGEST, caller: "agent-3", issuedAt: at(2_000) }),
    ];
    const clusters = correlate(events, { windowMs: WINDOW, minAgents: 3 });
    const digestClusters = clusters.filter((c) => c.signal === "identical-digest");
    expect(digestClusters.length).toBe(1);
    expect(digestClusters[0].count).toBe(3);
    expect(digestClusters[0].chainId).toBe(8453);
  });

  it("invariant: the same fan-out below the minAgents threshold does NOT flag", () => {
    const events: BillingEvent[] = [
      billing({ digest: DIGEST, caller: "agent-1", issuedAt: at(0) }),
      billing({ digest: DIGEST, caller: "agent-2", issuedAt: at(1_000) }),
    ];
    // Only two distinct callers, threshold is three.
    const clusters = correlate(events, { windowMs: WINDOW, minAgents: 3 });
    expect(clusters.filter((c) => c.signal === "identical-digest").length).toBe(0);
  });

  it("invariant: a SINGLE agent repeating the same digest never flags (correlation needs distinct callers)", () => {
    // One caller hammering the same request many times is not a cross-agent
    // pattern — distinct-caller count is 1, below any minAgents >= 2.
    const events: BillingEvent[] = [
      billing({ digest: DIGEST, caller: "agent-solo", issuedAt: at(0) }),
      billing({ digest: DIGEST, caller: "agent-solo", issuedAt: at(1_000) }),
      billing({ digest: DIGEST, caller: "agent-solo", issuedAt: at(2_000) }),
      billing({ digest: DIGEST, caller: "agent-solo", issuedAt: at(3_000) }),
    ];
    const clusters = correlate(events, { windowMs: WINDOW, minAgents: 3 });
    expect(clusters.filter((c) => c.signal === "identical-digest").length).toBe(0);
  });

  it("invariant: distinct callers OUTSIDE the window do not flag (window is measured over issuedAt)", () => {
    const events: BillingEvent[] = [
      billing({ digest: DIGEST, caller: "agent-1", issuedAt: at(0) }),
      billing({ digest: DIGEST, caller: "agent-2", issuedAt: at(30_000) }),
      // Third caller far outside a 60s window from the first two.
      billing({ digest: DIGEST, caller: "agent-3", issuedAt: at(10_000_000) }),
    ];
    const clusters = correlate(events, { windowMs: WINDOW, minAgents: 3 });
    // No 60s-wide span holds all three distinct callers.
    expect(clusters.filter((c) => c.signal === "identical-digest").length).toBe(0);
  });

  it("invariant: shared-refuse fallback clusters distinct callers refusing the same (chainId, amount_bucket) even when digests differ", () => {
    // KNOWN EVASION: an adversary mutates the payload per target, so every
    // digest is unique and identical-digest forms no group. The behavioral
    // fallback keys on the OUTCOME (refuse) + COARSE SHAPE (chain + band),
    // which the attacker cannot vary without changing the attack.
    const events: BillingEvent[] = [
      billing({ digest: "aa".padEnd(64, "1"), decision: "refuse", chainId: 8453, amount_bucket: "1e6-1e7", caller: "agent-1", issuedAt: at(0) }),
      billing({ digest: "bb".padEnd(64, "2"), decision: "refuse", chainId: 8453, amount_bucket: "1e6-1e7", caller: "agent-2", issuedAt: at(1_000) }),
      billing({ digest: "cc".padEnd(64, "3"), decision: "refuse", chainId: 8453, amount_bucket: "1e6-1e7", caller: "agent-3", issuedAt: at(2_000) }),
    ];
    const clusters = correlate(events, { windowMs: WINDOW, minAgents: 3 });
    const refuseClusters = clusters.filter((c) => c.signal === "shared-refuse");
    expect(refuseClusters.length).toBe(1);
    expect(refuseClusters[0].count).toBe(3);
    expect(refuseClusters[0].chainId).toBe(8453);
    expect(refuseClusters[0].amountBucket).toBe("1e6-1e7");
    // And the digest path formed nothing, since every digest was unique.
    expect(clusters.filter((c) => c.signal === "identical-digest").length).toBe(0);
  });

  it("invariant: shared-refuse does NOT cluster a single agent's repeated refusals", () => {
    const events: BillingEvent[] = [
      billing({ digest: "d1".padEnd(64, "1"), decision: "refuse", chainId: 8453, amount_bucket: "1e6-1e7", caller: "agent-solo", issuedAt: at(0) }),
      billing({ digest: "d2".padEnd(64, "2"), decision: "refuse", chainId: 8453, amount_bucket: "1e6-1e7", caller: "agent-solo", issuedAt: at(1_000) }),
      billing({ digest: "d3".padEnd(64, "3"), decision: "refuse", chainId: 8453, amount_bucket: "1e6-1e7", caller: "agent-solo", issuedAt: at(2_000) }),
    ];
    const clusters = correlate(events, { windowMs: WINDOW, minAgents: 3 });
    expect(clusters.filter((c) => c.signal === "shared-refuse").length).toBe(0);
  });

  it("invariant: refusals spread across DIFFERENT chains/bands do not share a cluster (attacker forced to give up uniformity)", () => {
    const events: BillingEvent[] = [
      billing({ digest: "e1".padEnd(64, "1"), decision: "refuse", chainId: 8453, amount_bucket: "1e6-1e7", caller: "agent-1", issuedAt: at(0) }),
      billing({ digest: "e2".padEnd(64, "2"), decision: "refuse", chainId: 1, amount_bucket: "1e6-1e7", caller: "agent-2", issuedAt: at(1_000) }),
      billing({ digest: "e3".padEnd(64, "3"), decision: "refuse", chainId: 8453, amount_bucket: "1e7-1e8", caller: "agent-3", issuedAt: at(2_000) }),
    ];
    const clusters = correlate(events, { windowMs: WINDOW, minAgents: 3 });
    // Each (chainId, band) shape has at most one caller — no shared-refuse group.
    expect(clusters.filter((c) => c.signal === "shared-refuse").length).toBe(0);
  });

  it("invariant: caller_asserted is never correlated as trusted — dropped at record, so no cluster can form from it", () => {
    // Route the events through the meter, which drops caller_asserted before the
    // store ever sees them, so correlate cannot cluster on them.
    const meter = createMeter();
    const digest = "9".repeat(64);
    for (const caller of ["agent-1", "agent-2", "agent-3"]) {
      meter.record({
        digest,
        provenance: "caller_asserted",
        decision: "allow",
        chainId: 8453,
        issuedAt: at(0),
        caller,
      });
    }
    const clusters = meter.correlate({ windowMs: WINDOW, minAgents: 3 });
    expect(clusters.length).toBe(0);
    expect(meter.store.recent(WINDOW).length).toBe(0);
  });

  it("invariant: an empty event set yields no clusters", () => {
    expect(correlate([], { windowMs: WINDOW, minAgents: 2 })).toEqual([]);
  });
});
