/**
 * AW-71 regression tests: sink and metering robustness.
 *
 * Every test here is load-bearing — each one fails if the specific guard it
 * covers is removed. Two previous attempts at this finding shipped a green
 * suite while the defect stayed live, so these pin the BEHAVIOUR under the
 * exact inputs that were broken, not the shape of the code that fixes them.
 *
 * The four defects, and the failure mode each test blocks:
 *
 *   1. resolveChainId accepted only a bare number and CAIP-2/v1 names, so
 *      "8453", "0x2105" and 8453n — all shapes real x402 payloads carry —
 *      filed themselves under the Solana sentinel, putting Base traffic in
 *      every report's Solana bucket.
 *   2. amountBucket used Number.isSafeInteger, so whole counts above 2^53 got
 *      no band at all — i.e. the SVM lamport lane's largest payments were the
 *      least labelled.
 *   3. monthlyInvoice THREW on a fractional includedVolume and on a
 *      number-typed price (losing the period's invoice), went NEGATIVE on a
 *      negative flat fee, and — the defect the brief did not list — let a
 *      JSON-string flatMicroUsdc reach `+` as a string, so 25 USDC plus
 *      overage billed as the concatenated string "2500000015000".
 *   4. recent() anchors its window on max(issuedAt), a caller-supplied field,
 *      so ONE future-dated row blinded correlate entirely.
 *
 * And the two failure modes the REVERTED attempts introduced, pinned here so
 * they cannot come back:
 *
 *   - dropping an event to "fail closed" (for an audit log that is fail-OPEN:
 *     it destroys the evidence, and became an event-suppression primitive);
 *   - a sentinel VALUE for "unreadable" that resolveChainId still accepted, so
 *     a caller could forge the marker.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import {
  configureEventSink,
  resetEventSink,
  recordVerdict,
  eventSinkStats,
  toEvents,
  amountBucket,
  resolveChainId,
  assertNoPlaintext,
  type PaymentEvent,
} from "../src/sink.js";
import {
  createMeter,
  createMemoryStore,
  monthlyInvoice,
  correlationFeed,
  CORRELATE_TAIL,
  type BillingEvent,
} from "../src/metering.js";

const SALT = "0123456789abcdef0123456789abcdef";
const REFUSE = {
  decision: "refuse" as const,
  findings: [{ code: "X402-101", severity: "critical" }],
};

let dir: string;
let spool: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "aw71-"));
  spool = path.join(dir, "events.jsonl");
});
afterEach(() => {
  resetEventSink();
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
});

function lines(): Array<Record<string, unknown>> {
  try {
    return fs
      .readFileSync(spool, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

// --- 1. chain id resolution -------------------------------------------------

describe("AW-71 / chain id: every documented shape resolves to its real id", () => {
  it("resolves bare-decimal, hex (both prefix cases), bigint and names", () => {
    // Each of these landed on 0 (the Solana sentinel) before the fix.
    expect(resolveChainId("8453")).toBe(8453);
    expect(resolveChainId("0x2105")).toBe(8453);
    expect(resolveChainId("0X2105")).toBe(8453);
    expect(resolveChainId(8453n)).toBe(8453);
    expect(resolveChainId("  8453  ")).toBe(8453);
    // These already worked and must keep working.
    expect(resolveChainId(8453)).toBe(8453);
    expect(resolveChainId("base")).toBe(8453);
    expect(resolveChainId("eip155:8453")).toBe(8453);
  });

  it("carries the resolved id onto the written record", () => {
    for (const [supplied, expected] of [
      ["8453", 8453],
      ["0x2105", 8453],
      ["0X2105", 8453],
      [8453n, 8453],
      ["base", 8453],
      [8453, 8453],
    ] as Array<[unknown, number]>) {
      const ev = toEvents(REFUSE, { chainId: supplied as never });
      expect(ev).toHaveLength(1);
      expect(ev[0].chain_id).toBe(expected);
      expect(ev[0].unreadable).toBeUndefined();
    }
  });

  it("keeps a genuine non-EVM chain on the sentinel WITHOUT marking it degraded", () => {
    // 0 and "solana" are real answers, not failures. Marking them would make
    // every Solana integrator's traffic look broken.
    for (const supplied of [0, "solana", undefined, null, ""]) {
      const ev = toEvents(REFUSE, { chainId: supplied as never });
      expect(ev).toHaveLength(1);
      expect(ev[0].chain_id).toBe(0);
      expect(ev[0].unreadable).toBeUndefined();
    }
  });
});

// --- 2. amount banding ------------------------------------------------------

describe("AW-71 / amount: whole counts above 2^53 get a band", () => {
  it("bands the SVM u64 lamport lane instead of returning null", () => {
    expect(amountBucket(1e18)).toBe("amt:1e12+");
    expect(amountBucket(2 ** 53)).toBe("amt:1e12+");
    expect(amountBucket(2 ** 60)).toBe("amt:1e12+");
    expect(amountBucket(1e15)).toBe("amt:1e12+");
  });

  it("bands hex amounts, the EVM's native uint256 spelling", () => {
    expect(amountBucket("0x2710")).toBe("amt:1e3-1e6");
    expect(amountBucket("0X2710")).toBe("amt:1e3-1e6");
  });

  it("still refuses to band what is not a whole count", () => {
    // A fractional or negative amount is not the same as an amount of zero;
    // folding them together would make an unparseable payload look free.
    for (const bad of [1.5, -5, NaN, Infinity, "abc", {}, []]) {
      expect(amountBucket(bad as never)).toBeNull();
    }
    expect(amountBucket(0)).toBe("amt:0");
  });
});

// --- 3. the record is ALWAYS written ---------------------------------------

describe("AW-71 / no evidence erasure: every input shape still produces a record", () => {
  // This is the property the second attempt destroyed. For a guard, fail-closed
  // means refuse the action; for an AUDIT LOG, dropping the record is fail-OPEN.
  const SHAPES: Array<[string, unknown]> = [
    ["number", 8453],
    ["decimal string", "8453"],
    ["hex", "0x2105"],
    ["bigint", 8453n],
    ["solana sentinel", 0],
    ["solana name", "solana"],
    ["undefined", undefined],
    ["null", null],
    ["garbage", "garbage"],
    ["object", {}],
    ["array", []],
    ["NaN", NaN],
    ["negative", -1],
    ["fractional", 1.5],
    ["empty string", ""],
    ["boolean", true],
    ["bare 0x", "0x"],
    ["malformed caip", "eip155:abc"],
    ["symbol", Symbol("s")],
  ];

  it.each(SHAPES)("emits exactly one event for chainId=%s", (_label, supplied) => {
    const ev = toEvents(REFUSE, { chainId: supplied as never });
    expect(ev).toHaveLength(1);
  });

  it("loses no finding from a multi-finding verdict, whatever the chain id", () => {
    const three = {
      decision: "refuse" as const,
      findings: [
        { code: "X402-101", severity: "critical" },
        { code: "X402-102", severity: "high" },
        { code: "X402-201", severity: "medium" },
      ],
    };
    for (const supplied of [8453, 0, "garbage", {}, undefined]) {
      const ev = toEvents(three, { chainId: supplied as never });
      expect(ev.map((e) => e.code)).toEqual(["X402-101", "X402-102", "X402-201"]);
    }
  });

  it("writes an explicit chainId=0 to disk — the case that cost Solana 100% of its records", () => {
    configureEventSink({ path: spool, salt: SALT });
    const n = recordVerdict(
      {
        decision: "refuse",
        findings: [
          { code: "X402-101", severity: "critical" },
          { code: "X402-102", severity: "high" },
          { code: "X402-201", severity: "medium" },
        ],
      },
      { chainId: 0 },
    );
    expect(n).toBe(3);
    expect(lines()).toHaveLength(3);
    const stats = eventSinkStats()!;
    expect(stats.written).toBe(3);
    expect(stats.dropped).toBe(0);
    // 0 is a real answer, so it is not degradation.
    expect(stats.degraded).toBe(0);
  });
});

// --- 4. the `unreadable` key ------------------------------------------------

describe("AW-71 / the doubt lives on its own key, not in chain_id's value", () => {
  it("marks an unreadable chain id without moving it off the sentinel", () => {
    const ev = toEvents(REFUSE, { chainId: "garbage" });
    expect(ev[0].chain_id).toBe(0);
    expect(ev[0].unreadable).toEqual(["chain_id"]);
  });

  it("marks an unreadable amount", () => {
    const ev = toEvents(REFUSE, { chainId: 8453, amount: "not-a-number" });
    expect(ev[0].amount_bucket).toBeUndefined();
    expect(ev[0].unreadable).toEqual(["amount"]);
  });

  it("distinguishes a genuine Solana row from an unreadable one ON DISK", () => {
    // Before the fix both were `chain_id: 0` and byte-identical, so an operator
    // could not locate the rows whose chain had been guessed.
    configureEventSink({ path: spool, salt: SALT });
    recordVerdict(REFUSE, { chainId: 0 });
    recordVerdict(REFUSE, { chainId: "garbage" });
    const rows = lines();
    expect(rows).toHaveLength(2);
    expect(rows[0].chain_id).toBe(0);
    expect(rows[0].unreadable).toBeUndefined();
    expect(rows[1].chain_id).toBe(0);
    expect(rows[1].unreadable).toEqual(["chain_id"]);
  });

  it("leaves an honest record at exactly seven keys", () => {
    configureEventSink({ path: spool, salt: SALT });
    recordVerdict(REFUSE, { payTo: "abc", amount: "5", chainId: 8453 });
    const row = lines()[0];
    expect(Object.keys(row).sort()).toEqual([
      "amount_bucket",
      "chain_id",
      "code",
      "decision",
      "payee_hash",
      "severity",
      "ts",
    ]);
  });

  it("does not share one mutable array between the events of a verdict", () => {
    const ev = toEvents(
      {
        decision: "refuse",
        findings: [
          { code: "X402-101", severity: "critical" },
          { code: "X402-102", severity: "high" },
        ],
      },
      { chainId: "garbage" },
    );
    expect(ev[0].unreadable).not.toBe(ev[1].unreadable);
    expect(ev[0].unreadable).toEqual(ev[1].unreadable);
  });
});

// --- 5. the marker cannot be forged ----------------------------------------

describe("AW-71 / no forgeable sentinel (the defect that killed attempt 2)", () => {
  it("resolves MAX_SAFE_INTEGER as an ordinary chain id in every spelling", () => {
    // Attempt 2 declared CHAIN_ID_UNRESOLVED = MAX_SAFE_INTEGER while
    // resolveChainId still ACCEPTED that value, so a caller could stamp their
    // own row "unreadable". The marker must be a key, not a number.
    for (const supplied of [
      Number.MAX_SAFE_INTEGER,
      "9007199254740991",
      "0x1fffffffffffff",
      BigInt(Number.MAX_SAFE_INTEGER),
    ]) {
      const ev = toEvents(REFUSE, { chainId: supplied as never });
      expect(ev[0].chain_id).toBe(Number.MAX_SAFE_INTEGER);
      expect(ev[0].unreadable).toBeUndefined();
    }
  });

  it("refuses a record whose `unreadable` key is outside the closed set", () => {
    const base: PaymentEvent = {
      code: "X402-101",
      severity: "critical",
      decision: "refuse",
      chain_id: 8453,
      ts: new Date().toISOString(),
    };
    expect(assertNoPlaintext({ ...base, unreadable: ["chain_id"] })).toEqual([]);
    expect(assertNoPlaintext({ ...base, unreadable: ["amount", "chain_id"] })).toEqual([]);
    // A plaintext address smuggled onto the new key is refused, not written.
    expect(
      assertNoPlaintext({ ...base, unreadable: ["0xdeadbeef"] }).join(),
    ).toContain("unreadable field not in vocabulary");
    expect(
      assertNoPlaintext({ ...base, unreadable: ["payee_hash"] }).join(),
    ).toContain("unreadable field not in vocabulary");
    expect(
      assertNoPlaintext({ ...base, unreadable: "chain_id" as never }).join(),
    ).toContain("unreadable not a non-empty array");
    expect(
      assertNoPlaintext({ ...base, unreadable: [] }).join(),
    ).toContain("unreadable not a non-empty array");
  });
});

// --- 6. the degraded counter -----------------------------------------------

describe("AW-71 / degraded is on the same unit as written", () => {
  it("never claims a record that did not reach disk", () => {
    // Attempt 2 asserted degraded=1 for an event it had already dropped.
    configureEventSink({ path: spool, salt: SALT });
    const n = recordVerdict(
      { decision: "refuse", findings: [{ code: "X402-999", severity: "critical" }] },
      { chainId: "garbage" },
    );
    expect(n).toBe(0);
    const stats = eventSinkStats()!;
    expect(stats.written).toBe(0);
    expect(stats.degraded).toBe(0);
    expect(lines()).toHaveLength(0);
  });

  it("does not count a degraded record that FAILED to reach disk", () => {
    // The counter must move only after writeThrough succeeds. Attempt 2 added
    // it before the write, so a failed write left `degraded` claiming records
    // the spool never received — and a counter that cannot be reconciled
    // against the bytes is not evidence of anything.
    configureEventSink({ path: spool, salt: SALT });
    // Turn the live spool into a FIFO underneath the sink. writeThrough's
    // liveness check sees the original name is gone, drops the cached fd, and
    // on reopen refuses a pipe -- a blocking open on one would hang the
    // payment path. So the write fails with degraded records pending.
    fs.rmSync(spool, { force: true });
    execFileSync("mkfifo", [spool]);
    const n = recordVerdict(
      {
        decision: "refuse",
        findings: [
          { code: "X402-101", severity: "critical" },
          { code: "X402-102", severity: "high" },
        ],
      },
      { chainId: "garbage" },
    );
    // A FIFO is refused rather than opened, so nothing was written.
    expect(n).toBe(0);
    const stats = eventSinkStats()!;
    expect(stats.written).toBe(0);
    expect(stats.dropped).toBe(2);
    // The records are degraded AND undelivered. Undelivered wins: they are not
    // on disk, so they must not be counted as degraded records that are.
    expect(stats.degraded).toBe(0);
    expect(stats.degraded).toBeLessThanOrEqual(stats.written);
  });

  it("reconciles against the spool over a stress run", () => {
    configureEventSink({ path: spool, salt: SALT });
    const codes = ["X402-101", "X402-102", "X402-201", "X402-301", "X402-401"];
    const chains: unknown[] = [
      8453, "8453", "0x2105", "base", "solana", 0, undefined,
      "garbage", {}, NaN, -1, "eip155:1",
    ];
    let expectedDegraded = 0;
    for (let i = 0; i < 600; i++) {
      const chainId = chains[i % chains.length];
      const unreadable =
        chainId === "garbage" ||
        (typeof chainId === "object" && chainId !== null) ||
        (typeof chainId === "number" && (Number.isNaN(chainId) || chainId < 0));
      if (unreadable) expectedDegraded += 2;
      recordVerdict(
        {
          decision: "refuse",
          findings: [
            { code: codes[i % 5], severity: "critical" },
            { code: codes[(i + 1) % 5], severity: "high" },
          ],
        },
        { chainId: chainId as never },
      );
    }
    const rows = lines();
    const stats = eventSinkStats()!;
    expect(stats.written).toBe(1200);
    expect(rows).toHaveLength(1200);
    expect(stats.dropped).toBe(0);
    // The counter must be reconcilable against the bytes, three ways.
    expect(stats.degraded).toBe(expectedDegraded);
    expect(stats.degraded).toBe(rows.filter((r) => r.unreadable !== undefined).length);
    expect(stats.degraded).toBeLessThanOrEqual(stats.written);
  });
});

// --- 7. the invoice ---------------------------------------------------------

const BILLABLE = "merchant_signed" as const;
function billing(n: number): BillingEvent[] {
  return Array.from({ length: n }, (_, i) => ({
    digest: "d" + i,
    provenance: BILLABLE,
    decision: "allow",
    chainId: 8453,
    issuedAt: new Date(1_700_000_000_000 + i * 1000).toISOString(),
    tier: "monthly" as const,
    caller: "c1",
  }));
}

describe("AW-71 / monthlyInvoice returns a complete invoice plus faults, never a throw", () => {
  it("does not concatenate a JSON-string price into the total", () => {
    // The defect the brief did not list: "25000000" + 15000n chose STRING
    // CONCATENATION over addition, billing "2500000015000" — ~99,800x — and
    // typing as a string all the way to the invoice.
    const r = monthlyInvoice(billing(15), {
      monthly: { flatMicroUsdc: "25000000" as never, includedVolume: 10 },
    });
    expect(typeof r.totalMicroUsdc).toBe("bigint");
    expect(r.totalMicroUsdc).toBe(25_015_000n);
  });

  it("floors a fractional includedVolume instead of throwing", () => {
    const r = monthlyInvoice(billing(15), {
      monthly: { flatMicroUsdc: 25_000_000n, includedVolume: 10.5 },
    });
    expect(r.totalMicroUsdc).toBe(25_015_000n);
    expect(r.faults).toEqual([
      { field: "includedVolume", reason: "fractional", usedInstead: "10" },
    ]);
  });

  it("coerces a number-typed price instead of throwing", () => {
    const r = monthlyInvoice(billing(15), {
      perCallMicroUsdc: 5 as never,
      monthly: { flatMicroUsdc: 25_000_000n, includedVolume: 10 },
    });
    expect(r.totalMicroUsdc).toBe(25_000_025n);
    expect(r.faults).toEqual([]);
  });

  it("never returns a negative invoice", () => {
    const r = monthlyInvoice(billing(15), {
      monthly: { flatMicroUsdc: -5_000_000n, includedVolume: 10_000 },
    });
    expect(r.totalMicroUsdc).toBeGreaterThanOrEqual(0n);
    expect(r.faults[0]).toMatchObject({ field: "flatMicroUsdc", reason: "negative" });
  });

  it("REPORTS AND REJECTS an out-of-range includedVolume rather than clamping it", () => {
    // Clamping 1e308 would mean no call in any month is ever overage — i.e. the
    // month silently becomes free.
    const r = monthlyInvoice(billing(15), {
      monthly: { flatMicroUsdc: 25_000_000n, includedVolume: 1e308 },
    });
    expect(r.faults).toEqual([
      { field: "includedVolume", reason: "out-of-range", usedInstead: "10000" },
    ]);
    expect(r.totalMicroUsdc).toBe(25_000_000n);
  });

  it("leaves an honest config with no faults and an unchanged total", () => {
    expect(monthlyInvoice(billing(15), {}).faults).toEqual([]);
    expect(monthlyInvoice(billing(15), {}).totalMicroUsdc).toBe(25_000_000n);
    const r = monthlyInvoice(billing(15), {
      monthly: { flatMicroUsdc: 25_000_000n, includedVolume: 10 },
    });
    expect(r.totalMicroUsdc).toBe(25_015_000n);
    expect(r.faults).toEqual([]);
  });

  it("never throws and never goes negative, for any config shape", () => {
    const hostile: unknown[] = [
      -1n, -1, 1.5, NaN, Infinity, "abc", {}, [], null, undefined, true, "1e10",
    ];
    for (const flat of hostile) {
      for (const incl of hostile) {
        const r = monthlyInvoice(billing(3), {
          monthly: { flatMicroUsdc: flat as never, includedVolume: incl as never },
        });
        expect(typeof r.totalMicroUsdc).toBe("bigint");
        expect(r.totalMicroUsdc).toBeGreaterThanOrEqual(0n);
      }
    }
  });
});

// --- 8. the correlation feed ------------------------------------------------

function seeded(n: number) {
  const store = createMemoryStore(200_000);
  for (let i = 0; i < n; i++) {
    store.append({
      digest: "SHARED",
      provenance: BILLABLE,
      decision: "refuse",
      chainId: 8453,
      issuedAt: new Date(1_700_000_000_000 + i * 100).toISOString(),
      tier: "monthly",
      caller: "agent" + (i % 4),
      amount_bucket: "amt:1e3-1e6",
    });
  }
  return store;
}

describe("AW-71 / one forged timestamp no longer blinds correlate", () => {
  it("still finds the clusters after a far-future row arrives", () => {
    const store = seeded(40);
    const meter = createMeter({ store });
    expect(meter.correlate({ windowMs: 60_000, minAgents: 2 })).toHaveLength(2);
    store.append({
      digest: "FORGE",
      provenance: BILLABLE,
      decision: "refuse",
      chainId: 8453,
      issuedAt: "2099-01-01T00:00:00.000Z",
      tier: "monthly",
      caller: "evil",
      amount_bucket: "amt:0",
    });
    // Before the fix this returned 0 — the forged row moved recent()'s right
    // edge past every honest row, so correlate saw one event.
    expect(meter.correlate({ windowMs: 60_000, minAgents: 2 })).toHaveLength(2);
  });

  it("leaves recent()'s documented contract alone", () => {
    // recent() is ALSO the billing surface — monthlyInvoice(store.recent(period))
    // — so widening it into a superset re-bills last period's calls. It is
    // deliberately still anchored on max(issuedAt).
    const store = seeded(40);
    store.append({
      digest: "FORGE",
      provenance: BILLABLE,
      decision: "refuse",
      chainId: 8453,
      issuedAt: "2099-01-01T00:00:00.000Z",
      tier: "monthly",
      caller: "evil",
    });
    expect(store.recent(60_000)).toHaveLength(1);
  });

  it("does not re-bill a previous period through recent()", () => {
    const store = createMemoryStore(200_000);
    const anchor = 1_700_000_000_000;
    for (let i = 0; i < 50; i++) {
      store.append({
        digest: "cur" + i, provenance: BILLABLE, decision: "allow", chainId: 8453,
        issuedAt: new Date(anchor + i * 1000).toISOString(),
        tier: "monthly", caller: "c1",
      });
    }
    for (let i = 0; i < 50; i++) {
      store.append({
        digest: "old" + i, provenance: BILLABLE, decision: "allow", chainId: 8453,
        issuedAt: new Date(anchor - 40 * 86_400_000 + i * 1000).toISOString(),
        tier: "monthly", caller: "c1",
      });
    }
    const invoice = monthlyInvoice(store.recent(30 * 86_400_000), {
      monthly: { flatMicroUsdc: 0n, includedVolume: 0 },
      perCallMicroUsdc: 1_000_000n,
    });
    expect(invoice.billableCalls).toBe(50);
    expect(invoice.totalMicroUsdc).toBe(50_000_000n);
  });

  it("selects by arrival order, which no timestamp can move", () => {
    const store = createMemoryStore(1000);
    for (let i = 0; i < 10; i++) {
      store.append({
        digest: "d" + i, provenance: BILLABLE, decision: "allow", chainId: 1,
        issuedAt: new Date(1_700_000_000_000 + i * 1000).toISOString(),
        tier: "monthly", caller: "c",
      });
    }
    store.append({
      digest: "FUTURE", provenance: BILLABLE, decision: "allow", chainId: 1,
      issuedAt: "2099-01-01T00:00:00.000Z", tier: "monthly", caller: "evil",
    });
    for (let i = 10; i < 15; i++) {
      store.append({
        digest: "d" + i, provenance: BILLABLE, decision: "allow", chainId: 1,
        issuedAt: new Date(1_700_000_000_000 + i * 1000).toISOString(),
        tier: "monthly", caller: "c",
      });
    }
    expect(store.tail!(5).map((e) => e.digest)).toEqual([
      "d10", "d11", "d12", "d13", "d14",
    ]);
  });

  it("ignores a hostile limit rather than returning an unbounded slice", () => {
    const store = seeded(5000);
    for (const limit of [-1, 0, NaN, 1e9, 1.5, Infinity, -Infinity, 2 ** 53]) {
      expect(store.tail!(limit)).toHaveLength(CORRELATE_TAIL);
    }
    expect(store.tail!(10)).toHaveLength(10);
  });

  it("loses no row when the store is smaller than the bound", () => {
    for (let trial = 0; trial < 50; trial++) {
      const n = 1 + Math.floor(Math.random() * 400);
      const store = createMemoryStore(100_000);
      const appended: BillingEvent[] = [];
      for (let i = 0; i < n; i++) {
        const e: BillingEvent = {
          digest: "d" + i, provenance: BILLABLE, decision: "refuse", chainId: 8453,
          issuedAt: new Date(
            1_700_000_000_000 + Math.floor((Math.random() - 0.5) * 4e6),
          ).toISOString(),
          tier: "monthly", caller: "c" + (i % 5),
        };
        store.append(e);
        appended.push(e);
      }
      expect(store.tail!(CORRELATE_TAIL)).toEqual(appended);
    }
  });

  it("falls back to recent() for a store that does not implement tail()", () => {
    // tail() is optional so an existing custom store still satisfies the
    // interface. Such a store keeps the original exposure; it must not crash.
    const rows: BillingEvent[] = [];
    const plain = {
      append(e: BillingEvent) { rows.push(e); },
      recent() { return rows.slice(); },
    };
    const meter = createMeter({ store: plain });
    for (let i = 0; i < 40; i++) {
      plain.append({
        digest: "SHARED", provenance: BILLABLE, decision: "refuse", chainId: 8453,
        issuedAt: new Date(1_700_000_000_000 + i * 100).toISOString(),
        tier: "monthly", caller: "agent" + (i % 4), amount_bucket: "amt:1e3-1e6",
      });
    }
    expect(meter.correlate({ windowMs: 60_000, minAgents: 2 })).toHaveLength(2);
  });

  it("survives a store whose tail() throws", () => {
    const bad = {
      append() {},
      recent() { return [] as BillingEvent[]; },
      tail(): ReadonlyArray<BillingEvent> { throw new Error("store is down"); },
    };
    expect(() => correlationFeed(bad, 60_000)).not.toThrow();
    expect(correlationFeed(bad, 60_000)).toEqual([]);
  });

  it("bounds the work correlate does, whatever the store holds", () => {
    // buildCluster's sliding window is O(n^2) in candidate-group size, so an
    // unbounded feed is a denial of service reachable from one account:
    // 20,000 rows measured at ~15s before this bound existed.
    const store = seeded(100_000);
    const meter = createMeter({ store });
    expect(store.tail!(CORRELATE_TAIL)).toHaveLength(CORRELATE_TAIL);
    const started = Date.now();
    const clusters = meter.correlate({ windowMs: 86_400_000 * 365, minAgents: 2 });
    expect(Date.now() - started).toBeLessThan(5000);
    expect(clusters).toHaveLength(2);
  });
});

describe("correlationFeed keeps a time window when the store has tail()", () => {
  const BASE = Date.parse("2026-09-01T00:00:00Z");
  const ev = (tMs: number, digest: string, caller: string) => ({
    issuedAt: new Date(tMs).toISOString(),
    decision: "refuse" as const,
    digest,
    chain_id: 8453,
    amount_bucket: "1-10",
    codes: ["X402-101"],
    caller,
  });

  it("excludes a cluster that is weeks stale", () => {
    // `tail` slices by insertion order, which is why it is preferred — a
    // forged future row cannot move its edge. But it carries no notion of
    // time, so returning it unfiltered drops recency entirely and a cluster
    // formed once would be reported as current forever.
    const rows = [
      ev(BASE, "old", "a"), ev(BASE + 1_000, "old", "b"),
      ev(BASE + 2_000, "old", "c"), ev(BASE + 3_000, "old", "d"),
      ev(BASE + 40 * 86_400_000, "fresh", "a"),
      ev(BASE + 40 * 86_400_000 + 1_000, "fresh", "b"),
      ev(BASE + 40 * 86_400_000 + 2_000, "fresh", "c"),
      ev(BASE + 40 * 86_400_000 + 3_000, "fresh", "d"),
    ];
    const store = {
      append: () => {},
      recent: () => rows,
      tail: () => rows,
    } as never;
    const feed = correlationFeed(store, 60_000, 2000);
    const digests = new Set(feed.map((e) => e.digest));
    expect(digests.has("fresh")).toBe(true);
    expect(digests.has("old")).toBe(false);
  });

  it("is not blinded by a single far-future row", () => {
    // The anchor is the MEDIAN, not the newest: the newest is precisely what
    // an attacker controls, and anchoring on it would reintroduce through the
    // back door the blinding this branch exists to prevent.
    const rows = [
      ev(BASE, "live", "a"), ev(BASE + 1_000, "live", "b"),
      ev(BASE + 2_000, "live", "c"), ev(BASE + 3_000, "live", "d"),
      ev(BASE + 365 * 86_400_000, "forged", "z"),
    ];
    const store = {
      append: () => {},
      recent: () => rows,
      tail: () => rows,
    } as never;
    const feed = correlationFeed(store, 60_000, 2000);
    expect(feed.some((e) => e.digest === "live")).toBe(true);
  });
});
