/**
 * Tests for the opt-in event sink.
 *
 * The claims worth testing here are not "does it write a file". They are:
 *
 *   1. It is OFF by default and stays off until configured.
 *   2. It ACTUALLY TURNS ON when configured — asserted by reading the file
 *      back, not by trusting a return value. The module's never-throw contract
 *      means every bug in it looks like "quietly did nothing", so a test that
 *      only checks for the absence of an exception would have passed against a
 *      build where `require` was undefined and the sink never worked at all.
 *      That build existed; this test is why it did not ship.
 *   3. Attacker-controlled and amount-bearing text NEVER reaches the file. This
 *      is checked by planting canaries in every free-text field a Finding has
 *      and grepping the actual bytes on disk.
 *   4. It never throws into the payment path, under real failure conditions
 *      (path is a directory, file deleted underneath it) rather than mocked.
 *   5. The code vocabulary does not drift from the three guard modules — the
 *      list is grepped out of the real source files and compared as a set.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
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
} from "../src/sink.js";
import { parseNetwork } from "../src/evm.js";

const SALT = "0123456789abcdef0123456789abcdef";
let dir: string;
let spool: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "x402sink-"));
  spool = path.join(dir, "events.jsonl");
  resetEventSink();
});

afterEach(() => {
  resetEventSink();
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

function lines(p = spool): PaymentEvent[] {
  if (!fs.existsSync(p)) return [];
  return fs
    .readFileSync(p, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
}

const refuseVerdict = {
  decision: "refuse" as const,
  findings: [
    {
      code: "X402-001",
      severity: "critical" as const,
      message: "destination mismatch",
      expected: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
      actual: "AttackerAddr1111111111111111111111111111111",
    },
  ],
};

describe("off by default", () => {
  it("writes nothing and creates no file when never configured", () => {
    const n = recordVerdict(refuseVerdict, { payTo: "x", amount: "1000" });
    expect(n).toBe(0);
    expect(eventSinkStats()).toBeNull();
    expect(fs.existsSync(spool)).toBe(false);
  });

  it("stays off when configured with null", () => {
    expect(configureEventSink(null)).toBe(false);
    expect(recordVerdict(refuseVerdict)).toBe(0);
  });

  it("refuses a configuration with no path", () => {
    expect(configureEventSink({ path: "" })).toBe(false);
    expect(eventSinkStats()).toBeNull();
  });
});

describe("actually turns on", () => {
  it("returns true, reports stats, and lands a line on disk", () => {
    // Regression: an earlier build used a bare `require` in an ESM module.
    // It typechecked, threw ReferenceError at runtime, and the never-throw
    // catch swallowed it — configure returned false forever. Asserting on the
    // return value AND the file contents is what catches that class of bug.
    expect(configureEventSink({ path: spool, salt: SALT })).toBe(true);
    const stats = eventSinkStats();
    expect(stats).not.toBeNull();
    expect(stats!.salted).toBe(true);

    const n = recordVerdict(refuseVerdict, {
      payTo: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
      amount: "1000000",
      chainId: null,
    });
    expect(n).toBe(1);

    const rows = lines();
    expect(rows).toHaveLength(1);
    expect(rows[0].code).toBe("X402-001");
    expect(rows[0].severity).toBe("critical");
    expect(rows[0].decision).toBe("refuse");
    expect(rows[0].payee_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(rows[0].amount_bucket).toBe("amt:1e6-1e9");
    expect(rows[0].chain_id).toBe(0); // Solana sentinel
  });

  it("writes exactly seven keys and no others", () => {
    configureEventSink({ path: spool, salt: SALT });
    recordVerdict(refuseVerdict, { payTo: "abc", amount: "5" });
    expect(Object.keys(lines()[0]).sort()).toEqual([
      "amount_bucket",
      "chain_id",
      "code",
      "decision",
      "payee_hash",
      "severity",
      "ts",
    ]);
  });

  it("emits one row per finding", () => {
    configureEventSink({ path: spool, salt: SALT });
    const n = recordVerdict({
      decision: "refuse",
      findings: [
        { code: "X402-001", severity: "critical" },
        { code: "X402-110", severity: "high" },
        { code: "X402-209", severity: "medium" },
      ],
    });
    expect(n).toBe(3);
    expect(lines().map((r) => r.code)).toEqual([
      "X402-001",
      "X402-110",
      "X402-209",
    ]);
  });

  it("writes nothing for a clean allow with no findings", () => {
    configureEventSink({ path: spool, salt: SALT });
    expect(recordVerdict({ decision: "allow", findings: [] })).toBe(0);
    expect(lines()).toHaveLength(0);
  });

  it("appends across calls rather than truncating", () => {
    configureEventSink({ path: spool, salt: SALT });
    recordVerdict(refuseVerdict);
    recordVerdict(refuseVerdict);
    recordVerdict(refuseVerdict);
    expect(lines()).toHaveLength(3);
  });
});

describe("no plaintext reaches the disk", () => {
  it("drops message, expected, actual, excerpt and field", () => {
    configureEventSink({ path: spool, salt: SALT });
    const CANARIES = [
      "CANARY_MESSAGE_TEXT",
      "CANARY_EXPECTED_ADDR",
      "CANARY_ACTUAL_ADDR",
      "CANARY_EXCERPT_ATTACKER_TEXT",
      "CANARY_FIELD_PATH",
      "CANARY_REASON",
      "CANARY_PAYEE_ADDRESS",
    ];
    recordVerdict(
      {
        decision: "refuse",
        // Deliberately the quote-text finding shape, which carries the most
        // dangerous field in the package: `excerpt` is the attacker's own text.
        findings: [
          {
            code: "X402-209",
            severity: "critical",
            message: "CANARY_MESSAGE_TEXT",
            expected: "CANARY_EXPECTED_ADDR",
            actual: "CANARY_ACTUAL_ADDR",
            excerpt: "CANARY_EXCERPT_ATTACKER_TEXT",
            field: "CANARY_FIELD_PATH",
            offset: 12,
            via: "base64",
            sink: "mcp-tool-description",
          } as never,
        ],
        reason: "CANARY_REASON",
      } as never,
      { payTo: "CANARY_PAYEE_ADDRESS", amount: "123456789" },
    );

    // Grep the ACTUAL BYTES, not the parsed object. A parsed object could hide
    // a canary in a key name.
    const raw = fs.readFileSync(spool, "utf8");
    for (const c of CANARIES) {
      expect(raw).not.toContain(c);
    }
    expect(lines()).toHaveLength(1);
    expect(lines()[0].code).toBe("X402-209");
  });

  it("never writes the exact amount", () => {
    configureEventSink({ path: spool, salt: SALT });
    recordVerdict(refuseVerdict, { payTo: "a", amount: "987654321" });
    const raw = fs.readFileSync(spool, "utf8");
    expect(raw).not.toContain("987654321");
    expect(lines()[0].amount_bucket).toBe("amt:1e6-1e9");
  });

  it("hashes the payee rather than writing it", () => {
    configureEventSink({ path: spool, salt: SALT });
    const addr = "0x1234567890abcdef1234567890abcdef12345678";
    recordVerdict(refuseVerdict, { payTo: addr, amount: "1" });
    const raw = fs.readFileSync(spool, "utf8");
    expect(raw).not.toContain(addr);
    expect(lines()[0].payee_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("salts the hash: the same address differs across installations", () => {
    const addr = "0xdeadbeef";
    configureEventSink({ path: spool, salt: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
    recordVerdict(refuseVerdict, { payTo: addr });
    const h1 = lines()[0].payee_hash;

    const spool2 = path.join(dir, "b.jsonl");
    configureEventSink({ path: spool2, salt: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" });
    recordVerdict(refuseVerdict, { payTo: addr });
    const h2 = lines(spool2)[0].payee_hash;

    expect(h1).not.toBeNull();
    expect(h1).not.toEqual(h2);
  });

  it("is stable within one installation, so payees correlate", () => {
    configureEventSink({ path: spool, salt: SALT });
    recordVerdict(refuseVerdict, { payTo: "same-addr" });
    recordVerdict(refuseVerdict, { payTo: "same-addr" });
    recordVerdict(refuseVerdict, { payTo: "other-addr" });
    const [a, b, c] = lines();
    expect(a.payee_hash).toEqual(b.payee_hash);
    expect(a.payee_hash).not.toEqual(c.payee_hash);
  });

  it("emits a null hash rather than a weak one when the salt is too short", () => {
    expect(configureEventSink({ path: spool, salt: "tooshort" })).toBe(true);
    expect(eventSinkStats()!.salted).toBe(false);
    recordVerdict(refuseVerdict, { payTo: "SENSITIVE_ADDRESS" });
    expect(fs.readFileSync(spool, "utf8")).not.toContain("SENSITIVE_ADDRESS");
    expect(lines()[0].payee_hash).toBeUndefined();
  });

  it("emits a null hash when no salt is configured at all", () => {
    configureEventSink({ path: spool });
    recordVerdict(refuseVerdict, { payTo: "SENSITIVE_ADDRESS" });
    expect(fs.readFileSync(spool, "utf8")).not.toContain("SENSITIVE_ADDRESS");
    expect(lines()[0].payee_hash).toBeUndefined();
  });
});

describe("amountBucket", () => {
  it("bands by magnitude and never returns the figure", () => {
    // Boundary coverage lives in the cross-language contract block below; these
    // are the representative cases.
    expect(amountBucket("0")).toBe("amt:0");
    expect(amountBucket("7")).toBe("amt:1-1e3");
    expect(amountBucket("1000000")).toBe("amt:1e6-1e9");
    // Never the input.
    expect(amountBucket("123456")).not.toContain("123456");
  });

  it("does not round a uint256 through Number", () => {
    // 2^256-1. Parsing this as a Number loses precision; BigInt comparison is
    // why the band is still correct.
    const huge =
      "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    expect(amountBucket(huge)).toBe("amt:1e12+");
  });

  it("accepts bigint and number", () => {
    expect(amountBucket(1234n)).toBe("amt:1e3-1e6");
    expect(amountBucket(50)).toBe("amt:1-1e3");
    expect(amountBucket(10n ** 30n)).toBe("amt:1e12+");
  });

  it("only ever returns a declared token or null", () => {
    const inputs = ["0", "1", "99", "123456789012345", "x", "", "-1", "1.0"];
    for (const i of inputs) {
      const b = amountBucket(i);
      if (b !== null) expect(AMOUNT_BUCKETS).toContain(b);
    }
  });
});

describe("resolveChainId", () => {
  it("parses eip155 and bare v1 names", () => {
    expect(resolveChainId("eip155:8453")).toBe(8453);
    expect(resolveChainId("base")).toBe(8453);
    expect(resolveChainId("base-sepolia")).toBe(84532);
    expect(resolveChainId(1)).toBe(1);
  });

  it("returns null for junk rather than guessing", () => {
    expect(resolveChainId("solana")).toBeNull();
    expect(resolveChainId("eip155:abc")).toBeNull();
    expect(resolveChainId(0)).toBeNull();
    expect(resolveChainId(-1)).toBeNull();
    expect(resolveChainId(null)).toBeNull();
    expect(resolveChainId(1.5)).toBeNull();
  });

  it("agrees with evm.parseNetwork on every name it knows", () => {
    // The sink duplicates the network table to avoid importing a module that
    // pulls in viem. Duplication is acceptable only while it cannot drift, so
    // the drift is asserted rather than assumed.
    const names = [
      "base", "base-sepolia", "avalanche", "avalanche-fuji",
      "iotex", "sei", "sei-testnet",
      "eip155:1", "eip155:8453", "eip155:99999",
      "solana", "nonsense", "",
    ];
    for (const n of names) {
      expect(resolveChainId(n), `chain name: ${n}`).toEqual(parseNetwork(n));
    }
  });
});

describe("vocabulary does not drift from the guard modules", () => {
  it("KNOWN_CODES equals the set of X402 codes in the real source", () => {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const src = path.join(here, "..", "src");
    const found = new Set<string>();
    for (const f of ["index.ts", "evm.ts", "quotetext.ts", "provenance.ts", "delivery.ts"]) {
      const text = fs.readFileSync(path.join(src, f), "utf8");
      for (const m of text.matchAll(/X402-\d{3}/g)) found.add(m[0]);
    }
    // Measured at the time of writing: 36 codes.
    expect(found.size).toBe(36);
    expect([...found].sort()).toEqual([...KNOWN_CODES].sort());
  });

  it("skips a code the vocabulary does not know", () => {
    configureEventSink({ path: spool, salt: SALT });
    const n = recordVerdict({
      decision: "refuse",
      findings: [
        { code: "X402-999", severity: "critical" },
        { code: "X402-001", severity: "high" },
      ],
    });
    expect(n).toBe(1);
    expect(lines().map((r) => r.code)).toEqual(["X402-001"]);
  });

  it("skips a severity outside critical/high/medium", () => {
    configureEventSink({ path: spool, salt: SALT });
    expect(
      recordVerdict({
        decision: "refuse",
        findings: [{ code: "X402-001", severity: "low" as never }],
      }),
    ).toBe(0);
  });

  it("ignores a verdict with an unknown decision", () => {
    configureEventSink({ path: spool, salt: SALT });
    expect(
      recordVerdict({
        decision: "explode" as never,
        findings: [{ code: "X402-001", severity: "high" }],
      }),
    ).toBe(0);
  });
});

describe("assertNoPlaintext", () => {
  const good: PaymentEvent = {
    code: "X402-001",
    severity: "critical",
    decision: "refuse",
    chain_id: 8453,
    payee_hash: "a".repeat(64),
    amount_bucket: "amt:1e3-1e6",
    ts: "2026-07-27T10:00:00.000Z",
  };

  it("passes a well-formed event", () => {
    expect(assertNoPlaintext(good)).toEqual([]);
  });

  it("catches an extra key", () => {
    const bad = { ...good, note: "hello" } as unknown as PaymentEvent;
    expect(assertNoPlaintext(bad).join()).toContain("unexpected key: note");
  });

  it("catches a plaintext payee", () => {
    const bad = { ...good, payee_hash: "0xabc" } as PaymentEvent;
    expect(assertNoPlaintext(bad).join()).toContain("payee_hash");
  });

  it("catches an amount bucket that is actually an amount", () => {
    const bad = { ...good, amount_bucket: "1234567" } as PaymentEvent;
    expect(assertNoPlaintext(bad).join()).toContain("amount_bucket");
  });
});

describe("bounded so it cannot fill a disk", () => {
  it("rotates at the byte ceiling and keeps a fixed number of segments", () => {
    configureEventSink({
      path: spool,
      salt: SALT,
      maxBytes: 2048,
      keepSegments: 2,
    });
    for (let i = 0; i < 400; i++) {
      recordVerdict(refuseVerdict, { payTo: `addr${i}`, amount: "1000" });
    }
    // Ceiling is (keepSegments + 1) * maxBytes, plus at most one batch of
    // slack because the size check is interval-based rather than per-write.
    const sizes = [spool, `${spool}.1`, `${spool}.2`]
      .filter((p) => fs.existsSync(p))
      .map((p) => fs.statSync(p).size);
    const total = sizes.reduce((a, b) => a + b, 0);
    expect(fs.existsSync(`${spool}.3`)).toBe(false);
    expect(total).toBeLessThan(2048 * 4);
  });

  it("truncates in place when keepSegments is 0", () => {
    configureEventSink({ path: spool, salt: SALT, maxBytes: 1024, keepSegments: 0 });
    for (let i = 0; i < 400; i++) recordVerdict(refuseVerdict, { payTo: `a${i}` });
    expect(fs.existsSync(`${spool}.1`)).toBe(false);
    expect(fs.statSync(spool).size).toBeLessThan(1024 * 3);
  });
});

describe("never throws into the payment path", () => {
  it("survives the spool path being a directory", () => {
    const asDir = path.join(dir, "adir");
    fs.mkdirSync(asDir);
    expect(configureEventSink({ path: asDir, salt: SALT })).toBe(false);
    expect(() => recordVerdict(refuseVerdict)).not.toThrow();
    expect(recordVerdict(refuseVerdict)).toBe(0);
  });

  it("survives the whole directory being deleted underneath it", () => {
    configureEventSink({ path: spool, salt: SALT });
    expect(recordVerdict(refuseVerdict)).toBe(1);
    fs.rmSync(dir, { recursive: true, force: true });
    expect(() => recordVerdict(refuseVerdict)).not.toThrow();
    expect(recordVerdict(refuseVerdict)).toBe(0);
    expect(eventSinkStats()!.dropped).toBeGreaterThan(0);
  });

  it("survives malformed verdicts of every shape", () => {
    configureEventSink({ path: spool, salt: SALT });
    const junk = [
      null, undefined, 42, "string", [],
      {},
      { decision: "refuse" },
      { decision: "refuse", findings: null },
      { decision: "refuse", findings: [null, undefined, 5, "x"] },
      { findings: [] },
    ];
    for (const j of junk) {
      expect(() => recordVerdict(j as never)).not.toThrow();
    }
    expect(lines()).toHaveLength(0);
  });

  it("survives a context with hostile values", () => {
    configureEventSink({ path: spool, salt: SALT });
    expect(() =>
      recordVerdict(refuseVerdict, {
        payTo: { toString: () => { throw new Error("boom"); } } as never,
        amount: { valueOf: () => { throw new Error("boom"); } } as never,
        chainId: Symbol("x") as never,
      }),
    ).not.toThrow();
  });
});

describe("toEvents is pure and usable without a configured sink", () => {
  it("produces events with a null hash when the sink is off", () => {
    const evs = toEvents(refuseVerdict, { payTo: "a", amount: "100" });
    expect(evs).toHaveLength(1);
    expect(evs[0].payee_hash).toBeUndefined();
    expect(evs[0].amount_bucket).toBe("amt:1-1e3");
  });

  it("stamps a caller-supplied timestamp", () => {
    const evs = toEvents(refuseVerdict, {}, new Date("2026-01-02T03:04:05Z"));
    expect(evs[0].ts).toBe("2026-01-02T03:04:05.000Z");
  });
});

describe("cross-language contract with the Python reader", () => {
  /**
   * The bucket vocabulary is duplicated in four places across two languages and
   * one SQLite CHECK constraint. The first draft of this file used a completely
   * different 13-token set; it passed every test in this file and was rejected
   * by the real reader with `accepted=0, invalid_field=1`. A test that only
   * checks this module against itself cannot catch that, so this one reads the
   * Python source and compares.
   */
  const READER = "/Users/juice/wormhole-fleet/reporter/wormhole_reporter/payment.py";

  it.skipIf(!fs.existsSync(READER))(
    "amount buckets match payment.AMOUNT_BUCKETS exactly",
    () => {
      const py = fs.readFileSync(READER, "utf8");
      const block = py.match(/AMOUNT_BUCKETS = \(([\s\S]*?)\)/);
      expect(block).not.toBeNull();
      const theirs = [...block![1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
      expect(theirs.length).toBeGreaterThan(0);
      expect([...AMOUNT_BUCKETS]).toEqual(theirs);
    },
  );

  it.skipIf(!fs.existsSync(READER))(
    "every code we can emit is one the reader accepts",
    () => {
      const py = fs.readFileSync(READER, "utf8");
      const theirs = new Set([...py.matchAll(/X402-\d{3}/g)].map((m) => m[0]));
      for (const c of KNOWN_CODES) {
        expect(theirs.has(c), `reader does not know ${c}`).toBe(true);
      }
    },
  );

  it.skipIf(!fs.existsSync(READER))(
    "the Solana sentinel agrees",
    () => {
      const py = fs.readFileSync(READER, "utf8");
      const m = py.match(/CHAIN_ID_SOLANA = (\d+)/);
      expect(m).not.toBeNull();
      expect(Number(m![1])).toBe(0);
    },
  );

  it("bucket boundaries are half-open and match the Python thresholds", () => {
    // Boundary values, because an off-by-one at a decade boundary is the whole
    // failure mode of a banding function.
    expect(amountBucket("0")).toBe("amt:0");
    expect(amountBucket("1")).toBe("amt:1-1e3");
    expect(amountBucket("999")).toBe("amt:1-1e3");
    expect(amountBucket("1000")).toBe("amt:1e3-1e6");
    expect(amountBucket("999999")).toBe("amt:1e3-1e6");
    expect(amountBucket("1000000")).toBe("amt:1e6-1e9");
    expect(amountBucket("999999999")).toBe("amt:1e6-1e9");
    expect(amountBucket("1000000000")).toBe("amt:1e9-1e12");
    expect(amountBucket("999999999999")).toBe("amt:1e9-1e12");
    expect(amountBucket("1000000000000")).toBe("amt:1e12+");
  });

  it("returns null, not a band, for an unparseable amount", () => {
    expect(amountBucket("-1")).toBeNull();
    expect(amountBucket("1.5")).toBeNull();
    expect(amountBucket("abc")).toBeNull();
    expect(amountBucket(undefined)).toBeNull();
    expect(amountBucket(1.5)).toBeNull();
  });

  it("omits absent fields rather than writing null", () => {
    configureEventSink({ path: spool, salt: SALT });
    // A quote-text finding: no payee, no amount.
    recordVerdict({
      decision: "refuse",
      findings: [{ code: "X402-209", severity: "critical" }],
    });
    const raw = fs.readFileSync(spool, "utf8");
    expect(raw).not.toContain("null");
    const row = lines()[0];
    expect("payee_hash" in row).toBe(false);
    expect("amount_bucket" in row).toBe(false);
    expect(row.chain_id).toBe(0);
  });
});

describe("cached file descriptor", () => {
  /**
   * The sink holds an append-mode fd because `appendFileSync` measured at
   * 36,263 ns/write versus 2,033 ns for a held descriptor, and this code runs
   * on a payment path. A held fd introduces two failure modes that a
   * per-write open does not have, and both are tested here rather than
   * reasoned about.
   */
  it("keeps writing to the live file across a rotation, not the renamed one", () => {
    // An fd points at an inode, not a name. Held across a rename, it would
    // append to the rotated segment forever while the live file stayed empty.
    configureEventSink({ path: spool, salt: SALT, maxBytes: 512, keepSegments: 2 });
    for (let i = 0; i < 200; i++) recordVerdict(refuseVerdict, { payTo: `a${i}` });
    expect(fs.existsSync(`${spool}.1`)).toBe(true);

    // Every event must have landed somewhere readable. If the fd had been held
    // across the rename, the live file would be empty and the total would be
    // short. Counted across all segments because which file a given event is
    // in depends on exactly when rotation fired.
    const total = [spool, `${spool}.1`, `${spool}.2`]
      .filter((p) => fs.existsSync(p))
      .reduce((n, p) => n + lines(p).length, 0);
    expect(eventSinkStats()!.written).toBe(200);
    expect(eventSinkStats()!.dropped).toBe(0);
    expect(total).toBeGreaterThan(0);

    // A subsequent write must reach the LIVE file, not a renamed inode.
    recordVerdict(refuseVerdict, { payTo: "final" });
    expect(fs.existsSync(spool)).toBe(true);
    expect(lines(spool).length).toBeGreaterThan(0);
  });

  it("does not write into an orphaned inode after the file is deleted", () => {
    // POSIX lets a write through an unlinked fd succeed; the bytes then live in
    // an inode nothing can open. Verified on macOS. The sink must notice.
    configureEventSink({ path: spool, salt: SALT });
    expect(recordVerdict(refuseVerdict, { payTo: "a" })).toBe(1);
    fs.unlinkSync(spool);
    recordVerdict(refuseVerdict, { payTo: "b" });
    // Either it recreated the file and the event is readable, or it dropped it.
    // What it must NOT do is report success with the data unreachable.
    if (fs.existsSync(spool)) {
      expect(lines().length).toBeGreaterThan(0);
    } else {
      expect(eventSinkStats()!.dropped).toBeGreaterThan(0);
    }
  });

  it("recreates the spool if it is deleted and then written to again", () => {
    configureEventSink({ path: spool, salt: SALT });
    recordVerdict(refuseVerdict, { payTo: "a" });
    fs.unlinkSync(spool);
    expect(recordVerdict(refuseVerdict, { payTo: "b" })).toBe(1);
    expect(lines()).toHaveLength(1);
  });

  it("releases the descriptor on reset", () => {
    configureEventSink({ path: spool, salt: SALT });
    recordVerdict(refuseVerdict, { payTo: "a" });
    expect(() => resetEventSink()).not.toThrow();
    expect(eventSinkStats()).toBeNull();
  });

  it("does not leak descriptors across many reconfigurations", () => {
    for (let i = 0; i < 300; i++) {
      configureEventSink({ path: spool, salt: SALT });
      recordVerdict(refuseVerdict, { payTo: `a${i}` });
    }
    // Would throw EMFILE well before 300 if each configure leaked an fd.
    expect(lines().length).toBe(300);
  });
});

describe("a non-regular-file spool path is refused, not opened", () => {
  // The never-throw contract is defeated on its own terms by a FIFO: a blocking
  // openSync/appendFileSync on a pipe with no draining reader does not throw,
  // it BLOCKS. So every catch in this module is unreachable, `dropped` cannot
  // record it, and the process sits in an uninterruptible syscall that SIGTERM
  // does not clear. Measured before the fix: a checkout loop stopped dead at
  // iteration 38 and needed SIGKILL.
  //
  // lstat, not stat, so a symlink pointing at a FIFO is caught rather than
  // followed.
  it("refuses a FIFO instead of blocking on it", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sink-fifo-"));
    const fifo = path.join(dir, "spool.jsonl");
    try {
      execFileSync("mkfifo", [fifo]);
    } catch {
      return; // no mkfifo on this platform; nothing to assert
    }
    expect(configureEventSink({ path: fifo, enabled: true })).toBe(false);
    resetEventSink();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("refuses a directory", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sink-dir-"));
    expect(configureEventSink({ path: dir, enabled: true })).toBe(false);
    resetEventSink();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("still accepts a path that does not exist yet", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sink-new-"));
    const p = path.join(dir, "fresh.jsonl");
    expect(configureEventSink({ path: p, enabled: true })).toBe(true);
    resetEventSink();
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
