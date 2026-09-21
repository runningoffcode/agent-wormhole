import { describe, it, expect } from "vitest";
import { inspectPayment } from "../src/index.js";

/**
 * AW-05 — the shape guard on decodeTransaction.
 *
 * Reported by zauth: a typed parameter is not a runtime check, and the value
 * arrives from JSON as `unknown`.
 */

describe("AW-05 — a typed parameter is not a runtime check", () => {
  const quote = {
    network: "solana",
    asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    payTo: "J3WmMHUixgfcUtL5ov4Cn6LE65cDybgAg7mc1PWGyVY",
    amount: "1000",
  };

  it("REGRESSION: an attacker-declared .length never reaches Buffer.from", () => {
    // `{ length: 2e8 }` is neither a string nor a Uint8Array, but the
    // parameter's TYPE said it must be one, so it fell through to
    // Buffer.from(arrayLike) — which honours .length and allocated 200MB in
    // 4.5s (measured). A large enough value is a V8 fatal no try/catch can
    // intercept: a 48-byte body killing the verifier process.
    const started = Date.now();
    const v = inspectPayment({ length: 2e8 } as never, quote);
    expect(v.decision).toBe("abstain");
    // Refused on shape, so nothing was allocated. The bug took seconds.
    expect(Date.now() - started).toBeLessThan(250);
  });

  it("abstains on every non-bytes shape rather than guessing", () => {
    for (const bad of [{}, [1, 2, 3], 42, null, undefined, { length: "9" }]) {
      expect(inspectPayment(bad as never, quote).decision).toBe("abstain");
    }
  });

  it("refuses a payload larger than a Solana packet before decoding it", () => {
    const v = inspectPayment(new Uint8Array(1233), quote);
    expect(v.decision).toBe("abstain");
  });

  it("lets a legal-size Uint8Array through to the real decoder", () => {
    // The guard must bound allocation without swallowing real traffic. These
    // bytes are under the packet limit, so they reach the decoder and are
    // judged on their contents — NOT rejected for their shape.
    const v = inspectPayment(new Uint8Array(200), quote);
    expect(String(v.reason ?? "")).not.toContain("must be base64 or bytes");
    expect(String(v.reason ?? "")).not.toContain("exceeds 1232 bytes");
    expect(v.decision).not.toBe("allow");
  });
});
