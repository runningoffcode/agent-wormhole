/**
 * The safety rail is the launch blocker, so it is tested before anything else
 * and adversarially: these tests try to REACH SETTLEMENT and must fail to.
 *
 * A conformance probe constructs deliberately-wrong payment authorisations. If
 * one settled, the project that exists to stop agents being tricked into paying
 * would have built a machine that pays. These assertions are the proof that
 * cannot happen.
 */
import { describe, it, expect } from "vitest";
import {
  safeUrl,
  assertProbeSafeValue,
  createTransport,
  ProbeSafetyError,
  MAX_PROBE_VALUE_BASE_UNITS,
} from "../src/safety.js";

describe("layer 1+2 — settlement is unreachable", () => {
  it("resolves only the two read-only operations", () => {
    expect(safeUrl("https://x402.org/facilitator", "supported")).toBe(
      "https://x402.org/facilitator/supported",
    );
    expect(safeUrl("https://x402.org/facilitator", "verify")).toBe(
      "https://x402.org/facilitator/verify",
    );
  });

  it("refuses a base URL that itself points at settlement", () => {
    // The operation type cannot express /settle, so the remaining way in is a
    // facilitator base URL that already contains it. Layer 2 catches that.
    expect(() => safeUrl("https://evil.example/settle", "verify")).toThrow(ProbeSafetyError);
    expect(() => safeUrl("https://x.example/broadcast", "verify")).toThrow(/settlement endpoint/);
    expect(() => safeUrl("https://x.example/submit", "supported")).toThrow(ProbeSafetyError);
  });

  it("refuses to send crafted authorisations in the clear", () => {
    expect(() => safeUrl("http://facilitator.example", "verify")).toThrow(/non-https/);
    // localhost is exempt so the fake facilitator in these tests is reachable.
    expect(() => safeUrl("http://127.0.0.1:9999", "verify")).not.toThrow();
  });

  it("refuses a base URL that is not a URL at all", () => {
    expect(() => safeUrl("not a url", "verify")).toThrow(/not a URL/);
  });

  it("the transport re-checks on EVERY request, not just at construction", async () => {
    // A prober that held a transport and later passed a hostile base URL must
    // still be stopped. The check lives in the request path, not the factory.
    const t = createTransport({ fetchImpl: (async () => new Response("{}")) as unknown as typeof fetch });
    await expect(t("https://evil.example/settle", "verify", {})).rejects.toThrow(ProbeSafetyError);
  });
});

describe("layer 3 — the value ceiling", () => {
  it("accepts values at or below the ceiling", () => {
    expect(assertProbeSafeValue("1", "t")).toBe(1n);
    expect(assertProbeSafeValue(MAX_PROBE_VALUE_BASE_UNITS, "t")).toBe(MAX_PROBE_VALUE_BASE_UNITS);
  });

  it("refuses anything above the ceiling", () => {
    expect(() => assertProbeSafeValue("1000000000", "underpay probe")).toThrow(/exceeds the probe ceiling/);
    expect(() => assertProbeSafeValue(MAX_PROBE_VALUE_BASE_UNITS + 1n, "t")).toThrow(ProbeSafetyError);
  });

  it("refuses an unparseable value rather than assuming it is small", () => {
    // "assume zero" is precisely the wrong default here: an amount we cannot
    // read is the case where guessing is most dangerous.
    for (const bad of [undefined, null, "", "abc", "1e9", -5, 1.5, {}, []]) {
      expect(() => assertProbeSafeValue(bad, "t"), String(bad)).toThrow(ProbeSafetyError);
    }
  });
});

describe("the rail holds under a hostile facilitator", () => {
  it("a facilitator that redirects toward settlement cannot be followed into it", async () => {
    // The transport builds its own URL from (base, operation) and never follows
    // a facilitator-supplied location, so a redirect cannot retarget the probe.
    let requested = "";
    const t = createTransport({
      fetchImpl: (async (url: string) => {
        requested = String(url);
        return new Response(JSON.stringify({ isValid: false }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }) as unknown as typeof fetch,
    });
    await t("https://facilitator.example", "verify", { paymentPayload: {} });
    expect(requested).toBe("https://facilitator.example/verify");
    expect(requested).not.toMatch(/settle/);
  });

  it("non-JSON from a facilitator is data, not a crash", async () => {
    const t = createTransport({
      fetchImpl: (async () => new Response("<html>rate limited</html>", { status: 429 })) as unknown as typeof fetch,
    });
    const r = await t("https://facilitator.example", "verify", {});
    expect(r.status).toBe(429);
    expect(r.json).toBeNull();
  });
});
