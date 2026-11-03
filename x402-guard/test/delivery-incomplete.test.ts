import { describe, expect, it } from "vitest";
import { inspectDelivery } from "../src/delivery.js";
import { handleMessage } from "../src/mcp.js";

describe("incomplete delivery evidence", () => {
  it.each([100, 101, 199, 300, 301, 302, 303, 304, 307, 308, 399])(
    "does not attest an HTTP %i response as a completed delivery",
    (status) => {
      const result = inspectDelivery({}, { status, body: "Continue elsewhere" });
      expect(result.decision).toBe("abstain");
      expect(result.receipt?.resource_digest).toBeNull();
    },
  );

  it("abstains when no response bytes were supplied", () => {
    const result = inspectDelivery({ mimeType: "application/json" }, { status: 200 });
    expect(result.decision).toBe("abstain");
    expect(result.receipt?.resource_digest).toBeNull();
  });

  it.each([400, 402, 403, 500])("still refuses HTTP %i without a body", (status) => {
    expect(inspectDelivery({}, { status }).decision).toBe("refuse");
  });

  it("distinguishes an observed empty body from missing evidence", () => {
    const result = inspectDelivery({}, { status: 200, body: "" });
    expect(result.decision).toBe("refuse");
    expect(result.findings.map((finding) => finding.code)).toContain("X402-404");
  });

  it("still allows a complete response", () => {
    const result = inspectDelivery(
      { mimeType: "application/json" },
      { status: 200, contentType: "application/json", body: '{"ok":true}' },
    );
    expect(result.decision).toBe("allow");
    expect(result.receipt?.resource_digest).toMatch(/^[a-f0-9]{64}$/);
  });

  it("reports missing delivery bytes through the public tool", async () => {
    const message = await handleMessage({
      jsonrpc: "2.0", id: 1, method: "tools/call",
      params: {
        name: "verify_delivery",
        arguments: { quote: {}, response: { status: 200 } },
      },
    });
    const result = JSON.parse((message as any).result.content[0].text);
    expect(result.decision).toBe("abstain");
    expect(result.receipt.resource_digest).toBeNull();
  });
});
