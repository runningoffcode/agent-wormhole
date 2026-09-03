/**
 * Address provenance at the signing checkpoint (X402-301).
 *
 * The properties that matter:
 *   1. The attack shape flags: a payee whose ONLY ledger origin is `read`.
 *   2. Legitimate flows stay silent: a quote or operator origin clears the
 *      address, and an address the ledger has never seen is NOT flagged —
 *      absence of provenance is not evidence of taint.
 *   3. The check reaches the agent through the MCP tool, appended as an
 *      advisory finding without touching the decision.
 */

import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseAddressLedger,
  checkPayeeProvenance,
  loadAddressLedger,
} from "../src/provenance.js";
import { handleMessage } from "../src/mcp.js";

const ATTACKER = "0x2222222222222222222222222222222222222222";
const MERCHANT = "0x1111111111111111111111111111111111111111";
const SOL = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

const line = (address: string, source: string) =>
  JSON.stringify({ address, source, via: "test", ts: "2026-09-03T00:00:00Z" });

describe("parseAddressLedger + checkPayeeProvenance", () => {
  it("flags a payee whose only origin is read text", () => {
    const prov = parseAddressLedger(line(ATTACKER, "read"));
    const f = checkPayeeProvenance(ATTACKER, prov);
    expect(f).toMatchObject({ code: "X402-301", severity: "high" });
  });

  it("a quote origin clears the address — the legitimate-merchant path", () => {
    const prov = parseAddressLedger(
      [line(MERCHANT, "read"), line(MERCHANT, "quote")].join("\n"),
    );
    expect(checkPayeeProvenance(MERCHANT, prov)).toBeNull();
  });

  it("an operator trust action clears the address", () => {
    const prov = parseAddressLedger(
      [line(ATTACKER, "read"), line(ATTACKER, "operator")].join("\n"),
    );
    expect(checkPayeeProvenance(ATTACKER, prov)).toBeNull();
  });

  it("an unseen address is not flagged — no ledger, no taint", () => {
    const prov = parseAddressLedger(line(ATTACKER, "read"));
    expect(checkPayeeProvenance(MERCHANT, prov)).toBeNull();
  });

  it("EVM comparison is case-insensitive; base58 is not", () => {
    const prov = parseAddressLedger(
      [line(ATTACKER.toUpperCase().replace("0X", "0x"), "read"), line(SOL, "read")].join("\n"),
    );
    expect(checkPayeeProvenance(ATTACKER, prov)).not.toBeNull();
    expect(checkPayeeProvenance(SOL, prov)).not.toBeNull();
    expect(checkPayeeProvenance(SOL.toLowerCase(), prov)).toBeNull();
  });

  it("torn and malformed lines are skipped, not fatal", () => {
    const prov = parseAddressLedger(
      [line(ATTACKER, "read"), "{not json", '{"address":5,"source":"read"}', ""].join("\n"),
    );
    expect(prov.tainted.has(ATTACKER)).toBe(true);
  });

  it("an unknown source value is ignored rather than trusted", () => {
    const prov = parseAddressLedger(line(ATTACKER, "model"));
    expect(prov.tainted.size).toBe(0);
    expect(prov.trusted.size).toBe(0);
  });
});

describe("through the MCP tool", () => {
  let dir: string | null = null;
  afterEach(() => {
    delete process.env.WORMHOLE_ADDRESS_LEDGER;
    if (dir !== null) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  it("appends X402-301 as advisory without changing the decision", async () => {
    dir = mkdtempSync(join(tmpdir(), "wormhole-prov-"));
    const ledger = join(dir, "addresses.jsonl");
    writeFileSync(ledger, line(ATTACKER, "read") + "\n");
    process.env.WORMHOLE_ADDRESS_LEDGER = ledger;

    const res: any = await handleMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "verify_payment",
        arguments: {
          network: "eip155:8453",
          quote: {
            network: "eip155:8453",
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            payTo: ATTACKER,
            amount: "1000000",
          },
          // Garbage payload: the verifier abstains, and the provenance
          // finding must still arrive — the two checks are independent.
          payload: { signature: "0x00", authorization: {} },
        },
      },
    });
    const out = JSON.parse(res.result.content[0].text);
    expect(out.decision).toBe("abstain");
    expect(out.findings.some((f: any) => f.code === "X402-301")).toBe(true);
  });

  it("stays silent when the ledger does not exist", async () => {
    process.env.WORMHOLE_ADDRESS_LEDGER = "/nonexistent/ledger.jsonl";
    const res: any = await handleMessage({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "verify_payment",
        arguments: {
          network: "eip155:8453",
          quote: {
            network: "eip155:8453",
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            payTo: ATTACKER,
            amount: "1000000",
          },
          payload: { signature: "0x00", authorization: {} },
        },
      },
    });
    const out = JSON.parse(res.result.content[0].text);
    expect(out.findings.some((f: any) => f.code === "X402-301")).toBe(false);
  });
});
