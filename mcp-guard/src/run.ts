#!/usr/bin/env node
/**
 * The runnable proxy. `node dist/run.js` (or the `mcp-trade-guard` bin) starts a
 * listener the agent points at instead of the broker, reads its policy from the
 * environment, and prints every guard decision as an audit line.
 *
 * This is the whole product for an operator: point your agent here, set the caps,
 * watch what the guard blocks. No account, no server of ours, no data leaving the
 * machine — the proxy runs beside the agent and forwards to the real broker.
 */

import { McpGuard, defaultPolicy } from "./index.js";
import { createProxyServer, type GuardEvent } from "./proxy.js";

function envNum(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v.trim() === "") return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function envList(name: string): string[] {
  const v = process.env[name];
  if (!v) return [];
  return v.split(",").map((s) => s.trim()).filter(Boolean);
}

const UPSTREAM = process.env.MCP_UPSTREAM ?? "https://agent.robinhood.com/mcp/trading";
const PORT = envNum("MCP_GUARD_PORT", 8900);
const HOST = process.env.MCP_GUARD_HOST ?? "127.0.0.1";

const policy = defaultPolicy({
  maxOrderUsd: envNum("MCP_MAX_ORDER_USD", 100),
  maxDailyUsd: envNum("MCP_MAX_DAILY_USD", 500),
  allowedSymbols: envList("MCP_ALLOWED_SYMBOLS"),
  onUnknownNotional: process.env.MCP_ALLOW_UNKNOWN === "1" ? "allow" : "refuse",
});

const guard = new McpGuard({ policy });

/** Audit line. Codes and normalised order only — never the payload text. */
function log(e: GuardEvent): void {
  const when = new Date(e.at).toISOString().slice(11, 19);
  if (e.direction === "request" && e.order) {
    const size = e.order.notionalUsd !== undefined ? `$${e.order.notionalUsd}` : `${e.order.quantity ?? "?"} sh`;
    const verb = e.decision === "refuse" ? "REFUSED" : "allowed";
    console.log(`${when}  order  ${verb.padEnd(8)} ${e.order.side} ${size} ${e.order.symbol}${e.code ? `  (${e.code})` : ""}`);
  } else if (e.direction === "response" && e.decision === "annotate") {
    console.log(`${when}  read   FLAGGED  injection in tool result  (${e.code})`);
  } else if (e.decision === "refuse") {
    console.log(`${when}  ${e.direction}  REFUSED  ${e.tool}  (${e.code})`);
  }
}

const server = createProxyServer({ guard, upstreamUrl: UPSTREAM, onEvent: log });

server.listen(PORT, HOST, () => {
  console.log(`mcp-trade-guard`);
  console.log(`  listening   http://${HOST}:${PORT}`);
  console.log(`  forwards to ${UPSTREAM}`);
  console.log(`  per-order   $${policy.maxOrderUsd}`);
  console.log(`  per-day     $${policy.maxDailyUsd}`);
  console.log(
    `  symbols     ${policy.allowedSymbols.length ? policy.allowedSymbols.join(", ") : "ANY (set MCP_ALLOWED_SYMBOLS to restrict)"}`,
  );
  console.log(`  priceless   ${policy.onUnknownNotional === "refuse" ? "refused (fail closed)" : "allowed (MCP_ALLOW_UNKNOWN=1)"}`);
  console.log(`\nPoint your agent's MCP endpoint at the address above instead of the broker.\n`);
});
