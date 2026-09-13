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
import type { ToolNameReport } from "./index.js";

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

// The advertised names belong to the server, so the operator must be able to
// state them. Without this the only fix for a mismatch was editing the package.
const orderTools = envList("MCP_ORDER_TOOLS");
const guard = new McpGuard({ policy, ...(orderTools.length ? { orderTools } : {}) });

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

/**
 * React to what the broker actually advertises.
 *
 * The guard intercepts by NAME, and the names are the server's to choose. Until
 * this ran, a vocabulary mismatch was invisible: the proxy printed its caps,
 * looked healthy, and forwarded every order untouched. Whatever else happens,
 * that silence is not acceptable — so an unguarded money-moving tool is printed
 * in full, and a guard matching NOTHING stops the process by default rather
 * than pretending to protect an account it is not protecting.
 */
function onToolList(r: ToolNameReport): void {
  if (r.matched.length > 0 && r.unguarded.length === 0) {
    console.log(`\n  guarding    ${r.matched.join(", ")}  (${r.advertised.length} tools advertised)\n`);
    return;
  }

  if (r.unguarded.length > 0) {
    console.error(`\n  !! UNGUARDED TOOLS — these move money and are NOT capped:`);
    for (const n of r.unguarded) console.error(`       ${n}`);
    console.error(`     Add them:  MCP_ORDER_TOOLS="${[...r.matched, ...r.unguarded].join(",")}"`);
  }

  if (r.matched.length === 0) {
    console.error(
      `\n  !! This guard matched NONE of the ${r.advertised.length} tools this server advertises.\n` +
        `     Every order would reach the broker uncapped. Refusing to run as a\n` +
        `     guard that guards nothing. Set MCP_ORDER_TOOLS to the real names,\n` +
        `     or MCP_ALLOW_UNMATCHED=1 to proceed anyway.\n`,
    );
    if (process.env.MCP_ALLOW_UNMATCHED !== "1") process.exit(1);
  }
  console.error("");
}

const server = createProxyServer({ guard, upstreamUrl: UPSTREAM, onEvent: log, onToolList });

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
  if (orderTools.length) console.log(`  order tools ${orderTools.join(", ")}  (MCP_ORDER_TOOLS)`);
  console.log(`\n  Tool names are checked against the broker's own listing on first use.`);
  console.log(`\nPoint your agent's MCP endpoint at the address above instead of the broker.\n`);
});
