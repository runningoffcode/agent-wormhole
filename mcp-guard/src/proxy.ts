/**
 * The wire-level guard: a transparent MCP proxy that sits between an agent and
 * an agentic-trading MCP server, and applies the policy in `index.ts` to every
 * `tools/call` that crosses it.
 *
 * ═══ WHY A PROXY, AND WHY AT THE JSON-RPC LAYER RATHER THAN THE SDK LAYER ═══
 *
 * The guard is only a guarantee if the agent cannot route around it. A library
 * the agent chooses to call is a suggestion. So this runs on the WIRE: the agent
 * points at this proxy instead of at the real server, and the proxy forwards
 * everything upstream — except a `tools/call` that places an order, which it
 * checks first and can REFUSE without the call ever reaching the broker.
 *
 * It works at the raw JSON-RPC layer, not through the MCP SDK, on purpose:
 *
 *   1. It stays a thin, forkable dependency. A trading guard that drags in a
 *      full protocol SDK is a bigger attack surface than the thing it guards.
 *   2. It is SERVER-AGNOSTIC. Robinhood does not publish its tool schema; a
 *      proxy that transforms the protocol would break the moment a field it did
 *      not model appeared. This one forwards bytes it does not need to
 *      understand and touches ONLY the two shapes it must: the `tools/call`
 *      request (to read name + arguments) and the `tools/call` result (to scan
 *      returned text). Everything else is passed through untouched.
 *
 * ═══ WHAT IT ENFORCES, AND IN WHICH DIRECTION ═══
 *
 *   Request  (agent → broker): if the tool is an order tool, `guardOrder` runs
 *     BEFORE forwarding. A refusal is returned to the agent as a normal tool
 *     result with `isError: true` and the reason — the call never reaches the
 *     broker, so no order is placed. This is the wall.
 *
 *   Response (broker → agent): if the tool is a read tool, `guardRead` scans the
 *     returned text and PREPENDS a warning when it matches an injection rule.
 *     Never dropped — a read moves no money, and the agent needs to see the
 *     content to reason, just with the untrusted-text flag attached.
 *
 * ═══ THE ARGUMENT-SHAPE PROBLEM, STATED HONESTLY ═══
 *
 * Robinhood's order arguments are not documented, so `extractOrder` reads the
 * fields agentic-trading tools conventionally use (symbol/ticker, side,
 * amount/notional/dollars, quantity/shares) and normalises them. When it cannot
 * find a dollar amount, that is the fail-closed case in `guardOrder`
 * (onUnknownNotional) — an order the proxy cannot size is refused by default
 * rather than waved through. If a real deployment sees an order tool whose
 * argument names differ, the fix is a field-mapping option, not silent
 * pass-through — and the log makes the unmapped shape visible immediately.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { McpGuard, type OrderIntent, type GuardDecision } from "./index.js";

/** One line of the audit log — what the proxy decided, never the payload text. */
export interface GuardEvent {
  at: number;
  direction: "request" | "response";
  tool: string;
  decision: GuardDecision["action"];
  /** Stable code on a refusal/annotation, for grouping. Never free text. */
  code?: string;
  /** For an order: the normalised intent, so a human can audit what was tried. */
  order?: OrderIntent;
}

export interface ProxyOptions {
  guard: McpGuard;
  /** The real MCP server this proxy forwards to, e.g. Robinhood's endpoint. */
  upstreamUrl: string;
  /** Called for every guarded decision. Wire a dashboard or a log file here. */
  onEvent?: (e: GuardEvent) => void;
  /** Injected for tests. */
  fetchImpl?: typeof fetch;
  now?: () => number;
}

/**
 * Pull an order out of a `tools/call` arguments object.
 *
 * Reads the conventional field names and returns `undefined` when the call is
 * not recognisably an order (which the caller treats as "not an order tool after
 * all", not as "an order to allow"). A missing dollar amount is preserved as
 * `notionalUsd: undefined` so `guardOrder`'s fail-closed branch handles it.
 */
export function extractOrder(args: unknown): OrderIntent | undefined {
  if (typeof args !== "object" || args === null) return undefined;
  const a = args as Record<string, unknown>;

  const sym = firstString(a, ["symbol", "ticker", "instrument", "stock"]);
  if (sym === undefined) return undefined;

  const sideRaw = (firstString(a, ["side", "action", "direction"]) ?? "").toLowerCase();
  const side: OrderIntent["side"] =
    sideRaw.includes("sell") ? "sell" : "buy"; // default to buy; sells are the safer default to allow, buys move money out

  const notionalUsd = firstNumber(a, [
    "notional",
    "notional_usd",
    "amount",
    "amount_usd",
    "dollars",
    "dollar_amount",
    "value",
    "total",
  ]);
  const quantity = firstNumber(a, ["quantity", "qty", "shares", "units"]);

  return {
    symbol: String(sym).toUpperCase(),
    side,
    ...(notionalUsd !== undefined ? { notionalUsd } : {}),
    ...(quantity !== undefined ? { quantity } : {}),
  };
}

function firstString(o: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) if (typeof o[k] === "string" && o[k] !== "") return o[k] as string;
  return undefined;
}
function firstNumber(o: Record<string, unknown>, keys: string[]): number | undefined {
  for (const k of keys) {
    const v = o[k];
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  }
  return undefined;
}

/** Extract every text block from a `tools/call` result's content array. */
function resultTexts(result: unknown): string[] {
  if (typeof result !== "object" || result === null) return [];
  const content = (result as { content?: unknown }).content;
  if (!Array.isArray(content)) return [];
  const out: string[] = [];
  for (const item of content) {
    if (typeof item === "object" && item !== null && typeof (item as { text?: unknown }).text === "string") {
      out.push((item as { text: string }).text);
    }
  }
  return out;
}

/** A refusal returned to the agent as a normal, non-throwing tool result. */
function refusalResult(id: unknown, reason: string) {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [
        {
          type: "text",
          text:
            `[mcp-trade-guard] refused: ${reason}. This order was blocked before ` +
            `it reached the broker. The cap is set by the account operator and ` +
            `cannot be changed by this agent or by anything it has read.`,
        },
      ],
      isError: true,
    },
  };
}

/**
 * Apply the guard to a single parsed JSON-RPC message flowing agent → upstream.
 *
 * Returns either `{ forward: msg }` (send it on, possibly annotated later) or
 * `{ respond: refusal }` (short-circuit; never touches upstream). Pure and
 * synchronous so it is trivially testable without a socket.
 */
export function guardRequest(
  msg: unknown,
  guard: McpGuard,
  onEvent?: (e: GuardEvent) => void,
  now: () => number = () => Date.now(),
): { forward: unknown } | { respond: unknown } {
  if (typeof msg !== "object" || msg === null) return { forward: msg };
  const m = msg as Record<string, unknown>;
  if (m["method"] !== "tools/call") return { forward: msg };

  const params = (m["params"] ?? {}) as Record<string, unknown>;
  const tool = typeof params["name"] === "string" ? params["name"] : "";
  if (!guard.isOrderTool(tool)) return { forward: msg };

  const order = extractOrder(params["arguments"]);
  if (order === undefined) {
    // An order tool whose arguments we could not read as an order. Fail closed:
    // refuse, and log the unmapped shape so it is visible, not silently passed.
    onEvent?.({ at: now(), direction: "request", tool, decision: "refuse", code: "MCP-000" });
    return { respond: refusalResult(m["id"], `could not read order arguments for ${tool}`) };
  }

  const decision = guard.guardOrder(order);
  onEvent?.({
    at: now(),
    direction: "request",
    tool,
    decision: decision.action,
    code: decision.action === "refuse" ? decision.code : undefined,
    order,
  });

  if (decision.action === "refuse") {
    return { respond: refusalResult(m["id"], decision.reason) };
  }
  return { forward: msg };
}

/**
 * Apply the guard to a single parsed JSON-RPC message flowing upstream → agent.
 *
 * Annotates a read result whose text matches an injection rule. Returns the
 * (possibly modified) message. The tool name is not on the response, so this is
 * best-effort by content: any result text that trips a rule gets the warning.
 */
export function guardResponse(
  msg: unknown,
  guard: McpGuard,
  onEvent?: (e: GuardEvent) => void,
  now: () => number = () => Date.now(),
): unknown {
  if (typeof msg !== "object" || msg === null) return msg;
  const m = msg as Record<string, unknown>;
  const result = m["result"];
  const texts = resultTexts(result);
  if (texts.length === 0) return msg;

  let annotated = false;
  const notes: string[] = [];
  for (const text of texts) {
    const d = guard.guardRead(text);
    if (d.action === "annotate") {
      annotated = true;
      notes.push(d.note);
      onEvent?.({ at: now(), direction: "response", tool: "(read)", decision: "annotate", code: d.findings[0] });
    }
  }
  if (!annotated) return msg;

  // Prepend a single combined warning block. The original content is preserved
  // in full after it — the agent still sees everything, just flagged.
  const r = result as { content?: unknown[] };
  const warning = {
    type: "text",
    text: notes.join("\n"),
  };
  return { ...m, result: { ...r, content: [warning, ...(Array.isArray(r.content) ? r.content : [])] } };
}

/**
 * Start the proxy listener. The agent connects here; this forwards to
 * `upstreamUrl`. Streamable HTTP is POST-with-JSON (and SSE for streaming); this
 * handles the JSON request/response path, which is what carries `tools/call`.
 * SSE frames from the upstream are passed through untouched — a guard does not
 * need to parse a stream it only forwards.
 */
export function createProxyServer(opts: ProxyOptions): Server {
  const doFetch = opts.fetchImpl ?? fetch;
  const now = opts.now ?? (() => Date.now());

  return createServer((req: IncomingMessage, res: ServerResponse) => {
    if (req.method !== "POST") {
      res.writeHead(405).end();
      return;
    }
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      let msg: unknown;
      try {
        msg = JSON.parse(raw);
      } catch {
        // Not JSON we parse (could be an SSE resumption or a batch we do not
        // model) — forward verbatim. A guard must not corrupt traffic it does
        // not understand.
        return forwardRaw(raw);
      }

      const guarded = guardRequest(msg, opts.guard, opts.onEvent, now);
      if ("respond" in guarded) {
        // Short-circuit: the order was refused, never sent upstream.
        const body = JSON.stringify(guarded.respond);
        res.writeHead(200, { "content-type": "application/json" }).end(body);
        return;
      }
      forwardRaw(JSON.stringify(guarded.forward));

      async function forwardRaw(bodyToSend: string) {
        // Copy the request headers the transport needs (session id, accept),
        // but never the Host — that must be the upstream's.
        const headers: Record<string, string> = { "content-type": "application/json" };
        for (const h of ["accept", "mcp-session-id", "mcp-protocol-version", "authorization"]) {
          const v = req.headers[h];
          if (typeof v === "string") headers[h] = v;
        }
        let upstream: Response;
        try {
          upstream = await doFetch(opts.upstreamUrl, {
            method: "POST",
            headers,
            body: bodyToSend,
          });
        } catch {
          res.writeHead(502, { "content-type": "application/json" }).end(
            JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "upstream unreachable" } }),
          );
          return;
        }

        const ct = upstream.headers.get("content-type") ?? "";
        // Pass session/protocol headers back down.
        const outHeaders: Record<string, string> = { "content-type": ct };
        for (const h of ["mcp-session-id", "mcp-protocol-version"]) {
          const v = upstream.headers.get(h);
          if (v) outHeaders[h] = v;
        }

        if (ct.includes("text/event-stream")) {
          // A streamed response. Forward the bytes as-is: we do not need to parse
          // a stream we are only relaying, and a read-scan on a streamed tool
          // result is a later refinement, not a correctness requirement.
          res.writeHead(upstream.status, outHeaders);
          if (upstream.body) {
            const reader = upstream.body.getReader();
            for (;;) {
              const { done, value } = await reader.read();
              if (done) break;
              res.write(Buffer.from(value));
            }
          }
          res.end();
          return;
        }

        const text = await upstream.text();
        let outBody = text;
        try {
          const parsed = JSON.parse(text);
          const scanned = guardResponse(parsed, opts.guard, opts.onEvent, now);
          outBody = JSON.stringify(scanned);
        } catch {
          // Not JSON — relay untouched.
        }
        res.writeHead(upstream.status, outHeaders).end(outBody);
      }
    });
  });
}
