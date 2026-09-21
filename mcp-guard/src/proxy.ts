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
import {
  McpGuard,
  classifyToolNames,
  toolNamesFromListResult,
  type OrderIntent,
  type GuardDecision,
  type ToolNameReport,
} from "./index.js";

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
  /**
   * Called once the upstream advertises its tools, with what this guard would
   * and would not intercept. The runner uses it to warn — or stop — when the
   * ruleset does not match the server it is actually in front of.
   */
  onToolList?: (report: ToolNameReport) => void;
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

  // AW-03. This used to take the FIRST alias that parsed and never look for a
  // second, so one decoy field decided the order's size while the broker read
  // a different one: `{quantity: 1000, notional: 1}` was sized at $1, executed
  // $25,000,000, and the audit row positively certified a $1 order.
  //
  // The guard forwards the ORIGINAL bytes, so it can never be the thing that
  // decides which field the broker honours. The only safe reading is to
  // collect every alias of a dimension and refuse when they disagree.
  const symbols = allStrings(a, ["symbol", "ticker", "instrument", "stock"]);
  if (symbols.length === 0) return undefined;

  const sideRaw = (firstString(a, ["side", "action", "direction"]) ?? "").toLowerCase();
  const side: OrderIntent["side"] =
    sideRaw.includes("sell") ? "sell" : "buy"; // default to buy; sells are the safer default to allow, buys move money out

  const notionals = allNumbers(a, [
    "notional",
    "notional_usd",
    "amount",
    "amount_usd",
    "dollars",
    "dollar_amount",
    "value",
    "total",
  ]);
  const quantities = allNumbers(a, ["quantity", "qty", "shares", "units"]);
  const currencies = allStrings(a, ["currency", "currency_code", "denom"]);

  return {
    // The cap must bound the LARGEST value any alias could be read as, since
    // the guard does not control which one the broker picks.
    symbol: String(symbols[0]).toUpperCase(),
    side,
    ...(notionals.length > 0 ? { notionalUsd: Math.max(...notionals) } : {}),
    ...(quantities.length > 0 ? { quantity: Math.max(...quantities) } : {}),
    symbolsSeen: symbols.map((x) => String(x).toUpperCase()),
    notionalsSeen: notionals,
    quantitiesSeen: quantities,
    currenciesSeen: currencies.map((c) => String(c).toUpperCase()),
  };
}

/** Every value present under any alias — the basis for refusing ambiguity. */
function allNumbers(a: Record<string, unknown>, keys: readonly string[]): number[] {
  const out: number[] = [];
  for (const k of keys) {
    const v = a[k];
    const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
    if (Number.isFinite(n)) out.push(n);
  }
  return out;
}

function allStrings(a: Record<string, unknown>, keys: readonly string[]): string[] {
  const out: string[] = [];
  for (const k of keys) if (typeof a[k] === "string" && a[k] !== "") out.push(a[k] as string);
  return out;
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
  // AW-02. A JSON-RPC batch is a top-level ARRAY. `typeof [] === "object"` and
  // `[].method` is undefined, so a batch fell through both checks below and
  // was stringified upstream verbatim: no element inspected, no cap applied,
  // no audit event. Measured at $10,000,000,000 in one 1.4MB batch with zero
  // guard events.
  //
  // MCP removed batching in the 2025-06-18 revision, but the current SDK still
  // accepts arrays, so a spec-current upstream executes them today. This guard
  // refuses the envelope rather than trying to model it: an unmodelled shape
  // fails closed, the same rule already applied to an unreadable order.
  if (Array.isArray(msg)) {
    onEvent?.({ at: now(), direction: "request", tool: "", decision: "refuse", code: "MCP-008" });
    return {
      respond: refusalResult(
        null,
        "batched JSON-RPC requests are not supported by this guard; send one request per message",
      ),
    };
  }
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
 * Inspect a `tools/list` response and report what this guard would intercept.
 *
 * Name matching fails OPEN — an order tool whose name is not in the ruleset is
 * forwarded with no cap applied, and nothing at runtime says so. Reconciling
 * against what the server actually advertises is the only way the operator
 * learns that their guard is inspecting nothing.
 *
 * Returns the report, or undefined when the message is not a tool listing.
 */
export function inspectToolList(msg: unknown, guard?: McpGuard): ToolNameReport | undefined {
  if (typeof msg !== "object" || msg === null) return undefined;
  const m = msg as Record<string, unknown>;
  if (!("result" in m)) return undefined;
  const names = toolNamesFromListResult(m["result"]);
  if (names.length === 0) return undefined;
  // Reconcile against the vocabulary THIS guard runs with. Checking the
  // shipped defaults instead would report an operator's correct configuration
  // as a total mismatch — a false alarm that teaches people to ignore it.
  return classifyToolNames(names, guard?.orderTools);
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
    // AW-17. The body was accumulated with NO cap and stringified inside an
    // async listener whose rejection nobody handled. A body past V8's maximum
    // string length throws ERR_STRING_TOO_LONG out of an unhandled promise
    // rejection and Node's default terminates the process — measured fatal at
    // 520MB in 435ms, non-zero exit, nothing restarts it. Memory amplification
    // arrives sooner: one 100MB body drove peak RSS to 766MB, so a 1GB
    // container OOM-kills at roughly 130-200MB of wire traffic. The oversized
    // body was also relayed IN FULL to the broker before the crash, making the
    // proxy an amplifier pointed at the upstream.
    //
    // A killed proxy is the product's thesis inverted: "the agent has no other
    // path to the tool" becomes "there are no caps at all".
    const MAX_BODY_BYTES = 4 * 1024 * 1024; // generous for JSON-RPC; far under the string limit
    const chunks: Buffer[] = [];
    let received = 0;
    let overflowed = false;
    req.on("data", (c) => {
      received += c.length;
      if (received > MAX_BODY_BYTES) {
        if (!overflowed) {
          overflowed = true;
          res.writeHead(413, { "content-type": "application/json" }).end(
            JSON.stringify(refusalResult(null, "request body exceeds the guard's limit")),
          );
          req.destroy();
        }
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (overflowed) return;
      // The listener is async and nobody awaits it, so ANY rejection inside is
      // an unhandled rejection and Node's default terminates the process. The
      // guard must outlive a bad request: a dead proxy means no caps at all.
      void (async () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      let msg: unknown;
      try {
        msg = JSON.parse(raw);
      } catch {
        // AW-44. This used to forward verbatim, reasoning that a guard must
        // not corrupt traffic it does not understand. That is the right rule
        // for a PROXY and the wrong one for a GUARD: a parser differential is
        // a bypass, not a fallback. A body this guard cannot read but the
        // broker can is precisely the attack — measured at $770,000,000
        // through a BOM-tolerant broker mock.
        //
        // The guard is in the money path by construction, so what it cannot
        // read, it refuses.
        opts.onEvent?.({
          at: now(),
          direction: "request",
          tool: "",
          decision: "refuse",
          code: "MCP-009",
        });
        const body = JSON.stringify(
          refusalResult(null, "request body is not JSON this guard can read, so it was not forwarded"),
        );
        res.writeHead(200, { "content-type": "application/json" }).end(body);
        return;
      }

      const guarded = guardRequest(msg, opts.guard, opts.onEvent, now);
      if ("respond" in guarded) {
        // Short-circuit: the order was refused, never sent upstream.
        const body = JSON.stringify(guarded.respond);
        res.writeHead(200, { "content-type": "application/json" }).end(body);
        return;
      }
      forwardRaw(JSON.stringify(guarded.forward));
      })().catch((err) => {
        // Answer, log, stay alive. Never a stack trace to the caller.
        try {
          opts.onEvent?.({
            at: now(),
            direction: "request",
            tool: "",
            decision: "refuse",
            code: "MCP-011",
          });
          if (!res.headersSent)
            res
              .writeHead(500, { "content-type": "application/json" })
              .end(JSON.stringify(refusalResult(null, "guard error; request was not forwarded")));
        } catch {
          /* the response is already gone; the point is that the process is not */
        }
        console.error("[mcp-guard] request handler error:", err instanceof Error ? err.message : err);
      });

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
          // AW-16. Everything below this branch used to be skipped, including
          // inspectToolList + onToolList — the `!! UNGUARDED TOOLS` fail-stop
          // that is 0.2.0's headline feature and exits rather than "run as a
          // guard that guards nothing". It never fired against a stock server.
          //
          // This is not an edge case, it is the PROTOCOL DEFAULT: the official
          // SDK sets enableJsonResponse=false, so a POST response carries
          // text/event-stream, and the proxy copies the agent's Accept header
          // through verbatim so it cannot steer the upstream to JSON.
          //
          // Measured consequence: a broker executed a $50,000 market order
          // while the console displayed "per-order $100 / per-day $500".
          //
          // The bytes are still relayed verbatim — a guard must not corrupt a
          // stream — but each SSE `data:` line is now parsed as it passes and
          // the same inspection runs on it.
          res.writeHead(upstream.status, outHeaders);
          let sseBuffer = "";
          const inspectSseLine = (line: string) => {
            if (!line.startsWith("data:")) return;
            const payload = line.slice(5).trim();
            if (!payload) return;
            try {
              const parsed = JSON.parse(payload);
              const report = inspectToolList(parsed, opts.guard);
              if (report) opts.onToolList?.(report);
              guardResponse(parsed, opts.guard, opts.onEvent, now);
            } catch {
              /* a fragment that is not a whole JSON message; the next flush may complete it */
            }
          };
          if (upstream.body) {
            const reader = upstream.body.getReader();
            for (;;) {
              const { done, value } = await reader.read();
              if (done) break;
              const bytes = Buffer.from(value);
              res.write(bytes);
              // Parse a COPY of the stream; never hold the relay on it.
              sseBuffer += bytes.toString("utf8");
              let nl: number;
              while ((nl = sseBuffer.indexOf("\n")) >= 0) {
                inspectSseLine(sseBuffer.slice(0, nl).trim());
                sseBuffer = sseBuffer.slice(nl + 1);
              }
              // Bound the carry so a stream with no newlines cannot grow it.
              if (sseBuffer.length > 1_000_000) sseBuffer = "";
            }
          }
          if (sseBuffer.trim()) inspectSseLine(sseBuffer.trim());
          res.end();
          return;
        }

        const text = await upstream.text();
        let outBody = text;
        try {
          const parsed = JSON.parse(text);
          // A tool listing is the one chance to check that this guard's name
          // rules match the server in front of it. Report it before anything
          // is allowed to trade.
          const report = inspectToolList(parsed, opts.guard);
          if (report) opts.onToolList?.(report);
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
