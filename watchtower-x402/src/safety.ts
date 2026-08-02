/**
 * The safety rail. Read this before the probers, because it is the reason the
 * probers are allowed to exist.
 *
 * ═══ THE PROBLEM, STATED PLAINLY ═══
 *
 * A conformance probe asks a facilitator "would you accept this payment you
 * should refuse?" That means constructing payment authorisations that are
 * deliberately wrong — an underpayment, a signature re-presented for a different
 * resource, one nonce sent twice. Those are the shapes of a real attack. A bug
 * in the harness that let one of them SETTLE would move value, and the project
 * whose whole thesis is "we stop agents being tricked into paying" would have
 * built a machine that pays.
 *
 * So settlement is not something the probers politely avoid. It is something
 * this module makes UNREACHABLE.
 *
 * ═══ HOW IT IS ENFORCED, IN LAYERS ═══
 *
 * 1. METHOD ALLOWLIST. A prober cannot name an endpoint; it names an OPERATION,
 *    and the only operations that exist are read-only ones. `/settle` is not a
 *    value this type can hold. There is no string a prober can pass to reach it.
 *
 * 2. URL INSPECTION AT THE TRANSPORT. Even a correctly-typed operation has its
 *    final URL checked for settle-shaped paths before the request leaves. This is
 *    belt-and-braces against a future contributor adding an operation that
 *    resolves somewhere unexpected.
 *
 * 3. A VALUE CEILING ON EVERY CONSTRUCTED AUTHORISATION. Every payment payload a
 *    prober builds passes through `assertProbeSafeValue`. Anything above the cap
 *    throws before it can be sent. A probe that is refused is a successful probe;
 *    a probe that could move real money is a bug, and this turns that bug into a
 *    crash instead of a transfer.
 *
 * The layers are deliberately redundant. Any one of them alone would be an
 * argument; three of them is a guarantee that survives someone editing one file
 * without reading this one.
 *
 * ═══ WHAT THIS DOES NOT PROTECT AGAINST ═══
 *
 * It does not stop a facilitator from settling on its own initiative after a
 * `/verify` — no client-side rail can. That is why probes run against a wallet
 * funded to a cap we are prepared to lose entirely, and why the first slice
 * probes only invariants observable at the `/verify` stage. If a probe ever needs
 * `/settle` to be meaningful, that probe does not ship until this file has a
 * different design and a human has signed off on it.
 */

/** The only operations a prober may perform. `settle` is absent by construction. */
export type SafeOperation = "supported" | "verify";

/** Paths that must never be requested, matched defensively against the final URL. */
const FORBIDDEN_PATH = /\/settle\b|\/execute\b|\/broadcast\b|\/submit\b/i;

/**
 * The most a probe authorisation may ever be worth, in base units.
 *
 * Set to a value that is trivially small on every chain we probe. It is not a
 * budget to spend — the probes are designed never to settle — it is the blast
 * radius if every other layer fails at once. Deliberately a constant rather than
 * a config option: an operator who can raise this from a config file will, and
 * the point of a rail is that it does not move.
 */
export const MAX_PROBE_VALUE_BASE_UNITS = 1000n; // 0.001 USDC at 6 decimals

export class ProbeSafetyError extends Error {
  constructor(message: string) {
    super(`probe safety: ${message}`);
    this.name = "ProbeSafetyError";
  }
}

/**
 * Resolve an operation to a URL, refusing anything settle-shaped.
 *
 * Takes the facilitator's base URL and a SafeOperation. Because the operation is
 * a union of two read-only strings, the caller cannot ask for settlement — and
 * the returned URL is checked anyway, in case a facilitator's base URL itself
 * contains a forbidden segment or a future operation is added carelessly.
 */
export function safeUrl(baseUrl: string, op: SafeOperation): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new ProbeSafetyError(`facilitator base URL is not a URL: ${String(baseUrl).slice(0, 60)}`);
  }
  if (url.protocol !== "https:" && url.hostname !== "127.0.0.1" && url.hostname !== "localhost") {
    // Probes carry crafted authorisations. Sending them in the clear to a remote
    // host is an unnecessary exposure; localhost is permitted for the fake
    // facilitator the tests run against.
    throw new ProbeSafetyError(`refusing a non-https facilitator: ${url.protocol}`);
  }
  const base = url.toString().replace(/\/+$/, "");
  const full = `${base}/${op}`;
  if (FORBIDDEN_PATH.test(full)) {
    throw new ProbeSafetyError(`resolved URL looks like a settlement endpoint: ${full}`);
  }
  return full;
}

/**
 * Refuse to construct an authorisation worth more than the ceiling.
 *
 * Called by every prober that builds a payment payload. Accepts the value as a
 * string or bigint because wire formats use decimal strings, and a value that
 * cannot be parsed is refused rather than assumed small — an unparseable amount
 * is exactly the case where "assume zero" would be dangerous.
 */
export function assertProbeSafeValue(value: unknown, context: string): bigint {
  let v: bigint;
  if (typeof value === "bigint") {
    v = value;
  } else if (typeof value === "string" && /^\d+$/.test(value.trim())) {
    v = BigInt(value.trim());
  } else if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    v = BigInt(value);
  } else {
    throw new ProbeSafetyError(
      `${context}: value is not a non-negative integer, refusing to build a probe from it`,
    );
  }
  if (v > MAX_PROBE_VALUE_BASE_UNITS) {
    throw new ProbeSafetyError(
      `${context}: ${v} exceeds the probe ceiling of ${MAX_PROBE_VALUE_BASE_UNITS} base units`,
    );
  }
  return v;
}

/**
 * The transport every prober uses. There is no other way to reach a facilitator
 * from this package, which is what makes the rail unavoidable rather than
 * advisory.
 *
 * `fetchImpl` is injected so the whole suite runs against a fake facilitator with
 * no network at all — the lying facilitator is the important test case, and a
 * prober that reached for the real network could not be given one.
 */
export interface ProbeTransport {
  (baseUrl: string, op: SafeOperation, body?: unknown): Promise<{
    status: number;
    json: unknown;
  }>;
}

export function createTransport(opts: {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /** Identifies the probe to the operator being probed. Politeness and honesty. */
  userAgent?: string;
} = {}): ProbeTransport {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const ua = opts.userAgent ?? "agent-wormhole-conformance (+https://agentwormhole.com/facilitators)";

  return async (baseUrl, op, body) => {
    const url = safeUrl(baseUrl, op); // layer 2 runs on every single request
    const res = await doFetch(url, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "user-agent": ua,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    let json: unknown = null;
    try {
      json = await res.json();
    } catch {
      // A facilitator that returns non-JSON is itself a finding, but it is the
      // prober's job to classify that, not the transport's job to throw.
      json = null;
    }
    return { status: res.status, json };
  };
}
