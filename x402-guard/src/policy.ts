/**
 * An opt-in spending policy for the payment guard (0.10.0).
 *
 * ═══ WHY CONFORMANCE IS NOT ENOUGH ═══
 *
 * Every other check in this package answers one question: is the payment about
 * to be signed the one the merchant quoted? When the merchant is the attacker
 * that question has the wrong answer built in, because the quote IS the attack.
 * V12's first critical x402 SDK finding (2026-10-22) was a default client that
 * paid the first option a server listed with no limit, so a hostile API could
 * ask for a wallet's whole balance. That payment matches its quote exactly;
 * conformance has no opinion on whether a price is reasonable. A budget does,
 * and only the payer can set one.
 *
 * ═══ OFF UNLESS SUPPLIED, UNREADABLE MEANS ABSTAIN ═══
 *
 * A caller who passes no policy gets exactly the answers it got before. A
 * caller who passes one gets every rule in it applied or no verdict at all:
 * an unknown key, an amount that is not a non-negative integer, an address
 * that does not parse, or two spellings of one asset with different caps is an
 * abstain, never a silently skipped rule. A caller who set a cap and got an
 * allow believes the cap was applied; a misspelt `maxPerPaymnet` that read as
 * "no policy" would be the exact failure this package exists to avoid.
 *
 * No imports, on purpose: both lanes use it, and the Solana entry point must
 * not pull in viem nor the EVM one the Solana runtime. Each lane hands in its
 * own address normaliser.
 */

export interface SpendPolicy {
  /**
   * The most one payment may move, per asset (EVM token address or Solana
   * mint), in the asset's base units. Once set, a payment in an asset with no
   * entry is refused: a cap list is a list of what may be paid.
   */
  maxPerPayment?: Readonly<Record<string, string | number | bigint>>;
  /** The only assets a payment may use. */
  assets?: readonly string[];
  /** The only payees a payment may go to (EVM address, or the Solana owner the quote names). */
  payees?: readonly string[];
  /**
   * The most one guard may sign in total over its lifetime, per asset, in base
   * units. Read by `guardEvmSigner` and `guardSigner` only, which see every
   * payment they sign; a single-payment check has no lifetime to total. Once
   * set, the guards refuse an asset with no entry.
   */
  maxTotal?: Readonly<Record<string, string | number | bigint>>;
}

export interface PolicyFinding {
  code: string;
  severity: "critical" | "high" | "medium";
  message: string;
  expected?: string;
  actual?: string;
}

/** A lane's address normaliser: a canonical spelling, or null when the input is not an address. */
export type NormalizeAddress = (address: string) => string | null;

/** A policy read and validated against one lane's addresses. */
export interface ReadPolicy {
  readonly maxPerPayment: ReadonlyMap<string, bigint> | null;
  readonly assets: ReadonlySet<string> | null;
  readonly payees: ReadonlySet<string> | null;
  readonly maxTotal: ReadonlyMap<string, bigint> | null;
}

const POLICY_KEYS = new Set(["maxPerPayment", "assets", "payees", "maxTotal"]);
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * A value as read once: plain data that the reader validates and that the
 * digest of an unreadable policy renders.
 *
 * Taking it reads every property exactly once, so a getter runs once and
 * nothing after it can see a different value. It records own keys of every
 * kind, so a symbol or a non-enumerable key cannot hide a rule
 * (AWG-010-11). It is bounded in depth and size, so a cyclic or enormous
 * value is cut off, which makes it unreadable instead of hanging the check.
 */
type Taken =
  | { readonly t: "string"; readonly v: string }
  | { readonly t: "number"; readonly v: number | string }
  | { readonly t: "bigint"; readonly v: string }
  | { readonly t: "boolean"; readonly v: boolean }
  | { readonly t: "null" }
  | { readonly t: "undefined" }
  | { readonly t: "other"; readonly v: string }
  | { readonly t: "array"; readonly plain: boolean; readonly v: readonly Taken[] }
  | {
      readonly t: "object";
      readonly plain: boolean;
      readonly symbols: number;
      readonly v: readonly (readonly [string, Taken])[];
    }
  | { readonly t: "cut" }
  | { readonly t: "threw" };

/** Deeper than any policy can be; past it a value is cut off, not followed. */
const TAKE_DEPTH = 6;
/** More values than any policy holds; past it the rest is cut off. */
const TAKE_SIZE = 100_000;

function take(value: unknown): Taken {
  // Each property of each object is read once per capture, however often the
  // object occurs. One cap map serving as both maxPerPayment and maxTotal had
  // its getter read twice, so the two rules could take two different amounts
  // from one property (AWG-010-17). The cache keeps property readings, a
  // throw included, and not captured subtrees, so each occurrence is still
  // charged against the depth and size bounds.
  const captures = new WeakMap<object, Map<PropertyKey, { value: unknown } | { error: unknown }>>();
  const at = (object: object, key: PropertyKey): unknown => {
    let properties = captures.get(object);
    if (properties === undefined) {
      properties = new Map();
      captures.set(object, properties);
    }
    let item = properties.get(key);
    if (item === undefined) {
      try {
        item = { value: Reflect.get(object, key, object) };
      } catch (error) {
        item = { error };
      }
      properties.set(key, item);
    }
    if ("error" in item) throw item.error;
    return item.value;
  };
  let left = TAKE_SIZE;
  const walk = (v: unknown, depth: number): Taken => {
    if (--left < 0) return { t: "cut" };
    try {
      switch (typeof v) {
        case "string":
          return { t: "string", v };
        case "number":
          return { t: "number", v: Number.isFinite(v) ? v : String(v) };
        case "bigint":
          return { t: "bigint", v: v.toString() };
        case "boolean":
          return { t: "boolean", v };
        case "undefined":
          return { t: "undefined" };
        case "object":
          break;
        default:
          return { t: "other", v: typeof v };
      }
      if (v === null) return { t: "null" };
      if (depth >= TAKE_DEPTH) return { t: "cut" };
      if (Array.isArray(v)) {
        const n: unknown = at(v, "length");
        if (typeof n !== "number" || n > left) return { t: "cut" };
        // A list is read as its elements, by index. A list that carries
        // anything else iterates differently from how it indexes, so it is
        // not plain. That covers a symbol such as its own iterator, a named
        // property, or a prototype other than Array's.
        let plain = Object.getPrototypeOf(v) === Array.prototype;
        if (plain) {
          for (const key of Reflect.ownKeys(v)) {
            if (key === "length") continue;
            if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= n) {
              plain = false;
              break;
            }
          }
        }
        const items: Taken[] = [];
        for (let i = 0; i < n; i++) items.push(walk(at(v, String(i)), depth + 1));
        return { t: "array", plain, v: items };
      }
      const proto: unknown = Object.getPrototypeOf(v);
      const entries: [string, Taken][] = [];
      let symbols = 0;
      for (const key of Reflect.ownKeys(v)) {
        if (typeof key !== "string") {
          symbols++;
          continue;
        }
        if (left <= 0) return { t: "cut" };
        entries.push([key, walk(at(v, key), depth + 1)]);
      }
      entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return { t: "object", plain: proto === Object.prototype || proto === null, symbols, v: entries };
    } catch {
      return { t: "threw" };
    }
  };
  return walk(value, 0);
}

/** A short description of a key for a reason string. */
function describe(key: string): string {
  return JSON.stringify(key.slice(0, 80));
}

/** A short description of a value as taken, for a reason string. */
function describeTaken(v: Taken): string {
  switch (v.t) {
    case "string":
      return describe(v.v);
    case "bigint":
      return `the bigint ${v.v.slice(0, 80)}`;
    case "number":
    case "boolean":
      return String(v.v);
    case "threw":
      return "a value whose reading threw";
    default:
      return `a value of type ${v.t}`;
  }
}

/** Why a part of the policy that is not the shape it should be cannot be read. */
function unreadablePart(name: string, v: Taken, shape: string): string {
  if (v.t === "threw") return `spendPolicy.${name} could not be read: reading it threw`;
  if (v.t === "cut") return `spendPolicy.${name} is deeper or larger than a policy can be`;
  return `spendPolicy.${name} is not ${shape}`;
}

/** A non-negative integer in base units, from a decimal string, a safe integer or a bigint. */
function amountOf(v: Taken): bigint | null {
  try {
    if (v.t === "bigint") {
      const b = BigInt(v.v);
      return b >= 0n ? b : null;
    }
    if (v.t === "number") return typeof v.v === "number" && Number.isSafeInteger(v.v) && v.v >= 0 ? BigInt(v.v) : null;
    if (v.t === "string" && /^[0-9]+$/.test(v.v.trim())) return BigInt(v.v.trim());
    return null;
  } catch {
    return null;
  }
}

function readAmountMap(name: string, v: Taken, norm: NormalizeAddress): Map<string, bigint> | string {
  if (v.t !== "object" || !v.plain) return unreadablePart(name, v, "a plain object of asset → amount");
  if (v.symbols > 0) return `spendPolicy.${name} carries a symbol key`;
  const out = new Map<string, bigint>();
  for (const [key, value] of v.v) {
    if (FORBIDDEN_KEYS.has(key)) return `spendPolicy.${name} carries the key ${key}`;
    const asset = norm(key);
    if (asset === null) return `spendPolicy.${name} names ${describe(key)}, which is not an address`;
    const amount = amountOf(value);
    if (amount === null) {
      return `spendPolicy.${name}[${describe(key)}] is not a non-negative integer in base units`;
    }
    // Two spellings of one asset (a checksummed and a lowercase address) with
    // different amounts: which one the caller meant cannot be known.
    const before = out.get(asset);
    if (before !== undefined && before !== amount) {
      return `spendPolicy.${name} gives the asset ${asset} two different amounts`;
    }
    out.set(asset, amount);
  }
  return out;
}

function readAddressSet(name: string, v: Taken, norm: NormalizeAddress): Set<string> | string {
  if (v.t !== "array" || !v.plain) return unreadablePart(name, v, "a plain array of addresses");
  const out = new Set<string>();
  for (const entry of v.v) {
    const address = entry.t === "string" ? norm(entry.v) : null;
    if (address === null) return `spendPolicy.${name} holds ${describeTaken(entry)}, which is not an address`;
    out.add(address);
  }
  return out;
}

function readTaken(p: Taken, norm: NormalizeAddress): ReadPolicy | string {
  if (p.t === "threw") return "spendPolicy could not be read: reading it threw";
  if (p.t === "cut") return "spendPolicy is deeper or larger than a policy can be";
  if (p.t !== "object" || !p.plain) return "spendPolicy is not a plain object";
  if (p.symbols > 0) {
    return "spendPolicy carries a symbol key, so the policy the caller meant cannot be read";
  }
  for (const [key] of p.v) {
    if (!POLICY_KEYS.has(key)) {
      return `spendPolicy carries an unknown key ${describe(key)}, so the policy the caller meant cannot be read`;
    }
  }
  // A rule present with the value undefined is a rule not set, as before.
  const rule = (name: string): Taken | null => {
    const found = p.v.find(([key]) => key === name);
    return found === undefined || found[1].t === "undefined" ? null : found[1];
  };
  const read: {
    maxPerPayment: Map<string, bigint> | null;
    assets: Set<string> | null;
    payees: Set<string> | null;
    maxTotal: Map<string, bigint> | null;
  } = { maxPerPayment: null, assets: null, payees: null, maxTotal: null };
  const caps = rule("maxPerPayment");
  if (caps !== null) {
    const m = readAmountMap("maxPerPayment", caps, norm);
    if (typeof m === "string") return m;
    read.maxPerPayment = m;
  }
  const totals = rule("maxTotal");
  if (totals !== null) {
    const m = readAmountMap("maxTotal", totals, norm);
    if (typeof m === "string") return m;
    read.maxTotal = m;
  }
  const assets = rule("assets");
  if (assets !== null) {
    const s = readAddressSet("assets", assets, norm);
    if (typeof s === "string") return s;
    read.assets = s;
  }
  const payees = rule("payees");
  if (payees !== null) {
    const s = readAddressSet("payees", payees, norm);
    if (typeof s === "string") return s;
    read.payees = s;
  }
  return read;
}

/**
 * Read a caller's policy against one lane's addresses. Returns the policy, or
 * the reason it cannot be read; the caller abstains with that reason.
 *
 * Reads the caller's value once (see Taken) and never throws. A getter that
 * throws, a revoked proxy, a bigint in an address list and a symbol key are
 * all policies that cannot be read, like any other, and none becomes an
 * exception out of a check that promised a verdict (AWG-010-07).
 */
export function readSpendPolicy(policy: unknown, norm: NormalizeAddress): ReadPolicy | string {
  return pinSpendPolicy(policy, norm).read;
}

/**
 * A policy read once, together with the form a request digest hashes. Both
 * come from one pass over the caller's value, so a receipt hashes the policy
 * its verdict applied (AWG-010-10).
 *
 * The form is built from the lane's own reading, so the digest is exactly as
 * wide as the check. Two spellings the reader takes as one policy, such as
 * "0010" and 10n, a checksummed and a lowercase address, a repeated payee, or
 * spaces around a mint, hash as one (AWG-010-05). A policy the reader cannot
 * read never hashes like one it can (AWG-010-04). It hashes as its reason and
 * the value as taken.
 *
 * `norm` is null when the request names no chain. Such a request abstains
 * before any policy applies.
 */
export function pinSpendPolicy(
  policy: unknown,
  norm: NormalizeAddress | null,
): { read: ReadPolicy | string; form: unknown } {
  const taken = take(policy);
  if (norm === null) {
    return { read: "the request names no chain to read spendPolicy's addresses on", form: { unresolved: taken } };
  }
  let read: ReadPolicy | string;
  try {
    read = readTaken(taken, norm);
  } catch {
    read = "spendPolicy could not be read: reading it threw";
  }
  if (typeof read === "string") return { read, form: { unreadable: read, raw: taken } };
  const amounts = (m: ReadonlyMap<string, bigint> | null): [string, string][] | null =>
    m === null
      ? null
      : [...m]
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([asset, amount]): [string, string] => [asset, amount.toString()]);
  const set = (x: ReadonlySet<string> | null): string[] | null => (x === null ? null : [...x].sort());
  return {
    read,
    form: {
      assets: set(read.assets),
      maxPerPayment: amounts(read.maxPerPayment),
      maxTotal: amounts(read.maxTotal),
      payees: set(read.payees),
    },
  };
}

/** The digest form of a policy alone (see pinSpendPolicy). */
export function canonicalSpendPolicy(policy: unknown, norm: NormalizeAddress | null): unknown {
  return pinSpendPolicy(policy, norm).form;
}

/**
 * The policy an options object carries, read once: null when it carries none,
 * otherwise the reading or the reason it cannot be read. Never throws. An
 * `options.spendPolicy` getter that throws is a policy that cannot be read,
 * not an exception (AWG-010-14).
 */
export function readPolicyOption(opts: unknown, norm: NormalizeAddress): ReadPolicy | null | string {
  let raw: unknown;
  try {
    raw = opts === null || opts === undefined ? undefined : (opts as { spendPolicy?: unknown }).spendPolicy;
  } catch {
    return "options.spendPolicy could not be read: reading it threw";
  }
  return raw === undefined ? null : readSpendPolicy(raw, norm);
}

/**
 * A guard's options for one signing. The policy is read once, and the check
 * gets the caller's options with `spendPolicy` replaced by plain data from
 * that one reading. Other options are still read from the caller's object,
 * as before, and with the caller's object as `this`. With no policy, the
 * replacement is undefined, so the check does not read the option a second
 * time either (AWG-010-08). Returns the reason when the policy cannot be read.
 */
export function pinPolicyOption<O extends object>(
  opts: O,
  norm: NormalizeAddress,
): { opts: O; policy: ReadPolicy | null } | string {
  let raw: unknown;
  try {
    raw = (opts as { spendPolicy?: unknown }).spendPolicy;
  } catch {
    return "options.spendPolicy could not be read: reading it threw";
  }
  const read = raw === undefined ? null : readSpendPolicy(raw, norm);
  if (typeof read === "string") return read;
  const holder = Object.create(opts, {
    spendPolicy: { value: read === null ? undefined : plainSpendPolicy(read), enumerable: true },
  });
  // Every other option is read from the caller's own object, with that object
  // as the receiver. Read through the holder, a getter ran with the holder as
  // `this`. An expectedPayer kept in a WeakMap keyed by the options then came
  // back undefined, and a nonce set made lazily on `this` was a new, empty set
  // on every signing, even for a caller with no policy at all (AWG-010-16).
  const pinned = new Proxy(holder, {
    get(target, key) {
      return key === "spendPolicy" ? Reflect.get(target, key) : Reflect.get(opts, key, opts);
    },
  }) as O;
  return { opts: pinned, policy: read };
}

/**
 * A reading as a plain policy again: what a guard hands its check, so that the
 * check reads exactly what the guard read. Reads back to the same reading.
 */
export function plainSpendPolicy(read: ReadPolicy): SpendPolicy {
  const out: {
    maxPerPayment?: Record<string, bigint>;
    assets?: string[];
    payees?: string[];
    maxTotal?: Record<string, bigint>;
  } = {};
  if (read.maxPerPayment !== null) out.maxPerPayment = Object.fromEntries(read.maxPerPayment);
  if (read.assets !== null) out.assets = [...read.assets];
  if (read.payees !== null) out.payees = [...read.payees];
  if (read.maxTotal !== null) out.maxTotal = Object.fromEntries(read.maxTotal);
  return out;
}

/**
 * The single-payment rules: the allowed assets (X402-502), the allowed payees
 * (X402-503) and the per-payment cap (X402-501). Every finding is critical, so
 * every lane refuses on it. `asset` and `payTo` must already be in the lane's
 * normalised spelling.
 */
export function checkSpendPolicy(
  policy: ReadPolicy,
  payment: { readonly asset: string; readonly payTo: string; readonly amount: bigint },
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];
  if (policy.assets !== null && !policy.assets.has(payment.asset)) {
    findings.push({
      code: "X402-502",
      severity: "critical",
      message: "the payment's asset is not one the spending policy allows",
      expected: [...policy.assets].join(", ").slice(0, 200),
      actual: payment.asset,
    });
  }
  if (policy.payees !== null && !policy.payees.has(payment.payTo)) {
    findings.push({
      code: "X402-503",
      severity: "critical",
      message: "the payment's payee is not one the spending policy allows",
      expected: [...policy.payees].join(", ").slice(0, 200),
      actual: payment.payTo,
    });
  }
  if (policy.maxPerPayment !== null) {
    const cap = policy.maxPerPayment.get(payment.asset);
    if (cap === undefined) {
      findings.push({
        code: "X402-502",
        severity: "critical",
        message:
          "the spending policy sets per-payment caps and none for this asset, so a payment in it is not one the policy allows",
        actual: payment.asset,
      });
    } else if (payment.amount > cap) {
      findings.push({
        code: "X402-501",
        severity: "critical",
        message:
          "the payment moves more than the spending policy's per-payment cap for this asset — a quote that asks for more than the payer allows is refused whatever it says",
        expected: `<= ${cap.toString()}`,
        actual: payment.amount.toString(),
      });
    }
  }
  return findings;
}

/**
 * A guard's running total per asset, for `maxTotal` (X402-504).
 *
 * The guard reserves before the wallet signs, and releases if the wallet does
 * not. Counting after signing would let two concurrent payments both pass the
 * check. Counting before without a release would charge a payment the wallet
 * refused.
 *
 * `reserve` returns a finding when the payment does not fit. Otherwise it
 * returns the release for exactly what that call holds, which runs at most
 * once. When nothing was held, because the policy sets no totals, the
 * release does nothing. The first version released a payment's amount
 * whether or not it had been reserved, so a failed call made while no total
 * was set refunded what earlier payments had used (AWG-010-12). A total counts
 * the payments signed while it is set.
 */
export function createSpendTracker(): {
  reserve(policy: ReadPolicy, asset: string, amount: bigint): PolicyFinding | (() => void);
  spent(asset: string): bigint;
} {
  const spent = new Map<string, bigint>();
  return {
    reserve(policy, asset, amount) {
      if (policy.maxTotal === null) return () => {};
      const cap = policy.maxTotal.get(asset);
      if (cap === undefined) {
        return {
          code: "X402-504",
          severity: "critical",
          message:
            "the spending policy sets lifetime totals and none for this asset, so this guard signs nothing in it",
          actual: asset,
        };
      }
      const before = spent.get(asset) ?? 0n;
      if (before + amount > cap) {
        return {
          code: "X402-504",
          severity: "critical",
          message: "the payment would take this guard past the spending policy's lifetime total for this asset",
          expected: `<= ${cap.toString()} in total`,
          actual: `${before.toString()} signed before, ${amount.toString()} asked`,
        };
      }
      spent.set(asset, before + amount);
      let held = true;
      return () => {
        if (!held) return;
        held = false;
        const after = (spent.get(asset) ?? 0n) - amount;
        if (after <= 0n) spent.delete(asset);
        else spent.set(asset, after);
      };
    },
    spent(asset) {
      return spent.get(asset) ?? 0n;
    },
  };
}
