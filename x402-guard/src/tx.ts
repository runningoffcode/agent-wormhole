/**
 * wormhole-x402/tx — refuse a transaction that is not the one the agent meant
 * to send (0.11.0). Offline, no RPC.
 *
 * ═══ THE GAP THIS CLOSES ═══
 *
 * `guardEvmSigner` checks x402 payments. Every other transaction, a borrow, an
 * approval, a swap, was refused, because there is no payment in it to check.
 * An agent that needed one had two choices: leave it unguarded, or name the
 * method in `allow`, which passed every transaction through unchecked. The
 * transaction usually comes from the other side (an MCP tool, an API that
 * answers with calldata), so "allow" meant signing whatever that side built.
 *
 * ═══ AN INTENT, FROM THE AGENT'S OWN CODE ═══
 *
 * The check compares a transaction with a declared intent: the chain, the
 * contract, the function, and what each argument may be. The intent comes
 * from the agent's code, never from the counterparty; a counterparty that
 * could write the intent could write the transaction too. A transaction is
 * allowed only when it is the intended call in every part the intent names,
 * and nothing is left out of the comparison by default: an argument nobody
 * constrains must be written `{ any: true }`.
 *
 * ═══ READABLE OR ABSTAIN ═══
 *
 * Calldata that does not decode with the intended signature, or decodes but
 * does not re-encode to the same bytes, is unreadable: trailing bytes, dirty
 * high bits and overlapping offsets all decode in a lenient decoder, and a
 * contract can read them differently from this check. So can a field this
 * check does not model, a name the signer would resolve, a blob, or a wrapper
 * (multicall, execute, a Safe transaction) whose inner calls the intent leaves
 * open. Unreadable is an abstain, never an allow.
 *
 * ═══ STANDING AUTHORITY ═══
 *
 * An approval, a permit, an operator grant, an ownership transfer or an
 * EIP-7702 delegation outlives the transaction: it lets someone else move
 * funds later. Those are allowed only when the intent names them exactly, and
 * an unlimited one only with `unlimited: true` on the intent.
 *
 * NOT IN SCOPE: what a contract does inside (simulate for that; this says
 * whether the transaction is the one intended), whether the intent is wise,
 * fees and nonce (the signer's), and Solana.
 */

import {
  decodeAbiParameters,
  decodeFunctionData,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  isAddress,
  parseAbiItem,
  parseAbiParameters,
  toFunctionSelector,
  type AbiFunction,
  type AbiParameter,
} from "viem";
import { checkSpendPolicy, readPolicyOption, type ReadPolicy, type SpendPolicy } from "./policy.js";
// Type-only: evm.ts imports this module, and the verdict shapes are its own.
import type { Finding, Verdict } from "./evm.js";

// --- what a caller writes ----------------------------------------------------

/** A non-negative integer in base units: a bigint, a safe integer, or a decimal string. */
export type Amount = bigint | number | string;

/** An amount exactly (`Amount` or `{ eq }`), or within bounds (`{ lte, gte }`, either or both). */
export type Bound = Amount | { readonly eq: Amount } | { readonly lte?: Amount; readonly gte?: Amount };

/**
 * What one argument of a call may be.
 *
 * - `{ eq }` exactly this value; `{ oneOf }` one of these values;
 * - `{ lte, gte }` an integer within bounds;
 * - `{ any: true }` unchecked, written out, never the default;
 * - `{ tuple }` a struct's components, in order;
 * - `{ items }` an array's items, in order, its length included;
 * - `{ abi, args }` bytes that hold ABI-encoded values (`abi` lists their
 *   types, as in `"address, uint256"`), decoded and checked in turn.
 */
export type Constraint =
  | { readonly eq: unknown }
  | { readonly oneOf: readonly unknown[] }
  | { readonly lte?: Amount; readonly gte?: Amount }
  | { readonly any: true }
  | { readonly tuple: readonly Constraint[] }
  | { readonly items: readonly Constraint[] }
  | { readonly abi: string; readonly args: readonly Constraint[] };

/** What the agent means to do, from the agent's own code. */
export type TxIntent =
  | {
      readonly kind: "native.transfer";
      readonly chainId: number | bigint;
      readonly to: string;
      readonly amount: Bound;
    }
  | {
      readonly kind: "erc20.transfer";
      readonly chainId: number | bigint;
      readonly token: string;
      /** The recipient, or the recipients any one of which may be paid. */
      readonly to: string | readonly string[];
      readonly amount: Bound;
    }
  | {
      readonly kind: "erc20.approve";
      readonly chainId: number | bigint;
      readonly token: string;
      readonly spender: string;
      /** The exact allowance, or "unlimited" for any amount up to the maximum. */
      readonly amount: Amount | "unlimited";
    }
  | {
      readonly kind: "call";
      readonly chainId: number | bigint;
      readonly target: string;
      /** The function, as in `"borrow((address,address,address,address,uint256),uint256,uint256,address,address)"`. */
      readonly signature: string;
      /** One constraint per argument, in order. */
      readonly args: readonly Constraint[];
      /** The native value sent with the call. Absent means none. */
      readonly value?: Bound;
      /** Required for a call that grants unlimited standing authority (see STANDING). */
      readonly unlimited?: true;
    };

export interface InspectTransactionOptions {
  /**
   * The opt-in spending policy (0.10.0), applied to the movements this check
   * can read: native value, and the token amounts of transfer, transferFrom,
   * approve, increaseAllowance and Permit2's approve and transferFrom. The
   * chain's native coin is named NATIVE_ASSET in it. Anything else a call
   * moves inside a contract is not visible here.
   */
  spendPolicy?: SpendPolicy;
}

/** The chain's native coin in a spending policy, as several aggregators name it. */
export const NATIVE_ASSET = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

/** Permit2's canonical address, the same on every chain it is deployed to. */
export const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

// --- read once, never throw --------------------------------------------------

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const MAX_UINT256 = (1n << 256n) - 1n;
/** Deeper than any intent needs; past it an intent is unreadable, not followed. */
const MAX_DEPTH = 16;

const isPlain = (v: unknown): v is object => {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};

/**
 * An object's own string-keyed properties, each read once, enumerable or not.
 * A signer reads `tx.to` whether or not it is enumerable, so the check reads it
 * too. Symbols are reported, so a reader of intents can refuse them.
 */
function snapshot(v: object): { props: Map<string, unknown>; symbols: number } | string {
  try {
    const props = new Map<string, unknown>();
    let symbols = 0;
    for (const key of Reflect.ownKeys(v)) {
      if (typeof key === "symbol") {
        symbols++;
        continue;
      }
      props.set(key, Reflect.get(v, key, v));
    }
    return { props, symbols };
  } catch (e) {
    return `reading it threw (${e instanceof Error ? e.message : String(e)})`;
  }
}

/** The strict address spelling the signers accept, lowercase; null when not an address. */
function addressOf(v: unknown): string | null {
  if (typeof v !== "string" || !isAddress(v)) return null;
  try {
    return getAddress(v).toLowerCase();
  } catch {
    return null;
  }
}

/** An address in the caller's own intent, read like a spending policy's: surrounding spaces allowed. */
function intentAddressOf(v: unknown): string | null {
  return typeof v === "string" ? addressOf(v.trim()) : null;
}

/** A non-negative integer from an Amount; null when it is not one. */
function amountOf(v: unknown): bigint | null {
  if (typeof v === "bigint") return v >= 0n ? v : null;
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v === "string" && /^\d+$/.test(v)) return BigInt(v);
  return null;
}

/** A chain id: a positive safe integer, a bigint, or a decimal or 0x-hex string. */
function chainOf(v: unknown): bigint | null {
  let n: bigint | null = null;
  if (typeof v === "bigint") n = v;
  else if (typeof v === "number" && Number.isSafeInteger(v)) n = BigInt(v);
  else if (typeof v === "string" && /^(\d+|0x[0-9a-fA-F]+)$/.test(v)) n = BigInt(v);
  return n !== null && n > 0n && n <= BigInt(Number.MAX_SAFE_INTEGER) ? n : null;
}

const isHex = (v: unknown): v is string => typeof v === "string" && /^0x([0-9a-fA-F]{2})*$/.test(v);

// --- the intent, read ---------------------------------------------------------

/** An amount range; `eq` reads as both bounds. */
interface Range {
  readonly lte: bigint | null;
  readonly gte: bigint | null;
}

/** A value as compared: addresses and bytes lowercase, integers as bigint, arrays and structs positional. */
type Norm = string | bigint | boolean | readonly Norm[];

/** A constraint read against its parameter's type. */
type Rule =
  | { readonly k: "eq"; readonly v: Norm }
  | { readonly k: "oneOf"; readonly v: readonly Norm[] }
  | { readonly k: "range"; readonly r: Range }
  | { readonly k: "any" }
  | { readonly k: "tuple"; readonly parts: readonly Rule[] }
  | { readonly k: "items"; readonly parts: readonly Rule[] }
  | { readonly k: "abi"; readonly params: readonly AbiParameter[]; readonly parts: readonly Rule[] };

interface ReadIntent {
  readonly kind: TxIntent["kind"];
  readonly chainId: bigint;
  /** The contract (or, for a native transfer, the recipient) the transaction must go to. */
  readonly target: string;
  readonly recipients: ReadonlySet<string> | null;
  readonly amount: Range | null;
  readonly spender: string | null;
  readonly allowance: bigint | "unlimited" | null;
  readonly fn: AbiFunction | null;
  readonly selector: string | null;
  readonly rules: readonly Rule[] | null;
  readonly value: Range;
  readonly unlimited: boolean;
}

const INTENT_KEYS: Readonly<Record<TxIntent["kind"], readonly string[]>> = {
  "native.transfer": ["kind", "chainId", "to", "amount"],
  "erc20.transfer": ["kind", "chainId", "token", "to", "amount"],
  "erc20.approve": ["kind", "chainId", "token", "spender", "amount"],
  call: ["kind", "chainId", "target", "signature", "args", "value", "unlimited"],
};

function readBound(v: unknown, what: string): Range | string {
  const exact = amountOf(v);
  if (exact !== null) return { lte: exact, gte: exact };
  if (!isPlain(v)) return `${what} is not an amount or a bound`;
  const s = snapshot(v);
  if (typeof s === "string") return `${what}: ${s}`;
  const keys = [...s.props.keys()];
  if (s.symbols > 0 || keys.length === 0 || keys.some((k) => !["eq", "lte", "gte"].includes(k))) {
    return `${what} must be an amount, { eq }, or { lte, gte }`;
  }
  if (s.props.has("eq")) {
    if (keys.length !== 1) return `${what} cannot combine eq with a bound`;
    const eq = amountOf(s.props.get("eq"));
    return eq === null ? `${what}.eq is not a non-negative integer` : { lte: eq, gte: eq };
  }
  const lte = s.props.has("lte") ? amountOf(s.props.get("lte")) : null;
  const gte = s.props.has("gte") ? amountOf(s.props.get("gte")) : null;
  if (s.props.has("lte") && lte === null) return `${what}.lte is not a non-negative integer`;
  if (s.props.has("gte") && gte === null) return `${what}.gte is not a non-negative integer`;
  if (lte !== null && gte !== null && gte > lte) return `${what} allows nothing: gte is above lte`;
  return { lte, gte };
}

// --- ABI types ----------------------------------------------------------------

/** An array parameter's element and length (null for a dynamic array); null when not an array. */
function arrayOf(p: AbiParameter): { element: AbiParameter; length: number | null } | null {
  const m = /^(.*)\[(\d*)\]$/.exec(p.type);
  if (m === null) return null;
  const element = { ...p, type: m[1]! } as AbiParameter;
  return { element, length: m[2] === "" ? null : Number(m[2]) };
}

const componentsOf = (p: AbiParameter): readonly AbiParameter[] | null =>
  p.type === "tuple" && "components" in p && Array.isArray(p.components) ? (p.components as readonly AbiParameter[]) : null;

/** An integer type's bounds; null when the type is not an integer. */
function intRange(type: string): { min: bigint; max: bigint } | null {
  const m = /^(u?)int(\d*)$/.exec(type);
  if (m === null) return null;
  const bits = BigInt(m[2] === "" ? 256 : Number(m[2]));
  return m[1] === "u" ? { min: 0n, max: (1n << bits) - 1n } : { min: -(1n << (bits - 1n)), max: (1n << (bits - 1n)) - 1n };
}

/** Does the type hold dynamic `bytes` anywhere, the shape an inner call travels in? */
function holdsBytes(p: AbiParameter): boolean {
  if (p.type === "bytes") return true;
  const arr = arrayOf(p);
  if (arr !== null) return holdsBytes(arr.element);
  const parts = componentsOf(p);
  return parts !== null && parts.some(holdsBytes);
}

/**
 * A value as compared, against its parameter's type; null when the value is
 * not one of that type. Reads a caller's value and a decoded one alike.
 */
function normalize(p: AbiParameter, v: unknown, depth = 0): Norm | null {
  if (depth > MAX_DEPTH) return null;
  const arr = arrayOf(p);
  if (arr !== null) {
    if (!Array.isArray(v)) return null;
    if (arr.length !== null && v.length !== arr.length) return null;
    const out: Norm[] = [];
    for (const item of v) {
      const n = normalize(arr.element, item, depth + 1);
      if (n === null) return null;
      out.push(n);
    }
    return out;
  }
  const parts = componentsOf(p);
  if (parts !== null) {
    let values: unknown[];
    if (Array.isArray(v)) values = v;
    else if (isPlain(v) && parts.every((c) => typeof c.name === "string" && c.name !== "")) {
      const s = snapshot(v);
      if (typeof s === "string" || s.symbols > 0 || s.props.size !== parts.length) return null;
      if (parts.some((c) => !s.props.has(c.name!))) return null;
      values = parts.map((c) => s.props.get(c.name!));
    } else return null;
    if (values.length !== parts.length) return null;
    const out: Norm[] = [];
    for (let i = 0; i < parts.length; i++) {
      const n = normalize(parts[i]!, values[i], depth + 1);
      if (n === null) return null;
      out.push(n);
    }
    return out;
  }
  if (p.type === "address") return intentAddressOf(v);
  if (p.type === "bool") return typeof v === "boolean" ? v : null;
  if (p.type === "string") return typeof v === "string" ? v : null;
  if (p.type === "bytes") return isHex(v) ? v.toLowerCase() : null;
  const fixed = /^bytes(\d+)$/.exec(p.type);
  if (fixed !== null) return isHex(v) && v.length === 2 + 2 * Number(fixed[1]) ? v.toLowerCase() : null;
  const range = intRange(p.type);
  if (range !== null) {
    let n: bigint | null = null;
    if (typeof v === "bigint") n = v;
    else if (typeof v === "number" && Number.isSafeInteger(v)) n = BigInt(v);
    else if (typeof v === "string" && /^-?\d+$/.test(v)) n = BigInt(v);
    return n !== null && n >= range.min && n <= range.max ? n : null;
  }
  return null;
}

function sameNorm(a: Norm, b: Norm): boolean {
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((x, i) => sameNorm(x, b[i]!));
  }
  return a === b;
}

const showNorm = (n: Norm): string =>
  Array.isArray(n) ? `[${n.map(showNorm).join(", ")}]` : typeof n === "bigint" ? n.toString() : String(n);

/** A constraint read against its parameter, or why it cannot be. */
function readRule(p: AbiParameter, c: unknown, where: string, depth: number): Rule | string {
  if (depth > MAX_DEPTH) return `${where} nests deeper than ${MAX_DEPTH} levels`;
  if (!isPlain(c)) return `${where} is not a constraint object`;
  const s = snapshot(c);
  if (typeof s === "string") return `${where}: ${s}`;
  if (s.symbols > 0) return `${where} has a symbol key, which no rule reads`;
  const keys = [...s.props.keys()].sort().join(",");
  const get = (k: string) => s.props.get(k);
  switch (keys) {
    case "eq": {
      const v = normalize(p, get("eq"));
      return v === null ? `${where}.eq is not a value of type ${p.type}` : { k: "eq", v };
    }
    case "oneOf": {
      const list = get("oneOf");
      if (!Array.isArray(list) || list.length === 0) return `${where}.oneOf must be a non-empty array`;
      const v: Norm[] = [];
      for (const item of list) {
        const n = normalize(p, item);
        if (n === null) return `${where}.oneOf holds a value that is not of type ${p.type}`;
        v.push(n);
      }
      return { k: "oneOf", v };
    }
    case "gte":
    case "lte":
    case "gte,lte": {
      const range = intRange(p.type);
      if (range === null) return `${where} bounds a ${p.type}, which is not an integer`;
      const read = (k: string): bigint | null | string => {
        if (!s.props.has(k)) return null;
        const n = normalize(p, get(k));
        return typeof n === "bigint" ? n : `${where}.${k} is not a ${p.type}`;
      };
      const lte = read("lte");
      const gte = read("gte");
      if (typeof lte === "string") return lte;
      if (typeof gte === "string") return gte;
      if (lte !== null && gte !== null && gte > lte) return `${where} allows nothing: gte is above lte`;
      return { k: "range", r: { lte, gte } };
    }
    case "any":
      return get("any") === true ? { k: "any" } : `${where}.any must be exactly true`;
    case "tuple": {
      const parts = componentsOf(p);
      const list = get("tuple");
      if (parts === null) return `${where} is a tuple rule on a ${p.type}`;
      if (!Array.isArray(list) || list.length !== parts.length) {
        return `${where}.tuple must hold one constraint per component (${parts.length})`;
      }
      const rules: Rule[] = [];
      for (let i = 0; i < parts.length; i++) {
        const r = readRule(parts[i]!, list[i], `${where}, component ${i + 1}`, depth + 1);
        if (typeof r === "string") return r;
        rules.push(r);
      }
      return { k: "tuple", parts: rules };
    }
    case "items": {
      const arr = arrayOf(p);
      const list = get("items");
      if (arr === null) return `${where} is an items rule on a ${p.type}`;
      if (!Array.isArray(list)) return `${where}.items must be an array`;
      if (arr.length !== null && list.length !== arr.length) return `${where}.items must hold ${arr.length} constraints`;
      const rules: Rule[] = [];
      for (let i = 0; i < list.length; i++) {
        const r = readRule(arr.element, list[i], `${where}, item ${i + 1}`, depth + 1);
        if (typeof r === "string") return r;
        rules.push(r);
      }
      return { k: "items", parts: rules };
    }
    case "abi,args": {
      if (p.type !== "bytes") return `${where} decodes a ${p.type}; only bytes can hold encoded values`;
      const abi = get("abi");
      const list = get("args");
      let params: readonly AbiParameter[];
      try {
        if (typeof abi !== "string") throw new Error("not a string");
        params = parseAbiParameters(abi) as readonly AbiParameter[];
      } catch {
        return `${where}.abi is not a list of ABI types`;
      }
      if (!Array.isArray(list) || list.length !== params.length) {
        return `${where}.args must hold one constraint per decoded value (${params.length})`;
      }
      const rules: Rule[] = [];
      for (let i = 0; i < params.length; i++) {
        const r = readRule(params[i]!, list[i], `${where}, decoded value ${i + 1}`, depth + 1);
        if (typeof r === "string") return r;
        rules.push(r);
      }
      return { k: "abi", params, parts: rules };
    }
    default:
      return `${where} must be exactly one of { eq }, { oneOf }, { lte, gte }, { any: true }, { tuple }, { items } or { abi, args }`;
  }
}

/** The function a signature names; null when it names none. */
function functionOf(signature: unknown): AbiFunction | null {
  if (typeof signature !== "string") return null;
  const text = signature.trim().replace(/^function\s+/, "");
  try {
    const item = parseAbiItem(`function ${text}`) as unknown;
    if (typeof item !== "object" || item === null || (item as AbiFunction).type !== "function") return null;
    return item as AbiFunction;
  } catch {
    return null;
  }
}

/** Read the caller's intent once, or say why it cannot be read. Never throws. */
function readIntent(intent: unknown): ReadIntent | string {
  if (!isPlain(intent)) return "the intent is not a plain object";
  const s = snapshot(intent);
  if (typeof s === "string") return `the intent: ${s}`;
  if (s.symbols > 0) return "the intent has a symbol key, which no rule reads";
  const kind = s.props.get("kind");
  if (typeof kind !== "string" || !(kind in INTENT_KEYS)) {
    return "the intent's kind is not native.transfer, erc20.transfer, erc20.approve or call";
  }
  const k = kind as TxIntent["kind"];
  const unknown = [...s.props.keys()].filter((key) => !INTENT_KEYS[k].includes(key) || FORBIDDEN_KEYS.has(key));
  if (unknown.length > 0) return `the intent has keys no rule reads: ${unknown.join(", ").slice(0, 120)}`;
  const chainId = chainOf(s.props.get("chainId"));
  if (chainId === null) return "the intent's chainId is not a positive integer";
  const base = { kind: k, chainId, recipients: null, amount: null, spender: null, allowance: null, fn: null, selector: null, rules: null, unlimited: false };

  if (k === "native.transfer") {
    const to = intentAddressOf(s.props.get("to"));
    if (to === null) return "the intent's to is not an address";
    const amount = readBound(s.props.get("amount"), "the intent's amount");
    if (typeof amount === "string") return amount;
    return { ...base, target: to, recipients: new Set([to]), amount, value: amount };
  }

  const token = intentAddressOf(s.props.get("token"));
  if (k === "erc20.transfer") {
    if (token === null) return "the intent's token is not an address";
    const raw = s.props.get("to");
    const list = Array.isArray(raw) ? raw : [raw];
    const recipients = new Set<string>();
    for (const r of list) {
      const a = intentAddressOf(r);
      if (a === null) return "the intent's to is not an address or a list of them";
      recipients.add(a);
    }
    if (recipients.size === 0) return "the intent's to lists no recipient";
    const amount = readBound(s.props.get("amount"), "the intent's amount");
    if (typeof amount === "string") return amount;
    return { ...base, target: token, recipients, amount, value: { lte: 0n, gte: 0n } };
  }

  if (k === "erc20.approve") {
    if (token === null) return "the intent's token is not an address";
    const spender = intentAddressOf(s.props.get("spender"));
    if (spender === null) return "the intent's spender is not an address";
    const raw = s.props.get("amount");
    const allowance = raw === "unlimited" ? "unlimited" : amountOf(raw);
    if (allowance === null || (typeof allowance === "bigint" && allowance > MAX_UINT256)) {
      return 'the intent\'s amount is not a non-negative integer or "unlimited"';
    }
    return { ...base, target: token, spender, allowance, value: { lte: 0n, gte: 0n } };
  }

  // call
  const target = intentAddressOf(s.props.get("target"));
  if (target === null) return "the intent's target is not an address";
  const fn = functionOf(s.props.get("signature"));
  if (fn === null) return "the intent's signature is not a function signature";
  const args = s.props.get("args");
  if (!Array.isArray(args) || args.length !== fn.inputs.length) {
    return `the intent's args must hold one constraint per argument (${fn.inputs.length})`;
  }
  const rules: Rule[] = [];
  for (let i = 0; i < fn.inputs.length; i++) {
    const r = readRule(fn.inputs[i]!, args[i], `argument ${i + 1}`, 0);
    if (typeof r === "string") return `the intent's ${r}`;
    rules.push(r);
  }
  const value = s.props.has("value") ? readBound(s.props.get("value"), "the intent's value") : { lte: 0n, gte: 0n };
  if (typeof value === "string") return value;
  const unlimited = s.props.get("unlimited");
  if (s.props.has("unlimited") && unlimited !== true) return "the intent's unlimited must be exactly true when present";
  return { ...base, target, fn, selector: toFunctionSelector(fn).toLowerCase(), rules, value, unlimited: unlimited === true };
}

// --- the transaction, read ----------------------------------------------------

/** Fields the check reads and holds the transaction to. */
const CHECKED_FIELDS = new Set([
  "to", "data", "input", "value", "chainId", "chain", "type",
  "authorizationList", "blobs", "blobVersionedHashes", "sidecars", "kzg", "maxFeePerBlobGas", "dataSuffix",
]);

/**
 * Fields that belong to the signer, which neither move funds nor change the
 * call: who signs, the nonce, gas and fees, and the access list. They pass to
 * the signer unchecked. Anything outside both lists abstains: a field this
 * check does not model can change what is signed (zkSync's customData carries
 * a paymaster that pulls tokens for fees, viem's dataSuffix appends bytes).
 */
const SIGNER_FIELDS = new Set([
  "from", "account", "nonce", "gas", "gasLimit", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas",
  "accessList", "assertChainId", "nonceManager", "blockTag", "enableCcipRead",
]);

/** A transaction as read once. */
export interface ReadTransaction {
  readonly to: string;
  readonly data: string;
  readonly value: bigint;
  /** The chain the transaction itself names (chainId, or viem's chain.id); null when it names none. */
  readonly chainId: bigint | null;
  /** What was read, for the signer: the checked fields in the form checked, the signer's fields as they were. */
  readonly fields: ReadonlyMap<string, unknown>;
}

const absent = (v: unknown) => v === undefined || v === null;

/** A value field: bigint, safe integer, decimal or 0x-hex string, or an ethers v5 BigNumber. */
function valueOf(v: unknown): bigint | null {
  if (absent(v)) return 0n;
  if (typeof v === "bigint") return v >= 0n ? v : null;
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v === "string") return /^(\d+|0x[0-9a-fA-F]+)$/.test(v) ? BigInt(v) : null;
  // An ethers v5 BigNumber is a frozen class instance holding its value as hex.
  if (typeof v === "object" && !Array.isArray(v)) {
    const s = snapshot(v as object);
    if (typeof s === "string" || s.props.get("_isBigNumber") !== true) return null;
    const hex = s.props.get("_hex");
    return typeof hex === "string" && /^0x[0-9a-fA-F]+$/.test(hex) ? BigInt(hex) : null;
  }
  return null;
}

function dataOf(v: unknown): string | null {
  if (absent(v)) return "0x";
  if (isHex(v)) return v.toLowerCase();
  if (v instanceof Uint8Array) return `0x${Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("")}`;
  return null;
}

/** The transactions this module read, so a check given one does not read the caller's object again. */
const readOnce = new WeakSet<object>();

/**
 * Read a transaction once: what a signer would read from it, or the findings
 * that refuse or abstain on it. A guard reads first, asks for the intent, and
 * hands the reading to `checkTransaction`, so the caller's object is read
 * exactly once.
 */
export function readTransaction(tx: unknown): ReadTransaction | Finding[] {
  if (typeof tx === "object" && tx !== null && readOnce.has(tx)) return tx as ReadTransaction;
  const unreadable = (message: string): Finding[] => [{ code: "X402-709", severity: "high", message }];
  if (!isPlain(tx)) return unreadable("the transaction is not a plain object, so what a signer reads from it cannot be told");
  const s = snapshot(tx);
  if (typeof s === "string") return unreadable(`the transaction cannot be read: ${s}`);
  const p = s.props;
  const unknown = [...p.keys()].filter((k) => !CHECKED_FIELDS.has(k) && !SIGNER_FIELDS.has(k));
  if (unknown.length > 0) {
    return unreadable(`the transaction carries fields this check does not model: ${unknown.join(", ").slice(0, 160)}`);
  }
  const findings: Finding[] = [];

  // Standing authority over the account itself: an EIP-7702 delegation.
  const auth = p.get("authorizationList");
  const type = p.get("type");
  const typeName = typeof type === "string" ? type.toLowerCase() : type;
  if (!(absent(auth) || (Array.isArray(auth) && auth.length === 0)) || [4, 4n, "0x4", "eip7702"].includes(typeName as never)) {
    findings.push({
      code: "X402-705",
      severity: "critical",
      message: "the transaction delegates the account's code (EIP-7702), standing authority no intent here grants",
    });
  }
  if (!(absent(type) || [0, 1, 2, 0n, 1n, 2n, "0x0", "0x1", "0x2", "legacy", "eip2930", "eip1559", 4, 4n, "0x4", "eip7702"].includes(typeName as never))) {
    findings.push(...unreadable("the transaction's type is not legacy, EIP-2930 or EIP-1559"));
  }
  for (const k of ["blobs", "blobVersionedHashes", "sidecars", "kzg", "maxFeePerBlobGas"]) {
    if (!absent(p.get(k))) {
      findings.push(...unreadable("the transaction carries blobs, which this check does not model"));
      break;
    }
  }
  const suffix = p.get("dataSuffix");
  if (!(absent(suffix) || suffix === "" || suffix === "0x")) {
    findings.push(...unreadable("the transaction carries a dataSuffix, bytes the signer appends after the checked calldata"));
  }

  const rawTo = p.get("to");
  let to = "";
  if (absent(rawTo)) {
    findings.push({
      code: "X402-701",
      severity: "critical",
      message: "the transaction names no recipient, so it would create a contract",
    });
  } else {
    const a = addressOf(rawTo);
    if (a === null) {
      findings.push(...unreadable("the transaction's to is not an address, such as a name the signer would resolve"));
    } else to = a;
  }
  const data = dataOf(p.get("data"));
  if (data === null) findings.push(...unreadable("the transaction's data is not hex bytes"));
  if (p.has("input") && !absent(p.get("input")) && dataOf(p.get("input")) !== (data ?? "0x")) {
    findings.push(...unreadable("the transaction's input differs from its data, so which one is sent cannot be told"));
  }
  const value = valueOf(p.get("value"));
  if (value === null) findings.push(...unreadable("the transaction's value is not a non-negative integer"));

  let chainId: bigint | null = null;
  const rawChain = p.get("chainId");
  if (!absent(rawChain)) {
    chainId = chainOf(rawChain);
    if (chainId === null) findings.push(...unreadable("the transaction's chainId is not a chain id"));
  }
  const chain = p.get("chain");
  let chainCopy: unknown = chain;
  if (!absent(chain)) {
    const c = isPlain(chain) ? snapshot(chain) : "not a plain object";
    const id = typeof c === "string" ? null : chainOf(c.props.get("id"));
    if (typeof c === "string" || id === null) {
      findings.push(...unreadable("the transaction's chain has no readable id"));
    } else if (chainId !== null && id !== chainId) {
      findings.push({
        code: "X402-701",
        severity: "critical",
        message: "the transaction's chainId and its chain name different chains",
        expected: chainId.toString(),
        actual: id.toString(),
      });
    } else {
      chainId = id;
      // The signer gets the chain as read, not the caller's object read again.
      chainCopy = Object.fromEntries(c.props);
    }
  }
  if (findings.length > 0) return findings;

  const fields = new Map<string, unknown>();
  for (const [k, v] of p) {
    if (SIGNER_FIELDS.has(k)) fields.set(k, v);
  }
  fields.set("to", rawTo);
  fields.set("data", data);
  fields.set("value", value);
  if (!absent(chain)) fields.set("chain", chainCopy);
  if (!absent(type)) fields.set("type", type);
  const out: ReadTransaction = Object.freeze({ to, data: data!, value: value!, chainId, fields });
  readOnce.add(out);
  return out;
}

// --- standing authority and wrappers -------------------------------------------

/**
 * Calls whose effect outlives the transaction. `exact` lists the arguments that
 * define the grant (who, what, how much), which the intent must fix with
 * `{ eq }`; every other argument except a signature must at least be bounded.
 * `unlimited(args)` says whether this call grants without limit.
 */
interface Standing {
  readonly exact: readonly number[];
  readonly free: readonly number[];
  readonly unlimited: (args: readonly unknown[]) => boolean;
}

const isMax = (bits: bigint) => (v: unknown) => {
  try {
    return BigInt(v as bigint) === (1n << bits) - 1n;
  } catch {
    return false;
  }
};

const STANDING_CALLS: readonly (readonly [string, Standing])[] = [
  ["approve(address,uint256)", { exact: [0, 1], free: [], unlimited: (a) => isMax(256n)(a[1]) }],
  ["increaseAllowance(address,uint256)", { exact: [0, 1], free: [], unlimited: (a) => isMax(256n)(a[1]) }],
  ["setApprovalForAll(address,bool)", { exact: [0, 1], free: [], unlimited: (a) => a[1] === true }],
  ["setOperator(address,bool)", { exact: [0, 1], free: [], unlimited: (a) => a[1] === true }],
  ["approve(address,uint256,uint256)", { exact: [0, 1, 2], free: [], unlimited: (a) => isMax(256n)(a[2]) }],
  ["transferOwnership(address)", { exact: [0], free: [], unlimited: () => false }],
  ["setAuthorization(address,bool)", { exact: [0, 1], free: [], unlimited: (a) => a[1] === true }],
  // EIP-2612: owner, spender, value; the deadline bounded; v, r, s the signature.
  ["permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", { exact: [0, 1, 2], free: [4, 5, 6], unlimited: (a) => isMax(256n)(a[2]) }],
  // DAI's permit: holder, spender, allowed; nonce and expiry bounded.
  ["permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)", { exact: [0, 1, 4], free: [5, 6, 7], unlimited: (a) => a[4] === true }],
  // Permit2: token, spender, amount; the expiration bounded.
  ["approve(address,address,uint160,uint48)", { exact: [0, 1, 2], free: [], unlimited: (a) => isMax(160n)(a[2]) }],
  ["permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)", { exact: [0, 1], free: [2], unlimited: () => false }],
  ["permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)", { exact: [0, 1], free: [2], unlimited: () => false }],
  ["setAuthorizationWithSig((address,address,bool,uint256,uint256),(uint8,bytes32,bytes32))", { exact: [0], free: [1], unlimited: (a) => Array.isArray(a[0]) ? a[0][2] === true : (a[0] as { isAuthorized?: unknown } | undefined)?.isAuthorized === true }],
];
const STANDING = new Map(STANDING_CALLS.map(([sig, s]) => [toFunctionSelector(`function ${sig}`).toLowerCase(), s]));

/**
 * Calls that carry other calls: a multicall, a router's or an account's
 * execute, a Safe transaction, a bundler's handleOps. Their inner calls are
 * readable only when the intent fixes the bytes they travel in; an inner call
 * left `any` abstains. `operation` is the argument that chooses call or
 * delegatecall, which must be fixed to a call.
 */
const WRAPPER_CALLS: readonly (readonly [string, number | null])[] = [
  ["multicall(bytes[])", null],
  ["multicall(uint256,bytes[])", null],
  ["multicall(bytes32,bytes[])", null],
  ["aggregate((address,bytes)[])", null],
  ["tryAggregate(bool,(address,bytes)[])", null],
  ["blockAndAggregate((address,bytes)[])", null],
  ["tryBlockAndAggregate(bool,(address,bytes)[])", null],
  ["aggregate3((address,bool,bytes)[])", null],
  ["aggregate3Value((address,bool,uint256,bytes)[])", null],
  ["execute(bytes,bytes[],uint256)", null],
  ["execute(bytes,bytes[])", null],
  ["execute(address,uint256,bytes)", null],
  ["execute(address,uint256,bytes,uint8)", 3],
  ["executeBatch((address,uint256,bytes)[])", null],
  ["executeBatch(address[],uint256[],bytes[])", null],
  ["executeBatch(address[],bytes[])", null],
  ["execute(bytes32,bytes)", null],
  ["executeFromExecutor(bytes32,bytes)", null],
  ["execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)", 3],
  ["execTransactionFromModule(address,uint256,bytes,uint8)", 3],
  ["execTransactionFromModuleReturnData(address,uint256,bytes,uint8)", 3],
  ["multiSend(bytes)", null],
  ["handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)", null],
  ["handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],address)", null],
];
const WRAPPERS = new Map(WRAPPER_CALLS.map(([sig, operation]) => [toFunctionSelector(`function ${sig}`).toLowerCase(), { operation }]));

/** Is this rule exact all the way down: eq, or structure made only of eq? */
function exact(r: Rule): boolean {
  if (r.k === "eq") return true;
  if (r.k === "tuple" || r.k === "items" || r.k === "abi") return r.parts.every(exact);
  return false;
}

/** Does this rule leave a bytes value, the shape an inner call travels in, unchecked? */
function leavesBytesOpen(p: AbiParameter, r: Rule): boolean {
  if (r.k === "any") return holdsBytes(p);
  if (r.k === "tuple") {
    const parts = componentsOf(p)!;
    return r.parts.some((x, i) => leavesBytesOpen(parts[i]!, x));
  }
  if (r.k === "items") {
    const element = arrayOf(p)!.element;
    return r.parts.some((x) => leavesBytesOpen(element, x));
  }
  if (r.k === "abi") return r.parts.some((x, i) => leavesBytesOpen(r.params[i]!, x));
  return false;
}

// --- matching -------------------------------------------------------------------

interface Match {
  readonly broken: string[];
  readonly unreadable: string[];
}

const show = (v: unknown): string => {
  if (typeof v === "bigint") return v.toString();
  try {
    return JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x)).slice(0, 120);
  } catch {
    return String(v).slice(0, 120);
  }
};

function inRange(n: bigint, r: Range): boolean {
  return (r.lte === null || n <= r.lte) && (r.gte === null || n >= r.gte);
}

const showRange = (r: Range): string =>
  r.lte !== null && r.lte === r.gte ? r.lte.toString() : [r.gte !== null ? `>= ${r.gte}` : "", r.lte !== null ? `<= ${r.lte}` : ""].filter(Boolean).join(" and ");

/** Hold one decoded value to its rule, collecting what breaks it and what cannot be read. */
function match(p: AbiParameter, r: Rule, v: unknown, where: string, out: Match, depth = 0): void {
  if (depth > MAX_DEPTH) {
    out.unreadable.push(`${where} nests deeper than ${MAX_DEPTH} levels`);
    return;
  }
  switch (r.k) {
    case "any":
      return;
    case "eq":
    case "oneOf": {
      const n = normalize(p, v);
      const allowed = r.k === "eq" ? [r.v] : r.v;
      if (n === null || !allowed.some((a) => sameNorm(a, n))) {
        out.broken.push(`${where} is ${n === null ? show(v) : showNorm(n)}, expected ${allowed.map(showNorm).join(" or ").slice(0, 300)}`);
      }
      return;
    }
    case "range": {
      const n = normalize(p, v);
      if (typeof n !== "bigint" || !inRange(n, r.r)) {
        out.broken.push(`${where} is ${n === null ? show(v) : showNorm(n)}, expected ${showRange(r.r)}`);
      }
      return;
    }
    case "tuple": {
      const parts = componentsOf(p)!;
      const values = Array.isArray(v) ? v : parts.map((c) => (v as Record<string, unknown>)[c.name ?? ""]);
      r.parts.forEach((x, i) => match(parts[i]!, x, values[i], `${where}, component ${i + 1}`, out, depth + 1));
      return;
    }
    case "items": {
      const element = arrayOf(p)!.element;
      if (!Array.isArray(v) || v.length !== r.parts.length) {
        out.broken.push(`${where} holds ${Array.isArray(v) ? v.length : "no"} items, expected ${r.parts.length}`);
        return;
      }
      r.parts.forEach((x, i) => match(element, x, v[i], `${where}, item ${i + 1}`, out, depth + 1));
      return;
    }
    case "abi": {
      const decoded = decodeCanonical(r.params, v, where);
      if (typeof decoded === "string") {
        out.unreadable.push(decoded);
        return;
      }
      r.parts.forEach((x, i) => match(r.params[i]!, x, decoded[i], `${where}, decoded value ${i + 1}`, out, depth + 1));
      return;
    }
  }
}

/**
 * Decode bytes with these types, and require that they re-encode to the same
 * bytes. A lenient decode reads trailing bytes, dirty padding and pointed-into
 * offsets as if they were clean; the contract reading them may not.
 */
function decodeCanonical(params: readonly AbiParameter[], bytes: unknown, where: string): readonly unknown[] | string {
  if (!isHex(bytes)) return `${where} is not hex bytes`;
  try {
    const values = decodeAbiParameters(params, bytes as `0x${string}`) as readonly unknown[];
    const again = encodeAbiParameters(params, values as unknown[]);
    if (again.toLowerCase() !== bytes.toLowerCase()) {
      return `${where} is not the canonical encoding of its values (trailing or non-zero padding bytes), so a contract may read it differently`;
    }
    return values;
  } catch {
    return `${where} does not decode as ${params.map((x) => x.type).join(", ")}`;
  }
}

// --- the check ------------------------------------------------------------------

/** A token or native movement this check can read, for the spending policy. */
export interface Movement {
  /** The token contract, or NATIVE_ASSET. Lowercase. */
  readonly asset: string;
  /** Who receives it, or who may pull it (an approval's spender). Lowercase. */
  readonly payTo: string;
  readonly amount: bigint;
}

/** What the guard needs beyond the verdict: the intent's chain, the movements, the transaction as read. */
export interface TransactionCheck {
  readonly verdict: Verdict;
  readonly chainId: bigint | null;
  readonly movements: readonly Movement[];
  readonly tx: ReadTransaction | null;
}

/** Which arguments are the asset, the payee and the amount: the called contract is the asset unless named. */
type Pick = (to: string, args: readonly unknown[]) => readonly [unknown, unknown, unknown];
const TOKEN_CALLS: readonly (readonly [string, Pick])[] = [
  ["transfer(address,uint256)", (to, a) => [to, a[0], a[1]]],
  ["transferFrom(address,address,uint256)", (to, a) => [to, a[1], a[2]]],
  ["approve(address,uint256)", (to, a) => [to, a[0], a[1]]],
  ["increaseAllowance(address,uint256)", (to, a) => [to, a[0], a[1]]],
  // Permit2: the token is an argument, not the contract called.
  ["approve(address,address,uint160,uint48)", (_to, a) => [a[0], a[1], a[2]]],
  ["transferFrom(address,address,uint160,address)", (_to, a) => [a[3], a[1], a[2]]],
];
const TOKEN_MOVES = new Map(
  TOKEN_CALLS.map(([sig, pick]) => [
    toFunctionSelector(`function ${sig}`).toLowerCase(),
    (to: string, args: readonly unknown[]): Movement | null => {
      const [asset, payTo, amount] = pick(to, args);
      const a = addressOf(asset);
      const b = addressOf(payTo);
      try {
        return a === null || b === null ? null : { asset: a, payTo: b, amount: BigInt(amount as bigint) };
      } catch {
        return null;
      }
    },
  ]),
);

/**
 * Check a transaction against the intent, and say what it moves. The guard's
 * entry point; `inspectTransaction` returns the verdict alone. `tx` is the
 * caller's transaction or a `readTransaction` reading of it.
 */
export function checkTransaction(intent: unknown, tx: unknown, opts: InspectTransactionOptions = {}): TransactionCheck {
  const none = (verdict: Verdict, chainId: bigint | null = null): TransactionCheck => ({ verdict, chainId, movements: [], tx: null });
  const read = readIntent(intent);
  if (typeof read === "string") {
    return none({
      decision: "abstain",
      reason: read,
      findings: [{ code: "X402-707", severity: "high", message: `the intent cannot be read: ${read}` }],
    });
  }
  let policy: ReadPolicy | null = null;
  try {
    const p = readPolicyOption(opts, (a) => intentAddressOf(a));
    if (typeof p === "string") {
      return none({ decision: "abstain", reason: `${p} — refusing to report the transaction as checked against it`, findings: [] }, read.chainId);
    }
    policy = p;
  } catch {
    return none({ decision: "abstain", reason: "the options cannot be read", findings: [] }, read.chainId);
  }

  const t = readTransaction(tx);
  if (Array.isArray(t)) return verdictOf(t, read.chainId, [], null);
  const findings: Finding[] = [];
  const unreadable = (message: string) => findings.push({ code: "X402-709", severity: "high", message });

  if (t.chainId !== null && t.chainId !== read.chainId) {
    findings.push({
      code: "X402-701",
      severity: "critical",
      message: "the transaction is for another chain than the intent's",
      expected: read.chainId.toString(),
      actual: t.chainId.toString(),
    });
  }
  if (t.to !== read.target) {
    findings.push({
      code: "X402-701",
      severity: "critical",
      message: read.kind === "native.transfer" ? "the transaction pays another recipient than the intent's" : "the transaction calls another contract than the intent's",
      expected: read.target,
      actual: t.to,
    });
  }
  if (!inRange(t.value, read.value)) {
    findings.push({
      code: "X402-704",
      severity: "critical",
      message: "the transaction's native value is not what the intent allows",
      expected: showRange(read.value),
      actual: t.value.toString(),
    });
  }

  const movements: Movement[] = [];
  if (t.value > 0n) movements.push({ asset: NATIVE_ASSET, payTo: t.to, amount: t.value });

  if (read.kind === "native.transfer") {
    if (t.data !== "0x") {
      findings.push({
        code: "X402-702",
        severity: "critical",
        message: "the transaction carries calldata; the intent is a plain native transfer",
        actual: `${t.data.slice(0, 10)}…`,
      });
    }
  } else {
    // Every other kind is one function call, decoded with its signature.
    const fn =
      read.kind === "call"
        ? read.fn!
        : (parseAbiItem(read.kind === "erc20.transfer" ? "function transfer(address,uint256)" : "function approve(address,uint256)") as AbiFunction);
    const selector = read.selector ?? toFunctionSelector(fn).toLowerCase();
    let args: readonly unknown[] | null = null;
    if (t.data.slice(0, 10) !== selector) {
      findings.push({
        code: "X402-702",
        severity: "critical",
        message: "the transaction calls another function than the intent's",
        expected: selector,
        actual: t.data.length >= 10 ? t.data.slice(0, 10) : "no function selector",
      });
    } else {
      try {
        const d = decodeFunctionData({ abi: [fn], data: t.data as `0x${string}` });
        const again = encodeFunctionData({ abi: [fn], functionName: fn.name, args: (d.args ?? []) as unknown[] });
        if (again.toLowerCase() !== t.data) {
          unreadable("the calldata is not the canonical encoding of its arguments (trailing or non-zero padding bytes), so the contract may read it differently from this check");
        } else args = (d.args ?? []) as readonly unknown[];
      } catch {
        unreadable(`the calldata does not decode as ${fn.name}(${fn.inputs.map((x) => x.type).join(",")})`);
      }
    }

    if (args !== null) {
      const m: Match = { broken: [], unreadable: [] };
      if (read.kind === "erc20.transfer") {
        const to = addressOf(args[0]);
        if (to === null || !read.recipients!.has(to)) {
          m.broken.push(`recipient is ${show(args[0])}, expected ${[...read.recipients!].join(" or ").slice(0, 300)}`);
        }
        if (!inRange(args[1] as bigint, read.amount!)) m.broken.push(`amount is ${show(args[1])}, expected ${showRange(read.amount!)}`);
      } else if (read.kind === "erc20.approve") {
        const spender = addressOf(args[0]);
        if (spender !== read.spender) {
          findings.push({
            code: "X402-705",
            severity: "critical",
            message: "the approval names another spender than the intent's, standing authority the intent does not grant",
            expected: read.spender!,
            actual: show(args[0]),
          });
        }
        if (read.allowance !== "unlimited" && args[1] !== read.allowance) {
          findings.push({
            code: "X402-705",
            severity: "critical",
            message: "the approval grants another allowance than the intent's exact amount",
            expected: read.allowance!.toString(),
            actual: show(args[1]),
          });
        }
      } else {
        fn.inputs.forEach((p, i) => match(p, read.rules![i]!, args![i], `argument ${i + 1} (${p.type})`, m));
        // Standing authority: the grant's terms exact, the rest bounded, unlimited only by name.
        const standing = STANDING.get(selector);
        if (standing !== undefined) {
          const loose = standing.exact.filter((i) => !exact(read.rules![i]!));
          const open = read.rules!.map((r, i) => (r.k === "any" && !standing.exact.includes(i) && !standing.free.includes(i) ? i : -1)).filter((i) => i >= 0);
          if (loose.length > 0 || open.length > 0) {
            findings.push({
              code: "X402-705",
              severity: "critical",
              message: `the call grants standing authority, which an intent allows only with its terms exact (${[...loose, ...open].map((i) => `argument ${i + 1}`).join(", ")} ${loose.length > 0 ? "must be { eq }" : "must be bounded"})`,
            });
          }
          if (standing.unlimited(args) && !read.unlimited) {
            findings.push({
              code: "X402-705",
              severity: "critical",
              message: "the call grants unlimited standing authority, which an intent allows only with unlimited: true",
            });
          }
        }
        // A wrapper's inner calls: readable only when the intent fixes the bytes they travel in.
        const wrapper = WRAPPERS.get(selector);
        if (wrapper !== undefined) {
          if (fn.inputs.some((p, i) => leavesBytesOpen(p, read.rules![i]!))) {
            unreadable("the call carries other calls in bytes the intent leaves open, so what it does cannot be read");
          }
          if (wrapper.operation !== null && !exact(read.rules![wrapper.operation]!)) {
            unreadable("the call can choose a delegatecall, and the intent does not fix its operation");
          } else if (wrapper.operation !== null && args[wrapper.operation] !== 0 && args[wrapper.operation] !== 0n) {
            unreadable("the call is a delegatecall, which runs another contract's code as the caller");
          }
        }
      }
      for (const b of m.broken) {
        findings.push({ code: "X402-703", severity: "critical", message: `the call's ${b}` });
      }
      for (const u of m.unreadable) unreadable(`the call's ${u}`);
      const move = TOKEN_MOVES.get(selector)?.(t.to, args);
      if (move) movements.push(move);
    }
  }

  if (policy !== null) {
    for (const move of movements) {
      for (const f of checkSpendPolicy(policy, move)) {
        findings.push({
          code: "X402-706",
          severity: "critical",
          message: `the spending policy refuses a movement in this transaction (${f.code}): ${f.message}`,
          expected: f.expected,
          actual: f.actual ?? `${move.amount} of ${move.asset} to ${move.payTo}`,
        });
      }
    }
  }
  return verdictOf(findings, read.chainId, movements, t);
}

function verdictOf(findings: Finding[], chainId: bigint | null, movements: readonly Movement[], tx: ReadTransaction | null): TransactionCheck {
  if (findings.some((f) => f.severity === "critical")) {
    return { verdict: { decision: "refuse", findings }, chainId, movements, tx };
  }
  const unread = findings.find((f) => f.code === "X402-709");
  if (unread !== undefined) {
    return { verdict: { decision: "abstain", findings, reason: unread.message }, chainId, movements, tx };
  }
  return { verdict: { decision: "allow", findings }, chainId, movements, tx };
}

/**
 * Check a transaction against what the agent meant to do, before it is
 * signed or sent. Offline and synchronous.
 *
 * `allow` means the transaction is the intended call in every part the intent
 * names. `refuse` names what differs. `abstain` means part of it cannot be
 * read, which a guard treats as a refusal.
 */
export function inspectTransaction(intent: TxIntent, tx: unknown, opts: InspectTransactionOptions = {}): Verdict {
  return checkTransaction(intent, tx, opts).verdict;
}

// --- presets --------------------------------------------------------------------

const boundRule = (b: Bound): Constraint => {
  if (typeof b === "object" && b !== null) return b as Constraint;
  return { eq: b };
};

/** The upper end of a bound, or null when it has none. */
function upper(b: Bound): Amount | null {
  if (typeof b !== "object" || b === null) return b;
  if ("eq" in b) return b.eq;
  return "lte" in b && b.lte !== undefined ? b.lte : null;
}

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

/**
 * Intents for calls agents make often, so an agent writes what it means
 * rather than a raw signature. Each returns a `call` intent; nothing here
 * reads the chain, so every address is the caller's.
 */
export const presets = {
  morpho: {
    /**
     * Morpho Blue's `borrow` of `assets` (in the loan token's base units),
     * share amount 0, from the exact market, on behalf of and paid to the
     * accounts named. `morpho` is the Morpho Blue contract on that chain.
     */
    borrow(p: {
      chainId: number | bigint;
      morpho: string;
      market: { loanToken: string; collateralToken: string; oracle: string; irm: string; lltv: Amount };
      assets: Bound;
      onBehalf: string;
      receiver: string;
    }): TxIntent {
      return {
        kind: "call",
        chainId: p.chainId,
        target: p.morpho,
        signature: "borrow((address,address,address,address,uint256),uint256,uint256,address,address)",
        args: [
          { tuple: [{ eq: p.market.loanToken }, { eq: p.market.collateralToken }, { eq: p.market.oracle }, { eq: p.market.irm }, { eq: p.market.lltv }] },
          boundRule(p.assets),
          { eq: 0 },
          { eq: p.onBehalf },
          { eq: p.receiver },
        ],
      };
    },
  },
  uniswapV4: {
    /**
     * One exact-input swap through a Uniswap UniversalRouter: `execute` with
     * the V4_SWAP command, whose actions are SWAP_EXACT_IN_SINGLE, SETTLE_ALL
     * and TAKE_ALL, so the output is taken by the caller.
     *
     * `fields` is the router's ExactInputSingleParams: 6 for routers built from
     * v4-periphery with per-hop slippage (`minHopPriceX36`, March 2026), which
     * includes both routers on Robinhood Chain; 5 for earlier ones. A wrong
     * count reads as unreadable calldata, never as a different swap.
     *
     * `amountIn` needs an upper bound, the most SETTLE_ALL may take; with the
     * native coin as input it must be exact, and the value sent equals it, so
     * nothing is left in the router for anyone to sweep. `deadline` bounds the
     * router's deadline, the time a signed swap stays valid.
     */
    swapExactInSingle(p: {
      chainId: number | bigint;
      router: string;
      fields: 5 | 6;
      poolKey: { currency0: string; currency1: string; fee: number | bigint; tickSpacing: number | bigint; hooks: string };
      zeroForOne: boolean;
      amountIn: Bound;
      minAmountOut: Amount;
      deadline: Bound;
      hookData?: string;
      minHopPriceX36?: Bound;
    }): TxIntent {
      if (p.fields !== 5 && p.fields !== 6) throw new TypeError("presets.uniswapV4.swapExactInSingle: fields must be 5 or 6");
      const most = upper(p.amountIn);
      if (most === null) throw new TypeError("presets.uniswapV4.swapExactInSingle: amountIn needs an upper bound");
      const currencyIn = p.zeroForOne ? p.poolKey.currency0 : p.poolKey.currency1;
      const currencyOut = p.zeroForOne ? p.poolKey.currency1 : p.poolKey.currency0;
      const nativeIn = intentAddressOf(currencyIn) === ZERO_ADDRESS;
      const exactIn = typeof p.amountIn !== "object" || p.amountIn === null || "eq" in p.amountIn;
      if (nativeIn && !exactIn) {
        throw new TypeError("presets.uniswapV4.swapExactInSingle: with the native coin as input, amountIn must be exact");
      }
      const key = { tuple: [{ eq: p.poolKey.currency0 }, { eq: p.poolKey.currency1 }, { eq: p.poolKey.fee }, { eq: p.poolKey.tickSpacing }, { eq: p.poolKey.hooks }] };
      const swap =
        p.fields === 6
          ? { abi: "((address,address,uint24,int24,address),bool,uint128,uint128,uint256,bytes)", args: [{ tuple: [key, { eq: p.zeroForOne }, boundRule(p.amountIn), { gte: p.minAmountOut }, p.minHopPriceX36 === undefined ? { any: true } : boundRule(p.minHopPriceX36), { eq: p.hookData ?? "0x" }] }] }
          : { abi: "((address,address,uint24,int24,address),bool,uint128,uint128,bytes)", args: [{ tuple: [key, { eq: p.zeroForOne }, boundRule(p.amountIn), { gte: p.minAmountOut }, { eq: p.hookData ?? "0x" }] }] };
      return {
        kind: "call",
        chainId: p.chainId,
        target: p.router,
        signature: "execute(bytes,bytes[],uint256)",
        args: [
          { eq: "0x10" },
          {
            items: [
              {
                abi: "bytes, bytes[]",
                args: [
                  { eq: "0x060c0f" },
                  {
                    items: [
                      swap as Constraint,
                      { abi: "address, uint256", args: [{ eq: currencyIn }, { lte: most }] },
                      { abi: "address, uint256", args: [{ eq: currencyOut }, { gte: p.minAmountOut }] },
                    ],
                  },
                ],
              },
            ],
          },
          boundRule(p.deadline),
        ],
        value: nativeIn ? { eq: most } : 0,
      };
    },
  },
  permit2: {
    /**
     * Permit2's `approve`: `spender` may pull up to `amount` of `token` through
     * Permit2 until `expiration`. Standing authority, so the amount is exact.
     */
    approve(p: {
      chainId: number | bigint;
      token: string;
      spender: string;
      amount: Amount;
      expiration: Bound;
      permit2?: string;
    }): TxIntent {
      return {
        kind: "call",
        chainId: p.chainId,
        target: p.permit2 ?? PERMIT2,
        signature: "approve(address,address,uint160,uint48)",
        args: [{ eq: p.token }, { eq: p.spender }, { eq: p.amount }, boundRule(p.expiration)],
      };
    },
  },
} as const;
