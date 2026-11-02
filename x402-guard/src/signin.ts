/**
 * Sign-in requests bound to the site the agent contacted (0.10.0).
 *
 * ═══ THE ATTACK ═══
 *
 * V12's third critical x402 SDK finding (2026-10-22): the client's
 * Sign-In-With-X wrapper copied `domain` and `uri` from a server's 402 response
 * into a login message and signed it, without comparing them with the site the
 * client had contacted. A server could fetch a fresh login challenge from
 * another site in its own session, hand it to the agent, and log in there as
 * the agent's wallet. The target's own checks pass: the message names it and
 * carries a genuine signature. The missing check belongs on the signer.
 *
 * ═══ WHERE THIS RUNS ═══
 *
 * The guarded signers refuse message signing by default, which blocks the
 * relay along with every honest login. An application that allows message
 * signing to use Sign-In-With-X gets this check instead of a pass-through:
 * the same rule x402's own fix adopted (its SIWx spec and PRs #3133, #3192,
 * #3193) — the request must name the site the agent contacted, by its domain
 * and by its URI. A message that is not a sign-in request is untouched.
 *
 * ═══ FAIL CLOSED ON ANYTHING THAT LOOKS LIKE ONE ═══
 *
 * Recognition is deliberately wider than parsing. Text that carries the
 * EIP-4361 / CAIP-122 header phrase — after folding Unicode lookalikes and
 * removing invisible characters — or the `URI:` and `Nonce:` fields of one, is
 * a sign-in request; it must then parse strictly, with exactly one header and
 * exactly one URI, or it is refused. A message a lenient verifier might accept
 * as a login and this parser cannot read is the bypass, so it is refused
 * rather than waved through. A login in some other format entirely is not
 * recognised: keep message signing off unless the application needs it.
 *
 * ═══ THE SIGNER SIGNS WHAT WAS CHECKED ═══
 *
 * A message is read once, the way the signer reads it, and the signer is
 * handed that reading rather than the caller's argument (AW-67's rule for
 * transactions, applied to messages). An argument two signers would read
 * differently is refused. An earlier version of this file read the `raw` of
 * `{ message, raw }` while viem signed its `message`.
 *
 * No imports beyond a type: both lanes use it.
 */
import type { PolicyFinding } from "./policy.js";

export interface SignInVerdict {
  decision: "allow" | "refuse";
  /** Whether the message is a sign-in request at all. One that is not is allowed as before. */
  signIn: boolean;
  findings: PolicyFinding[];
  reason?: string;
}

/** The site the agent contacted: an origin or URL, or a function read at signing time. */
export type OriginSource =
  | string
  | URL
  | (() => string | URL | null | undefined)
  | null
  | undefined;

const PHRASE = "wants you to sign in with your";
const HEADER =
  /^(?:([a-zA-Z][a-zA-Z0-9+.-]*):\/\/)?([^\s/?#]+) wants you to sign in with your ([^\n]+?) account:$/;
const AUTHORITY = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?$/;

/** Folded for recognition only: lookalikes to their plain form, invisible characters out, spaces collapsed. */
function fold(text: string): string {
  return text
    .normalize("NFKC")
    .replace(/[\p{Cf}\p{Zl}\p{Zp}]/gu, (c) => (c === " " || c === " " ? "\n" : ""))
    .replace(/[^\S\n]+/g, " ")
    .toLowerCase();
}

/**
 * Line breaks other than `\n`, CRLF included. Some verifiers split lines on
 * them (Python's `splitlines`, a multiline JavaScript regex), so a URI line
 * behind one is a line this parser never sees and theirs does. The siwe
 * library and the Wallet Standard's parser both refuse CRLF, so a login
 * written with it is no login they accept (AWG-010-13).
 */
const OTHER_LINE_BREAK = /[\r\v\f\x1c-\x1e\x85\u2028\u2029]/;
/** Any line break at all, for the fields a wallet writes into a message of its own. */
const ANY_LINE_BREAK = /[\r\n\v\f\x1c-\x1e\x85\u2028\u2029]/;

/** The site to bind to, as a URL, from the caller's source or a quote's resource. */
export function resolveOrigin(source: OriginSource, fallback?: unknown): URL | null {
  let v: unknown = source;
  try {
    if (typeof v === "function") v = (v as () => unknown)();
  } catch {
    return null;
  }
  if (v === undefined || v === null || v === "") v = fallback;
  if (v instanceof URL) v = v.href;
  if (typeof v !== "string") return null;
  try {
    const u = new URL(v.trim());
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    if (u.username !== "" || u.password !== "") return null;
    return u;
  } catch {
    return null;
  }
}

const decode = (bytes: Uint8Array): string => new TextDecoder("utf-8", { fatal: false }).decode(bytes);

function hexBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array((hex.length - 2) / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 + i * 2, 4 + i * 2), 16);
  return bytes;
}

/** viem's SignableMessage — a string, or `{ raw }` as hex or bytes — and bare bytes, read once. */
function signable(m: unknown): { text: string; value: unknown } | null {
  if (typeof m === "string") return { text: m, value: m };
  if (m instanceof Uint8Array) {
    const copy = new Uint8Array(m);
    return { text: decode(copy), value: copy };
  }
  if (typeof m === "object" && m !== null && !Array.isArray(m)) {
    const raw = (m as Record<string, unknown>)["raw"];
    if (raw instanceof Uint8Array) {
      const copy = new Uint8Array(raw);
      return { text: decode(copy), value: { raw: copy } };
    }
    if (typeof raw === "string" && /^0x([0-9a-fA-F]{2})*$/.test(raw)) {
      return { text: decode(hexBytes(raw)), value: { raw } };
    }
  }
  return null;
}

/**
 * A message as an EVM signer receives it, read once: its text, and the
 * argument to hand the signer in place of the caller's.
 *
 * ethers signs a string or bytes; viem signs `message`, a string or `{ raw }`.
 * The argument handed on is built from this one read — a copy of any bytes, a
 * fresh object — so a getter or a shared buffer cannot show the check one
 * message and the signer another. `message` beside a top-level `raw` is not
 * read at all (AWG-010-01): viem signs the one, a signer that reads `raw`
 * would sign the other, and the guard does not get to pick.
 */
export function readSignerMessage(arg: unknown): { text: string; arg: unknown } | null {
  try {
    if (typeof arg !== "object" || arg === null || arg instanceof Uint8Array) {
      const m = signable(arg);
      return m === null ? null : { text: m.text, arg: m.value };
    }
    if (Array.isArray(arg)) return null;
    const o = arg as Record<string, unknown>;
    if (!("message" in o) || "raw" in o) return null;
    // One pass over the caller's object reads each own enumerable property
    // once, `message` included, so no getter runs twice (AWG-010-08). A
    // `message` the pass does not copy, because it is inherited or not
    // enumerable, is read once on its own.
    const copy: Record<string, unknown> = { ...o };
    const m = signable(Object.prototype.hasOwnProperty.call(copy, "message") ? copy["message"] : o["message"]);
    return m === null ? null : { text: m.text, arg: { ...copy, message: m.value } };
  } catch {
    // A getter that throws, a revoked proxy: not a message this guard read.
    return null;
  }
}

function refuse(code: "X402-601" | "X402-602", message: string, reason: string, extra: Partial<PolicyFinding> = {}): SignInVerdict {
  return { decision: "refuse", signIn: true, findings: [{ code, severity: "critical", message, ...extra }], reason };
}

const NO_ORIGIN = (): SignInVerdict =>
  refuse(
    "X402-602",
    "a sign-in request reached the signer with no known site to bind it to — the guard cannot tell a login for the site the agent contacted from one relayed for another",
    "pass `origin`, the site the agent contacted, to sign in through this guard",
  );

/** Is this text a sign-in request? Wider than the parser, on purpose. */
export function isSignInText(text: string): boolean {
  const f = fold(text);
  if (f.includes(PHRASE)) return true;
  const lines = f.split("\n");
  return lines.some((l) => /^\s*uri\s*:/.test(l)) && lines.some((l) => /^\s*nonce\s*:/.test(l));
}

/** The host a header or input authority names, read as a URL of the given scheme: lowercase, default port dropped. */
function hostOf(authority: string, protocol: string): string | null {
  try {
    return new URL(`${protocol}//${authority}`).host;
  } catch {
    return null;
  }
}

const UNREADABLE = (): SignInVerdict =>
  refuse(
    "X402-602",
    "the message handed to the signer could not be read as text — or reads as two different messages — so whether it is a sign-in request cannot be told",
    "an unreadable message is refused rather than signed unread",
  );

/**
 * Check one message a signer is about to sign. Not a sign-in request: allow, as
 * before. A sign-in request: refused unless it parses strictly and names the
 * site the agent contacted by its domain, its URI and any scheme it states.
 */
export function inspectSignIn(message: unknown, origin: OriginSource, fallback?: unknown): SignInVerdict {
  return checkSignerMessage(message, origin, fallback).verdict;
}

/**
 * inspectSignIn for a guard: the verdict, and the argument to hand the signer —
 * the copy the verdict was reached on, never the caller's own object.
 */
export function checkSignerMessage(
  message: unknown,
  origin: OriginSource,
  fallback?: unknown,
): { verdict: SignInVerdict; arg: unknown } {
  const read = readSignerMessage(message);
  if (read === null) return { verdict: UNREADABLE(), arg: message };
  return { verdict: inspectSignInText(read.text, origin, fallback), arg: read.arg };
}

/**
 * Messages whose signature serves as a credential (0.11.0): a fixed line that
 * names no site, such as an Orbio wallet key, the signature of `Orbio API key
 * · chain 4663 · epoch 0`. Such a line is signed only while the agent is
 * talking to the site that issues it, over https, that site or a subdomain of
 * it. Recognised after folding, like a sign-in header, and wider than the exact
 * line on purpose.
 */
const CREDENTIAL_LINES: readonly { readonly name: string; readonly phrase: string; readonly site: string }[] = [
  { name: "an Orbio wallet key", phrase: "orbio api key", site: "orbio.so" },
];

/** The check on a message's text. */
export function inspectSignInText(text: string, origin: OriginSource, fallback?: unknown): SignInVerdict {
  const folded = fold(text);
  const credential = CREDENTIAL_LINES.find((c) => folded.includes(c.phrase));
  if (credential !== undefined) {
    const site = resolveOrigin(origin, fallback);
    const what = `the message is ${credential.name}, a signature that works as a credential wherever it is shown`;
    if (site === null) {
      return refuse("X402-602", `${what}, and no site is known to bind it to`, "pass `origin`, the site the agent contacted, to sign it through this guard");
    }
    const host = site.hostname.toLowerCase();
    if (site.protocol !== "https:" || (host !== credential.site && !host.endsWith(`.${credential.site}`))) {
      return refuse("X402-601", `${what}, and the agent is talking to another site`, `${credential.name} belongs to ${credential.site}, not ${site.host}`, {
        expected: credential.site,
        actual: `${site.protocol}//${site.host}`,
      });
    }
    // Bound to its site; a sign-in request carrying it is still held to its own.
  }
  if (!isSignInText(text)) return { decision: "allow", signIn: credential !== undefined, findings: [] };

  const site = resolveOrigin(origin, fallback);
  if (site === null) return NO_ORIGIN();

  const malformed = (why: string): SignInVerdict =>
    refuse(
      "X402-602",
      `the message reads as a sign-in request and does not parse as one (${why}), so the site it would log into cannot be checked`,
      why,
    );

  if (OTHER_LINE_BREAK.test(text)) return malformed("a line break other than \\n");
  const lines = text.split("\n");
  if (fold(text).split(PHRASE).length - 1 !== 1) return malformed("not exactly one sign-in header");
  const header = HEADER.exec(lines[0] ?? "");
  if (header === null) return malformed("the first line is not the sign-in header");
  const scheme = header[1];
  const domain = header[2] ?? "";
  if (!AUTHORITY.test(domain)) return malformed("the domain is not a plain host[:port]");

  const uriLike = lines.filter((l) => /^\s*uri\s*:/i.test(fold(l)));
  const uriLines = lines.filter((l) => /^URI: \S+$/.test(l));
  if (uriLike.length !== 1 || uriLines.length !== 1) return malformed("not exactly one URI line");
  let uri: URL;
  try {
    uri = new URL((uriLines[0] as string).slice(5));
  } catch {
    return malformed("the URI does not parse");
  }
  if (uri.username !== "" || uri.password !== "") return malformed("the URI carries credentials");

  // Compared as origins (AWG-010-06): `data.example:443` under https is the
  // site `https://data.example`, and refusing it refused an honest login. The
  // header's authority is read under its own scheme when it states one, the
  // site's when it does not.
  const wanted = site.host;
  const mismatch = (what: string, actual: string): SignInVerdict =>
    refuse(
      "X402-601",
      `the sign-in request's ${what} names a site other than the one the agent contacted — a login relayed for another site is the session takeover V12 reported`,
      `${what} ${actual} is not ${wanted}`,
      { expected: wanted, actual },
    );
  const protocol = scheme === undefined ? site.protocol : `${scheme.toLowerCase()}:`;
  const domainHost = hostOf(domain, protocol);
  if (domainHost !== wanted) return mismatch("domain", domainHost ?? domain.toLowerCase());
  if (uri.host !== wanted || uri.protocol !== site.protocol) {
    return mismatch("URI", `${uri.protocol}//${uri.host}`);
  }
  if (protocol !== site.protocol) return mismatch("scheme", protocol.slice(0, -1));
  return { decision: "allow", signIn: true, findings: [] };
}

/** The fields a wallet writes as text into the message it builds from a signIn input. */
const SIGN_IN_TEXT_FIELDS = [
  "domain",
  "address",
  "statement",
  "uri",
  "version",
  "chainId",
  "nonce",
  "issuedAt",
  "expirationTime",
  "notBefore",
  "requestId",
] as const;

/**
 * A Wallet Standard `signIn` input, read once into a plain copy — the copy a
 * guard checks and hands the wallet, so a getter cannot name one site to the
 * check and another to the wallet. Null when it is not an object.
 */
export function readSignInInput(input: unknown): Record<string, unknown> | null {
  try {
    if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
    // fromEntries defines own properties, so a "__proto__" key stays a key.
    return Object.fromEntries(
      Object.entries(input).map(([k, v]) => [k, Array.isArray(v) ? [...v] : v]),
    );
  } catch {
    return null;
  }
}

/**
 * Check a Wallet Standard `signIn` input (Sign-In-With-Solana). The input IS a
 * sign-in request, so it must name the site the agent contacted: a missing
 * domain is refused, because the wallet would then fill in one of its own
 * choosing, and an agent's wallet has no page whose origin that would be.
 */
export function inspectSignInInput(input: unknown, origin: OriginSource, fallback?: unknown): SignInVerdict {
  const i = readSignInInput(input);
  if (i === null) {
    return refuse("X402-602", "the signIn input is not an object, so the site it would log into cannot be checked", "unreadable signIn input");
  }
  const site = resolveOrigin(origin, fallback);
  if (site === null) return NO_ORIGIN();
  const wanted = site.host;
  // Every field the wallet writes into its message must be text as given. A
  // wallet converts anything else to text itself, and an array or an object
  // with a toString of its own can come out as any lines it likes: a nested
  // statement became a URI line the check never read (AWG-010-09).
  for (const field of SIGN_IN_TEXT_FIELDS) {
    if (i[field] !== undefined && typeof i[field] !== "string") {
      return refuse(
        "X402-602",
        `the signIn input's ${field} is not text, so what the wallet would write for it cannot be checked`,
        "non-text signIn field",
      );
    }
  }
  const resources = i["resources"];
  if (resources !== undefined && (!Array.isArray(resources) || resources.some((r) => typeof r !== "string"))) {
    return refuse(
      "X402-602",
      "the signIn input's resources is not a list of text, so what the wallet would write for it cannot be checked",
      "non-text signIn field",
    );
  }
  // The wallet writes these fields into a message of its own, one per line; a
  // line break in any of them writes a line the wallet did not mean to (a
  // second URI, a second header), and no field of a sign-in request has one.
  for (const v of Object.values(i)) {
    const parts = Array.isArray(v) ? v : [v];
    if (parts.some((p) => typeof p === "string" && ANY_LINE_BREAK.test(p))) {
      return refuse(
        "X402-602",
        "a field of the signIn input carries a line break, which would write a line of its own into the message the wallet builds",
        "line break in a signIn field",
      );
    }
  }
  const domain = i["domain"];
  if (typeof domain !== "string" || domain === "") {
    return refuse(
      "X402-602",
      "the signIn input names no domain, so the wallet would choose the site it logs into — refused rather than signed for a site nobody named",
      "signIn without a domain",
    );
  }
  if (!AUTHORITY.test(domain)) {
    return refuse("X402-602", "the signIn input's domain is not a plain host[:port]", "malformed signIn domain");
  }
  const domainHost = hostOf(domain, site.protocol);
  if (domainHost !== wanted) {
    const actual = domainHost ?? domain.toLowerCase();
    return refuse(
      "X402-601",
      "the signIn input's domain names a site other than the one the agent contacted — a login relayed for another site is the session takeover V12 reported",
      `domain ${actual} is not ${wanted}`,
      { expected: wanted, actual },
    );
  }
  if (i["uri"] !== undefined) {
    let uri: URL;
    try {
      if (typeof i["uri"] !== "string") throw new TypeError("not a string");
      uri = new URL(i["uri"]);
    } catch {
      return refuse("X402-602", "the signIn input's uri is not a URL", "malformed signIn uri");
    }
    if (uri.username !== "" || uri.password !== "") {
      return refuse("X402-602", "the signIn input's uri carries credentials", "malformed signIn uri");
    }
    if (uri.host !== wanted || uri.protocol !== site.protocol) {
      const actual = `${uri.protocol}//${uri.host}`;
      return refuse(
        "X402-601",
        "the signIn input's uri names a site other than the one the agent contacted",
        `uri ${actual} is not ${site.protocol}//${wanted}`,
        { expected: wanted, actual },
      );
    }
  }
  return { decision: "allow", signIn: true, findings: [] };
}
