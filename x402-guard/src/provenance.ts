// src/provenance.ts
/**
 * Address provenance at the signing checkpoint — the join between the two
 * sensors this project uniquely runs.
 *
 * THE QUESTION. Every disclosed agent wallet-drain has the same shape: the
 * agent read text that named an attacker's address, was persuaded, and paid
 * it. The persuasion is unbounded and unscannable in the limit; the ADDRESS
 * is not — it must appear byte-exact to be useful, and where it first entered
 * the agent's context is a fact. The readguard hook (wormhole-guard, Python)
 * records that fact into a local JSONL ledger as reads happen; this module
 * reads the ledger at signing time and answers: is this payee an address
 * whose ONLY known origin is untrusted prose?
 *
 * X402-301, HIGH, ADVISORY BY DESIGN (for now). A provenance hit does not
 * flip a conformance allow to refuse: the quoted payment still matches its
 * quote, and this module cannot know whether the operator genuinely intends a
 * new merchant. What it knows is that nothing legitimate introduced the
 * address — no quote's structured payTo field, no operator trust action — so
 * the finding says exactly that and the operator (or their policy layer)
 * decides. Advisory first is the same discipline every guard here shipped
 * with: a wrong blocking rule stops the user's agent mid-task; a wrong
 * advisory costs a glance.
 *
 * PURITY, PRESERVED. `checkPayeeProvenance` is a pure function of its inputs;
 * the filesystem read lives in `loadAddressLedger`, which the TRANSPORT calls
 * (the MCP server, a signer wrapper) — never the verdict core. `verify()`
 * remains a pure function of its request.
 */

export interface AddressProvenance {
  /** Addresses with at least one quote/operator origin. */
  trusted: ReadonlySet<string>;
  /** Addresses whose ONLY origin is untrusted read text. */
  tainted: ReadonlySet<string>;
}

import { createRequire } from "node:module";
import type { Finding } from "./index.js";

/**
 * Fold ledger JSONL into origin sets. Malformed lines are skipped — the
 * ledger is written append-only by a hook that must never block, so a torn
 * final line is an expected state, not an error.
 */
export function parseAddressLedger(jsonl: string): AddressProvenance {
  const sources = new Map<string, Set<string>>();
  for (const line of jsonl.split("\n")) {
    const t = line.trim();
    if (t.length === 0) continue;
    let e: unknown;
    try {
      e = JSON.parse(t);
    } catch {
      continue;
    }
    if (e === null || typeof e !== "object") continue;
    const { address, source } = e as { address?: unknown; source?: unknown };
    if (typeof address !== "string" || typeof source !== "string") continue;
    if (source !== "read" && source !== "quote" && source !== "operator") continue;
    const key = normalizeAddress(address);
    const set = sources.get(key) ?? new Set<string>();
    set.add(source);
    sources.set(key, set);
  }
  const trusted = new Set<string>();
  const tainted = new Set<string>();
  for (const [addr, s] of sources) {
    if (s.has("quote") || s.has("operator")) trusted.add(addr);
    else tainted.add(addr);
  }
  return { trusted, tainted };
}

/** EVM addresses compare case-insensitively; base58 is case-significant. */
function normalizeAddress(a: string): string {
  return /^0x[0-9a-fA-F]{40}$/.test(a) ? a.toLowerCase() : a;
}

/**
 * The check. Non-null exactly when the payee's only known origin is `read`.
 * An address the ledger has never seen returns null — absence of provenance
 * is not evidence of taint, and a ledger that was never populated must not
 * flag every payment.
 */
export function checkPayeeProvenance(
  payTo: string,
  prov: AddressProvenance,
): Finding | null {
  const key = normalizeAddress(payTo);
  if (!prov.tainted.has(key) || prov.trusted.has(key)) return null;
  return {
    code: "X402-301",
    severity: "high",
    message:
      "the payee's only known origin is untrusted text the agent read — no " +
      "quote's structured payTo field and no operator trust action ever " +
      "introduced this address. Verify the merchant out-of-band before paying " +
      "(`wormhole addresses trust <address>` records a deliberate decision)",
    actual: payTo,
  };
}

/**
 * Transport-side loader. Reads the ledger the Python hook writes; a missing
 * or unreadable file is an EMPTY provenance, never an error — the check
 * degrades to silence exactly like an unpopulated ledger.
 */
export function loadAddressLedger(path?: string): AddressProvenance {
  const empty: AddressProvenance = { trusted: new Set(), tainted: new Set() };
  try {
    // createRequire, lazily — importing this module performs no filesystem
    // access; only calling the loader does.
    const require = createRequire(import.meta.url);
    const { readFileSync } = require("node:fs") as typeof import("node:fs");
    const { homedir } = require("node:os") as typeof import("node:os");
    const { join } = require("node:path") as typeof import("node:path");
    const p =
      path ??
      process.env.WORMHOLE_ADDRESS_LEDGER ??
      join(homedir(), ".wormhole", "addresses.jsonl");
    return parseAddressLedger(readFileSync(p, "utf8"));
  } catch {
    return empty;
  }
}
