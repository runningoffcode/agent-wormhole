"""Address provenance — WHERE a wallet address entered the agent's context.

The question this ledger answers is the one every disclosed agent wallet-drain
shares: the agent read text that named an attacker's address, was persuaded,
and signed a payment to it. The address travelled untrusted-prose -> model
output -> transaction, every time. No amount of persuasion changes the FACT of
where an address first appeared, and unlike the text around it, the address
itself cannot be paraphrased -- it has to appear byte-exact to be useful to
the attacker. So provenance is checkable arithmetic where content rules are an
arms race.

Three origins, in trust order:

    operator   the human said "this address is mine/known" (CLI)
    quote      a structured payTo field in an x402 402 body -- the merchant's
               own machine-readable ask, the channel conformance verifies
    read       any other address-shaped token in text the agent read

An address whose ONLY origin is `read` is tainted: nothing legitimate
introduced it. The payment guard (wormhole-x402 >= 0.5.3) surfaces that as
X402-301 at the signing checkpoint.

THE LEDGER IS A LOCAL FILE, LIKE EVERYTHING ELSE HERE. Append-only JSONL at
~/.wormhole/addresses.jsonl, written by the readguard hook as reads happen,
read by the TypeScript guard at signing time. Nothing is transmitted, ever.
An entry is {address, source, via, ts} -- the address and where it came from,
nothing about what surrounded it.

RECORDING MUST NEVER BREAK THE HOOK. Every write path is wrapped by the
caller; a full disk or an unreadable ledger degrades to "no provenance
recorded", never to a failed read hook standing between the agent and its
tool output.

FALSE-POSITIVE POSTURE. Base58 matching is deliberately strict (length 32-44
AND decodes to exactly 32 bytes), but transaction hashes and mints share that
shape, so the ledger over-records rather than under-records. That is the safe
direction: an extra `read` entry only ever matters if a payment is later made
TO that exact value -- which is precisely the event worth flagging.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

# --- shapes ------------------------------------------------------------------

EVM_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
# Base58, Solana alphabet, pubkey-plausible length. Verified by decode below.
B58_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _b58_byte_len(token: str) -> int | None:
    """Decoded byte length of a base58 token, or None if not base58."""
    n = 0
    for ch in token:
        d = _B58_INDEX.get(ch)
        if d is None:
            return None
        n = n * 58 + d
    length = (n.bit_length() + 7) // 8 if n else 0
    # Leading '1's encode leading zero bytes.
    for ch in token:
        if ch != "1":
            break
        length += 1
    return length


def extract_addresses(text: str) -> set[str]:
    """Every address-shaped token in `text`.

    EVM addresses are lowercased (case is only a checksum); Solana pubkeys are
    kept verbatim (base58 is case-significant) and must decode to exactly 32
    bytes -- which drops 64-byte signatures and most look-alikes.
    """
    out: set[str] = set()
    for m in EVM_RE.finditer(text):
        out.add(m.group(0).lower())
    for m in B58_RE.finditer(text):
        if _b58_byte_len(m.group(0)) == 32:
            out.add(m.group(0))
    return out


def quote_payees(text: str) -> set[str]:
    """payTo values from an x402-shaped JSON body, if `text` is one.

    A 402 response the agent reads is itself tool output, so without this the
    ledger would taint every legitimate merchant: their payTo appears in prose
    the moment the quote is read. A payTo delivered in the STRUCTURED field of
    a 402 body is the channel conformance verifies -- it earns `quote`, not
    `read`. Only exact `payTo` keys count; an address in a description does
    not become trusted by being near one.
    """
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return set()
    out: set[str] = set()

    def walk(node: object, depth: int = 0) -> None:
        if depth > 6:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "payTo" and isinstance(v, str):
                    for a in extract_addresses(v):
                        out.add(a)
                else:
                    walk(v, depth + 1)
        elif isinstance(node, list):
            for v in node:
                walk(v, depth + 1)

    # Only x402-shaped documents get the exemption at all.
    if isinstance(doc, dict) and ("accepts" in doc or "payTo" in doc):
        walk(doc)
    return out


# --- the ledger --------------------------------------------------------------

def ledger_path() -> Path:
    override = os.environ.get("WORMHOLE_ADDRESS_LEDGER")
    if override:
        return Path(override)
    return Path.home() / ".wormhole" / "addresses.jsonl"


_MAX_LEDGER_BYTES = 5 * 1024 * 1024
_KEEP_LINES_ON_TRIM = 20_000


def _existing_pairs(path: Path) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                    pairs.add((str(e.get("address")), str(e.get("source"))))
                except ValueError:
                    continue
    except OSError:
        pass
    return pairs


def record(addresses: set[str], source: str, via: str,
           path: Path | None = None) -> int:
    """Append (address, source) pairs not already in the ledger.

    Returns how many entries were written. Deduplication is per (address,
    source): the same address arriving as `read` a hundred times is one line,
    but the same address later arriving in a quote adds its `quote` line --
    the upgrade is the point.
    """
    if not addresses:
        return 0
    if source not in ("read", "quote", "operator"):
        raise ValueError(f"unknown source: {source}")
    p = path or ledger_path()
    p.parent.mkdir(parents=True, exist_ok=True)

    seen = _existing_pairs(p)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    wrote = 0
    with p.open("a", encoding="utf-8") as fh:
        for a in sorted(addresses):
            if (a, source) in seen:
                continue
            fh.write(json.dumps(
                {"address": a, "source": source, "via": via, "ts": now},
                separators=(",", ":")) + "\n")
            wrote += 1

    try:
        if p.stat().st_size > _MAX_LEDGER_BYTES:
            lines = p.read_text(encoding="utf-8",
                                errors="replace").splitlines(keepends=True)
            p.write_text("".join(lines[-_KEEP_LINES_ON_TRIM:]),
                         encoding="utf-8")
    except OSError:
        pass
    return wrote


def record_from_text(text: str, via: str, path: Path | None = None) -> int:
    """What the readguard hook calls: quote payees as `quote`, the rest `read`."""
    payees = quote_payees(text)
    everything = extract_addresses(text)
    wrote = record(payees, "quote", via, path=path)
    wrote += record(everything - payees, "read", via, path=path)
    return wrote


def classify(path: Path | None = None) -> dict[str, set[str]]:
    """The ledger folded down: which addresses have which origins."""
    p = path or ledger_path()
    sources: dict[str, set[str]] = {}
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                a, s = str(e.get("address", "")), str(e.get("source", ""))
                if a and s in ("read", "quote", "operator"):
                    sources.setdefault(a, set()).add(s)
    except OSError:
        pass
    trusted = {a for a, s in sources.items() if s & {"quote", "operator"}}
    tainted = {a for a, s in sources.items() if s == {"read"}}
    return {"trusted": trusted, "tainted": tainted}


# --- CLI ---------------------------------------------------------------------

def run(args, out=None) -> int:
    """`wormhole addresses [trust <address>]`."""
    import sys
    out = out or sys.stdout
    path = Path(args.ledger) if getattr(args, "ledger", None) else ledger_path()

    if getattr(args, "trust", None):
        addr = args.trust.strip()
        found = extract_addresses(addr)
        if not found:
            print(f"not an address shape: {addr}", file=out)
            return 2
        record(found, "operator", "cli:addresses trust", path=path)
        print(f"recorded as operator-trusted: {', '.join(sorted(found))}",
              file=out)
        return 0

    kinds = classify(path=path)
    print(f"ledger: {path}", file=out)
    print(f"  trusted (quote/operator origin): {len(kinds['trusted'])}",
          file=out)
    print(f"  read-only origin (tainted):      {len(kinds['tainted'])}",
          file=out)
    for a in sorted(kinds["tainted"])[:20]:
        print(f"    {a}", file=out)
    if len(kinds["tainted"]) > 20:
        print(f"    ... and {len(kinds['tainted']) - 20} more", file=out)
    print("  a payment to a tainted address is flagged X402-301 at the "
          "signing checkpoint", file=out)
    return 0
