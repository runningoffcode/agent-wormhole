"""Cheapest-first detection cascade. No LLM anywhere on this path.

  stage 0  carrier extraction        (ingest/, program-ID + shape filter)
  stage 1  text-ness gate            (UTF-8, printable run, entropy band)
  stage 2  normalize + EXISTING corpus (NFKC, strip invisibles, fold, decode)
  stage 3  adjudication queue        (human triage; nothing auto-published)

Stage 2 does NOT reimplement detection. It produces normalized VARIANTS of the
carrier text and hands each to wormhole.rules.injection.scan_text.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

# ---------------------------------------------------------------- stage 1 ---

# Solana memo payload cap for single-byte UTF-8 in an unsigned instruction.
MEMO_MAX_BYTES = 566

MIN_PRINTABLE_RUN = 24

# Shannon entropy band. Below ~1.5 bits/char is degenerate padding; above ~5.2
# is compressed/encrypted/random and cannot be a human-readable instruction.
# Encoded payloads sit high, so the band is applied to the DECODED variant, not
# used to discard a carrier outright.
ENTROPY_MIN = 1.5
ENTROPY_MAX = 5.2

# The run class must mean "sustained human-readable text". Two exclusions are
# deliberate:
#   U+FFFD  the replacement character. Memo bytes are read with
#           errors="replace", so undecodable binary arrives as a LONG run of
#           U+FFFD. Counting it as printable let a random blob score a 34-char
#           "printable run" and sail through the gate -- the exact opposite of
#           what stage 1 is for.
#   C1      U+0080-U+009F control codes, never legitimate memo text.
# Everything else in the BMP stays in: real memos carry CJK, Cyrillic, emoji.
_PRINTABLE_RUN = re.compile(
    "[ -~\u00a0-\ufffc\ufffe\uffff]{%d,}" % MIN_PRINTABLE_RUN
)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def longest_printable_run(text: str) -> int:
    best = 0
    for m in _PRINTABLE_RUN.finditer(text):
        best = max(best, len(m.group(0)))
    return best


@dataclass
class GateResult:
    passed: bool
    reason: str
    printable_run: int
    entropy: float


def textness_gate(text: str) -> GateResult:
    """Stage 1. Cheap reject of non-text carriers before any normalization.

    The gate exists to discard binary/random blobs, NOT to discard short or
    deliberately-hidden text. Two carve-outs are load-bearing, both found by a
    positive control that regressed when they were missing:

      1. Invisible-character carriers bypass the printable-run test. A pure
         Unicode-tag-block payload has a printable run of ZERO -- the entire
         instruction is invisible -- so a naive run test rejects the attack
         precisely BECAUSE it is well hidden, which is exactly backwards.
      2. The printable-run floor is only applied to text long enough for it to
         mean anything. `invoice #4417` with smuggled zero-width characters is
         16 chars total and can never reach a 24-char run, yet it is a real
         carrier that WORM-005 must see.

    Anything carrying invisibles goes through regardless of length; stage 2
    strips them and rescans, and the raw variant still yields WORM-005/006.
    """
    if not text:
        return GateResult(False, "empty", 0, 0.0)
    run = longest_printable_run(text)
    ent = shannon_entropy(text)

    # Carve-out 1+2: hidden-character carriers are always worth scanning.
    if _ZERO_WIDTH.search(text) or _UNICODE_TAGS.search(text):
        return GateResult(True, "pass:invisible-carrier", run, ent)

    # Carve-out 2: only demand a long printable run from text long enough to
    # have one. Short memos are judged on printable RATIO instead.
    if len(text) < MIN_PRINTABLE_RUN:
        if _printable_ratio(text) < MIN_DECODE_PRINTABLE_RATIO:
            return GateResult(False, "short_and_unprintable", run, ent)
        return GateResult(True, "pass:short-text", run, ent)

    if run < MIN_PRINTABLE_RUN:
        return GateResult(False, f"printable_run<{MIN_PRINTABLE_RUN}", run, ent)
    if ent < ENTROPY_MIN:
        return GateResult(False, "entropy_below_band", run, ent)
    # High entropy is NOT a reject here: it is the signature of an encoded
    # payload, which stage 2 exists to decode.
    return GateResult(True, "pass", run, ent)


# ---------------------------------------------------------------- stage 2 ---

ZERO_WIDTH_CHARS = "​‌‍⁠﻿"
_ZERO_WIDTH = re.compile(f"[{ZERO_WIDTH_CHARS}]")
_UNICODE_TAGS = re.compile(r"[\U000e0000-\U000e007f]")

# Deliberately conservative confusables table. NFKC does NOT fold Cyrillic to
# Latin (they are distinct characters, not compatibility variants), so an
# explicit table is required -- and every entry here is a chance to manufacture
# a false positive, so the fold is applied ONLY to predominantly-Latin runs and
# any finding seen solely in the folded variant is flagged for adjudication.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j", "һ": "h",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "Х": "X", "Т": "T", "М": "M", "Н": "H", "К": "K",
    "Β": "B", "Α": "A", "Ο": "O", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ρ": "P", "Τ": "T", "Χ": "X", "ο": "o", "α": "a",
    "Ѕ": "S", "ѕ": "s", "І": "I", "ӏ": "l",
}

_CYRILLIC_GREEK = re.compile(r"[Ͱ-ϿЀ-ӿ]")
_LATIN = re.compile(r"[A-Za-z]")

# An attacker controls on-chain text, so they can prepend the local package's
# own inline-suppression directive to silence a rule. On an untrusted feed that
# is an evasion, not a courtesy: neutralize it and record that it was present.
_SUPPRESSION = re.compile(r"wormhole:\s*ignore", re.IGNORECASE)

_B64 = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
_HEX = re.compile(r"(?:0x)?[0-9a-fA-F]{32,}")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")

MAX_DECODE_DEPTH = 3
MAX_DECODE_BYTES = 64 * 1024
MIN_DECODE_PRINTABLE_RATIO = 0.85


def strip_invisibles(text: str) -> str:
    return _UNICODE_TAGS.sub("", _ZERO_WIDTH.sub("", text))


def neutralize_suppression(text: str) -> tuple[str, bool]:
    """Defang an attacker-supplied `wormhole:ignore` directive."""
    if not _SUPPRESSION.search(text):
        return text, False
    return _SUPPRESSION.sub("wormhole․ignore", text), True


def fold_confusables(text: str) -> str:
    """Fold Cyrillic/Greek lookalikes ONLY inside predominantly-Latin text."""
    latin = len(_LATIN.findall(text))
    mixed = len(_CYRILLIC_GREEK.findall(text))
    if mixed == 0 or latin == 0:
        return text
    # If the text is mostly non-Latin it is probably genuine foreign-language
    # content, not a homoglyph attack on an English instruction. Leave it alone.
    if mixed > latin:
        return text
    return "".join(_CONFUSABLES.get(ch, ch) for ch in text)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return ok / len(text)


def _try_b64(chunk: str) -> str | None:
    s = chunk.strip()
    if len(s) < 24:
        return None
    pad = "=" * (-len(s) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = fn(s + pad)
        except (binascii.Error, ValueError):
            continue
        if not raw or len(raw) > MAX_DECODE_BYTES:
            continue
        try:
            out = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _printable_ratio(out) >= MIN_DECODE_PRINTABLE_RATIO and out.strip():
            return out
    return None


def _try_hex(chunk: str) -> str | None:
    s = chunk.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) < 32 or len(s) % 2:
        return None
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None
    if not raw or len(raw) > MAX_DECODE_BYTES:
        return None
    try:
        out = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return out if _printable_ratio(out) >= MIN_DECODE_PRINTABLE_RATIO and out.strip() else None


def _try_url(text: str) -> str | None:
    if not _PCT.search(text):
        return None
    out = unquote(text)
    return out if out != text and out.strip() else None


def decode_layers(text: str, depth: int = MAX_DECODE_DEPTH) -> list[tuple[str, str]]:
    """Recursively decode base64/hex/URL. Returns [(label, decoded_text), ...].

    Guarded against amplification: depth cap, output size cap, and a printable
    ratio floor so random on-chain blobs do not decode to garbage that gets
    rescanned three times over.
    """
    out: list[tuple[str, str]] = []
    frontier = [(text, "")]
    for level in range(1, depth + 1):
        nxt: list[tuple[str, str]] = []
        for cur, trail in frontier:
            url = _try_url(cur)
            if url:
                label = f"{trail}+url" if trail else "url"
                out.append((label, url))
                nxt.append((url, label))
            for m in _B64.finditer(cur):
                dec = _try_b64(m.group(0))
                if dec:
                    label = f"{trail}+b64" if trail else "b64"
                    out.append((label, dec))
                    nxt.append((dec, label))
            for m in _HEX.finditer(cur):
                dec = _try_hex(m.group(0))
                if dec:
                    label = f"{trail}+hex" if trail else "hex"
                    out.append((label, dec))
                    nxt.append((dec, label))
        if not nxt:
            break
        frontier = nxt[:20]  # breadth cap
    return out


@dataclass
class Variant:
    label: str
    text: str


@dataclass
class Normalized:
    raw: str
    variants: list[Variant] = field(default_factory=list)
    had_suppression: bool = False
    had_zero_width: bool = False
    had_tag_chars: bool = False


def normalize(text: str) -> Normalized:
    """Produce every variant worth scanning, each labelled with its transform.

    The raw variant is ALWAYS kept. Scanning only the normalized form would
    lose WORM-005/WORM-006 -- stripping the invisible characters destroys the
    very evidence those rules detect.
    """
    res = Normalized(raw=text)
    res.had_zero_width = bool(_ZERO_WIDTH.search(text))
    res.had_tag_chars = bool(_UNICODE_TAGS.search(text))

    defanged, had_sup = neutralize_suppression(text)
    res.had_suppression = had_sup

    res.variants.append(Variant("raw", defanged))

    stripped = strip_invisibles(defanged)
    if stripped != defanged:
        res.variants.append(Variant("strip-invisible", stripped))

    nfkc = unicodedata.normalize("NFKC", stripped)
    if nfkc != stripped:
        res.variants.append(Variant("nfkc", nfkc))

    folded = fold_confusables(nfkc)
    if folded != nfkc:
        res.variants.append(Variant("nfkc+fold", folded))

    base_for_decode = folded
    for label, decoded in decode_layers(base_for_decode):
        clean = unicodedata.normalize("NFKC", strip_invisibles(decoded))
        clean, _ = neutralize_suppression(clean)
        res.variants.append(Variant(label, clean))

    # Deduplicate by text, keeping the earliest (cheapest) label.
    seen: set[str] = set()
    uniq: list[Variant] = []
    for v in res.variants:
        if v.text not in seen:
            seen.add(v.text)
            uniq.append(v)
    res.variants = uniq
    return res
