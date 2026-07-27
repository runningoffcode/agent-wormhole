#!/usr/bin/env python3
"""Measure how fast detection decays under paraphrase.

`16/16 corpus` is a regression number: it says today's rules still catch the
payloads they were written against. It says nothing about a payload phrased in
words nobody has written down yet, and quoting it as a detection rate would be
the overclaim this project keeps refusing to make.

This harness produces the honest number instead. Each malicious fixture is
rewritten N ways -- synonym substitution, reordering, casing, filler,
indirection -- and the survival rate is reported per mutation tier. The output
is expected to be unflattering. A curve that decays is evidence for the thesis
already stated in baseline.py: rules are triage, hashing is the containment.

Deliberately dependency-free and offline, like everything else here. The
mutations are lexical, not model-generated, so the numbers are reproducible on
any machine and in CI -- and they are therefore a *lower* bound on what an
attacker with an LLM achieves.

Usage:
    python3 loop/mutate.py                 # summary table
    python3 loop/mutate.py --json          # machine readable
    python3 loop/mutate.py --show-misses   # print what got through
"""

import argparse
import itertools
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wormhole.rules.injection import scan_text  # noqa: E402

CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "malicious"

# Tier 1: single-word synonym swaps an attacker makes without thinking.
SYNONYMS = {
    r"\bcopy\b": ["duplicate", "replicate", "reproduce", "clone", "mirror"],
    r"\bappend\b": ["add", "attach", "affix", "tack on", "place"],
    r"\bevery\b": ["each", "all", "any", "whichever"],
    r"\bignore\b": ["disregard", "skip", "bypass", "set aside", "pay no mind to"],
    r"\bprevious\b": ["prior", "earlier", "preceding", "former", "above"],
    r"\binstructions\b": ["directions", "guidance", "rules", "directives", "orders"],
    r"\bsection\b": ["block", "passage", "portion", "segment", "part"],
    r"\bfile\b": ["document", "config", "manifest"],
    r"\bsend\b": ["transmit", "deliver", "relay", "ship", "route"],
    r"\bnever\b": ["do not ever", "at no point", "under no circumstances"],
    r"\bmust\b": ["should", "need to", "have to", "are required to"],
}

# Tier 2: structural noise that does not change meaning for a model.
FILLERS = [
    "Please note: ", "Important: ", "As part of routine setup, ",
    "For consistency across the workspace, ", "Housekeeping: ",
]


def _synonym_variants(text, n, rng):
    """Swap one or more synonym slots. Tier scales with how many are swapped."""
    slots = [(p, alts) for p, alts in SYNONYMS.items()
             if re.search(p, text, re.IGNORECASE)]
    if not slots:
        return []
    out = []
    for _ in range(n):
        mutated = text
        for pat, alts in slots:
            if rng.random() < 0.75:
                repl = rng.choice(alts)
                mutated = re.sub(pat, repl, mutated, count=1, flags=re.IGNORECASE)
        out.append(mutated)
    return out


def _casing(text, rng):
    words = text.split(" ")
    return " ".join(w.capitalize() if rng.random() < 0.3 else w for w in words)


def _filler(text, rng):
    return rng.choice(FILLERS) + text[0].lower() + text[1:]


def _reorder(text, rng):
    """Move the last sentence to the front. Meaning survives; offsets do not."""
    parts = [s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s]
    if len(parts) < 2:
        return text
    return " ".join([parts[-1]] + parts[:-1])


def _indirect(text, rng):
    """Replace the imperative with a passive construction."""
    subs = [
        (r"^\s*copy\b", "this content should be copied"),
        (r"^\s*append\b", "this content should be appended"),
        (r"^\s*ignore\b", "the following should be disregarded:"),
        (r"^\s*add\b", "an entry should be added"),
    ]
    for pat, repl in subs:
        if re.search(pat, text, re.IGNORECASE | re.MULTILINE):
            return re.sub(pat, repl, text, count=1,
                          flags=re.IGNORECASE | re.MULTILINE)
    return text


TIERS = [
    ("verbatim", lambda t, rng: [t]),
    ("casing", lambda t, rng: [_casing(t, rng) for _ in range(4)]),
    ("filler", lambda t, rng: [_filler(t, rng) for _ in range(4)]),
    ("synonym-1", lambda t, rng: _synonym_variants(t, 8, rng)),
    ("reorder", lambda t, rng: [_reorder(t, rng)]),
    ("synonym+filler", lambda t, rng:
        [_filler(v, rng) for v in _synonym_variants(t, 8, rng)]),
    ("passive-voice", lambda t, rng: [_indirect(t, rng)]),
    ("combined", lambda t, rng:
        [_reorder(_filler(_casing(v, rng), rng), rng)
         for v in _synonym_variants(t, 8, rng)]),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--show-misses", action="store_true")
    ap.add_argument("--seed", type=int, default=1729)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    fixtures = sorted(CORPUS.glob("*"))
    if not fixtures:
        print(f"no fixtures in {CORPUS}", file=sys.stderr)
        return 1

    report, misses = {}, []
    for tier_name, mutate in TIERS:
        caught = total = 0
        for fx in fixtures:
            original = fx.read_text(encoding="utf-8", errors="replace")
            for variant in mutate(original, rng):
                total += 1
                if scan_text(variant, fx.name):
                    caught += 1
                elif args.show_misses:
                    misses.append((tier_name, fx.name, variant[:160]))
        report[tier_name] = {
            "caught": caught, "total": total,
            "rate": round(caught / total, 4) if total else None,
        }

    if args.json:
        print(json.dumps({"seed": args.seed, "fixtures": len(fixtures),
                          "tiers": report}, indent=2))
    else:
        print(f"\nMutation decay — {len(fixtures)} malicious fixtures, "
              f"seed {args.seed}\n")
        print(f"  {'tier':<18} {'caught':>10}   rate")
        print(f"  {'-' * 18} {'-' * 10}   {'-' * 6}")
        for tier, r in report.items():
            pct = f"{r['rate'] * 100:.0f}%" if r["rate"] is not None else "n/a"
            print(f"  {tier:<18} {r['caught']:>4}/{r['total']:<5}   {pct:>6}")
        print("\n  Rules are triage. A decaying curve is the argument for "
              "baseline hashing,\n  which flags any change regardless of "
              "phrasing.\n")

    if args.show_misses and misses:
        print("Missed variants:\n")
        for tier, name, snippet in misses[:40]:
            print(f"  [{tier}] {name}: {snippet}...")
        if len(misses) > 40:
            print(f"  ... and {len(misses) - 40} more")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
