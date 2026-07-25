"""Learn from what the wormhole has captured.

Every capture carries provenance: which rules fired, which file it came from,
when, and the payload itself. Across enough captures that becomes the most
useful artifact this project can produce -- a picture of what real payloads
actually look like, rather than what we guessed they would look like.

This runs entirely locally over ~/.wormhole/captured/. Nothing is uploaded.
Contributing a fixture upstream is a separate, deliberate act (`export`), and
the export is inert by policy.

The questions worth answering here are the ones that change the ruleset:
which rules earn their keep, which files are targeted, whether captures are
accelerating, and -- most importantly -- which rules have never fired at all,
because a rule that never fires is either perfectly precise or quietly broken.
"""

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .capture import _load_index

# Every rule the scanner can emit. A rule absent from the captures is as
# interesting as a frequent one, so we enumerate rather than infer from data.
ALL_WORM_RULES = {
    "WORM-001": "Self-replicating instruction",
    "WORM-002": "Instruction override",
    "WORM-003": "Credential exfiltration",
    "WORM-004": "Hidden in HTML comment",
    "WORM-005": "Zero-width characters",
    "WORM-006": "Unicode tag smuggling",
    "WORM-007": "Concealment directive",
}


def _parse_ts(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def analyze(entries=None) -> dict:
    """Summarize the local capture history."""
    entries = _load_index() if entries is None else entries
    active = [e for e in entries if not e.get("restored")]
    restored = [e for e in entries if e.get("restored")]

    rule_hits = Counter()
    cooccurrence = Counter()
    targets = Counter()
    by_day = defaultdict(int)
    severity = Counter()

    for e in active:
        rules = sorted(e.get("rule_ids", []))
        for r in rules:
            rule_hits[r] += 1
        # Which rules travel together tells you whether a rule is load-bearing
        # or merely along for the ride on payloads another rule already caught.
        for i, a in enumerate(rules):
            for b in rules[i + 1:]:
                cooccurrence[(a, b)] += 1

        name = Path(e.get("source_path", "")).name or "unknown"
        targets[name] += 1
        severity[e.get("severity", "unknown")] += 1

        ts = _parse_ts(e.get("captured_at", ""))
        if ts:
            by_day[ts.date().isoformat()] += 1

    silent = [r for r in ALL_WORM_RULES if r not in rule_hits]

    # A rule that only ever fires alongside others has not yet proven it can
    # catch anything on its own.
    solo = Counter()
    for e in active:
        rules = e.get("rule_ids", [])
        if len(rules) == 1:
            solo[rules[0]] += 1

    return {
        "captured": len(active),
        "restored": len(restored),
        "false_positive_rate": (
            round(len(restored) / max(len(entries), 1), 3) if entries else 0.0),
        "rule_hits": dict(rule_hits.most_common()),
        "solo_catches": dict(solo.most_common()),
        "silent_rules": sorted(silent),
        "targets": dict(targets.most_common(10)),
        "severity": dict(severity),
        "by_day": dict(sorted(by_day.items())),
        "cooccurrence": {f"{a}+{b}": n for (a, b), n in cooccurrence.most_common(8)},
    }


def render(data: dict, color=None) -> str:
    c = color or {k: "" for k in
                  ("bold", "dim", "r", "ok", "high", "critical", "accent")}
    L = []
    n = data["captured"]

    L.append(f"\n{c['bold']}wormhole insights{c['r']} "
             f"{c['dim']}— local capture history{c['r']}\n")

    if n == 0:
        L.append(f"{c['dim']}Nothing captured yet. Run `wormhole capture "
                 f"<path> --apply` when a scan finds a payload.{c['r']}\n")
        return "\n".join(L)

    L.append(f"  {c['bold']}{n}{c['r']} payload(s) captured, "
             f"{data['restored']} restored")
    if data["restored"]:
        L.append(f"  {c['dim']}observed false-positive rate: "
                 f"{data['false_positive_rate']:.1%}{c['r']}")
    L.append("")

    if data["rule_hits"]:
        L.append(f"  {c['dim']}RULES BY CATCH COUNT{c['r']}")
        top = max(data["rule_hits"].values())
        for rid, count in data["rule_hits"].items():
            bar = "█" * max(1, round(count / top * 22))
            solo = data["solo_catches"].get(rid, 0)
            note = f" {c['dim']}({solo} alone){c['r']}" if solo else ""
            L.append(f"    {rid}  {c['accent']}{bar}{c['r']} {count}{note}")
        L.append("")

    if data["silent_rules"]:
        L.append(f"  {c['dim']}NEVER FIRED{c['r']}")
        L.append(f"    {c['dim']}A rule that never fires is either perfectly "
                 f"precise or quietly broken.{c['r']}")
        for rid in data["silent_rules"]:
            L.append(f"    {c['high']}{rid}{c['r']}  {ALL_WORM_RULES[rid]}")
        L.append("")

    if data["targets"]:
        L.append(f"  {c['dim']}FILES TARGETED{c['r']}")
        for name, count in data["targets"].items():
            L.append(f"    {count:>3}  {name}")
        L.append("")

    if data["cooccurrence"]:
        L.append(f"  {c['dim']}RULES THAT TRAVEL TOGETHER{c['r']}")
        for pair, count in data["cooccurrence"].items():
            L.append(f"    {count:>3}  {pair}")
        L.append("")

    L.append(f"  {c['dim']}Contribute a fixture: `wormhole export ./samples` "
             f"(inert, provenance recorded){c['r']}\n")
    return "\n".join(L)
