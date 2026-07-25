"""Command-line interface."""

import argparse
import json
import sys
from pathlib import Path

from .baseline import record, verify, BASELINE_FILE
from .rules.injection import scan_text
from . import scoring
from .scanners.posture import (
    find_agent_configs, check_permissions, check_writable_configs,
    check_mcp_servers, check_skills,
)
from .scanners.runtime import scan_sessions, to_findings, find_transcripts

C = {
    "critical": "\033[97;41m", "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[94m", "info": "\033[90m", "ok": "\033[92m",
    "dim": "\033[90m", "bold": "\033[1m", "r": "\033[0m",
}


def _paint(enabled: bool):
    return C if enabled else {k: "" for k in C}


def gather(root: Path, include_global: bool = True) -> list:
    """Run every check and return findings."""
    findings = []
    configs = find_agent_configs(root)

    for cfg in configs:
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(text, path=str(cfg)))

    findings.extend(check_writable_configs(configs))

    if include_global:
        home = Path.home()
        for settings in (home / ".claude/settings.json",
                         home / ".claude/settings.local.json",
                         root / ".claude/settings.json",
                         root / ".claude/settings.local.json"):
            if settings.is_file():
                findings.extend(check_permissions(settings))
        cj = home / ".claude.json"
        if cj.is_file():
            findings.extend(check_mcp_servers(cj))
        findings.extend(check_skills(home / ".claude/skills"))

    return findings, configs


def render(findings, configs, color=True, verbose=False, blast=None):
    c = _paint(color)
    out = []
    out.append(f"\n{c['bold']}wormhole{c['r']} {c['dim']}"
               f"— agent worm posture scan{c['r']}\n")

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    out.append(f"{c['dim']}scanned {len(configs)} agent config file(s){c['r']}\n")

    if blast is not None:
        out.append(scoring.render(blast, c))
        out.append("")

    actionable = [f for f in findings if f.severity != "info"]
    if not actionable:
        out.append(f"{c['ok']}✓ no issues found{c['r']}\n")

    for f in sorted(findings, key=lambda x: (x.severity_rank, x.rule_id)):
        if f.severity == "info" and not verbose:
            continue
        tag = f" {f.severity.upper()} "
        out.append(f"{c[f.severity]}{tag}{c['r']} {c['bold']}{f.title}{c['r']}"
                   f"  {c['dim']}[{f.rule_id}]{c['r']}")
        if f.path:
            loc = f"{f.path}:{f.line}" if f.line else f.path
            out.append(f"  {c['dim']}{loc}{c['r']}")
        for line in f.detail.split("\n"):
            out.append(f"  {line}")
        if f.excerpt:
            out.append(f"  {c['dim']}> {f.excerpt}{c['r']}")
        if f.remediation:
            out.append(f"  {c['ok']}fix:{c['r']} {f.remediation}")
        if f.references:
            out.append(f"  {c['dim']}ref: {'; '.join(f.references)}{c['r']}")
        out.append("")

    parts = [f"{c[s]}{counts[s]} {s}{c['r']}"
             for s in ("critical", "high", "medium", "low", "info")
             if s in counts]
    out.append(("  ".join(parts) if parts else f"{c['ok']}clean{c['r']}") + "\n")
    return "\n".join(out)


def as_json(findings):
    return json.dumps([{
        "rule_id": f.rule_id, "severity": f.severity, "title": f.title,
        "detail": f.detail, "path": f.path, "line": f.line,
        "excerpt": f.excerpt, "remediation": f.remediation,
        "references": f.references,
    } for f in findings], indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="wormhole",
        description="Detect and contain self-replicating prompt attacks "
                    "against AI agents.")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan for injection payloads and posture issues")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true", help="include info findings")
    s.add_argument("--local-only", action="store_true",
                   help="skip global settings/MCP/skill checks")
    s.add_argument("--fail-on", default="high",
                   choices=["critical", "high", "medium", "low", "never"],
                   help="exit nonzero at or above this severity (default: high)")
    s.add_argument("--blast-radius", action="store_true",
                   help="score host capability and weight findings by it")

    w = sub.add_parser("watch",
                       help="scan session transcripts for injection in tool output")
    w.add_argument("path", nargs="?", default=None,
                   help="project transcript dir (default: all recent sessions)")
    w.add_argument("--limit", type=int, default=20,
                   help="how many recent sessions to scan (default: 20)")
    w.add_argument("--json", action="store_true")
    w.add_argument("--no-color", action="store_true")
    w.add_argument("--fail-on", default="high",
                   choices=["critical", "high", "medium", "low", "never"])

    j = sub.add_parser("capture",
                       help="pull payloads into the wormhole, preserving originals")
    j.add_argument("path", nargs="?", default=".")
    j.add_argument("--apply", action="store_true",
                   help="actually modify files (default is a dry run)")
    j.add_argument("--no-color", action="store_true")

    jl = sub.add_parser("captured", help="list captured payloads")
    jl.add_argument("--all", action="store_true", help="include restored entries")
    jl.add_argument("--json", action="store_true")
    jl.add_argument("--no-color", action="store_true")

    jr = sub.add_parser("restore", help="pull a file back out of the Wormhole (false positive)")
    jr.add_argument("entry_id")
    jr.add_argument("--no-color", action="store_true")

    je = sub.add_parser("export", help="export captured payloads as corpus samples")
    je.add_argument("dest")
    je.add_argument("--no-color", action="store_true")

    ins = sub.add_parser("insights",
                         help="what the local capture history reveals")
    ins.add_argument("--json", action="store_true")
    ins.add_argument("--no-color", action="store_true")

    b = sub.add_parser("baseline", help="record hashes of agent config files")
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("--no-color", action="store_true")

    v = sub.add_parser("verify", help="check configs against recorded baseline")
    v.add_argument("path", nargs="?", default=".")
    v.add_argument("--json", action="store_true")
    v.add_argument("--no-color", action="store_true")

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 0

    root = Path(args.path).resolve() if getattr(args, "path", None) else Path.cwd()
    color = not getattr(args, "no_color", False) and sys.stdout.isatty()
    c = _paint(color)

    if args.cmd == "watch":
        target = Path(args.path).resolve() if args.path else None
        hits = scan_sessions(target, limit=args.limit)
        findings = to_findings(hits)
        n = len(find_transcripts(target, limit=args.limit))
        if args.json:
            print(as_json(findings))
        else:
            print(f"\n{c['bold']}wormhole{c['r']} {c['dim']}— runtime scan of "
                  f"{n} session(s){c['r']}")
            if not findings:
                print(f"\n{c['ok']}✓ no injection attempts found in tool output"
                      f"{c['r']}\n")
            else:
                print(render(findings, [], color, verbose=True))
        if args.fail_on == "never":
            return 0
        threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.fail_on]
        return 1 if any(f.severity_rank <= threshold for f in findings) else 0

    if args.cmd == "scan":
        findings, configs = gather(root, include_global=not args.local_only)
        blast = None
        if args.blast_radius:
            blast = scoring.compute(findings)
            for f in findings:
                if f.rule_id.startswith("WORM"):
                    f.severity = scoring.weight_severity(f.severity, blast)
        if args.json:
            print(as_json(findings))
        else:
            print(render(findings, configs, color, args.verbose, blast))
        if args.fail_on == "never":
            return 0
        threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.fail_on]
        return 1 if any(f.severity_rank <= threshold for f in findings) else 0

    if args.cmd == "capture":
        from . import capture as cap
        configs = find_agent_configs(root)
        results = []
        for cfg in configs:
            try:
                text = cfg.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            fs = scan_text(text, path=str(cfg))
            if any(f.rule_id.startswith("WORM") for f in fs):
                results.append(cap.swallow(cfg, fs,
                                                 dry_run=not args.apply))
        if not results:
            print(f"\n{c['ok']}✓ no payloads to capture{c['r']}\n")
            return 0
        mode = "APPLIED" if args.apply else "DRY RUN — nothing modified"
        print(f"\n{c['bold']}capture{c['r']} {c['dim']}({mode}){c['r']}\n")
        for r in results:
            print(f"{c['high']}{r['path']}{c['r']}")
            print(f"  rules: {', '.join(r.get('rules', []))}")
            print(f"  lines removed: {r.get('lines_removed', 0)}")
            for s in r.get("snippets", [])[:3]:
                for ln in s.split("\n")[:4]:
                    print(f"  {c['dim']}- {ln[:100]}{c['r']}")
            if r.get("wormhole_id"):
                print(f"  {c['ok']}swallowed as{c['r']} {r['wormhole_id']}")
            if not r.get("fully_clean", True):
                print(f"  {c['critical']} INCOMPLETE {c['r']} payloads remain "
                      f"after excision — review this file by hand")
            print()
        if not args.apply:
            print(f"{c['dim']}re-run with --apply to capture. Originals are "
                  f"preserved and restorable.{c['r']}\n")
        return 0

    if args.cmd == "captured":
        from . import capture as cap
        entries = cap.list_entries(include_restored=args.all)
        if args.json:
            print(json.dumps(entries, indent=2))
            return 0
        if not entries:
            print(f"\n{c['dim']}the Wormhole is empty{c['r']}\n")
            return 0
        print(f"\n{c['bold']}captured payloads{c['r']} "
              f"{c['dim']}({len(entries)}){c['r']}\n")
        for e in entries:
            flag = f" {c['dim']}[restored]{c['r']}" if e.get("restored") else ""
            print(f"{c['high']}{e['id']}{c['r']}{flag}")
            print(f"  from   {e['source_path']}:{e['line']}")
            print(f"  rules  {', '.join(e['rule_ids'])}   {e['captured_at']}")
            print(f"  {c['dim']}{e['excerpt'][:120]}{c['r']}\n")
        return 0

    if args.cmd == "restore":
        from . import capture as cap
        r = cap.restore(args.entry_id)
        ok = r["status"] == "restored"
        print(f"\n{c['ok'] if ok else c['high']}{r['status']}{c['r']} "
              f"{r.get('path', args.entry_id)}\n")
        return 0 if ok else 1

    if args.cmd == "export":
        from . import capture as cap
        r = cap.export_corpus(Path(args.dest))
        print(f"\n{c['ok']}✓{c['r']} exported {r['count']} sample(s) to "
              f"{r['dest']}\n")
        return 0

    if args.cmd == "insights":
        from . import insights as ins_mod
        data = ins_mod.analyze()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            pal = dict(c); pal["accent"] = c["ok"]
            print(ins_mod.render(data, pal))
        return 0

    if args.cmd == "baseline":
        configs = find_agent_configs(root)
        skills = Path.home() / ".claude/skills"
        if skills.is_dir():
            configs += [p for p in skills.rglob("*.md") if p.is_file()]
        entries = record(configs)
        print(f"\n{c['ok']}✓{c['r']} baselined {len(configs)} file(s) "
              f"({len(entries)} total tracked)")
        print(f"{c['dim']}  stored at {BASELINE_FILE}{c['r']}")
        print(f"{c['dim']}  run `wormhole verify` to detect modification{c['r']}\n")
        return 0

    if args.cmd == "verify":
        configs = find_agent_configs(root)
        findings = verify([str(p) for p in configs] if configs else None)
        if args.json:
            print(as_json(findings))
        else:
            print(render(findings, configs, color, verbose=True))
        return 1 if any(f.severity_rank <= 1 for f in findings) else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
