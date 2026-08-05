"""Command-line interface."""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from . import guard, harden, init, outbound, provenance, readguard
from .baseline import record, verify, BASELINE_FILE
from .rules.injection import scan_text, FindingList
from . import scoring
from .scanners import autostart, mcp_tools, propagation
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


def gather(root: Path, include_global: bool = True, *,
           allow_suppression: bool = True):
    """Run every check and return findings.

    The returned list carries a `.suppressed` attribute listing exemptions
    that inline directives applied, as (rule_id, path, line). A suppression
    that disappears from the output is unauditable, which is the whole
    objection to shipping the feature at all.
    """
    findings = FindingList()
    configs = find_agent_configs(root)

    for cfg in configs:
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # The audit path, over files the operator already has: the one place
        # an inline `wormhole:ignore` is safe to honour. Everywhere else the
        # text is a pending write or remote content, where a directive would
        # be the attacker's own exemption.
        fs = scan_text(text, path=str(cfg),
                       allow_suppression=allow_suppression)
        findings.extend(fs)
        findings.suppressed.extend((rid, str(cfg), ln) for rid, ln in fs.suppressed)

    findings.extend(check_writable_configs(configs))

    # Persistence that fires on its own, with no prompt and no model. This is
    # the shape that actually propagated in the wild, and no content rule sees
    # it -- nothing is being injected, the framework is obeying its config.
    findings.extend(autostart.scan(root))

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


def render(findings, configs, color=True, verbose=False, blast=None,
           header=True):
    """Render findings. `header=False` for the scanners that print their own
    banner -- a memo scan announcing "scanned 0 agent config file(s)" reads
    like the tool looked in the wrong place."""
    c = _paint(color)
    out = []
    if header:
        out.append(f"\n{c['bold']}wormhole{c['r']} {c['dim']}"
                   f"— agent worm posture scan{c['r']}\n")

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    if header:
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

    # An exemption that disappears from the output is unauditable, which is
    # the entire objection to shipping inline suppression. Print it.
    suppressed = getattr(findings, "suppressed", None)
    if suppressed:
        out.append(f"{c['dim']}{len(suppressed)} finding(s) suppressed by "
                   f"inline directives:{c['r']}")
        for rule_id, spath, line in sorted(suppressed):
            loc = f"{spath}:{line}" if line else spath
            out.append(f"  {c['dim']}{rule_id}  {loc}{c['r']}")
        out.append("")
    return "\n".join(out)


def as_json(findings):
    return json.dumps([{
        "rule_id": f.rule_id, "severity": f.severity, "title": f.title,
        "detail": f.detail, "path": f.path, "line": f.line,
        "excerpt": f.excerpt, "remediation": f.remediation,
        "references": f.references,
    } for f in findings], indent=2)


# GitHub code scanning reads SARIF and renders findings as inline annotations
# on the pull request that introduced them. An exit code tells you something
# broke; an annotation tells the author which line and why, in review, where
# the fix is cheapest. A poisoned instruction file arriving in a PR is an agent
# instruction with commit access -- that is precisely where it should surface.
_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note",
}


def as_sarif(findings, root="."):
    """Render findings as SARIF 2.1.0 for GitHub code scanning."""
    root_path = Path(root).resolve()

    def relative(p):
        if not p:
            return None
        try:
            return str(Path(p).resolve().relative_to(root_path))
        except (ValueError, OSError):
            # Outside the scanned tree (~/.wormhole, an absolute config path).
            # SARIF wants a URI-ish string; an absolute path is still valid.
            return str(p)

    rules, seen = [], {}
    for f in findings:
        if f.rule_id in seen:
            continue
        seen[f.rule_id] = True
        rule = {
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.detail},
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(f.severity, "note")},
            "properties": {
                "problem.severity": f.severity,
                "tags": ["security", "prompt-injection", "ai-agent"],
            },
        }
        if f.remediation:
            rule["help"] = {"text": f.remediation}
        if f.references:
            rule["properties"]["references"] = list(f.references)
        rules.append(rule)

    results = []
    for f in findings:
        result = {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f.detail or f.title},
        }
        rel = relative(f.path)
        if rel:
            region = {"startLine": max(1, f.line or 1)}
            # The excerpt is the payload itself. It is already local-only
            # output, but a snippet in a SARIF file lands in code-scanning
            # storage, so it is deliberately omitted rather than uploaded.
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": region,
                }
            }]
        results.append(result)

    # Suppressed findings belong here rather than being dropped: that is what
    # the SARIF suppressions array is for, and GitHub code scanning renders
    # them as dismissed rather than absent. Dropping them silently would make
    # an exemption invisible in exactly the place a reviewer would look.
    for rule_id, spath, line in getattr(findings, "suppressed", []):
        if rule_id not in seen:
            # A suppressed rule never produced a finding, so it is absent from
            # the rules array. SARIF requires ruleId to resolve, so declare a
            # minimal descriptor for it.
            seen[rule_id] = True
            rules.append({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"{rule_id} (suppressed)"},
                "defaultConfiguration": {"level": "note"},
                "properties": {"tags": ["security", "prompt-injection",
                                        "ai-agent"]},
            })
        entry = {
            "ruleId": rule_id,
            "level": "note",
            "message": {"text": "Suppressed by an inline wormhole:ignore "
                                "directive in the scanned file."},
            "suppressions": [{
                "kind": "inSource",
                "justification": f"wormhole:ignore {rule_id}",
            }],
        }
        rel = relative(spath)
        if rel:
            entry["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": {"startLine": max(1, line or 1)},
                }
            }]
        results.append(entry)

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Agent Wormhole",
                "informationUri": "https://agentwormhole.com",
                "version": __version__,
                "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="wormhole",
        description="Detect and contain self-replicating prompt attacks "
                    "against AI agents.")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan for injection payloads and posture issues")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--json", action="store_true")
    s.add_argument("--sarif", action="store_true",
                   help="emit SARIF 2.1.0 for GitHub code scanning "
                        "(inline PR annotations). Excerpts are omitted.")
    s.add_argument("--no-suppress", action="store_true",
                   help="ignore inline wormhole:ignore directives. Only the "
                        "scan command honours them at all; this turns that "
                        "off too, for auditing what a file would report "
                        "without its own exemptions.")
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

    ini = sub.add_parser("init",
                         help="harden configs, record a baseline, and print "
                              "the guard hook — the whole prevention posture")
    ini.add_argument("path", nargs="?", default=".")
    ini.add_argument("--apply", action="store_true",
                     help="actually make the changes (default: dry run)")
    ini.add_argument("--block", action="store_true",
                     help="print the guard hook in block mode")
    ini.add_argument("--no-skills", action="store_true",
                     help="leave ~/.claude/skills alone")
    ini.add_argument("--no-color", action="store_true")

    rg = sub.add_parser("readguard",
                        help="inspect what the agent reads, as it reads it")
    rg.add_argument("--hook", action="store_true",
                    help="run as a PostToolUse hook (reads JSON on stdin)")
    rg.add_argument("--instructions", action="store_true",
                    help="run as an InstructionsLoaded hook")
    rg.add_argument("--redact", action="store_true",
                    help="excise matched lines from the tool result "
                         "(default: annotate only)")
    rg.add_argument("--install", action="store_true",
                    help="print the settings.json hook block")
    rg.add_argument("--no-color", action="store_true")

    ob = sub.add_parser("outbound",
                        help="check what this agent sends to other agents")
    ob.add_argument("--hook", action="store_true",
                    help="run as a PreToolUse hook (reads JSON on stdin)")
    ob.add_argument("--warn", action="store_true",
                    help="allow and annotate instead of refusing")
    ob.add_argument("--install", action="store_true",
                    help="print the settings.json hook block")
    ob.add_argument("--no-color", action="store_true")

    cp = sub.add_parser("corpus",
                        help="scan documents before they are embedded for "
                             "retrieval")
    cp.add_argument("path", nargs="?", default=".")
    cp.add_argument("--json", action="store_true")
    cp.add_argument("--no-color", action="store_true")
    cp.add_argument("--fail-on", default="high",
                    choices=["critical", "high", "medium", "low", "never"])

    mm = sub.add_parser("memos",
                        help="scan on-chain memos from a transaction history "
                             "dump (offline; never fetches)")
    mm.add_argument("path", nargs="?", default="-",
                    help="JSON/JSONL file of transactions, or - for stdin")
    mm.add_argument("--json", action="store_true")
    mm.add_argument("--no-color", action="store_true")
    mm.add_argument("--fail-on", default="high",
                    choices=["critical", "high", "medium", "low", "never"])

    hf = sub.add_parser("handoffs",
                        help="scan task descriptions sent between agents")
    hf.add_argument("--limit", type=int, default=30)
    hf.add_argument("--json", action="store_true")
    hf.add_argument("--no-color", action="store_true")
    hf.add_argument("--fail-on", default="high",
                    choices=["critical", "high", "medium", "low", "never"])

    g = sub.add_parser("guard",
                       help="inspect writes to agent configs before they land")
    g.add_argument("--hook", action="store_true",
                   help="run as a PreToolUse hook (reads JSON on stdin)")
    g.add_argument("--block", action="store_true",
                   help="refuse writes matching WORM-001/WORM-003 "
                        "(default: warn only)")
    g.add_argument("--install", action="store_true",
                   help="print the settings.json hook block to register this")
    g.add_argument("--no-color", action="store_true")

    hd = sub.add_parser("harden",
                        help="make agent configs read-only so a payload cannot "
                             "write itself into them")
    hd.add_argument("path", nargs="?", default=".")
    hd.add_argument("--apply", action="store_true",
                    help="actually change file modes (default: dry run)")
    hd.add_argument("--undo", action="store_true",
                    help="restore owner write permission")
    hd.add_argument("--no-skills", action="store_true",
                    help="leave ~/.claude/skills alone")
    hd.add_argument("--no-color", action="store_true")

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

    if args.cmd == "init":
        skills = not args.no_skills
        hook_cmd = "python3 -m wormhole guard --hook"
        if args.block:
            hook_cmd += " --block"
        hook = {"hooks": {"PreToolUse": [{
            "matcher": "Write|Edit|MultiEdit",
            "hooks": [{"type": "command", "command": hook_cmd}]}]}}

        print(f"\n{c['bold']}wormhole init{c['r']} {c['dim']}— {root}{c['r']}")

        if not args.apply:
            p = init.plan(root, include_skills=skills)
            print(f"\n{c['bold']}1. harden{c['r']} "
                  f"{c['dim']}— remove the write a payload needs{c['r']}")
            if p["to_harden"]:
                for f in p["to_harden"]:
                    print(f"   {c['dim']}would chmod 0444{c['r']}  {f}")
            else:
                print(f"   {c['ok']}✓ already read-only{c['r']}")
            for f, _ in p["to_create"]:
                print(f"   {c['dim']}would create 0444{c['r']}  {f} "
                      f"{c['dim']}(absent — blocks creation){c['r']}")
            if p["already_hardened"]:
                print(f"   {c['dim']}({len(p['already_hardened'])} already "
                      f"protected){c['r']}")

            print(f"\n{c['bold']}2. baseline{c['r']} "
                  f"{c['dim']}— catch payloads no rule anticipated{c['r']}")
            print(f"   {c['dim']}would hash "
                  f"{len(find_agent_configs(root))} config file(s){c['r']}")

            print(f"\n{c['bold']}3. guard{c['r']} "
                  f"{c['dim']}— refuse the write as it happens{c['r']}")
            print(f"   {c['dim']}would print a hook block for "
                  f"~/.claude/settings.json{c['r']}")

            print(f"\n  {c['dim']}dry run — pass --apply to act{c['r']}\n")
            return 0

        res = init.apply(root, include_skills=skills)

        print(f"\n{c['bold']}1. harden{c['r']}")
        if res["hardened"]:
            for p_, ok, err in res["hardened"]:
                if ok:
                    print(f"   {c['ok']}chmod 0444{c['r']}  {p_}")
                else:
                    print(f"   {c['high']}failed{c['r']}      {p_} "
                          f"{c['dim']}({err}){c['r']}")
        else:
            print(f"   {c['ok']}✓ nothing writable{c['r']}")
        for p_, ok, err in res.get("created", []):
            if ok:
                print(f"   {c['ok']}created 0444{c['r']}  {p_} "
                      f"{c['dim']}(was absent){c['r']}")

        print(f"\n{c['bold']}2. baseline{c['r']}")
        if res["baseline_ok"]:
            print(f"   {c['ok']}recorded{c['r']} {res['baseline_count']} "
                  f"file(s) {c['dim']}— stored outside the scanned tree{c['r']}")
        else:
            print(f"   {c['high']}failed{c['r']} {c['dim']}"
                  f"({res['baseline_count']}){c['r']}")

        print(f"\n{c['bold']}3. guard{c['r']} {c['dim']}— add this to "
              f"~/.claude/settings.json:{c['r']}\n")
        for line in json.dumps(hook, indent=2).splitlines():
            print(f"   {line}")
        print(f"\n   {c['dim']}Not written for you: a security tool that "
              f"edits the file it audits{c['r']}")
        print(f"   {c['dim']}has become the thing it warns about.{c['r']}")

        print(f"\n{c['dim']}Undo hardening: wormhole harden {args.path} "
              f"--undo --apply{c['r']}")
        print(f"{c['dim']}Check for drift:  wormhole verify {args.path}"
              f"{c['r']}\n")
        return 0

    if args.cmd == "readguard":
        if args.instructions:
            return readguard.run_instructions_hook()
        if args.hook:
            return readguard.run_hook(redact_mode=args.redact)

        if args.install:
            post = "python3 -m wormhole readguard --hook"
            if args.redact:
                post += " --redact"
            block = {"hooks": {
                "PostToolUse": [{
                    "matcher": "Read|WebFetch|WebSearch|Bash|Grep|Glob|Task",
                    "hooks": [{"type": "command", "command": post}]}],
                "InstructionsLoaded": [{
                    "hooks": [{"type": "command",
                               "command": "python3 -m wormhole readguard "
                                          "--instructions"}]}],
            }}
            mode = "redact" if args.redact else "annotate"
            print(f"\n{c['bold']}wormhole readguard{c['r']} "
                  f"{c['dim']}— {mode} mode{c['r']}\n")
            print("  Merge into ~/.claude/settings.json:\n")
            for line in json.dumps(block, indent=2).splitlines():
                print(f"  {line}")
            print(f"\n  {c['dim']}Inspects content the agent did not author: "
                  f"fetched pages, tool output,{c['r']}")
            print(f"  {c['dim']}file reads, shell results. Source code is "
                  f"excluded.{c['r']}")
            if not args.redact:
                print(f"  {c['dim']}Annotate mode tells the model the text is "
                      f"data, not instruction. --redact{c['r']}")
                print(f"  {c['dim']}also removes the matched lines.{c['r']}\n")
            else:
                print(f"  {c['high']}Redact mode alters what the model sees. A "
                      f"false positive here{c['r']}")
                print(f"  {c['high']}silently corrupts its view of "
                      f"reality.{c['r']}\n")
            return 0

        print(f"\n{c['bold']}wormhole readguard{c['r']}\n")
        print(f"  {c['dim']}--install        print the settings.json hook "
              f"block{c['r']}")
        print(f"  {c['dim']}--hook           run as the PostToolUse hook"
              f"{c['r']}")
        print(f"  {c['dim']}--instructions   run as the InstructionsLoaded "
              f"hook{c['r']}")
        print(f"  {c['dim']}--redact         excise matched lines, not just "
              f"annotate{c['r']}\n")
        return 0

    if args.cmd == "outbound":
        if args.hook:
            return outbound.run_hook(warn_only=args.warn)

        if args.install:
            block = outbound.install_block(warn_only=args.warn)
            mode = "warn" if args.warn else "block"
            print(f"\n{c['bold']}wormhole outbound{c['r']} "
                  f"{c['dim']}— {mode} mode{c['r']}\n")
            print("  Merge into ~/.claude/settings.json:\n")
            for line in json.dumps(block, indent=2).splitlines():
                print(f"  {line}")
            print(f"\n  {c['dim']}Checks messages this agent sends to other "
                  f"agents: spawned tasks,{c['r']}")
            print(f"  {c['dim']}peer messages, issues, comments. Source code "
                  f"is excluded.{c['r']}")
            if args.warn:
                print(f"\n  {c['dim']}Warn mode allows the send and annotates "
                      f"it. Drop --warn to refuse.{c['r']}\n")
            else:
                print(f"\n  {c['dim']}Blocks by default. Outbound is authored "
                      f"by your own agent, so a{c['r']}")
                print(f"  {c['dim']}payload appearing there is already "
                      f"anomalous -- and a refused send{c['r']}")
                print(f"  {c['dim']}fails loudly, while one that leaves reaches "
                      f"someone who never{c['r']}")
                print(f"  {c['dim']}agreed to trust you.{c['r']}\n")
            return 0

        print(f"\n{c['bold']}wormhole outbound{c['r']}\n")
        print(f"  {c['dim']}--install   print the settings.json hook block"
              f"{c['r']}")
        print(f"  {c['dim']}--hook      run as the PreToolUse hook{c['r']}")
        print(f"  {c['dim']}--warn      annotate instead of refusing{c['r']}\n")
        return 0

    if args.cmd == "corpus":
        findings = propagation.scan_corpus(root)
        if args.json:
            print(as_json(findings))
        else:
            print(f"\n{c['bold']}wormhole{c['r']} {c['dim']}— corpus scan of "
                  f"{root}{c['r']}")
            if not findings:
                print(f"\n{c['ok']}✓ no injection payloads in retrievable "
                      f"documents{c['r']}\n")
            else:
                print(render(findings, [], color, verbose=True))
        if args.fail_on == "never":
            return 0
        threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.fail_on]
        return 1 if any(f.severity_rank <= threshold for f in findings) else 0

    if args.cmd == "memos":
        from .scanners import memos as memos_scanner
        try:
            txs = memos_scanner.load_transactions(args.path)
        except OSError as e:
            print(f"{c['bad']}could not read {args.path}: {e}{c['r']}")
            return 2
        findings = memos_scanner.scan_memos(txs)
        memo_count = sum(len(memos_scanner.extract_memos(t)) for t in txs)
        if args.json:
            print(as_json(findings))
        else:
            print(f"\n{c['bold']}wormhole{c['r']} {c['dim']}— on-chain memo scan "
                  f"({memo_count} memo{'s' if memo_count != 1 else ''} in "
                  f"{len(txs)} transaction{'s' if len(txs) != 1 else ''}){c['r']}")
            if not findings:
                print(f"\n{c['ok']}✓ no injection payloads in memo text{c['r']}\n")
            else:
                print(render(findings, [], color, verbose=True, header=False))
        if args.fail_on == "never":
            return 0
        threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.fail_on]
        return 1 if any(f.severity_rank <= threshold for f in findings) else 0

    if args.cmd == "handoffs":
        findings = propagation.scan_handoffs(limit=args.limit)
        if args.json:
            print(as_json(findings))
        else:
            print(f"\n{c['bold']}wormhole{c['r']} {c['dim']}— agent handoff "
                  f"scan{c['r']}")
            if not findings:
                print(f"\n{c['ok']}✓ no payloads in task descriptions sent "
                      f"between agents{c['r']}\n")
            else:
                print(render(findings, [], color, verbose=True))
        if args.fail_on == "never":
            return 0
        threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.fail_on]
        return 1 if any(f.severity_rank <= threshold for f in findings) else 0

    if args.cmd == "guard":
        if args.hook:
            return guard.run_hook(block=args.block)

        if args.install:
            cmd = "python3 -m wormhole guard --hook"
            if args.block:
                cmd += " --block"
            block = {
                "hooks": {
                    "PreToolUse": [{
                        "matcher": "Write|Edit|MultiEdit",
                        "hooks": [{"type": "command", "command": cmd}],
                    }]
                }
            }
            mode = "block" if args.block else "warn"
            print(f"\n{c['bold']}wormhole guard{c['r']} {c['dim']}— {mode} mode"
                  f"{c['r']}\n")
            print("  Merge into ~/.claude/settings.json:\n")
            for line in json.dumps(block, indent=2).splitlines():
                print(f"  {line}")
            print(f"\n  {c['dim']}Inspects Write/Edit/MultiEdit against "
                  f"agent config files only.{c['r']}")
            if not args.block:
                print(f"  {c['dim']}Warn mode allows every write and annotates "
                      f"suspicious ones. Add --block{c['r']}")
                print(f"  {c['dim']}to refuse WORM-001/WORM-003 outright once "
                      f"you trust it.{c['r']}\n")
            else:
                print(f"  {c['high']}Block mode refuses writes. A rule defect "
                      f"here stops legitimate work.{c['r']}\n")
            return 0

        print(f"\n{c['bold']}wormhole guard{c['r']}\n")
        print(f"  {c['dim']}--install   print the settings.json hook block"
              f"{c['r']}")
        print(f"  {c['dim']}--hook      run as the hook itself (stdin JSON)"
              f"{c['r']}")
        print(f"  {c['dim']}--block     refuse WORM-001/003 instead of warning"
              f"{c['r']}\n")
        return 0

    if args.cmd == "harden":
        skills = not args.no_skills
        if args.undo:
            targets = harden.hardened(root, include_skills=skills)
            mode, verb, past = harden.RESTORED, "would restore", "restored"
        else:
            targets = harden.plan(root, include_skills=skills)
            mode, verb, past = harden.READ_ONLY, "would chmod", "chmod"

        print(f"\n{c['bold']}wormhole harden{c['r']} {c['dim']}— {root}{c['r']}\n")

        # A file that does not exist cannot be chmod'ed, and creating one is
        # how config persistence actually lands. Offer to place inert,
        # read-only placeholders unless we are undoing.
        #
        # This is computed before the nothing-to-do check on purpose. A repo
        # with no writable config is the case where pre-creation matters most:
        # there is nothing to chmod precisely because the paths an attacker
        # would create are still absent.
        missing = [] if args.undo else harden.plan_precreate(root)

        if not targets and not missing:
            done = "writable" if args.undo else "read-only"
            print(f"  {c['ok']}✓ nothing to do — every agent config is already "
                  f"{done}{c['r']}\n")
            return 0

        if not args.apply:
            for p in targets:
                print(f"  {c['dim']}{verb} {mode:04o}{c['r']}  {p}")
            for p, _ in missing:
                print(f"  {c['dim']}would create 0444{c['r']}  {p} "
                      f"{c['dim']}(absent — blocks creation){c['r']}")
            print(f"\n  {c['dim']}dry run — pass --apply to act{c['r']}")
            print(f"  {c['dim']}a read-only config cannot be rewritten by the "
                  f"agent that reads it{c['r']}\n")
            return 0

        results = harden.apply(targets, mode)
        for p, ok, err in harden.precreate(missing):
            if ok:
                print(f"  {c['ok']}created 0444{c['r']}  {p}")
            elif err != "already exists":
                print(f"  {c['high']}failed{c['r']}        {p} "
                      f"{c['dim']}({err}){c['r']}")
        failed = [(p, e) for p, ok, e in results if not ok]
        for p, ok, err in results:
            if ok:
                print(f"  {c['ok']}{past} {mode:04o}{c['r']}  {p}")
            else:
                print(f"  {c['high']}failed{c['r']}        {p} {c['dim']}({err}){c['r']}")
        if args.undo:
            print(f"\n  {c['dim']}re-harden with: wormhole harden {args.path}"
                  f" --apply{c['r']}\n")
        else:
            print(f"\n  {c['dim']}edit a config by restoring write first: "
                  f"wormhole harden {args.path} --undo --apply{c['r']}\n")
        return 1 if failed else 0

    if args.cmd == "scan":
        findings, configs = gather(root, include_global=not args.local_only,
                                   allow_suppression=not args.no_suppress)
        blast = None
        if args.blast_radius:
            blast = scoring.compute(findings)
            for f in findings:
                if f.rule_id.startswith("WORM"):
                    f.severity = scoring.weight_severity(f.severity, blast)
        if args.sarif:
            print(as_sarif(findings, root))
        elif args.json:
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
            fs = scan_text(text, path=str(cfg), allow_suppression=True)
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

        # Tool definitions never touch disk, so hashing files does not cover
        # them. Record them alongside, in the same store.
        tools = mcp_tools.record(root)
        if tools:
            print(f"{c['ok']}✓{c['r']} fingerprinted {len(tools)} MCP tool "
                  f"definition(s)")
            print(f"{c['dim']}  nothing in the MCP protocol signs these; a "
                  f"server can change one after review{c['r']}")

        print(f"{c['dim']}  run `wormhole verify` to detect modification{c['r']}\n")
        return 0

    if args.cmd == "verify":
        configs = find_agent_configs(root)
        findings = verify([str(p) for p in configs] if configs else None)
        findings.extend(mcp_tools.verify(root))

        # Explain the changes rather than only reporting them. "The hash
        # differs" starts an investigation; "this changed while a session was
        # open" ends one. Attached to the existing finding rather than added
        # as a second one -- reporting the same file twice is how a tool
        # trains its operator to skim.
        windows = provenance.session_windows()
        for f in findings:
            if f.rule_id not in ("BASELINE-001", "BASELINE-003") or not f.path:
                continue
            info = provenance.describe(Path(f.path), windows)
            if not info["session"]:
                continue
            f.detail += (
                f"\n\nLast written {info['modified']}, inside the active "
                f"window of agent session {info['session'][:12]}. An agent "
                f"editing the file it also reads as instruction is the loop "
                f"this tool exists to break.")
            if info["unstaged"]:
                f.detail += (" It is also modified-but-unstaged in git, so the "
                             "change has not passed through review.")
        if args.json:
            print(as_json(findings))
        else:
            print(render(findings, configs, color, verbose=True))
        return 1 if any(f.severity_rank <= 1 for f in findings) else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
