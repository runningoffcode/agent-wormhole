"""Posture checks: what an agent is *allowed* to do.

Content rules find a payload that is already present. These checks find the
conditions that decide what a payload could accomplish if one arrived.

The motivating evidence is AgentWorm (arXiv:2603.15727, NDSS 2026). Across
2,250 trials on five models, sandbox isolation was the only built-in control
that broke the infection loop, driving attack success to 0% across all vectors.
Execution restriction blocked payload execution but left persistence and
propagation approximately unchanged, producing what the authors call
"asymptomatic carriers" — agents that never run the payload and infect their
neighbours regardless.

Capability, not detection, is what bounds the damage.
"""

import json
import os
import re
from pathlib import Path

from ..rules.injection import Finding

# Permission entries that grant unbounded shell access regardless of any
# narrower rules present alongside them.
WILDCARD_BASH = re.compile(r"^Bash\(\s*\*\s*\)$|^Bash$", re.IGNORECASE)

# Commands that can reach the network and carry data outward.
EGRESS_CMD = re.compile(
    r"^Bash\(\s*(curl|wget|ssh|scp|rsync|nc|ncat|telnet|ftp)\b", re.IGNORECASE)

# Commands that can write files, i.e. establish persistence.
PERSIST_CMD = re.compile(
    r"^Bash\(\s*(tee|cp|mv|ln|chmod|sed|dd)\b", re.IGNORECASE)

# Files loaded into an agent's system prompt at session start. Every one of
# these is a dual-anchor persistence target in the AgentWorm sense: read
# unconditionally, with no integrity or provenance check.
CONFIG_NAMES = (
    # Claude Code / open agent convention
    "AGENTS.md", "agents.md", "CLAUDE.md", "claude.md",
    # Cursor legacy root file (deprecated in favour of .cursor/rules/*.mdc,
    # still honoured, so still worth scanning)
    ".cursorrules",
    # Windsurf
    ".windsurfrules", ".windsurf-rules",
    # Google Gemini CLI
    "GEMINI.md",
    # GitHub Copilot (repo-wide)
    "copilot-instructions.md",
)

# Directory-scoped rule formats: every file inside counts as agent config.
# Cursor moved to .cursor/rules/*.mdc; Copilot added .github/instructions/.
CONFIG_GLOBS = (
    (".cursor/rules", "*.mdc"),
    (".github/instructions", "*.instructions.md"),
    (".windsurf/rules", "*.md"),
)


def find_agent_configs(root: Path, max_depth: int = 4) -> list:
    """Locate agent instruction files under root."""
    found = []
    root = Path(root)
    skip = {"node_modules", ".git", "venv", ".venv", "dist", "build",
            "__pycache__", ".next", "target", "vendor", ".cache"}
    keep_dotdirs = {".claude", ".cursor", ".github", ".windsurf"}
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        if len(d.parts) - root_depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [x for x in dirnames if x not in skip
                       and not (x.startswith(".") and x not in keep_dotdirs)]
        for fn in filenames:
            if fn in CONFIG_NAMES:
                found.append(d / fn)

    # Directory-scoped rule formats (Cursor .mdc, Copilot instructions).
    for subdir, pattern in CONFIG_GLOBS:
        base = root / subdir
        if base.is_dir():
            found.extend(p for p in base.rglob(pattern) if p.is_file())

    return sorted(set(found))


def check_permissions(settings_path: Path) -> list:
    """Audit a settings.json permission block for capability overreach."""
    findings = []
    try:
        data = json.loads(Path(settings_path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        return [Finding(
            rule_id="POSTURE-000", severity="info",
            title="Settings file unreadable",
            detail=str(e), path=str(settings_path),
            remediation="Verify the file exists and is valid JSON.")]

    perms = data.get("permissions", {}) or {}
    allow = perms.get("allow", []) or []
    deny = perms.get("deny", []) or []
    p = str(settings_path)

    wildcards = [a for a in allow if WILDCARD_BASH.match(a.strip())]
    if wildcards:
        specific = sum(1 for a in allow if a.strip().startswith("Bash(")
                       and not WILDCARD_BASH.match(a.strip()))
        findings.append(Finding(
            rule_id="POSTURE-001", severity="critical",
            title="Unrestricted shell access granted",
            detail=(
                f"`{wildcards[0]}` permits any shell command. "
                + (f"The {specific} narrower Bash rules in this file are "
                   "therefore decorative — they constrain nothing. "
                   if specific else "")
                + "An agent with unrestricted shell can write to its own "
                  "configuration, which is the persistence mechanism worms "
                  "rely on to survive a restart."),
            path=p,
            remediation=(
                "Remove the wildcard and keep the specific rules. If a broad "
                "grant is genuinely needed, scope it per-project rather than "
                "globally, and pair it with sandbox isolation."),
            references=["arXiv:2603.15727 §6.3 (dual-anchor persistence)"]))

    egress = [a for a in allow if EGRESS_CMD.match(a.strip())]
    if egress and not wildcards:
        findings.append(Finding(
            rule_id="POSTURE-002", severity="medium",
            title=f"Network egress permitted ({len(egress)} commands)",
            detail=(
                f"Allowed: {', '.join(sorted(set(e[:22] for e in egress))[:6])}. "
                "Egress capability is what converts a local compromise into "
                "data loss or onward propagation."),
            path=p,
            remediation="Restrict to known hosts where the workflow allows it.")
        )

    if not deny:
        findings.append(Finding(
            rule_id="POSTURE-003", severity="low",
            title="No deny rules configured",
            detail=(
                "An explicit deny list is the cheapest defense-in-depth layer. "
                "Denies are evaluated ahead of allows, so a small list can "
                "protect high-value paths even under a broad allow."),
            path=p,
            remediation=(
                'Add targeted denies, e.g.: "Read(./.env)", "Read(**/*.pem)", '
                '"Bash(curl * ~/.ssh/*)", "Write(**/AGENTS.md)"')))

    return findings


def check_writable_configs(configs: list) -> list:
    """A config the agent can write is a config a worm can persist into."""
    findings = []
    for cfg in configs:
        try:
            writable = os.access(cfg, os.W_OK)
        except OSError:
            continue
        if writable:
            findings.append(Finding(
                rule_id="POSTURE-004", severity="medium",
                title="Agent config is writable",
                detail=(
                    "This file is loaded into the system prompt on every start "
                    "and is writable by the running user. AgentWorm's entire "
                    "persistence mechanism is writing into exactly this kind of "
                    "file; the payload then reloads automatically for as long as "
                    "the file survives."),
                path=str(cfg),
                remediation=(
                    "Track the file's hash with `wormhole baseline`, then run "
                    "`wormhole verify` to detect modification. Make it "
                    "read-only where the workflow permits: chmod 444"),
                references=["arXiv:2603.15727 (AgentWorm, NDSS 2026)"]))
    return findings


def check_mcp_servers(claude_json: Path) -> list:
    """Enumerate MCP servers. Each is untrusted input reaching the agent."""
    findings = []
    try:
        data = json.loads(Path(claude_json).read_text())
    except (OSError, json.JSONDecodeError):
        return findings

    servers = {}
    for name, cfg in (data.get("mcpServers") or {}).items():
        servers[name] = ("global", cfg)
    for proj, pdata in (data.get("projects") or {}).items():
        for name, cfg in ((pdata or {}).get("mcpServers") or {}).items():
            servers[f"{name} [{Path(proj).name}]"] = (proj, cfg)

    remote = []
    for name, (scope, cfg) in servers.items():
        if not isinstance(cfg, dict):
            continue
        url = cfg.get("url") or ""
        if url or cfg.get("type") in ("sse", "http"):
            remote.append((name, url))

    if remote:
        listing = ", ".join(f"{n}" for n, _ in remote[:6])
        findings.append(Finding(
            rule_id="POSTURE-005", severity="medium",
            title=f"Remote MCP servers configured ({len(remote)})",
            detail=(
                f"{listing}. Tool output from a remote server is untrusted input "
                "that lands directly in the agent's context. A compromised or "
                "malicious server can inject instructions the agent will act on."),
            path=str(claude_json),
            remediation=(
                "Confirm you control or trust each endpoint. Prefer pinned local "
                "servers over remote ones for anything privileged."))
        )
    return findings


def check_skills(skills_dir: Path) -> list:
    """Skills are the supply chain. AgentWorm's best vector, at 82%."""
    findings = []
    skills_dir = Path(skills_dir)
    if not skills_dir.is_dir():
        return findings
    entries = [d for d in skills_dir.iterdir() if d.is_dir()]
    if entries:
        findings.append(Finding(
            rule_id="POSTURE-006", severity="info",
            title=f"{len(entries)} skill(s) installed",
            detail=(
                f"{', '.join(sorted(d.name for d in entries)[:8])}. Skill content "
                "is loaded into the agent's context. Skill supply-chain "
                "poisoning was the highest-yield infection vector measured by "
                "AgentWorm at 82% attack success, ahead of web injection (51%) "
                "and direct instruction replication (55%); the authors describe "
                "every model tested as universally vulnerable to it."),
            path=str(skills_dir),
            remediation=(
                "Review the provenance of any skill you did not write. "
                "`wormhole baseline` will hash them so later modification is "
                "visible."),
            references=["arXiv:2603.15727 (Vector B: 82% ASR)"]))
    return findings
