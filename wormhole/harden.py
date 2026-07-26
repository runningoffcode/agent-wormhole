"""Make agent config files unwritable by the agent that reads them.

A worm needs read *and* write on the same file to reproduce: it is loaded into
the system prompt at session start, and it copies itself into the next config
the agent touches. Remove the write and the replication loop has nowhere to
close, regardless of whether any rule recognises the payload.

This is the cheap approximation of sandbox isolation. Isolation is the control
that actually drives infection to zero, but it lives in the agent framework and
almost nobody enables it. Dropping the write bit is something the operator can
do today, from outside the agent, with no framework support.

Scope, stated honestly: this stops an agent from rewriting a config through
ordinary file writes. It does not stop a process running as the same user that
deliberately restores the mode first, and it does nothing about payloads that
arrive through tool output rather than disk. It raises the cost of the most
common propagation path; it is not a boundary.
"""

import os
import stat
from pathlib import Path

from .scanners.posture import find_agent_configs

# Read for owner and group, write for nobody. Kept deliberately narrow: the
# operator edits these files by raising the mode back, which is a visible act.
READ_ONLY = 0o444
# What a hardened file is restored to. Owner-writable, matching the usual
# default for a checked-out source file.
RESTORED = 0o644

# Config paths an agent loads but which frequently do not exist yet. These are
# the ones that matter most: you cannot chmod a file that is absent, so an
# attacker who CREATES one lands a payload that hardening never covered.
#
# This is not hypothetical. Miasma (June 2026, 73 Microsoft repositories) did
# not edit existing configuration -- it created .claude/settings.json,
# .gemini/settings.json, .cursor/rules/setup.mdc and .vscode/tasks.json, each
# carrying a hook or task that runs a dropper on session start or folder open.
# CVE-2026-25725 has the same shape: a Claude Code sandbox escape that worked
# precisely because settings.json did not exist, so bubblewrap could not
# read-only-bind it.
#
# Creating these empty and read-only closes the hole. An empty JSON object is
# inert to every agent that reads it, and 0444 means the create fails.
PRECREATE = (
    (".claude/settings.json", "{}\n"),
    (".gemini/settings.json", "{}\n"),
    (".vscode/tasks.json", '{"version": "2.0.0", "tasks": []}\n'),
    ("AGENTS.md", ""),
    ("CLAUDE.md", ""),
)


def _writable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & stat.S_IWUSR)
    except OSError:
        return False


def plan(root: Path, include_skills: bool = True) -> list:
    """Return the config files that are currently agent-writable.

    Skills are included by default: skill supply-chain poisoning was the
    highest-yield vector in the AgentWorm trials, and a skill file is read
    into context exactly like an instruction file.
    """
    root = Path(root)
    targets = [p for p in find_agent_configs(root) if _writable(p)]

    if include_skills:
        skills = Path.home() / ".claude" / "skills"
        if skills.is_dir():
            targets.extend(p for p in skills.rglob("*.md")
                           if p.is_file() and _writable(p))

    return sorted(set(targets))


def plan_precreate(root: Path) -> list:
    """Config paths that do not exist yet and could be created by an attacker.

    Returns (path, placeholder_content) pairs. Only paths whose parent
    directory already exists, or is one the agent tooling owns, are offered --
    creating .gemini/ inside a project that has never used Gemini is noise.
    """
    root = Path(root)
    out = []
    for rel, placeholder in PRECREATE:
        p = root / rel
        if p.exists():
            continue
        parent = p.parent
        # Root-level files are always in scope. Files inside a tool directory
        # only matter if that tool is actually in use here.
        if parent == root or parent.is_dir():
            out.append((p, placeholder))
    return out


def precreate(pairs) -> list:
    """Create each missing path with inert content, then make it read-only."""
    results = []
    for p, placeholder in pairs:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            # Refuse to clobber anything that appeared since planning.
            if p.exists():
                results.append((p, False, "already exists"))
                continue
            p.write_text(placeholder, encoding="utf-8")
            os.chmod(p, READ_ONLY)
            results.append((p, True, None))
        except OSError as exc:
            results.append((p, False, str(exc)))
    return results


def hardened(root: Path, include_skills: bool = True) -> list:
    """Return config files that are already read-only."""
    root = Path(root)
    found = [p for p in find_agent_configs(root) if not _writable(p)]
    if include_skills:
        skills = Path.home() / ".claude" / "skills"
        if skills.is_dir():
            found.extend(p for p in skills.rglob("*.md")
                         if p.is_file() and not _writable(p))
    return sorted(set(found))


def apply(paths, mode: int = READ_ONLY) -> list:
    """Set `mode` on each path. Returns (path, ok, error) triples.

    Symlinks are refused rather than followed. `os.chmod` dereferences by
    default, and the threat model here is an agent that can write into the
    project: it could leave `CLAUDE.md` pointing at a private file elsewhere,
    and `--undo` would then widen that file's permissions to 0644. A config
    file is never legitimately a symlink, so declining costs nothing.
    """
    results = []
    for p in paths:
        try:
            if Path(p).is_symlink():
                results.append(
                    (p, False, "refusing to change mode through a symlink")
                )
                continue
            os.chmod(p, mode)
            results.append((p, True, None))
        except OSError as exc:
            results.append((p, False, str(exc)))
    return results
