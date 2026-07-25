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
    """Set `mode` on each path. Returns (path, ok, error) triples."""
    results = []
    for p in paths:
        try:
            os.chmod(p, mode)
            results.append((p, True, None))
        except OSError as exc:
            results.append((p, False, str(exc)))
    return results
