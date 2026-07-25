"""Pre-write guard: inspect a write before it reaches an agent config file.

Everything else in this project runs after the fact. `scan` reads what is
already on disk, `watch` reads transcripts of what already happened. Both tell
you an infection arrived; neither stops it arriving.

This runs at the moment of the write. Claude Code invokes a PreToolUse hook
before Write/Edit executes, passes the pending tool input on stdin as JSON, and
honours a decision returned on stdout. That is the only point in the loop where
a payload can be refused rather than reported.

Default is warn, not block. A rule defect in a reporting tool is noise; the
same defect in a blocking tool breaks the operator's agent mid-task. This
project has already shipped one rule that fired on ordinary documentation
("re-add it to the Makefile if a rebase drops it"), so block mode is opt-in
until the corpus has earned it.
"""

import json
import sys
from pathlib import Path

from .rules.injection import scan_text
from .scanners.posture import CONFIG_NAMES

# Only writes to files an agent will later read as instructions are inspected.
# A payload in application source is a different problem and not this hook's.
WATCHED_SUFFIXES = (".md", ".mdc")
WATCHED_DIRS = ("skills", ".claude", ".cursor", ".github", ".windsurf")

# Which rules justify refusing a write in block mode. WORM-001 and WORM-003 are
# the two with an unambiguous structural signature (self-replication and
# credential exfiltration) and no corpus false positives. The softer rules warn
# even in block mode.
BLOCKING_RULES = ("WORM-001", "WORM-003")


def is_watched(path: str) -> bool:
    """True when `path` is a file an agent loads as instructions."""
    if not path:
        return False
    p = Path(path)
    if p.name in CONFIG_NAMES:
        return True
    if p.suffix in WATCHED_SUFFIXES:
        return any(part in WATCHED_DIRS for part in p.parts)
    return False


def pending_content(tool: str, tool_input: dict) -> str:
    """Extract the text a tool call is about to commit to disk."""
    if tool == "Write":
        return tool_input.get("content", "") or ""
    if tool in ("Edit", "MultiEdit"):
        # Only the incoming text can carry a payload; the string being replaced
        # is already on disk and is `scan`'s problem, not the guard's.
        edits = tool_input.get("edits")
        if isinstance(edits, list):
            return "\n".join(e.get("new_string", "") or "" for e in edits)
        return tool_input.get("new_string", "") or ""
    return ""


def inspect(tool: str, tool_input: dict, block: bool = False) -> dict:
    """Judge one pending tool call.

    Returns a dict with `action` (allow | warn | block), the findings that
    justified it, and a human-readable reason.
    """
    path = tool_input.get("file_path") or tool_input.get("path") or ""
    if tool not in ("Write", "Edit", "MultiEdit") or not is_watched(path):
        return {"action": "allow", "findings": [], "reason": ""}

    text = pending_content(tool, tool_input)
    if not text.strip():
        return {"action": "allow", "findings": [], "reason": ""}

    findings = scan_text(text, path=path)
    if not findings:
        return {"action": "allow", "findings": [], "reason": ""}

    ids = [f.rule_id for f in findings]
    blocking = [f for f in findings if f.rule_id in BLOCKING_RULES]

    if block and blocking:
        worst = blocking[0]
        return {
            "action": "block",
            "findings": ids,
            "reason": (
                f"{worst.rule_id}: {worst.title}. Refused a write to "
                f"{Path(path).name} — the text instructs its own reproduction "
                f"or exfiltrates a credential. If this is a false positive, "
                f"run the write again with the guard in warn mode."
            ),
        }

    return {
        "action": "warn",
        "findings": ids,
        "reason": (
            f"{', '.join(ids)} matched text being written to "
            f"{Path(path).name}. Allowed — the guard is in warn mode."
        ),
    }


def run_hook(stream=None, out=None, block: bool = False) -> int:
    """Read a PreToolUse payload on stdin, emit a decision on stdout.

    Exit code is always 0: a guard that crashes the agent on malformed input is
    worse than one that abstains. A failure to parse means allow.
    """
    stream = stream or sys.stdin
    out = out or sys.stdout
    try:
        payload = json.load(stream)
    except (ValueError, OSError):
        return 0

    tool = payload.get("tool_name") or payload.get("tool") or ""
    tool_input = payload.get("tool_input") or payload.get("input") or {}
    if not isinstance(tool_input, dict):
        return 0

    verdict = inspect(tool, tool_input, block=block)

    if verdict["action"] == "block":
        json.dump({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": verdict["reason"],
            }
        }, out)
    elif verdict["action"] == "warn":
        json.dump({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "additionalContext": verdict["reason"],
            }
        }, out)

    return 0
