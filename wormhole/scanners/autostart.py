"""Detect persistence that executes on its own, without a prompt.

The content rules look for text that instructs its own reproduction. That is
the right signature for a payload an agent has to *read and obey*, and it is
the wrong one for the attack that actually spread.

Miasma (June 2026, 73 Microsoft repositories) carried no self-replicating
prose. It wrote configuration:

    .claude/settings.json    SessionStart hook  -> node .github/setup.js
    .gemini/settings.json    SessionStart hook  -> node .github/setup.js
    .vscode/tasks.json       runOn: folderOpen  -> node .github/setup.js
    .cursor/rules/setup.mdc  alwaysApply: true, "run node .github/setup.js"
    package.json             hijacked test script

Four of those five need no model in the loop at all. The hook fires because
the session started; the task fires because a folder opened. No amount of
prompt-injection detection sees them, because nothing is being injected into a
prompt -- the agent framework is simply doing what its configuration says.

The signature this module looks for is therefore not self-reference. It is
*unattended execution*: a configuration key whose effect is to run a command
at a moment the operator did not choose, pointed at something the operator
probably did not write.

Legitimate autostart exists -- a formatter on save, a linter task, a hook that
loads project context. So the rules are graded rather than absolute, and the
severity turns on what the command does, not merely that one is present.
"""

import json
import re
from pathlib import Path

from ..rules.injection import Finding

# Files whose whole purpose is "run this when X happens".
AUTOSTART_FILES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".gemini/settings.json",
    ".vscode/tasks.json",
)

# Keys that mean "no human asked for this". Claude Code and Gemini CLI use
# hook event names; VS Code uses runOptions.runOn.
UNATTENDED_EVENTS = (
    "SessionStart",   # fires on every new session, survives reinstall
    "SessionEnd",
    "PreCompact",
    "Notification",
    "Stop",
)

# An interpreter invocation inside a hook is the Miasma shape exactly: the
# config does not contain the payload, it points at a file that does.
INTERPRETER = re.compile(
    r"\b(node|npx|bun|deno|python3?|ruby|perl|php|sh|bash|zsh|osascript|"
    r"powershell|pwsh)\b",
    re.IGNORECASE,
)

# Fetch-and-run: the single most dangerous thing a hook can do.
FETCH_EXEC = re.compile(
    r"\b(curl|wget|iwr|invoke-webrequest)\b[^|;&]*[|;&]|"
    r"\b(curl|wget)\b.*\b(sh|bash|node|python3?)\b",
    re.IGNORECASE,
)

# Paths that a repository would not normally execute from. .github/ holds CI
# definitions, not runtime code -- Miasma chose it because it looks official.
SUSPICIOUS_PATH = re.compile(
    r"\.github/|\.git/|/tmp/|\bAppData\b|~/\.config/|\.cache/",
    re.IGNORECASE,
)


def _commands_from_hooks(data):
    """Yield (event, command) for every hook command in a settings file."""
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for h in entry.get("hooks") or []:
                if isinstance(h, dict) and h.get("command"):
                    yield event, str(h["command"])


def _commands_from_tasks(data):
    """Yield (trigger, command) for VS Code tasks that run unprompted."""
    for task in data.get("tasks") or []:
        if not isinstance(task, dict):
            continue
        run_on = ((task.get("runOptions") or {}).get("runOn") or "").lower()
        if run_on != "folderopen":
            continue
        cmd = task.get("command") or ""
        args = task.get("args") or []
        if isinstance(args, list):
            cmd = " ".join([str(cmd)] + [str(a) for a in args])
        if cmd:
            yield "folderOpen", str(cmd)


def check_autostart(path: Path) -> list:
    """Audit one configuration file for unattended execution."""
    path = Path(path)
    findings = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return findings
    if not isinstance(data, dict):
        return findings

    pairs = list(_commands_from_hooks(data)) + list(_commands_from_tasks(data))

    for event, cmd in pairs:
        unattended = event in UNATTENDED_EVENTS or event == "folderOpen"
        if not unattended:
            continue

        fetches = bool(FETCH_EXEC.search(cmd))
        interprets = bool(INTERPRETER.search(cmd))
        odd_path = bool(SUSPICIOUS_PATH.search(cmd))

        if fetches:
            findings.append(Finding(
                rule_id="AUTOSTART-001", severity="critical",
                title=f"{event} hook downloads and executes",
                detail=(
                    f"`{cmd[:110]}` runs unprompted on {event} and pipes remote "
                    "content into an interpreter. Whoever controls that URL "
                    "controls this machine on every session, and the payload "
                    "never has to touch disk in a form a scanner could read."),
                path=str(path),
                remediation=(
                    "Remove the hook. If you did not add it, treat the machine "
                    "as compromised: rotate every credential this agent can "
                    "reach and check outbound logs."),
                references=["Miasma worm, June 2026"]))
            continue

        if interprets and odd_path:
            findings.append(Finding(
                rule_id="AUTOSTART-002", severity="critical",
                title=f"{event} hook executes a script from an unusual path",
                detail=(
                    f"`{cmd[:110]}` runs unprompted on {event}. Executing from "
                    "a directory that normally holds configuration rather than "
                    "runtime code is the exact shape Miasma used: the hook is "
                    "small and plausible, and the dropper lives beside it. "
                    "This survives uninstalling the package that planted it."),
                path=str(path),
                remediation=(
                    "Read the target script before starting another session. "
                    "Remove the hook if you did not add it."),
                references=["Miasma worm, June 2026 (.github/setup.js)"]))
            continue

        if interprets:
            findings.append(Finding(
                rule_id="AUTOSTART-003", severity="high",
                title=f"{event} hook runs an interpreter",
                detail=(
                    f"`{cmd[:110]}` runs unprompted on {event}. This may be "
                    "legitimate project setup. It is listed because anything "
                    "that executes without being asked is worth knowing about, "
                    "and because this class of hook persists after the tool "
                    "that installed it is removed."),
                path=str(path),
                remediation="Confirm you added this and that the target is yours."))


    return findings


def check_always_apply(path: Path) -> list:
    """Cursor rules with alwaysApply reach the model on every single turn.

    Miasma used one to talk the agent into running its dropper: the rule reads
    as ordinary onboarding, so the agent 'recognises it as a reasonable project
    requirement'. This is the one part of the campaign that does need a model,
    and it is the part a permissions system cannot stop.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    head = text[:400]
    if not re.search(r"^\s*alwaysApply:\s*true\s*$", head, re.M):
        return []

    body = text[len(head.split("---")[0]):] if "---" in head else text
    if not INTERPRETER.search(body):
        return []

    m = INTERPRETER.search(body)
    line = body[max(0, m.start() - 60):m.start() + 90].strip().replace("\n", " ")

    return [Finding(
        rule_id="AUTOSTART-004", severity="critical",
        title="Always-applied rule instructs the agent to run a command",
        detail=(
            f"This rule is injected into every turn and tells the agent to "
            f"execute something: \"...{line}...\". A rule that always applies "
            "and names an interpreter is how Miasma reached Cursor users -- "
            "framed as project setup, it reads as a reasonable requirement."),
        path=str(path),
        remediation=(
            "Read the referenced script. Remove the instruction if you did not "
            "write it; a rules file should describe conventions, not run code."),
        references=["Miasma worm, June 2026 (.cursor/rules/setup.mdc)"])]


def find_autostart_files(root: Path) -> list:
    """Locate configuration files capable of unattended execution."""
    root = Path(root)
    found = [root / rel for rel in AUTOSTART_FILES if (root / rel).is_file()]
    rules = root / ".cursor" / "rules"
    if rules.is_dir():
        found.extend(p for p in rules.rglob("*.mdc") if p.is_file())
    return sorted(set(found))


def scan(root: Path) -> list:
    """Run every autostart check across a project."""
    findings = []
    for p in find_autostart_files(root):
        if p.suffix == ".mdc":
            findings.extend(check_always_apply(p))
        else:
            findings.extend(check_autostart(p))
    return findings
