"""Who changed this file, and was an agent running at the time.

`verify` can say a config's hash no longer matches. It cannot say whether you
edited it in your editor or an agent rewrote it mid-session, and that is the
question an operator actually asks first. "The hash differs" starts an
investigation; "this changed at 14:02 while a Claude Code session was open, and
you have no editor history for it" ends one.

This is deliberately built from evidence the operating system already keeps,
because the alternative -- a daemon watching the filesystem -- is a privileged
background process, which is a worse thing to install than the risk it
mitigates.

Three signals, none conclusive alone:

  mtime vs session windows   a change inside an agent session's active window
                             is attributable to that session
  ownership and mode         a file whose owner or mode changed since baseline
                             was touched by something other than an editor
  git status                 a tracked file modified but never staged, in a
                             repo with a clean index, is an unattended edit

The output is a judgement with its reasoning attached, not a verdict. An agent
legitimately edits configs all the time; the point is to make the operator
aware of *when* it happened so an unexpected one stands out.
"""

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .rules.injection import Finding

TRANSCRIPT_ROOT = Path.home() / ".claude" / "projects"

# How close a modification must be to session activity to be attributed to it.
# Generous, because transcript timestamps record model turns rather than the
# moment a tool wrote to disk.
ATTRIBUTION_WINDOW_S = 900


def _mtime(path: Path):
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None


def session_windows(limit: int = 40) -> list:
    """(start, end, session_id) for recent agent sessions, from transcripts."""
    if not TRANSCRIPT_ROOT.is_dir():
        return []

    # Session transcripts are named for their session UUID and sit directly in
    # a project directory. Subagent and workflow journals live in nested
    # directories and are not sessions -- including them would attribute a
    # config change to a "session" that never touched the filesystem.
    def is_session(p: Path) -> bool:
        if p.parent.parent != TRANSCRIPT_ROOT:
            return False
        stem = p.stem
        return len(stem) == 36 and stem.count("-") == 4

    files = sorted(
        (p for p in TRANSCRIPT_ROOT.rglob("*.jsonl")
         if p.is_file() and is_session(p)),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:limit]

    windows = []
    for f in files:
        try:
            stat = f.stat()
        except OSError:
            continue
        end = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        # st_ctime is inode-change time, not creation time, so on a file that
        # is appended to it equals mtime and the window collapses to a point.
        # Use birthtime where the platform records it, and fall back to the
        # first record's own timestamp.
        start = None
        bt = getattr(stat, "st_birthtime", None)
        if bt:
            start = datetime.fromtimestamp(bt, tz=timezone.utc)
        else:
            start = _first_record_time(f)
        if start is None or start > end:
            start = end
        windows.append((start, end, f.stem))
    return windows


def _first_record_time(path: Path):
    """Timestamp of a transcript's first record, if it carries one."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    return None
                ts = rec.get("timestamp")
                if isinstance(ts, str):
                    try:
                        return datetime.fromisoformat(
                            ts.replace("Z", "+00:00"))
                    except ValueError:
                        return None
                return None
    except OSError:
        return None
    return None


def _attribute(path: Path, windows: list):
    """Which session, if any, was active when this file was last written."""
    m = _mtime(path)
    if m is None:
        return None
    for start, end, sid in windows:
        lo = start.timestamp() - ATTRIBUTION_WINDOW_S
        hi = end.timestamp() + ATTRIBUTION_WINDOW_S
        if lo <= m.timestamp() <= hi:
            return sid, m
    return None


def _git_unstaged(path: Path) -> bool:
    """True when the file is tracked and modified but not staged."""
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain", "--", str(path)],
            cwd=str(path.parent), capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    line = (out.stdout or "").strip()
    # " M path" = modified, unstaged. "?? path" = untracked.
    return line.startswith(" M") or line.startswith("??")


def describe(path: Path, windows=None) -> dict:
    """Everything known about how this file came to be in its current state."""
    path = Path(path)
    windows = session_windows() if windows is None else windows
    m = _mtime(path)

    info = {
        "path": str(path),
        "modified": m.isoformat(timespec="seconds") if m else None,
        "session": None,
        "unstaged": _git_unstaged(path),
        "mode": None,
        "owner": None,
    }

    try:
        st = path.stat()
        info["mode"] = oct(st.st_mode & 0o777)
        info["owner"] = st.st_uid
    except OSError:
        pass

    attributed = _attribute(path, windows)
    if attributed:
        info["session"] = attributed[0]

    return info


def check(paths, windows=None) -> list:
    """Findings for configs that changed during an agent session.

    Only fires alongside an actual integrity failure -- this module explains a
    change, it does not decide that one happened. Callers pass the paths that
    `verify` already flagged.
    """
    windows = session_windows() if windows is None else windows
    findings = []

    for p in paths:
        p = Path(p)
        info = describe(p, windows)
        if not info["session"]:
            continue

        detail = (
            f"Last written {info['modified']}, inside the active window of "
            f"agent session {info['session'][:12]}. An agent editing the file "
            f"it also reads as instruction is the exact loop this tool exists "
            f"to break, so a change you did not make yourself is worth "
            f"reading before the next session starts."
        )
        if info["unstaged"]:
            detail += (" The file is also modified-but-unstaged in git, so the "
                       "change has not passed through review.")

        findings.append(Finding(
            rule_id="PROV-001", severity="high",
            title="Config changed during an agent session",
            detail=detail,
            path=str(p),
            remediation=(
                "Diff the file against the last commit. If you did not make "
                "this edit, treat every agent that has since loaded it as "
                "having run whatever it now says."),
        ))

    return findings
