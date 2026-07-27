"""Baseline and verification: the containment half of the tool.

Detection rules only catch payloads that match a known shape. Hashing catches
*any* modification, including payloads written by an attacker this tool has
never seen. That property matters more than rule coverage: the rules will
always lag novel phrasing, but a changed hash is a changed hash.

The baseline is stored outside the scanned tree, in ~/.wormhole. That raises
the cost of tampering -- a payload scoped to the project directory, a poisoned
dependency, or a CI job with only the workspace mounted cannot reach it -- and
it is why the record survives the case this tool is actually built for.

Scope, stated plainly, because the containment claim is only as good as its
weakest assumption: the agent runs as the same uid you do, and ~/.wormhole is
0700 owned by that uid. An agent with unrestricted shell access can therefore
read, rewrite, or delete this file exactly as you can. Nothing here is a
cryptographic guarantee against a fully compromised session.

What it does buy: tampering must be deliberate and targeted rather than
incidental. Re-recording the baseline is a distinct act from writing to the
project, so a worm that only edits config files leaves the record intact and
gets caught by it. `verify` reports a corrupt file loudly (BASELINE-004,
high) rather than treating it as absence, so wiping the baseline is not a
quiet way to pass a check.

The durable control against an agent that can reach ~/.wormhole is the same
one that applies to `harden`: restrict what the agent is permitted to do.
Sandbox isolation drove attack success to zero in research; it lives in your
agent framework, not in this tool.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .rules.injection import Finding

BASELINE_DIR = Path.home() / ".wormhole"
BASELINE_FILE = BASELINE_DIR / "baseline.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CorruptBaseline(Exception):
    """The baseline file exists but could not be parsed.

    Distinct from absence on purpose. Swallowing the parse error and returning
    {} made a corrupt record indistinguishable from a fresh install: `verify`
    reported "no baseline recorded" at info severity and exited clean, which is
    the silent-allow failure mode the guard hook is explicitly designed to
    avoid. A truncated write, a full disk, or an attacker who cannot delete the
    file but can scribble on it all land here.
    """


def load_baseline() -> dict:
    if not BASELINE_FILE.exists():
        return {}
    try:
        return json.loads(BASELINE_FILE.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CorruptBaseline(str(exc)) from exc


def _write_atomic(path: Path, data: str, mode: int = 0o600) -> None:
    """Write via a temp file in the same directory, then os.replace.

    Every writer here used a plain write_text(), which truncates before it
    writes: a crash or a full disk between those two steps leaves a zero-length
    or half-written file. os.replace is atomic within a filesystem, so a reader
    sees either the old contents or the new ones and never a partial record.
    """
    tmp = path.with_name(f".{path.name}.tmp{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def save_baseline(entries: dict) -> Path:
    BASELINE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {"version": 1, "updated": _now(), "files": entries}
    BASELINE_DIR.chmod(0o700)
    _write_atomic(BASELINE_FILE, json.dumps(payload, indent=2))
    return BASELINE_FILE


def record(paths) -> dict:
    """Hash each path and persist. Returns the stored entry map."""
    existing = load_baseline().get("files", {})
    for p in paths:
        p = Path(p)
        if not p.is_file():
            continue
        existing[str(p.resolve())] = {
            "sha256": sha256(p),
            "size": p.stat().st_size,
            "recorded": _now(),
        }
    save_baseline(existing)
    return existing


def verify(paths=None) -> list:
    """Compare current state against the recorded baseline."""
    try:
        stored = load_baseline().get("files", {})
    except CorruptBaseline as exc:
        # Loud and high, never info. An unreadable baseline means every
        # subsequent check in this run is unbacked -- reporting that as "no
        # baseline recorded" would hand the operator a clean exit on a machine
        # whose containment record has been destroyed.
        return [Finding(
            rule_id="BASELINE-004", severity="high",
            title="Baseline file is unreadable",
            detail=(f"{BASELINE_FILE} exists but could not be parsed ({exc}). "
                    f"Nothing was verified. A corrupt record is not the same "
                    f"as no record: it can mean an interrupted write, a full "
                    f"disk, or tampering by something that could not delete "
                    f"the file."),
            path=str(BASELINE_FILE),
            remediation=("Inspect the file before overwriting it -- it is the "
                         "only evidence of what changed. Once reviewed, "
                         "re-record with: wormhole baseline"))]

    findings = []

    if not stored:
        return [Finding(
            rule_id="BASELINE-000", severity="info",
            title="No baseline recorded",
            detail=("Nothing to verify against. A baseline is what lets you "
                    "detect a payload whose wording no rule anticipates."),
            remediation="Run: wormhole baseline")]

    targets = {str(Path(p).resolve()) for p in paths} if paths else set(stored)

    for path_str in sorted(targets):
        entry = stored.get(path_str)
        p = Path(path_str)

        if entry is None:
            findings.append(Finding(
                rule_id="BASELINE-003", severity="high",
                title="Agent config not in baseline",
                detail=(
                    "This file was not present when the baseline was taken. An "
                    "agent instruction file appearing on its own is how "
                    "config-based persistence actually lands: Miasma (June "
                    "2026) established itself in 73 Microsoft repositories by "
                    "creating .claude/settings.json, .gemini/settings.json, "
                    ".cursor/rules/setup.mdc and .vscode/tasks.json rather than "
                    "editing anything that already existed. A file that never "
                    "existed cannot be caught by a content diff, and cannot be "
                    "protected by making existing files read-only."),
                path=path_str,
                remediation=(
                    "If you did not create this file, treat it as hostile: read "
                    "it before any agent loads it, and check whether it invokes "
                    "a script on session start. If you did create it, re-run "
                    "`wormhole baseline` to adopt it."),
                references=["Miasma worm, June 2026 (config-file persistence)"]))
            continue

        if not p.is_file():
            findings.append(Finding(
                rule_id="BASELINE-002", severity="medium",
                title="Baselined file is missing",
                detail="A file under integrity monitoring no longer exists.",
                path=path_str,
                remediation="Restore it, or re-baseline if removal was intended."))
            continue

        current = sha256(p)
        if current != entry["sha256"]:
            findings.append(Finding(
                rule_id="BASELINE-001", severity="high",
                title="Agent config modified since baseline",
                detail=(
                    f"Content hash changed (recorded {entry['recorded']}).\n"
                    f"      expected {entry['sha256'][:16]}...\n"
                    f"      actual   {current[:16]}..."),
                path=path_str,
                remediation=(
                    "Review the diff before an agent loads this file again. If "
                    "you did not make this change, treat every agent that has "
                    "read it as compromised: revert the file, rotate reachable "
                    "credentials, and check outbound logs for propagation.")))

    return findings
