"""Baseline and verification: the containment half of the tool.

Detection rules only catch payloads that match a known shape. Hashing catches
*any* modification, including payloads written by an attacker this tool has
never seen. That property matters more than rule coverage: the rules will
always lag novel phrasing, but a changed hash is a changed hash.

The baseline is stored outside the scanned tree so that an agent writing to
its own project cannot silently rewrite the record of what it used to be.
"""

import hashlib
import json
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


def load_baseline() -> dict:
    if not BASELINE_FILE.exists():
        return {}
    try:
        return json.loads(BASELINE_FILE.read_text())
    except json.JSONDecodeError:
        return {}


def save_baseline(entries: dict) -> Path:
    BASELINE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {"version": 1, "updated": _now(), "files": entries}
    BASELINE_DIR.chmod(0o700)
    BASELINE_FILE.write_text(json.dumps(payload, indent=2))
    BASELINE_FILE.chmod(0o600)
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
    stored = load_baseline().get("files", {})
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
                rule_id="BASELINE-003", severity="medium",
                title="Agent config not in baseline",
                detail="This file was not present when the baseline was taken.",
                path=path_str,
                remediation=("Confirm you created it, then re-run "
                             "`wormhole baseline`.")))
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
