"""One command that leaves the machine measurably harder to infect.

The research finding this project exists because of is not that a defense is
missing. It is that the defense exists and 0 of 82 real deployments had it
switched on. That is an adoption failure, and adoption failures are made of
steps: every command between "I learned I am exposed" and "I am no longer
exposed" is a place where someone stops.

`scan` reports. `harden`, `guard` and `baseline` each fix one thing, and each
is a separate decision the operator has to make and remember. This collapses
them into one call, keeps the project's dry-run convention, and prints what it
changed so the operator can undo any piece of it.

Ordering is deliberate:

  1. harden    remove the write. Works on payloads no rule has ever seen, so
               it is the strongest control here and runs first.
  2. baseline  record hashes AFTER hardening, so the recorded state is the
               clean, protected one. Catches whatever the rules miss.
  3. guard     print the hook block. Cannot be installed for the operator --
               it edits settings.json, and a security tool that silently
               rewrites the file it is auditing has become the thing it warns
               about.
"""

from pathlib import Path

from . import harden as harden_mod
from .baseline import record
from .scanners.posture import find_agent_configs


def plan(root: Path, include_skills: bool = True) -> dict:
    """What `init` would do, without doing any of it."""
    root = Path(root)
    return {
        "to_harden": harden_mod.plan(root, include_skills=include_skills),
        "already_hardened": harden_mod.hardened(root, include_skills=include_skills),
    }


def apply(root: Path, include_skills: bool = True) -> dict:
    """Harden, then baseline. Returns what actually happened.

    The guard hook is never written for the operator; see the module note.
    """
    root = Path(root)
    targets = harden_mod.plan(root, include_skills=include_skills)
    results = harden_mod.apply(targets, harden_mod.READ_ONLY)

    # Baseline after hardening so the recorded hashes describe the protected
    # state. Baselining first would enshrine the pre-fix bytes as "known good".
    configs = find_agent_configs(root)
    try:
        entries = record(configs)
        baseline_ok, baseline_n = True, len(entries)
    except OSError as exc:
        baseline_ok, baseline_n = False, str(exc)

    return {
        "hardened": [(p, ok, err) for p, ok, err in results],
        "baseline_ok": baseline_ok,
        "baseline_count": baseline_n,
    }
