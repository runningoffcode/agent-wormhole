"""AW-30 and AW-31 — the two CI findings, as tests.

AW-30 was arbitrary code execution in EVERY consumer's CI, from one file in an
unreviewed pull request, with the gate reporting green. AW-31 meant the
action's default configuration silently disabled half the product.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class TestActionImportHijack(unittest.TestCase):
    """AW-30: `python -m wormhole` must not resolve from the scanned repo."""

    def test_action_does_not_run_from_the_callers_workspace(self):
        # The fix is structural and lives in action.yml: the run step's
        # working-directory must be the ACTION's checkout, never the caller's
        # workspace, because `-m` puts the CWD at sys.path[0] ahead of
        # PYTHONPATH. Assert the shape, since the failure is a YAML property.
        action = (REPO / "action.yml").read_text()
        self.assertIn("working-directory: ${{ github.action_path }}", action)
        self.assertNotIn(
            "working-directory: ${{ github.workspace }}",
            action,
            "the scan step must not run from the caller's workspace",
        )

    def test_a_hostile_wormhole_package_in_the_target_is_not_imported(self):
        with tempfile.TemporaryDirectory() as ws:
            hostile = Path(ws) / "wormhole"
            hostile.mkdir()
            (hostile / "__init__.py").write_text("")
            # If this ran, the marker would appear and the gate would exit 0.
            (hostile / "__main__.py").write_text(
                "print('PWNED'); raise SystemExit(0)\n"
            )
            proc = subprocess.run(
                [sys.executable, "-m", "wormhole", "scan", ws, "--no-color"],
                cwd=REPO,  # what the fixed action does
                capture_output=True,
                text=True,
            )
            self.assertNotIn("PWNED", proc.stdout + proc.stderr)
            self.assertIn("wormhole", proc.stdout.lower())


class TestLocalOnlyScope(unittest.TestCase):
    """AW-31: --local-only must skip HOME, not the scanned repo's own config."""

    def _scan(self, target, home, *extra):
        return subprocess.run(
            [sys.executable, "-m", "wormhole", "scan", str(target),
             "--fail-on", "high", "--no-color", *extra],
            cwd=REPO,
            capture_output=True,
            text=True,
            env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
        )

    def test_local_only_still_scans_the_repos_own_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".claude").mkdir(parents=True)
            # The auditor's exact reproduction: a repo granting Bash(*).
            (ws / ".claude/settings.json").write_text(
                json.dumps({"permissions": {"allow": ["Bash(*)", "Bash(curl:*)"], "deny": []}})
            )
            home = Path(tmp) / "emptyhome"
            home.mkdir()

            proc = self._scan(ws, home, "--local-only")
            # Was: "no issues found", exit 0 — an affirmative all-clear on a
            # repository granting unrestricted shell.
            self.assertIn("POSTURE-001", proc.stdout)
            self.assertEqual(proc.returncode, 1)

    def test_a_clean_repo_still_passes_under_local_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            home = Path(tmp) / "emptyhome"
            home.mkdir()
            self.assertEqual(self._scan(ws, home, "--local-only").returncode, 0)

    def test_local_only_does_not_reach_into_HOME(self):
        # The half of the flag that is real and must keep working: a user's
        # own machine config is not CI's business.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            home = Path(tmp) / "home"
            (home / ".claude").mkdir(parents=True)
            (home / ".claude/settings.json").write_text(
                json.dumps({"permissions": {"allow": ["Bash(*)"], "deny": []}})
            )
            self.assertEqual(self._scan(ws, home, "--local-only").returncode, 0)
            # ...and without the flag, it is found.
            self.assertEqual(self._scan(ws, home).returncode, 1)


if __name__ == "__main__":
    unittest.main()
