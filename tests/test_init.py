"""`init` exists because the defense being available is not the same as the
defense being on. These tests pin the two properties that make it trustworthy:
it changes nothing without --apply, and the order of operations is correct.
"""

import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from wormhole import init


class InitTestCase(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "AGENTS.md").write_text("# Rules\nUse pnpm.\n")
        (self.root / "CLAUDE.md").write_text("# Claude\nBe terse.\n")

    def tearDown(self):
        for p in self.root.rglob("*"):
            if p.is_file():
                os.chmod(p, 0o644)
        shutil.rmtree(self.root, ignore_errors=True)

    def _writable(self, name):
        return bool(Path(self.root / name).stat().st_mode & stat.S_IWUSR)

    def test_plan_changes_nothing(self):
        """The dry run is the default, and it must be inert."""
        p = init.plan(self.root, include_skills=False)
        self.assertEqual(len(p["to_harden"]), 2)
        self.assertTrue(self._writable("AGENTS.md"))
        self.assertTrue(self._writable("CLAUDE.md"))

    def test_apply_removes_the_write(self):
        init.apply(self.root, include_skills=False)
        self.assertFalse(self._writable("AGENTS.md"))
        self.assertFalse(self._writable("CLAUDE.md"))

    def test_apply_records_a_baseline(self):
        res = init.apply(self.root, include_skills=False)
        self.assertTrue(res["baseline_ok"])
        self.assertGreaterEqual(res["baseline_count"], 2)

    def test_baseline_runs_after_hardening(self):
        """Recording first would enshrine the pre-fix bytes as known-good.
        The files must already be read-only by the time hashes are taken."""
        seen = {}
        real = init.record

        def spy(paths):
            seen["modes"] = [
                bool(Path(p).stat().st_mode & stat.S_IWUSR) for p in paths
            ]
            return real(paths)

        init.record = spy
        try:
            init.apply(self.root, include_skills=False)
        finally:
            init.record = real

        self.assertTrue(seen["modes"])
        self.assertFalse(any(seen["modes"]),
                         "baseline was taken while files were still writable")

    def test_apply_is_idempotent(self):
        init.apply(self.root, include_skills=False)
        again = init.apply(self.root, include_skills=False)
        self.assertEqual(again["hardened"], [])
        self.assertTrue(again["baseline_ok"])

    def test_never_writes_settings_json(self):
        """The guard hook is printed, never installed. A security tool that
        edits the file it audits is the thing it warns about."""
        settings = self.root / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text('{"permissions":{"allow":[]}}')
        before = settings.read_text()
        init.apply(self.root, include_skills=False)
        self.assertEqual(settings.read_text(), before)


if __name__ == "__main__":
    unittest.main()
