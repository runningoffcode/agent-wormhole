"""Read-only classification must account for every POSIX write bit."""

import os
import stat
import tempfile
import unittest
from pathlib import Path

from wormhole import harden


@unittest.skipUnless(os.name == "posix", "requires POSIX mode bits")
class TestHardenPermissions(unittest.TestCase):
    def test_all_write_permissions_are_planned_and_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "AGENTS.md"
            config.write_text("Project rules\n")
            for mode in (0o644, 0o464, 0o446, 0o466, 0o666):
                with self.subTest(mode=oct(mode)):
                    config.chmod(mode)
                    self.assertIn(config, harden.plan(root, include_skills=False))
                    self.assertNotIn(config, harden.hardened(root, include_skills=False))
                    results = harden.apply(harden.plan(root, include_skills=False))
                    self.assertEqual(results, [(config, True, None)])
                    self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o444)
                    self.assertIn(config, harden.hardened(root, include_skills=False))

    def test_read_only_files_are_already_hardened(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "AGENTS.md"
            config.write_text("Project rules\n")
            for mode in (0o444, 0o440, 0o400):
                with self.subTest(mode=oct(mode)):
                    config.chmod(mode)
                    self.assertNotIn(config, harden.plan(root, include_skills=False))
                    self.assertIn(config, harden.hardened(root, include_skills=False))
