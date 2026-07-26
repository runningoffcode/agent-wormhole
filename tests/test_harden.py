"""Tests for `harden` — the half that does not need to recognise a payload."""

import os
import stat
import tempfile
import unittest
from pathlib import Path

from wormhole import harden


class TestSymlinkRefusal(unittest.TestCase):
    """A config path that is a symlink must not be chmod-ed through.

    os.chmod follows symlinks, and the threat model is an agent that can write
    into the project: it could point CLAUDE.md at a private file elsewhere and
    have `harden --undo` widen that file to 0644.
    """

    def test_apply_refuses_a_symlinked_config(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            secret = root / "secret.txt"
            secret.write_text("private")
            os.chmod(secret, 0o600)

            link = root / "CLAUDE.md"
            link.symlink_to(secret)

            results = harden.apply([link], harden.RESTORED)

            self.assertEqual(len(results), 1)
            _, ok, err = results[0]
            self.assertFalse(ok)
            self.assertIn("symlink", err)
            # the target's mode is untouched
            self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)

    def test_apply_still_hardens_a_real_file(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "AGENTS.md"
            cfg.write_text("house rules")
            os.chmod(cfg, 0o644)

            results = harden.apply([cfg], harden.READ_ONLY)

            self.assertTrue(results[0][1])
            self.assertEqual(stat.S_IMODE(cfg.stat().st_mode), harden.READ_ONLY)


if __name__ == "__main__":
    unittest.main()
