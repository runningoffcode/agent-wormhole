"""State on disk must fail loud, and must never be left half-written.

Two failure modes are covered here, both reported by an external reviewer:

  - load_baseline() swallowed JSONDecodeError and returned {}, so `verify`
    emitted BASELINE-000 "no baseline recorded" at info severity and exited
    clean. A corrupt record was indistinguishable from a fresh install --
    the same silent-allow shape the guard hook is explicitly designed to
    avoid.

  - every writer used a plain write_text(), which truncates before it writes.
    A crash, a full disk, or a killed process between those two steps
    produces exactly the corrupt file above. os.replace is atomic within a
    filesystem, so a reader sees the old contents or the new ones, never a
    partial record.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wormhole import baseline


class CorruptBaselineIsLoud(unittest.TestCase):

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.file = self.home / "baseline.json"
        self._patches = [
            mock.patch.object(baseline, "BASELINE_DIR", self.home),
            mock.patch.object(baseline, "BASELINE_FILE", self.file),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()

    def test_absent_baseline_is_info(self):
        findings = baseline.verify()
        self.assertEqual([f.rule_id for f in findings], ["BASELINE-000"])
        self.assertEqual(findings[0].severity, "info")

    def test_truncated_baseline_is_high_and_distinct(self):
        """The exact state an interrupted write leaves behind."""
        self.file.write_text('{"version": 1, "files": {"a": ')
        findings = baseline.verify()
        self.assertEqual([f.rule_id for f in findings], ["BASELINE-004"])
        self.assertEqual(findings[0].severity, "high")

    def test_empty_baseline_file_is_high(self):
        """Zero-length is the most likely corruption: truncate, then die."""
        self.file.write_text("")
        findings = baseline.verify()
        self.assertEqual([f.rule_id for f in findings], ["BASELINE-004"])
        self.assertEqual(findings[0].severity, "high")

    def test_binary_garbage_is_high_not_a_crash(self):
        self.file.write_bytes(b"\xff\xfe\x00\x01 not utf-8")
        findings = baseline.verify()
        self.assertEqual([f.rule_id for f in findings], ["BASELINE-004"])

    def test_load_raises_rather_than_returning_empty(self):
        self.file.write_text("{nope")
        with self.assertRaises(baseline.CorruptBaseline):
            baseline.load_baseline()


class AtomicWrites(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_replaces_existing_content_completely(self):
        target = self.dir / "state.json"
        target.write_text('{"old": true}')
        baseline._write_atomic(target, '{"new": true}')
        self.assertEqual(json.loads(target.read_text()), {"new": True})

    def test_applies_the_requested_mode(self):
        target = self.dir / "state.json"
        baseline._write_atomic(target, "{}", mode=0o400)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o400)

    def test_failure_leaves_the_original_intact_and_no_temp_behind(self):
        """The property that matters: an interrupted write must not destroy
        the record it was replacing."""
        target = self.dir / "state.json"
        target.write_text('{"original": true}')

        real_replace = os.replace

        def boom(src, dst):
            raise OSError("simulated disk failure")

        with mock.patch.object(os, "replace", boom):
            with self.assertRaises(OSError):
                baseline._write_atomic(target, '{"partial": ')

        self.assertEqual(json.loads(target.read_text()), {"original": True})
        leftovers = [p.name for p in self.dir.iterdir() if ".tmp" in p.name]
        self.assertEqual(leftovers, [], f"temp files left behind: {leftovers}")
        os.replace = real_replace

    def test_round_trips_through_save_and_load(self):
        with mock.patch.object(baseline, "BASELINE_DIR", self.dir), \
             mock.patch.object(baseline, "BASELINE_FILE",
                               self.dir / "baseline.json"):
            baseline.save_baseline({"/tmp/x": {"sha256": "abc", "size": 1}})
            loaded = baseline.load_baseline()
        self.assertIn("/tmp/x", loaded["files"])


if __name__ == "__main__":
    unittest.main()
