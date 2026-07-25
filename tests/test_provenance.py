"""Attributing a config change to an agent session.

`verify` says the hash differs. That starts an investigation. "This changed at
14:02 while a session was open, and it is unstaged in git" ends one.

Built only from evidence the OS already keeps, because the alternative is a
privileged daemon watching the filesystem -- a worse thing to install than the
risk it mitigates.
"""

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from wormhole import provenance


class TestSessionWindows(unittest.TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self._patch = mock.patch.object(
            provenance, "TRANSCRIPT_ROOT", self.root)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    def _session(self, name):
        proj = self.root / "proj"
        proj.mkdir(exist_ok=True)
        p = proj / f"{name}.jsonl"
        p.write_text(json.dumps({"timestamp": "2026-07-25T10:00:00Z"}) + "\n")
        return p

    def test_only_real_sessions_count(self):
        """Subagent and workflow journals sit in nested directories and never
        touch the filesystem. Counting them would attribute a config change to
        a 'session' that could not have made it."""
        self._session("00000000-0000-0000-0000-000000000000")
        nested = self.root / "proj" / "subagents" / "workflows"
        nested.mkdir(parents=True)
        (nested / "journal.jsonl").write_text("{}\n")
        (nested / "agent-abc123.jsonl").write_text("{}\n")

        ids = [sid for _, _, sid in provenance.session_windows()]
        self.assertEqual(ids, ["00000000-0000-0000-0000-000000000000"])

    def test_window_is_a_span_not_a_point(self):
        """st_ctime equals st_mtime on an appended file, which would collapse
        every window to an instant and attribute nothing."""
        self._session("11111111-1111-1111-1111-111111111111")
        (start, end, _), = provenance.session_windows()
        self.assertLessEqual(start, end)


class TestAttribution(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.cfg = self.dir / "CLAUDE.md"
        self.cfg.write_text("# Claude\nBe terse.\n")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_change_inside_a_session_window_is_attributed(self):
        now = datetime.now(timezone.utc)
        windows = [(now - timedelta(minutes=30), now, "abc123def456")]
        findings = provenance.check([self.cfg], windows)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PROV-001")
        self.assertEqual(findings[0].severity, "high")

    def test_change_outside_every_window_is_not_attributed(self):
        """An edit made in an editor, with no agent running, is not evidence
        of anything and must not be reported as though it were."""
        old = datetime.now(timezone.utc) - timedelta(days=30)
        windows = [(old, old + timedelta(minutes=10), "abc123")]
        self.assertEqual(provenance.check([self.cfg], windows), [])

    def test_describe_reports_what_it_knows(self):
        info = provenance.describe(self.cfg, [])
        self.assertEqual(info["path"], str(self.cfg))
        self.assertIsNotNone(info["modified"])
        self.assertIsNotNone(info["mode"])

    def test_missing_file_does_not_raise(self):
        info = provenance.describe(self.dir / "nope.md", [])
        self.assertIsNone(info["modified"])


if __name__ == "__main__":
    unittest.main()
