"""Verification must retain missing files within the requested project."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from wormhole import baseline, cli
from wormhole.scanners import mcp_tools


class TestVerifyScope(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.project = self.home / "project"
        self.other = self.home / "project-other"
        self.project.mkdir()
        self.other.mkdir()
        store = self.home / "store"
        patches = [
            patch.object(baseline, "BASELINE_DIR", store),
            patch.object(baseline, "BASELINE_FILE", store / "baseline.json"),
            patch.object(mcp_tools, "TOOLS_FILE", store / "tools.json"),
            patch.object(Path, "home", return_value=self.home),
            patch.object(cli.provenance, "session_windows", return_value=[]),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def make_config(self, relative, root=None):
        path = (root or self.project) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Ordinary notes\n", encoding="utf-8")
        return path

    def verify_project(self):
        output = io.StringIO()
        with redirect_stdout(output):
            cli.main(["verify", str(self.project), "--json"])
        return json.loads(output.getvalue())

    def test_deleted_config_is_reported_while_another_remains(self):
        kept = self.make_config("AGENTS.md")
        removed = self.make_config("nested/AGENTS.md")
        baseline.record([kept, removed])
        removed.unlink()
        findings = self.verify_project()
        self.assertEqual([(f["rule_id"], f["path"]) for f in findings],
                         [("BASELINE-002", str(removed.resolve()))])

    def test_removing_last_config_does_not_check_another_project(self):
        removed = self.make_config("AGENTS.md")
        unrelated = self.make_config("AGENTS.md", self.other)
        baseline.record([removed, unrelated])
        removed.unlink()
        unrelated.write_text("Changed in another project\n", encoding="utf-8")
        findings = self.verify_project()
        self.assertEqual([(f["rule_id"], f["path"]) for f in findings],
                         [("BASELINE-002", str(removed.resolve()))])

    def test_empty_untracked_project_has_no_baseline(self):
        unrelated = self.make_config("AGENTS.md", self.other)
        baseline.record([unrelated])
        unrelated.write_text("Changed elsewhere\n", encoding="utf-8")
        self.assertEqual([f["rule_id"] for f in self.verify_project()], ["BASELINE-000"])

    def test_changed_and_new_configs_remain_visible(self):
        changed = self.make_config("AGENTS.md")
        baseline.record([changed])
        changed.write_text("Edited notes\n", encoding="utf-8")
        self.make_config("nested/AGENTS.md")
        self.assertEqual({f["rule_id"] for f in self.verify_project()},
                         {"BASELINE-001", "BASELINE-003"})

    def test_library_unscoped_verification_still_checks_all_records(self):
        one = self.make_config("AGENTS.md")
        two = self.make_config("AGENTS.md", self.other)
        baseline.record([one, two])
        one.unlink()
        two.unlink()
        self.assertEqual({f.path for f in baseline.verify()}, {str(one), str(two)})
