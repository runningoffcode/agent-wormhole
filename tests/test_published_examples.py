"""What we publish must match what we ship.

Two examples people copy, each pinned here because each was wrong once:

  * The hooks README's copy-paste block documented ``python3 -m wormhole``,
    which under the pipx install the same page recommends exits 1 with empty
    stdout -- the allow signal. The block is generated from settings.json;
    this pins that the two cannot drift again.
  * The e2e harness wrote its result to a fixed name under /tmp. On a shared
    host that is a path anyone can pre-create as a symlink, and the script
    runs as whoever invoked it.
"""
import ast
import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


class HooksReadmeMatchesSettings(unittest.TestCase):
    def test_readme_block_is_settings_json(self):
        readme = (REPO / "examples/claude-code-hooks/README.md").read_text(encoding="utf-8")
        settings = (REPO / "examples/claude-code-hooks/settings.json").read_text(encoding="utf-8")
        m = re.search(r"```json\n(\{\n  \"hooks\": \{.*?)\n```", readme, re.S)
        self.assertIsNotNone(m, "the README no longer carries a hooks JSON block")
        self.assertEqual(json.loads(m.group(1)), json.loads(settings))

    def test_readme_does_not_document_the_module_form(self):
        readme = (REPO / "examples/claude-code-hooks/README.md").read_text(encoding="utf-8")
        self.assertNotIn("python3 -m wormhole", readme)

    def test_settings_hooks_use_the_console_script(self):
        # CONTROL for the test above: the thing the README is generated from
        # must itself be right, or the two agree on the wrong command.
        settings = json.loads((REPO / "examples/claude-code-hooks/settings.json").read_text(encoding="utf-8"))
        commands = [
            h["command"]
            for group in settings["hooks"].values()
            for entry in group
            for h in entry["hooks"]
        ]
        self.assertTrue(commands)
        for cmd in commands:
            self.assertNotIn("python3 -m wormhole", cmd)
            self.assertIn("wormhole ", cmd)


class E2eResultPathIsNotFixed(unittest.TestCase):
    def test_no_fixed_tmp_literal(self):
        tree = ast.parse((REPO / "e2e/worm_propagation.py").read_text(encoding="utf-8"))
        fixed = [
            n.value
            for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("/tmp/")
        ]
        self.assertEqual(fixed, [])

    def test_result_path_is_operator_controllable(self):
        src = (REPO / "e2e/worm_propagation.py").read_text(encoding="utf-8")
        self.assertIn("WORM_E2E_RESULT", src)
        self.assertIn("tempfile.mkstemp", src)


if __name__ == "__main__":
    unittest.main()
