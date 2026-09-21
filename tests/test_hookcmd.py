"""AW-26 — the documented quickstart installed hooks that could not run.

Every hook registration hardcoded ``python3 -m wormhole``. The documented
install is ``pipx install wormhole-guard``, which isolates the package from the
system interpreter, so the registered command exited 1 with "No module named
wormhole" and EMPTY STDOUT — and empty stdout is this project's own documented
allow signal. The control was inert on the operator's machine before any
attacker arrived, and inert in the quietest possible way.
"""

import json
import subprocess
import sys
import unittest
from unittest import mock

from wormhole.hookcmd import hook_base, fail_closed


class HookBase(unittest.TestCase):
    def test_prefers_the_console_script_pipx_guarantees(self):
        with mock.patch("shutil.which", return_value="/somewhere/bin/wormhole"):
            self.assertEqual(hook_base(), "wormhole")

    def test_falls_back_to_the_interpreter_that_can_import_us(self):
        # Never `python3`: the whole defect was assuming the system
        # interpreter can import a package pipx deliberately isolated.
        with mock.patch("shutil.which", return_value=None):
            base = hook_base()
        self.assertEqual(base, f"{sys.executable} -m wormhole")
        self.assertNotEqual(base, "python3 -m wormhole")

    def test_no_emitted_command_hardcodes_python3(self):
        from wormhole import outbound

        with mock.patch("shutil.which", return_value="/somewhere/bin/wormhole"):
            block = outbound.install_block()
        cmd = block["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertNotIn("python3 -m wormhole", cmd)
        self.assertIn("wormhole outbound --hook", cmd)


class FailClosed(unittest.TestCase):
    """The wrapper's whole job is the case where the scanner cannot start."""

    def _run(self, command: str, stdin: str = "{}") -> subprocess.CompletedProcess:
        # Executed for real: the behaviour lives in the shell, not in Python.
        return subprocess.run(
            ["sh", "-c", command],
            input=stdin,
            capture_output=True,
            text=True,
        )

    def test_a_scanner_that_cannot_start_denies_instead_of_going_silent(self):
        r = self._run(fail_closed("this-command-does-not-exist-anywhere"))
        self.assertTrue(r.stdout, "a startup failure must not produce empty stdout")
        payload = json.loads(r.stdout)
        self.assertEqual(
            payload["hookSpecificOutput"]["permissionDecision"], "deny"
        )

    def test_a_scanner_that_ran_and_allowed_stays_silent(self):
        # Exit 0 with no output is the allow signal, and the wrapper must not
        # turn an allow into a deny.
        r = self._run(fail_closed("true"))
        self.assertEqual(r.stdout, "")
        self.assertEqual(r.returncode, 0)

    def test_the_scanners_own_output_passes_through_untouched(self):
        real = '{"hookSpecificOutput":{"permissionDecision":"deny"}}'
        r = self._run(fail_closed(f"printf %s '{real}'"))
        self.assertEqual(r.stdout, real)

    def test_exit_2_keeps_its_contractual_meaning(self):
        # The hook contract already gives exit 2 a blocking meaning; the
        # wrapper must not overwrite it with its own deny.
        r = self._run(fail_closed("exit 2"))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_output_plus_nonzero_exit_is_the_scanners_answer_not_ours(self):
        real = '{"hookSpecificOutput":{"permissionDecision":"deny"}}'
        r = self._run(fail_closed(f"printf %s '{real}'; exit 1"))
        self.assertEqual(r.stdout, real)


if __name__ == "__main__":
    unittest.main()
