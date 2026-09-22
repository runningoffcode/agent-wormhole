"""AW-30, AW-31, AW-59 and AW-81 — the CI findings, as tests.

AW-30 was arbitrary code execution in EVERY consumer's CI, from one file in an
unreviewed pull request, with the gate reporting green. AW-31 meant the
action's default configuration silently disabled half the product. AW-81 was
the same green-gate code execution again by a different route: caller inputs
spliced textually into the run: block. AW-59 is the mutable `@main` pin in the
published example.
"""

import json
import os
import re
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


def _scan_step():
    """The `Run Agent Wormhole` step, as (env mapping, run script).

    Parsed by hand rather than with PyYAML: this project ships zero runtime
    dependencies on purpose, and a test is not a reason to add one.
    """
    lines = (REPO / "action.yml").read_text().splitlines()
    start = next(i for i, l in enumerate(lines)
                 if l.strip() == "- name: Run Agent Wormhole")
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("    - name:")), len(lines))
    body = lines[start:end]

    env, run, section = {}, [], None
    for line in body:
        stripped = line.strip()
        if stripped == "env:":
            section = "env"
            continue
        if stripped in ("run: |", "run: |-"):
            section = "run"
            continue
        if section == "env":
            # A key at the env block's own indent ends it; deeper lines are
            # this step's other keys, comments, or the values themselves.
            if stripped.startswith("#") or not stripped:
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*: .*", stripped):
                key, value = stripped.split(": ", 1)
                env[key] = value
            else:
                section = None
        elif section == "run":
            if stripped and not line.startswith("        "):
                section = None
                continue
            run.append(line[8:])

    # The parser only understands `run: |`. A refactor to `run: >-` (or any
    # other block spelling) would silently yield an EMPTY script, and every
    # negative injection test below would then "pass" against nothing at all.
    # Fail here instead, loudly, so the suite cannot go blind.
    script = "\n".join(run)
    assert "python3 -m wormhole scan" in script, (
        "could not parse the Run Agent Wormhole script out of action.yml "
        "(did the `run: |` block spelling change?) -- refusing to run the "
        "injection tests against an empty script"
    )
    return env, script


def _run_step_with_inputs(inputs, workspace, **env_over):
    """Expand the action's run: block the way the GitHub runner does, then
    execute it under bash.

    The runner substitutes ${{ inputs.X }} into the script TEXTUALLY, before
    bash sees a single token, and passes env: values through the process
    environment. Reproducing both is the only way to test AW-81 honestly.
    """
    step_env, script = _scan_step()

    def expand(text):
        return re.sub(r"\$\{\{\s*inputs\.([a-z-]+)\s*\}\}",
                      lambda m: inputs[m.group(1)], text)

    env = {
        "PATH": os.environ["PATH"],
        "GITHUB_WORKSPACE": workspace,
        "RUNNER_TEMP": workspace,
    }
    for key, value in step_env.items():
        env[key] = expand(value)
    # HOME and CDPATH are what the cd-option and cd-search attacks steer, so
    # the harness has to be able to set them the way a caller workflow can.
    env.update(env_over)

    # Stub python3 so the step reports its argv instead of scanning, which is
    # what argument-injection has to be observed through.
    bindir = Path(workspace) / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "python3"
    stub.write_text(
        '#!/bin/sh\nprintf "ARGV:"; for a in "$@"; do printf " [%s]" "$a"; done; echo\n'
    )
    stub.chmod(0o755)
    env["PATH"] = f"{bindir}:{env['PATH']}"

    return subprocess.run(["bash", "-c", expand(script)],
                          cwd=REPO, capture_output=True, text=True, env=env)


class TestActionInputInjection(unittest.TestCase):
    """AW-81: caller inputs must reach the script as data, never as syntax."""

    BASE = {"path": ".", "fail-on": "high",
            "blast-radius": "true", "local-only": "true"}

    def _inputs(self, **over):
        merged = dict(self.BASE)
        merged.update({k.replace("_", "-"): v for k, v in over.items()})
        return merged

    def test_inputs_are_bound_through_env_not_spliced_into_the_script(self):
        # GitHub's documented mitigation, and the property the rest of this
        # class depends on: no ${{ inputs.* }} anywhere in the run: body.
        env, script = _scan_step()
        self.assertNotIn("${{ inputs.", script)
        self.assertEqual(
            {"WH_PATH", "WH_FAIL_ON", "WH_LOCAL_ONLY", "WH_BLAST_RADIUS"},
            set(env),
        )

    def _assert_no_marker(self, payload_inputs, marker):
        with tempfile.TemporaryDirectory() as ws:
            token = Path(ws) / marker
            inputs = {k: v.replace("@MARKER@", str(token))
                      for k, v in payload_inputs.items()}
            proc = _run_step_with_inputs(inputs, ws)
            self.assertFalse(
                token.exists(),
                f"input executed as shell: {proc.stdout}{proc.stderr}",
            )
            return proc

    def test_path_cannot_close_the_quote_and_run_a_command(self):
        # The auditor's payload. Was: touch ran as the runner user and the
        # step still exited 0, so the gate went green on the payload's own PR.
        self._assert_no_marker(
            self._inputs(path='."; touch @MARKER@; echo "'), "pwned_quote")

    def test_path_cannot_smuggle_a_command_substitution(self):
        self._assert_no_marker(
            self._inputs(path="$(touch @MARKER@)"), "pwned_cmdsub")

    def test_local_only_cannot_break_out_of_its_test(self):
        # Was: closed the [ "..." = "true" ] test, ran touch, and silently
        # dropped --local-only from the scan in the process.
        self._assert_no_marker(
            self._inputs(local_only='true" ] && touch @MARKER@; [ "x'),
            "pwned_local")

    def test_fail_on_cannot_smuggle_extra_flags_through_word_splitting(self):
        # $ARGS was unquoted, so this reached the scanner as two argv words
        # and turned on a flag the caller never granted.
        with tempfile.TemporaryDirectory() as ws:
            proc = _run_step_with_inputs(
                self._inputs(fail_on="high --evil-extra-flag"), ws)
            self.assertNotIn("--evil-extra-flag", proc.stdout)

    def test_an_invalid_fail_on_fails_the_step_loudly(self):
        with tempfile.TemporaryDirectory() as ws:
            proc = _run_step_with_inputs(self._inputs(fail_on="hgih"), ws)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("fail-on must be one of", proc.stderr)

    def test_the_five_documented_severities_are_all_accepted(self):
        for level in ("critical", "high", "medium", "low", "never"):
            with self.subTest(level=level), tempfile.TemporaryDirectory() as ws:
                proc = _run_step_with_inputs(self._inputs(fail_on=level), ws)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn(f"[--fail-on] [{level}]", proc.stdout)

    def test_an_honest_path_with_a_space_still_scans_that_directory(self):
        # The flip side of the fix: quoting must make spaces WORK, not break.
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "my repo").mkdir()
            proc = _run_step_with_inputs(self._inputs(path="my repo"), ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("my repo]", proc.stdout)

    def test_flags_are_still_toggled_off_when_the_inputs_are_false(self):
        with tempfile.TemporaryDirectory() as ws:
            proc = _run_step_with_inputs(
                self._inputs(local_only="false", blast_radius="false"), ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("--local-only", proc.stdout)
            self.assertNotIn("--blast-radius", proc.stdout)

    def test_an_invalid_fail_on_does_not_echo_the_caller_value(self):
        # The rejection message lands in the consumer's CI log, readable by
        # anyone who can read the run, and on a fork PR the value is chosen by
        # the attacker. Name the input; never quote it back.
        secret = "zzsentinel-should-not-reach-the-log"
        with tempfile.TemporaryDirectory() as ws:
            proc = _run_step_with_inputs(self._inputs(fail_on=secret), ws)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("fail-on must be one of", proc.stderr)
            self.assertNotIn(secret, proc.stderr + proc.stdout)


class TestActionPathConfinement(unittest.TestCase):
    """AW-81, second half: `path` must not be parsed as cd's OPTIONS.

    Binding through env: stops the value being bash syntax. It does NOT stop
    `cd` reading it as its own flags. Every case below used to exit 0 while
    scanning a tree that was not the caller's repo -- a green gate that never
    looked at what it was gating, which is the exact failure AW-81 is about.
    """

    BASE = {"path": ".", "fail-on": "high",
            "blast-radius": "true", "local-only": "true"}

    def _run(self, path, ws, **env_over):
        inputs = dict(self.BASE, path=path)
        return _run_step_with_inputs(inputs, ws, **env_over)

    def test_an_option_like_path_is_refused_not_resolved_to_home(self):
        # `cd -L` / `cd -P` / `cd --` take the value as an option, leaving cd
        # with no operand, so it goes to $HOME: the scan read the RUNNER's
        # home directory and still exited 0.
        for path in ("-L", "-P", "--"):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as ws:
                home = Path(ws) / "runner-home"
                home.mkdir()
                proc = self._run(path, ws, HOME=str(home))
                self.assertNotEqual(
                    proc.returncode, 0,
                    f"path={path!r} was accepted: {proc.stdout}")
                self.assertNotIn(str(home), proc.stdout)
                self.assertNotIn("ARGV:", proc.stdout,
                                 "the scan ran despite an unresolvable path")

    def test_a_dash_path_neither_jumps_to_oldpwd_nor_echoes_into_target(self):
        # `cd -` goes to $OLDPWD *and prints it*, so the print was captured
        # into TARGET as well -- a two-line TARGET aimed at the action's own
        # checkout rather than the caller's repo.
        with tempfile.TemporaryDirectory() as ws:
            proc = self._run("-", ws)
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertNotIn(str(REPO), proc.stdout)
            self.assertNotIn("ARGV:", proc.stdout)

    def test_cdpath_cannot_redirect_a_relative_path_out_of_the_workspace(self):
        # CDPATH is inheritable: a caller workflow sets it at job or workflow
        # level and composite steps inherit it. With CDPATH=/evil, a path of
        # `src` silently resolved to /evil/src and the scan exited 0.
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "src").mkdir()
            decoy = Path(ws) / "decoy"
            (decoy / "src").mkdir(parents=True)
            proc = self._run("src", ws, CDPATH=str(decoy))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            # realpath: the action resolves with `pwd -P`, and on macOS the
            # tempdir root is itself a symlink (/var -> /private/var).
            self.assertIn(f"[{Path(ws).resolve()}/src]", proc.stdout)
            self.assertNotIn(str(Path(decoy).resolve()), proc.stdout)

    def test_an_absolute_path_outside_the_workspace_is_refused(self):
        # Deliberate: this action scans the caller's checked-out repo in CI.
        # A target outside $GITHUB_WORKSPACE has no honest use, and refusing
        # is what turns the silent redirects above into loud failures.
        with tempfile.TemporaryDirectory() as ws:
            proc = self._run("/etc", ws)
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertNotIn("ARGV:", proc.stdout)

    def test_a_climbing_path_cannot_escape_the_workspace(self):
        with tempfile.TemporaryDirectory() as outer:
            ws = Path(outer) / "workspace"
            ws.mkdir()
            (Path(outer) / "sibling").mkdir()
            proc = self._run("../sibling", str(ws))
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertNotIn("ARGV:", proc.stdout)

    def test_a_sibling_sharing_the_workspace_name_prefix_is_refused(self):
        # The confinement check compares path PREFIXES, so /work/repo-evil
        # must not read as living inside /work/repo.
        with tempfile.TemporaryDirectory() as outer:
            ws = Path(outer) / "repo"
            ws.mkdir()
            (Path(outer) / "repo-evil").mkdir()
            proc = self._run("../repo-evil", str(ws))
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertNotIn("ARGV:", proc.stdout)

    def test_an_honest_subdirectory_still_scans(self):
        # Confinement must not break the normal case.
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "src").mkdir()
            proc = self._run("src", ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(f"[{Path(ws).resolve()}/src]", proc.stdout)


class TestActionFlagTestQuoting(unittest.TestCase):
    """AW-81: the quotes on the local-only / blast-radius `[` tests.

    Unquoted, the value word-splits into `[`'s own operator grammar, so a
    caller string like `x = x -o true` makes the test true and forces the flag
    ON. --local-only decides whether the scan reads global settings, so an
    unquoted test hands the caller control of the scan's scope through an
    expression rather than through the input's value.

    The first attempt's suite could not see this: unquoting either test still
    passed all 15 tests. These are the mutants that kill it.
    """

    BASE = {"path": ".", "fail-on": "high",
            "blast-radius": "false", "local-only": "false"}

    TEST_OPERATOR_PAYLOAD = "x = x -o true"

    def test_local_only_cannot_be_forced_on_by_a_test_operator(self):
        with tempfile.TemporaryDirectory() as ws:
            proc = _run_step_with_inputs(
                dict(self.BASE, **{"local-only": self.TEST_OPERATOR_PAYLOAD}),
                ws)
            self.assertNotIn(
                "--local-only", proc.stdout,
                "a caller value forced --local-only ON through `[`'s operator "
                "grammar: the test expression is unquoted")

    def test_blast_radius_cannot_be_forced_on_by_a_test_operator(self):
        with tempfile.TemporaryDirectory() as ws:
            proc = _run_step_with_inputs(
                dict(self.BASE,
                     **{"blast-radius": self.TEST_OPERATOR_PAYLOAD}),
                ws)
            self.assertNotIn("--blast-radius", proc.stdout)

    def test_a_multiword_value_does_not_crash_the_test_expression(self):
        # Unquoted, a plain two-word value is a `[` syntax error, which under
        # `set -e` fails the step for a reason that has nothing to do with the
        # caller's actual request.
        with tempfile.TemporaryDirectory() as ws:
            proc = _run_step_with_inputs(
                dict(self.BASE, **{"local-only": "not true"}), ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("--local-only", proc.stdout)


PLACEHOLDER = "REPLACE_WITH_RELEASE_COMMIT_SHA"


def _published_pins():
    """Every `uses: .../agent-wormhole@REF` we publish, as (file, ref).

    Both the example workflow and the docs are copy-paste sources for
    consumers, so both are in scope. AW-59 was reported against the example
    and docs/scanning.md kept shipping `@v1` regardless.
    """
    found = []
    for rel in ("examples/ci-github-action/using-the-action.yml",
                "docs/scanning.md"):
        path = REPO / rel
        for line in path.read_text().splitlines():
            stripped = line.strip().lstrip("#").strip()
            # Match ANY `uses:` line, not just the `- uses:` inline form. The
            # ordinary two-line step -- `- name: ...` then `uses: ...` -- is at
            # least as common, and a parser that only saw the inline form let a
            # mutable @main ref be republished with every pin test green, which
            # is the exact defect this audit exists to make unrepeatable.
            if stripped.startswith("- uses:"):
                ref = stripped.split("uses:", 1)[1].strip()
            elif stripped.startswith("uses:"):
                ref = stripped.split("uses:", 1)[1].strip()
            else:
                continue
            if "agent-wormhole@" not in ref:
                continue
            found.append((rel, ref.split("#")[0].strip().split("@")[-1]))
    return found


class TestWorkspaceConfinementCannotCollapse(unittest.TestCase):
    """AW-81: the confinement check must not pass by comparing a directory
    with itself.

    `cd -- ""` is a no-op, so an empty GITHUB_WORKSPACE made TARGET and
    WORKSPACE_REAL both resolve to the action's own checkout. The prefix test
    then trivially passed and the gate scanned the ACTION instead of the
    caller's repo, exiting 0 -- the same green-gate-that-never-looked failure
    AW-81 and AW-30 are both about.
    """

    def test_an_empty_workspace_is_refused_not_compared_with_itself(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run_step_with_inputs(
                {"path": ".", "fail-on": "high",
                 "local-only": "true", "blast-radius": "true"},
                tmp,
                GITHUB_WORKSPACE="",
            )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertNotIn("ARGV:", proc.stdout,
                         "the scanner ran despite an unusable workspace")

    def test_an_unresolvable_workspace_is_refused(self):
        # An empty WORKSPACE_REAL would make the prefix test "$TARGET/" == /*,
        # which is true for every absolute path. It must fail closed on its
        # own rather than relying on `set -e` staying in the script.
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run_step_with_inputs(
                {"path": ".", "fail-on": "high",
                 "local-only": "true", "blast-radius": "true"},
                tmp,
                GITHUB_WORKSPACE=str(Path(tmp) / "does-not-exist"),
            )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertNotIn("ARGV:", proc.stdout)

    def test_an_honest_workspace_still_scans(self):
        # The guards must not cost honest callers their scan.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "repo").mkdir()
            proc = _run_step_with_inputs(
                {"path": "repo", "fail-on": "high",
                 "local-only": "true", "blast-radius": "true"},
                tmp,
            )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ARGV:", proc.stdout)
        self.assertIn("repo", proc.stdout)


class TestConsumerExamplePinning(unittest.TestCase):
    """AW-59: what we publish must not point consumers at a mutable ref --
    and must not point them at an immutable ref that predates AW-81 either.
    """

    def test_every_published_example_pins_the_action(self):
        pins = _published_pins()
        self.assertTrue(pins, "no published `uses:` line found to check")
        for rel, pin in pins:
            with self.subTest(file=rel):
                self.assertRegex(
                    pin, r"^(?:[0-9a-f]{40}|%s)$" % re.escape(PLACEHOLDER),
                    f"{rel} publishes a mutable ref ({pin!r}); a branch or "
                    "tag is a pointer somebody else can move, and this "
                    "action runs with the consumer's token and source",
                )

    def test_a_pinned_sha_actually_contains_the_aw81_hardening(self):
        """The shape of a pin proves nothing.

        The first attempt at AW-59 asserted only that the ref was 40 hex
        characters. It passed against a SHA whose action.yml still spliced
        ${{ inputs.path }} straight into the run: block -- i.e. the published
        example told consumers to run the injectable action, and the test
        that was supposed to be guarding that said green. 'deadbeef' * 5
        passed it too.

        So resolve the pin and read the file. A pin is acceptable only if the
        commit it names really carries the env:-bound, injection-free step.
        """
        for rel, pin in _published_pins():
            with self.subTest(file=rel):
                if pin == PLACEHOLDER:
                    # Unfilled on purpose: no commit in this repository
                    # contains the fix yet. The release process fills it, and
                    # this test is what checks the value it fills in.
                    continue

                proc = subprocess.run(
                    ["git", "cat-file", "-p", f"{pin}:action.yml"],
                    cwd=REPO, capture_output=True, text=True,
                )
                if proc.returncode != 0:
                    # A shallow clone -- which is what actions/checkout makes
                    # by default -- has the tip and nothing behind it, so a
                    # perfectly good pin to an earlier commit is simply not
                    # present locally. That is not the same as a fabricated
                    # SHA, and failing on it would make this guard fire on
                    # every CI run while saying nothing about the pin.
                    #
                    # Distinguish the two: if the object is genuinely absent
                    # AND history is truncated, skip; if history is complete,
                    # an unresolvable pin is a real failure.
                    if (REPO / ".git" / "shallow").exists():
                        # subTest swallows skipTest as a failure, so step over
                        # this file rather than raising.
                        print(
                            f"\n  [pin audit] {rel} pins {pin}; shallow clone "
                            "cannot resolve it — run with full history to audit",
                            file=sys.stderr,
                        )
                        continue
                self.assertEqual(
                    proc.returncode, 0,
                    f"{rel} pins {pin}, which is not a commit in this "
                    "repository (a fabricated or foreign SHA is not a pin)",
                )
                pinned = proc.stdout
                self.assertNotIn(
                    "${{ inputs.", pinned.split("run: |", 1)[-1],
                    f"{rel} pins {pin}, whose action.yml still splices caller "
                    "inputs into the run: block -- publishing that pin tells "
                    "consumers to run the pre-AW-81 injectable action",
                )
                for var in ("WH_PATH", "WH_FAIL_ON",
                            "WH_LOCAL_ONLY", "WH_BLAST_RADIUS"):
                    self.assertIn(
                        var, pinned,
                        f"{rel} pins {pin}, which predates the AW-81 env: "
                        "binding",
                    )
                self.assertIn(
                    'cd -- "$WH_PATH"', pinned,
                    f"{rel} pins {pin}, which predates the AW-81 cd option "
                    "terminator",
                )


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
