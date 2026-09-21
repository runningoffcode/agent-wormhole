"""Where a registered hook command comes from.

One definition, imported by every --install path, because a second copy is a
second thing to forget when the packaging changes.
"""

import shutil
import sys


def hook_base() -> str:
    """The command string a registered hook should invoke.

    AW-26. Every hook registration hardcoded ``python3 -m wormhole``. The
    documented install is ``pipx install wormhole-guard``, which creates an
    isolated venv and puts only the ``wormhole`` console script on PATH — the
    package is deliberately NOT importable by the system ``python3``. So the
    registered command exited 1 with "No module named wormhole" and produced
    EMPTY STDOUT, and both readings of the hook contract turn that into "no
    objection": Claude Code treats a non-zero exit other than 2 as a
    non-blocking error, and this project's own demo.sh documents empty stdout
    as the allow signal.

    The result was the quietest possible failure. An operator merges the hook
    blocks, sees the guard's normal silence on clean traffic, and has no
    protection at all — before any attacker arrives. Reproduced in a clean
    environment: exit 1, empty stdout, the write proceeds.

    Resolved at ``--install`` time rather than baked in: prefer the console
    script that pipx and pip both provide, and fall back to the interpreter
    currently running, which is by construction one that can import this
    module. ``python3`` is never assumed.
    """
    console = shutil.which("wormhole")
    if console:
        return "wormhole"
    return f"{sys.executable} -m wormhole"




# The one blocking hook: if the scanner cannot run, this is what the operator
# needs to see instead of silence.
_STARTUP_DENY = (
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
    '"permissionDecision":"deny","permissionDecisionReason":'
    '"wormhole-guard could not run (the hook command failed to start). '
    'Refusing the tool call rather than allowing it unchecked \\u2014 a guard '
    'that cannot run is not a guard that approves. Fix the hook command, or '
    'remove the hook if you meant to disable it."}}'
)


def fail_closed(command: str) -> str:
    """Wrap a hook command so a startup failure denies instead of going silent.

    AW-26's second half. The shipped command string was wrong, and that is
    fixed — but the reason a wrong string was invisible for so long is that
    the failure mode is indistinguishable from success: a hook that cannot
    start writes nothing to stdout, and nothing on stdout is the allow signal.
    Any future packaging change reopens the same hole in the same silence.

    So the decision cannot live in the Python that failed to start. This is a
    POSIX-sh wrapper: run the scanner, and if it exits non-zero having printed
    NOTHING, print a deny. A scanner that ran and chose to allow prints its own
    output and exits 0, so the wrapper never sees it. Exit 2 is passed through
    untouched, since the hook contract already gives it a blocking meaning.

    Only the blocking hook is wrapped. `readguard` annotates and `outbound`
    warns by default; denying those on a startup failure would turn a
    misconfiguration into an outage rather than a refusal.
    """
    return (
        f"out=$({command} 2>/dev/null); rc=$?; "
        f'if [ -n "$out" ]; then printf %s "$out"; exit $rc; fi; '
        f"if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then exit $rc; fi; "
        f"printf %s '{_STARTUP_DENY}'"
    )
