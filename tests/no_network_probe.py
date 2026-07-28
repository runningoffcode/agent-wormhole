"""Import the free package under a syscall-level network veto.

Run as a subprocess, never imported. The point is that the veto is installed
BEFORE the package is imported, in a process where nothing else has run, so
there is no ordering in which an import-time network call slips past.

Usage:
    python3 tests/no_network_probe.py wormhole            # exit 0 = clean
    python3 tests/no_network_probe.py wormhole.cli
    python3 tests/no_network_probe.py --self-test         # must exit 3

Exit codes:
    0  imported cleanly, no network syscall attempted, no third-party import
    3  a network syscall was attempted   <- the gate fires
    4  a third-party module was imported <- the gate fires
    1  the import itself failed

WHY AN AUDIT HOOK AND NOT MOCKING `socket`:

    Monkeypatching `socket.socket` checks one library's front door. It misses
    `os.open` on a unix socket, `subprocess` shelling out to curl, a C
    extension calling connect(2) directly, `urllib` holding a reference
    captured before the patch, and `http.client` in a module imported earlier.

    `sys.addaudithook` (PEP 578, Python 3.8+) sits at the CPython level. Every
    one of these paths raises one of the audit events below on the way out:
    `socket.connect`, `socket.getaddrinfo`, `urllib.Request`,
    `subprocess.Popen`, `os.exec`, `ftplib.connect`. The hook cannot be
    removed once installed and cannot be bypassed from Python.

    It is not a kernel-level guarantee. A C extension that calls connect(2)
    without going through CPython's socket module raises no audit event, and a
    ctypes call into libc would need `ctypes` (audited) but the resulting
    syscall would not be. That residual gap is why this package has zero
    third-party dependencies and why the third-party-import check below is part
    of the same gate: the audit hook proves the pure-Python code is clean, and
    the dependency check proves there is no C extension present to worry about.
    Neither claim is sufficient alone.

WHY IT DOES NOT USE unittest:

    A test that runs inside the main test process is a test that runs after
    `unittest discover` has already imported hundreds of modules. This has to
    be a clean interpreter, so it is a script, and `test_safe.py` shells out to
    it. That also makes it runnable by hand in CI on its own, which is how the
    workflow uses it.
"""

import sys

# Audit events that mean "something is talking to the network, or is about to".
# `socket.getaddrinfo` is included because a DNS lookup is already a packet on
# the wire, and because it is the event that fires first in almost every real
# call path — catching it gives a clearer failure than waiting for connect.
NETWORK_EVENTS = (
    "socket.connect",
    "socket.connect_ex",
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "socket.sendto",
    "socket.bind",
    "urllib.Request",
    "ftplib.connect",
    "ftplib.sendcmd",
    "smtplib.connect",
    "smtplib.send",
    "http.client.connect",
    "http.client.send",
    # Shelling out is an exfiltration path that no socket hook would see.
    "subprocess.Popen",
    "os.exec",
    "os.posix_spawn",
    "os.system",
)

_violation = []


def _hook(event, args):
    if event in NETWORK_EVENTS:
        # Recording rather than raising: an exception here could be swallowed
        # by a bare `except` inside the imported code, and a swallowed
        # violation is a passing test. The record is checked after the import
        # returns, where nothing can catch it.
        #
        # repr() of args is bounded because an audit event on a send carries
        # the payload, and this probe's own output should not become a
        # plaintext leak of the thing it is auditing.
        _violation.append((event, repr(args)[:200]))


def _selftest():
    """Prove the hook actually detects a socket open.

    A gate that cannot fail is not a gate. This branch deliberately opens a
    real socket and connects it, and the script must exit 3. CI runs this
    before it runs the real check, so a hook that silently stopped working
    fails the build instead of passing it.
    """
    sys.addaudithook(_hook)
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        # 198.51.100.0/24 is RFC 5737 TEST-NET-2: guaranteed unroutable, so
        # this never actually reaches anything, but connect() is attempted and
        # the audit event fires regardless of the outcome.
        s.connect(("198.51.100.1", 9))
    except Exception:
        pass
    finally:
        s.close()
    if not _violation:
        print("SELF-TEST FAILED: opened a socket and the audit hook saw "
              "nothing. The network gate is broken.", file=sys.stderr)
        return 1
    print("self-test: hook fired on a real socket connect -> "
          + _violation[0][0])
    return 3


def _third_party(before):
    """Modules imported by the target that are neither stdlib nor ours.

    `sys.stdlib_module_names` is 3.10+; on 3.8/3.9 the check degrades to the
    package-prefix test only, and says so, rather than pretending to a
    guarantee it cannot make on that interpreter.
    """
    stdlib = getattr(sys, "stdlib_module_names", None)
    added = set(sys.modules) - before
    out = []
    for name in sorted(added):
        top = name.split(".")[0]
        if top.startswith("_") or top in ("wormhole", "tests"):
            continue
        mod = sys.modules.get(name)
        if mod is None:  # failed/partial import placeholder
            continue
        if stdlib is not None and top in stdlib:
            continue
        if stdlib is None:
            # Without stdlib_module_names, fall back to location: a module
            # under the interpreter's own lib dir is stdlib.
            f = getattr(mod, "__file__", None) or ""
            if not f or "site-packages" not in f:
                continue
        out.append(name)
    return out


def main(argv):
    if "--self-test" in argv:
        return _selftest()

    targets = [a for a in argv[1:] if not a.startswith("-")] or ["wormhole"]

    sys.addaudithook(_hook)
    before = set(sys.modules)

    import importlib
    for t in targets:
        try:
            importlib.import_module(t)
        except Exception as exc:
            print("IMPORT FAILED: %s: %s" % (t, exc), file=sys.stderr)
            return 1

    if _violation:
        print("NETWORK GATE FAILED: importing %s attempted a network "
              "operation." % ", ".join(targets), file=sys.stderr)
        for event, args in _violation:
            print("  %s %s" % (event, args), file=sys.stderr)
        print("\nThe free package must never open a socket. Move whatever "
              "needs the network into the separate opt-in reporting package.",
              file=sys.stderr)
        return 3

    extras = _third_party(before)
    if extras:
        print("DEPENDENCY GATE FAILED: importing %s pulled in non-stdlib "
              "modules:" % ", ".join(targets), file=sys.stderr)
        for name in extras:
            print("  %s" % name, file=sys.stderr)
        return 4

    stdlib_checked = getattr(sys, "stdlib_module_names", None) is not None
    print("clean: %s imported with no network syscall" % ", ".join(targets))
    print("       %d modules imported, 0 third-party%s"
          % (len(set(sys.modules) - before),
             "" if stdlib_checked else " (location-based check, "
             "sys.stdlib_module_names unavailable on this interpreter)"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
