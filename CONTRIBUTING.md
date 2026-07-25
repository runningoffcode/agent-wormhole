# Contributing

## The one rule that matters

**Every new detection rule ships with a benign twin.**

For each fixture you add to `corpus/malicious/`, add a file to `corpus/benign/`
that discusses the same attack without being one — security documentation, a
threat model, a legitimate config that happens to use similar words. If your
rule fires on the twin, it does not ship.

This is enforced by `loop/replay.sh` and runs in CI on every pull request.

The reason is simple: a security tool that reports false positives gets
uninstalled, and an uninstalled tool protects nobody. Coverage is not worth
noise. When a rule cannot be made precise, prefer a posture recommendation over
a detection rule.

## Adding a detection rule

1. Write the malicious fixture in `corpus/malicious/`. **Inert only** — no live
   endpoints, no working self-replicating payloads (see SECURITY.md).
2. Write the benign twin in `corpus/benign/`.
3. Add the rule to `quarantine/rules/injection.py`. Rules generally require a
   replication cue *and* a delivery cue in proximity; see `_near()`.
4. Add unit tests in `tests/test_rules.py` for the rule internals.
5. Run the gate:

```bash
python3 -m unittest discover -s tests
./loop/replay.sh
```

Both must pass, and `replay.sh` must report `FN=0 FP=0`.

## Adding posture checks

Posture checks live in `quarantine/scanners/posture.py` and describe *capability*
rather than content. When adding one, also decide which link of the infection
loop it evidences — `execute`, `persist`, or `propagate` — and register it in
`quarantine/scoring.py` so blast radius stays accurate.

## Supporting a new agent framework

Add its config filenames to `CONFIG_NAMES` (or `CONFIG_GLOBS` for
directory-scoped formats like Cursor's `.cursor/rules/*.mdc`) in
`quarantine/scanners/posture.py`. If the framework has a permissions model, add
a parser alongside `check_permissions()`.

Please include a link to the framework's documentation for the config format in
your PR — we cite sources for behavior claims.

## Style

- Standard library only. The tool must run from a checkout with no install.
- Comments explain *why*, not *what*. Assume the reader can read Python.
- Findings must include actionable remediation. "This is bad" is not a finding;
  "remove the wildcard and keep the specific rules" is.
- Claims about attack effectiveness need a citation with a real, checkable
  reference. No invented statistics, ever.

## Running everything

```bash
python3 -m unittest discover -s tests -v   # unit tests
./loop/replay.sh                           # corpus gate
python3 -m quarantine scan . --local-only  # tool must be clean on itself
```
