# Security policy

## Reporting a vulnerability

Please do not open a public issue for a vulnerability in this tool. Open a
GitHub security advisory, or contact the maintainers privately.

Findings we especially want to hear about:

- A payload shape that evades detection (a false negative in the rules)
- A way to make the Wormhole write outside its intended path
- A way to make the MCP server perform a write operation

## What this project will not publish

**No working payloads.** Every fixture in `corpus/malicious/` is inert by
policy: no live endpoints, no functional self-replicating prompts, no domains
that resolve. Fixtures exist to exercise the detector, not to be run.

Publishing a functional worm to demonstrate a worm detector would be a net
negative regardless of intent, and would forfeit the credibility this project
depends on. Pull requests containing working payloads will be rejected.

If you have a real captured payload, `wormhole export` produces inert
samples with provenance recorded. Neutralize endpoints before contributing one.

## Design constraints that are security properties

These are deliberate and should not be "fixed":

**The MCP server is read-only.** It reports; it never writes, deletes, or
re-baselines. A security tool reachable by the agent is reachable by anything
that has compromised the agent. A worm that could ask the scanner to disable a
rule or re-baseline a tampered file would be using the defense as tooling.
Remediation stays in the CLI, where a human runs it.

**The baseline lives outside the scanned tree.** Hashes are stored in
`~/.wormhole/`, not in the repository, so an agent writing to its own project
cannot silently rewrite the record of what the files used to be.

**`wormhole` defaults to a dry run.** Modifying files requires `--apply`, and every
excision preserves the complete original for byte-for-byte restore. Irreversible
defaults on a security tool cause data loss on false positives.

**Wormhole contents are inert on disk.** `~/.wormhole/captured/` is `0700`, payload
files are `0400` with a `.quarantined` suffix, so nothing there is loaded as
agent configuration or executed.

## Scope and honest limits

This tool detects and reports. It does not prevent infection, and it is not a
substitute for sandbox isolation — which is, per the research it cites, the
control that actually breaks the infection loop.

- Regex rules match payload *shapes*. Novel phrasing will evade them; this is
  why baseline/verify exists and why it matters more than rule coverage.
- Runtime scanning reads session transcripts after the fact. It tells you an
  injection attempt reached your agent; it does not block it.
- Posture checks currently understand Claude Code's permission format best.
  Other frameworks are detected but less deeply analyzed.
