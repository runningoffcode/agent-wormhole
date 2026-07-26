# Changelog

## wormhole-x402 0.1.2 — 2026-07-25

A pre-launch audit of the instruction walk found the guard inspected only
`TransferChecked`. Three fixes, five of the six new tests fail against the
previous source.

- **Rider transfers are refused.** A plain `Transfer` (discriminant 3) or a
  System-program lamport transfer could ride beside a correct payment and the
  verdict was still `allow` — the exact promise the package makes, defeated by
  adding one instruction. Both are now refused, as is a second transfer to the
  quoted destination (`X402-007` covers the SOL case).
- **Unreadable amounts abstain rather than allow.** A `quote.amount` that would
  not parse as an integer silently skipped the comparison. A check that could
  not run must never read as a check that passed.
- **Token-2022 destinations are derived correctly.** Only the legacy ATA was
  derived, so every legitimate Token-2022 payment was refused. Both forms are
  derived now, since which program owns the mint is on-chain state this package
  deliberately does not fetch.

## wormhole-guard 0.1.1 — 2026-07-25

- `harden` no longer changes a file's mode through a symlink. `os.chmod`
  dereferences, so an agent able to write into the project could point
  `CLAUDE.md` at a private file and have `--undo` widen it to `0644`.
- Packaging metadata: `license = "Apache-2.0"` with explicit `license-files`,
  so PyPI shows the identifier rather than the full license text.

## 0.1.0 — 2026-07-25

First release. Detection, prevention and containment for self-replicating
prompt payloads in AI agent configuration.

### Prevention

- `harden` makes agent configs and skills read-only, and pre-creates the config
  paths that do not exist yet as inert read-only files. The second half matters
  as much as the first: you cannot `chmod` a file that is absent, and the
  attacks that have actually propagated work by *creating* configuration rather
  than editing it.
- `guard` inspects a pending Write or Edit through a Claude Code `PreToolUse`
  hook and can refuse it. Warns by default; `--block` refuses `WORM-001` and
  `WORM-003` only — the two rules with an unambiguous structural signature.
- `readguard` inspects what the agent *reads*, through `PostToolUse` and
  `InstructionsLoaded`. Annotates by default; `--redact` removes matched lines.
- `init` runs the whole prevention posture in one command.

### Detection

- Seven content rules for self-replicating and exfiltrating text.
- Four autostart rules for configuration that executes with no prompt and no
  model — session hooks, folder-open tasks, always-applied rules.
- Seven posture rules for what a payload could accomplish if it arrived, plus a
  blast-radius score across execute → persist → propagate.
- Runtime scanning of session transcripts, distinguishing source code from
  prose so that reading a credential-handling file is not an incident.

### Integrity

- `baseline` and `verify` fingerprint config files *and* MCP tool definitions.
  Nothing in the MCP protocol signs a tool definition or requires a client to
  re-validate one, so a server can present one description at review time and
  another later.
- Provenance attribution: a change is reported alongside the agent session that
  was active when it happened.

### Containment

- `capture` excises payloads while preserving originals byte-for-byte.
  Reversible with `restore`. Runs iteratively, because a payload can occupy
  several blocks and removing only the first would leave the second live.

### Scope

- `handoffs` reads transcripts for payloads travelling between agents. There is
  no interception point for this — a parent composes a child's task in memory —
  so it is detection after the fact.
- `corpus` scans documents before they are embedded for retrieval, which is the
  last point at which the text is still text.

### Known limits

Rules match payload shapes, not meaning; novel phrasing evades them. `guard`
and `readguard` depend on the agent framework calling them. Nothing here
removes an infection from a running agent. The control that drives attack
success to zero is sandbox isolation, and it lives in the agent framework —
and per Anthropic's own documentation it does not cover Read, Edit or Write by
default.
