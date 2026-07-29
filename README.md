# Agent Wormhole

[![ci](https://github.com/runningoffcode/agent-wormhole/actions/workflows/ci.yml/badge.svg)](https://github.com/runningoffcode/agent-wormhole/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/wormhole-guard?label=pypi%20wormhole-guard)](https://pypi.org/project/wormhole-guard/)
[![npm](https://img.shields.io/npm/v/wormhole-x402?label=npm%20wormhole-x402)](https://www.npmjs.com/package/wormhole-x402)
[![Python](https://img.shields.io/pypi/pyversions/wormhole-guard)](https://pypi.org/project/wormhole-guard/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pyproject.toml)
[![Telemetry](https://img.shields.io/badge/telemetry-none-brightgreen)](docs/limits.md#no-telemetry)
[![Corpus](https://img.shields.io/badge/corpus-17%2F17%20·%2015%2F15-informational)](corpus/)

**Your agents talk to each other. Make sure they aren't passing something on.**

**[agentwormhole.com](https://agentwormhole.com)** · [wormhole-guard on PyPI](https://pypi.org/project/wormhole-guard/) · [wormhole-x402 on npm](https://www.npmjs.com/package/wormhole-x402)

Agents spawn agents, hand off work, comment on issues, and read each other's
output. One compromised agent stops being a victim and becomes a carrier — and
the assistant on the other side is exactly as obedient as yours.

Underneath that is an asymmetry nobody owns: your vendor protects its own
`settings.json`, but nothing protects your `CLAUDE.md`, `AGENTS.md`, or
`.cursor/rules`, and by default your agent can write to all of them.

```
$ wormhole scan .

 CRITICAL  SessionStart hook executes a script from an unusual path  [AUTOSTART-002]
  .claude/settings.json
  `node .github/setup.js` runs unprompted on SessionStart. This survives
  uninstalling the package that planted it.

 HIGH  Agent config not in baseline  [BASELINE-003]
  .cursor/rules/setup.mdc
  This file was not present when the baseline was taken.
```

No dependencies beyond Python 3.8+. No account, no API token, no network call.
Your `CLAUDE.md` never leaves the machine.

## Why

**June 2026: the Miasma worm disabled 73 Microsoft GitHub repositories.** It
did not exploit a memory bug. It wrote agent configuration:

| File | Mechanism |
|---|---|
| `.claude/settings.json` | `SessionStart` hook → `node .github/setup.js` |
| `.gemini/settings.json` | same |
| `.cursor/rules/setup.mdc` | `alwaysApply: true`, "run the setup script" |
| `.vscode/tasks.json` | `runOn: folderOpen` |
| `package.json` | hijacked `test` script |

It targeted 15 AI coding agents ([Dataminr](https://www.dataminr.com/resources/intel-briefs/miasma-worm-open-sourced/)
analysis of the open-sourced toolkit; the June writeups counted the five files
above), and the persistence **survives
`npm uninstall` and survives reinstalling the agent** — the settings file
outlives both. It also re-encrypted itself on every write, so hash-matching a
known payload never finds it.

Four of those five anchors need no model in the loop at all. The hook fires
because a session started. That is why this tool checks configuration, not
just prose.

Two more things make the gap structural rather than accidental: **Cursor was
told and declined to own it** (Pillar Security's Rules File Backdoor, disclosed
Feb–Mar 2025; Cursor's response was that the risk falls under user
responsibility), and **sandboxing does not cover the files that matter** —
Claude Code's own docs state that *"Read, Edit, and Write use the permission
system directly rather than running through the sandbox"*, with default write
access to the working directory.

The mechanism paper is
[arXiv:2603.15727](https://arxiv.org/html/2603.15727v3) (*AgentWorm*, NDSS 2026):
82% attack success via skill supply-chain poisoning, 0% once sandbox isolation
was enabled — and **0 of 82** publicly indexed agent configurations had it
enabled. The defense that works exists and nobody is running it. That gap is a
tooling problem, and this is the tool.

Full version, including prior art and how a payload travels between agents:
**[docs/threat-model.md](docs/threat-model.md)**.

## Install

```bash
pipx install wormhole-guard
wormhole scan ~/your-project --blast-radius
```

The distribution is `wormhole-guard`. `agent-wormhole` on PyPI is an unrelated
project. The command and the import package are both `wormhole`.

Standard library only, so it also runs straight from a checkout with no install
step at all:

```bash
git clone https://github.com/runningoffcode/agent-wormhole
cd agent-wormhole
python3 -m wormhole scan ~/your-project --blast-radius
```

## Quickstart

Thirty seconds, in a project you care about:

```bash
wormhole scan ~/project --blast-radius   # what is there now
wormhole init ~/project                  # harden + baseline + print the hooks
```

`init` is a dry run until you pass `--apply`. It prints the three steps it
would take so you can read them first.

Then wire the three hooks into `~/.claude/settings.json`. Each command prints
a JSON fragment to merge — nothing writes your agent's configuration for you:

```bash
wormhole outbound --install   # sends: refuse to pass a payload on
wormhole readguard --install  # reads: PostToolUse + InstructionsLoaded
wormhole guard --install      # writes: the PreToolUse hook
```

Three doors. `readguard` covers what arrives — fetched pages, shell output, MCP
responses — which is how every publicly disclosed agent compromise of 2026
actually got in. `outbound` covers what your agent passes to a subagent, a
peer, or an issue another team's bot will read. `guard` and `harden` cover
whether anything can persist to the next session.

`outbound` is the only one that blocks by default. Inbound content is untrusted
by definition and there is a lot of it, so those rules stay conservative.
Outbound was composed by your own agent, so a payload appearing there is
already anomalous — and a refused send fails loudly, while one that leaves
reaches an operator who never agreed to trust you.

A complete worked version with a real `settings.json` and a blocked write is in
[examples/claude-code-hooks](examples/claude-code-hooks/); the rest is in
[docs/hooks.md](docs/hooks.md).

## What it does, precisely

This is an **integrity monitor for the files your agent reads as
instructions**. The parts that matter do not care what the payload says.

| | | Survives rephrasing? |
|---|---|---|
| **Prevent** | `harden` removes the write, and pre-creates absent config paths so a payload cannot create one either | yes — no rule involved |
| **Notice** | `baseline`/`verify` hash every config; a changed or unrecorded file is a finding | yes — hashing is indifferent to wording |
| **Refuse** | `guard` inspects a pending write through a PreToolUse hook and can decline it | partly — rule-based |
| **Detect** | content rules for payload shapes, autostart rules for unattended execution, posture rules for capability | no — evadable, use as triage |
| **Contain** | `capture` excises payloads, preserving originals byte-for-byte for restore | n/a |

The ordering is deliberate. Prevention and integrity are the durable half;
rules are convenience on top. A tool that leads with its rule count is
competing on the one axis that decays.

The control that drives infection to zero is sandbox isolation, and it lives in
your agent framework, not here — and per Anthropic's own docs it does not cover
Read/Edit/Write by default. This tool makes that gap impossible to overlook.

Details: [docs/rules.md](docs/rules.md) for the rule catalogue and the
regression suite, [docs/scanning.md](docs/scanning.md) for `scan`, `memos`,
`handoffs`, `corpus` and containment.

## Two packages

| | Protects | Install |
|---|---|---|
| **[wormhole-guard](https://pypi.org/project/wormhole-guard/)** | The instruction files your coding agents read | `pipx install wormhole-guard` |
| **[wormhole-x402](https://www.npmjs.com/package/wormhole-x402)** | The payments your agents sign | `npm install wormhole-x402` |

Same thesis, two places an agent reads instructions it did not write. The
Python core is dependency-free; the TypeScript package has no network calls at
all. Neither phones anywhere.

When the agent holds a wallet, everything above costs you a revert and a
payment does not. `wormhole-x402` compares a transaction against the merchant's
own 402 quote — a channel the model never touches — because a payment to an
attacker's address simulates perfectly. See [docs/x402.md](docs/x402.md) and
[examples/x402-solana](examples/x402-solana/).

## Limits

Stated plainly, because a security tool that overclaims is worse than none:

- Regex rules catch *shapes*, not meaning. Novel phrasing evades them.
  **Detection falls to roughly 71% under combined mutation**, and that is an
  upper bound rather than a floor — the mutations are lexical and offline, so
  an attacker with a language model does better.
- The control that drives infection to zero is **sandbox isolation, and it
  lives in your agent framework, not here**.
- `watch` reads transcripts after the fact. It tells you an injection attempt
  reached your agent; it does not block it.
- Nothing here removes an infection from a running agent, and nothing here
  contains an agent running as root. `wormhole` cleans files.
- **Memo worms are not happening yet** — we scanned 40,000 Solana mainnet
  signatures, extracted 1,064 memos, and found **zero** injection findings. A
  null result is worth publishing because it makes a first occurrence visible.
- In the payment guard, `abstain` is not an all-clear. It means the guard could
  not evaluate the input.
- Miasma is confirmed in the wild, and it spread through package installs while
  persisting via agent config. **Fully autonomous** self-replication — a payload
  rewriting itself into peers' configs with no package manager involved — is
  still demonstrated in a lab, not observed. We will not blur those two.

There is no warranty, and this sends nothing anywhere: no account, no API
token, no network call at any point. Both in full, along with what the tool
does not cover: **[docs/limits.md](docs/limits.md)**.

## Documentation

| | |
|---|---|
| [docs/threat-model.md](docs/threat-model.md) | Miasma, the vendor gap, AgentWorm, how a payload travels |
| [docs/rules.md](docs/rules.md) | Rule catalogue, regression suite, mutation decay, suppression |
| [docs/hooks.md](docs/hooks.md) | `guard` / `readguard` / `outbound` in depth, and `harden` |
| [docs/scanning.md](docs/scanning.md) | `scan`, `memos`, `handoffs`, `corpus`, capture, CI, SARIF, MCP |
| [docs/x402.md](docs/x402.md) | The payment guard: Solana, EVM, quote text |
| [docs/limits.md](docs/limits.md) | No warranty, no telemetry, limits, supported formats |

Runnable examples, each with its actual output pasted in:
[claude-code-hooks](examples/claude-code-hooks/) ·
[x402-solana](examples/x402-solana/) ·
[x402-evm](examples/x402-evm/) ·
[quote-scanning](examples/quote-scanning/) ·
[ci-github-action](examples/ci-github-action/) ·
[agent-fleet](examples/agent-fleet/) ·
[index](docs/README.md)

## Contributing

Every new detection rule ships with a benign twin — a file discussing the same
attack without being one. If the rule fires on the twin, it does not ship. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Apache 2.0.
