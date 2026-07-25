# Agent Wormhole

[![ci](https://github.com/runningoffcode/agent-wormhole/actions/workflows/ci.yml/badge.svg)](https://github.com/runningoffcode/agent-wormhole/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/wormhole-guard)](https://pypi.org/project/wormhole-guard/)
[![Python](https://img.shields.io/pypi/pyversions/wormhole-guard)](https://pypi.org/project/wormhole-guard/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pyproject.toml)
[![Telemetry](https://img.shields.io/badge/telemetry-none-brightgreen)](#no-telemetry)
[![Corpus](https://img.shields.io/badge/corpus-15%2F15%20·%2014%2F14-informational)](corpus/)

**Your agents talk to each other. Make sure they aren't passing something on.**

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

It targeted 15 AI coding agents, and the persistence **survives
`npm uninstall` and survives reinstalling the agent** — the settings file
outlives both. It also re-encrypted itself on every write, so hash-matching a
known payload never finds it.

Four of those five anchors need no model in the loop at all. The hook fires
because a session started. That is why this tool checks configuration, not
just prose.

Two more things make the gap structural rather than accidental:

- **Cursor was told and declined to own it.** Pillar Security's Rules File
  Backdoor (disclosed Feb–Mar 2025) hid instructions in `.cursor/rules` using
  invisible Unicode. Cursor's response was that the risk falls under user
  responsibility. This is how you take that responsibility.
- **Sandboxing does not cover the files that matter.** Claude Code's own docs
  state that *"Read, Edit, and Write use the permission system directly rather
  than running through the sandbox"*, with default write access to the working
  directory. The research result below — that sandbox isolation drives attack
  success to zero — does not transfer to a default install.

The mechanism paper is
[arXiv:2603.15727](https://arxiv.org/abs/2603.15727) (preprint, Mar 2026,
rev. Jul 2026): 2,250 trials, 82% attack success via skill supply-chain
poisoning (63% aggregate across all three vectors), 0% once sandbox isolation
was enabled — and **0 of 82** publicly indexed agent configurations had it
enabled. 62% had gateway authentication instead, which does not stop
propagation.

The defense that works exists and nobody is running it. That gap is a tooling
problem, and this is the tool. See [MISSION.md](MISSION.md).

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

## Use

Prevention — these run before a payload lands:

```bash
wormhole init ~/project                  # harden + baseline + print the hooks
wormhole outbound --install              # sends: refuse to pass a payload on
wormhole readguard --install             # reads: PostToolUse + InstructionsLoaded
wormhole guard --install                 # writes: the PreToolUse hook
wormhole harden ~/project --apply        # drop the write bit, block creation
wormhole harden ~/project --undo --apply # restore write permission
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

Detection and containment — these run after:

```bash
wormhole scan ~/project --blast-radius   # payloads, posture, blast radius
wormhole baseline ~/project              # fingerprint configs
wormhole verify ~/project                # detect modification
wormhole watch --limit 20                # injection attempts in tool output
wormhole capture ~/project               # preview capture (dry run)
wormhole capture ~/project --apply       # capture, preserving originals
wormhole captured                        # list what has been contained
wormhole restore <id>                    # pull one back out, byte-for-byte
wormhole insights                        # what the capture history reveals
wormhole handoffs                        # payloads in agent-to-agent tasks
wormhole corpus ./docs                   # documents before they are embedded
```

`handoffs` and `corpus` cover the two vectors this tool sees least well, and
the limits are worth stating. A task description passed to a child agent has no
interception point — the parent composes it in memory — so `handoffs` reads
transcripts after the fact. A vector store has no standard format, so `corpus`
scans documents *before* ingestion, which is the last point at which the text
is still text.

`guard` warns by default. Block mode refuses only WORM-001 and WORM-003 — the
two rules with an unambiguous structural signature and no corpus false
positives — because a rule defect in a blocking tool stops legitimate work
rather than printing noise.

`scan` and `watch` exit nonzero at or above `--fail-on` (default `high`), so
they drop into CI as-is.

## The Wormhole

Captured payloads go into the Wormhole rather than the bin.

```bash
wormhole capture ~/project --apply   # excise payloads, keep originals
wormhole captured                # what has been captured
wormhole restore <id>        # pull one back out (false positive)
wormhole export ./samples    # inert fixtures for rule development
```

Deleting a payload destroys the evidence needed to answer the only questions
that matter after an infection: what wrote this, when, and did it spread. It
also turns a false positive into data loss, which is how a security tool loses
its users. So the original file is preserved byte-for-byte with a full
provenance record, and every capture is reversible.

Excision runs iteratively — excise, rescan, repeat — because a payload can
occupy several separate blocks. AgentWorm's dual-anchor design uses exactly
two, and removing only the first would leave the second live while making the
file look treated. If the file cannot be brought clean, the run says
`INCOMPLETE` rather than claiming success.

The Wormhole is `0700`; payloads are stored `0400` with a `.quarantined`
suffix, so nothing in it is loaded as agent config or executed.

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

## Detection rules

**Content** — text shaped like a self-replicating payload:

| | |
|---|---|
| `WORM-001` | Self-replicating instruction (self-reference + copy verb + destination) |
| `WORM-002` | Instruction-override phrasing |
| `WORM-003` | Credential exfiltration to an external destination |
| `WORM-004` | Directives hidden in HTML comments |
| `WORM-005` | Zero-width characters |
| `WORM-006` | Unicode tag-block smuggling (invisible, model-readable) |
| `WORM-007` | Concealment directives ("do not tell the user") |

**Autostart** — configuration that executes with no prompt and no model. This
is the shape that actually propagated in the wild:

| | |
|---|---|
| `AUTOSTART-001` | Unattended hook downloads and executes (`curl … \| sh`) |
| `AUTOSTART-002` | Unattended hook runs a script from a config directory |
| `AUTOSTART-003` | Unattended hook runs an interpreter |
| `AUTOSTART-004` | Always-applied Cursor rule instructing the agent to run a command |

`PreToolUse` is deliberately not treated as unattended — it fires because the
agent is already acting, and it is how `guard` itself ships.

**MCP tool integrity** — the one artifact here that never touches disk. A
server answers `tools/list` at connect time and the name, description and
schema it returns are injected into the model's context, where they read as
instruction. Nothing in the protocol signs that answer and nothing requires a
client to re-check it, so a server can be benign when you review it and
different a week later with no file having changed.

| | |
|---|---|
| `MCP-001` | A tool definition no longer matches what was recorded |
| `MCP-002` | A tool that was not present when the baseline was taken |
| `MCP-003` | A recorded tool is no longer declared |
| `MCP-WORM-*` | The content rules, applied to a tool description |

`wormhole baseline` fingerprints them alongside your config files; `verify`
reports drift. Reformatted JSON is not a change — only the name, description
and schema are hashed.

**Posture** — what a payload could accomplish if it arrived: unrestricted shell
(`POSTURE-001`), network egress (`-002`), missing deny rules (`-003`), writable
configs (`-004`), remote MCP servers (`-005`), installed skills (`-006`).

**Integrity** — `BASELINE-001/002/003`: changed, missing, or untracked config.
This is the half that catches payloads no rule anticipated.

**Runtime** — `RUNTIME-*`: the same content rules applied to tool output in
session transcripts, covering the supply-chain channel that never touches disk.

## The regression suite

```
$ ./loop/replay.sh
detected 15/15   clean 14/14   FN=0 FP=0
```

**This is a regression suite, not a detection rate.** It is measured on
fixtures written for this repository, so it proves the rules still behave as
intended after a change — nothing more. Anyone quoting it as accuracy against
real attackers, including us, is overclaiming. Rule-based detection is evadable
by construction: Trail of Bits bypassed every major skill scanner in under an
hour, and paraphrase alone defeats published classifiers.

What the suite does enforce is the discipline that makes the rules usable:
every malicious fixture ships a **benign twin** that holds the payload's
incriminating surface features and varies only the property the rule keys on.
A keyword matcher fails the pair in both directions. If a rule fires on the
twin, it does not ship. This caught two real false negatives and one critical
false positive before release.

The benign half is deliberately adversarial: a threat-model document, a config
saying "include the license header in every source file you create", a `.env`
guide, a legitimate skill that writes to `CHANGELOG.md`, a `SessionStart` hook
running `git fetch`, and this project's own guard hook.

Verified additionally against 7 real projects: 0 findings.

## No warranty

Apache 2.0, and the liability terms are worth reading rather than assuming:

> Unless required by applicable law or agreed to in writing, Licensor provides
> the Work **"AS IS", WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND**, either
> express or implied. You are solely responsible for determining the
> appropriateness of using or redistributing the Work and assume any risks
> associated with Your exercise of permissions under this License.
>
> In no event shall any Contributor be liable to You for damages, including any
> direct, indirect, special, incidental, or consequential damages of any
> character arising as a result of this License or out of the use or inability
> to use the Work.

— [LICENSE](LICENSE), §7 and §8

In plain terms: this is a detection and hardening tool, not a guarantee. It can
miss a payload it has never seen, it can be wrong about one it has, and it does
not make an agent safe. Read [Limits](#limits) before you rely on it for
anything, and keep the control that actually works — sandbox isolation — on
your list regardless.

Apache 2.0 also carries an express patent grant (§3), which is why this project
stays on it rather than moving to a shorter permissive license.

## No telemetry

This tool reads the most sensitive surface in your setup: prompts, permissions,
credentials-adjacent configuration, and the contents of files your agent treats
as instructions. So it sends none of it anywhere.

- No account, no API token, no network call at any point.
- No dependencies beyond the Python standard library, so nothing is pulled in
  that could change this later.
- The baseline and capture stores live in `~/.wormhole`, on your machine.
- `wormhole insights` analyses your own capture history locally. There is no
  global feed, deliberately — building one would require exactly the data this
  promise forbids.

Contributing a fixture upstream is a separate, deliberate act (`wormhole
export`), and exports are inert by policy: no live endpoints, no working
payloads.

Verify it rather than believing it. The whole tool is ~4,000 lines of
dependency-free Python:

```bash
# No network client is imported anywhere. This prints nothing.
grep -rnE "^\s*(import|from)\s+(socket|urllib|http|requests|aiohttp)" wormhole/
```

## Supported config formats

`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*.mdc`,
`.windsurfrules`, `.windsurf/rules/*.md`,
`.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`.

Permission analysis currently understands Claude Code's `settings.json` best.

## Continuous auditing

```bash
loop/install-cron.sh          # every 6h; --remove to uninstall
```

Silent when nothing changed; logs to `~/.wormhole/logs/` and raises a
notification when a tracked config is modified or a payload appears.
[loop/RESEARCH.md](loop/RESEARCH.md) documents how new rules get added without
eroding the false-positive rate.

## CI

```yaml
- uses: runningoffcode/agent-wormhole@v1
  with:
    fail-on: high
```

## MCP server

Lets an agent audit its own posture. Read-only by design — it reports and never
writes, because a security tool the agent can ask to modify config is itself an
injection target.

```json
{
  "mcpServers": {
    "wormhole": {
      "command": "python3",
      "args": ["-m", "wormhole.mcp_server"],
      "cwd": "/path/to/agent-wormhole"
    }
  }
}
```

Tools: `scan_agent_configs`, `check_integrity`, `blast_radius`,
`scan_session_history`.

## Limits

Stated plainly, because a security tool that overclaims is worse than none:

- Regex rules catch *shapes*, not meaning. Novel phrasing evades them — which is
  why `baseline`/`verify` exists and matters more than rule coverage.
- `watch` reads transcripts after the fact. It tells you an injection attempt
  reached your agent; it does not block it.
- Nothing here removes an infection from a running agent. `wormhole` cleans files.
- No worm has been publicly confirmed propagating in the wild. The preconditions
  are present today and the posture findings are real regardless.

## Contributing

Every new detection rule ships with a benign twin — a file discussing the same
attack without being one. If the rule fires on the twin, it does not ship. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Apache 2.0.
