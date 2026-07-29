# Rules and detection

The full rule catalogue, the regression suite that keeps it honest, and the
measured cost of evading it.

[← README](../README.md) · [Threat model](threat-model.md) · [Scanning](scanning.md) · [Limits](limits.md)

---

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

---

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

---

## The regression suite

```
$ ./loop/replay.sh
detected 17/17   clean 15/15   FN=0 FP=0
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

### What it actually costs to evade

Since "17/17" says nothing about phrasing nobody has written down yet, here is
the number that does. `loop/mutate.py` rewrites every malicious fixture and
reports what survives:

```
$ python3 loop/mutate.py

  tier                   caught   rate
  verbatim             17/17       100%
  casing               68/68       100%
  filler               68/68       100%
  synonym-1           104/136       76%
  reorder              17/17       100%
  synonym+filler      104/136       76%
  passive-voice        16/17         94%
  combined             97/136        71%
```

**Detection falls to roughly 71% under combined mutation, and one round of
synonym substitution costs about a quarter of it.** The mutations are lexical
and offline, so an attacker with a language model does better than this — treat
71% as an upper bound, not a floor.

That curve is the argument for the rest of the tool. `baseline` and `verify`
flag *any* change to a watched file regardless of wording, and `harden` removes
the write access a payload needs to persist at all. Neither has to recognise
anything. Rules are triage; containment is the product.

---

## Suppressing a finding

`--fail-on` is only adoptable with an escape hatch narrower than `|| true`.
Put a directive on the finding's line, or the line above it:

```markdown
<!-- wormhole:ignore WORM-002 -->
Ignore all previous formatting conventions and use tabs.
```

Rule IDs are required — there is no blanket ignore, because an unreviewable
opt-out is indistinguishable from uninstalling the tool.

**Only `wormhole scan` honours these directives.** The blocking write hook, the
read path (`readguard`), outbound handoffs, and every scanner ignore them
entirely. The reasoning is that "an attacker who can write to the file could
also write the comment" holds only for `scan`, which audits a file that already
exists — it is false for `guard`, which is judging a write that has *not* landed
yet, and false for remote content, which the attacker authored with no
file-write capability behind it at all. Suppression is therefore opt-in per call
site, and off by default, so a call site added later inherits the safe
behaviour.

Applied suppressions are printed in the scan summary and emitted in SARIF's
`suppressions` array, where GitHub renders them as dismissed rather than
absent. `--no-suppress` ignores them entirely. An exemption that vanishes from
the output is unauditable, which is the only reason the feature is defensible.

---

Related: [Scanning](scanning.md) for the commands that apply these rules ·
[x402](x402.md) for the same idea applied to quote text ·
[Limits](limits.md) for what rules cannot do.

Run it: [examples/ci-github-action](../examples/ci-github-action/)
