# quarantine

Find out what your AI agent is actually allowed to do — and get told when its
instructions change behind your back.

```
$ quarantine scan .

blast radius  severe (8/10)
  execute    ██████████ 10
  persist    ███████░░░ 7
  propagate  ████████░░ 8
   LOOP CLOSED  execute → persist → propagate are all reachable: an infection
                here can complete a full cycle unassisted.

 CRITICAL  Unrestricted shell access granted  [POSTURE-001]
  ~/.claude/settings.json
  `Bash(*)` permits any shell command. The 71 narrower Bash rules in this file
  are therefore decorative — they constrain nothing.
```

Agent frameworks load `AGENTS.md` and `CLAUDE.md` into the system prompt at
every session start, with no integrity or provenance check. Those files are
usually writable by the agent itself. Anything written there runs with the
agent's full permissions on every subsequent session, and can be copied onward
into the next config the agent touches.

`quarantine` finds payloads with that shape, scores what an infection could
reach, and fingerprints your configs so modification becomes visible.

No dependencies beyond Python 3.8+. Nothing leaves your machine.

## Why

In March 2026, researchers demonstrated the first self-replicating worm against
a production-scale agent framework across 2,250 trials
([arXiv:2603.15727](https://arxiv.org/abs/2603.15727), NDSS 2026). Three of
their numbers explain this project:

- **82%** — attack success via skill supply-chain poisoning, the highest of any
  vector, "universally vulnerable" across every model tested.
- **0%** — attack success once sandbox isolation was enabled. It was the only
  built-in control that broke the infection loop.
- **0%** — the share of 82 real, publicly indexed agent configurations that had
  sandbox isolation enabled. 62% had enabled gateway authentication instead,
  which does not stop propagation.

The defense that works exists and nobody is running it. That gap is a tooling
problem, and this is the tool. See [MISSION.md](MISSION.md).

## Use

```bash
quarantine scan ~/project --blast-radius   # payloads, posture, blast radius
quarantine baseline ~/project              # fingerprint configs
quarantine verify ~/project                # detect modification
quarantine watch --limit 20                # injection attempts in tool output
quarantine wormhole ~/project              # preview capture (dry run)
quarantine wormhole ~/project --apply      # capture, preserving originals
```

`scan` and `watch` exit nonzero at or above `--fail-on` (default `high`), so
they drop into CI as-is.

## The Wormhole

Captured payloads go into the Wormhole rather than the bin.

```bash
quarantine wormhole ~/project --apply   # excise payloads, keep originals
quarantine wormhole-list                # what has been captured
quarantine wormhole-restore <id>        # pull one back out (false positive)
quarantine wormhole-export ./samples    # inert fixtures for rule development
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

It **detects, scores, and alerts**. It does not eliminate infections, and it is
not a substitute for sandbox isolation.

| | |
|---|---|
| **Detect** | 7 content rules for payload shapes; 6 posture rules for capability; runtime scan of tool output |
| **Score** | Blast radius across the execute → persist → propagate infection loop |
| **Alert** | Baseline hashing catches modification no rule anticipated |
| **Contain** | `wormhole` excises payloads, preserving originals for restore |

The control that actually drives infection to zero is sandbox isolation, and it
lives in your agent framework, not here. This tool makes its absence impossible
to overlook.

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

**Posture** — what a payload could accomplish if it arrived: unrestricted shell
(`POSTURE-001`), network egress (`-002`), missing deny rules (`-003`), writable
configs (`-004`), remote MCP servers (`-005`), installed skills (`-006`).

**Integrity** — `BASELINE-001/002/003`: changed, missing, or untracked config.
This is the half that catches payloads no rule anticipated.

**Runtime** — `RUNTIME-*`: the same content rules applied to tool output in
session transcripts, covering the supply-chain channel that never touches disk.

## Accuracy

Rules require a replication cue *and* a delivery cue in proximity, so files that
merely *discuss* prompt injection do not trip them.

```
$ ./loop/replay.sh
detected 7/7   clean 6/6   FN=0 FP=0
```

The benign corpus is deliberately adversarial: a threat-model document, a
config saying "include the license header in every source file you create", a
`.env` setup guide, and a legitimate skill that writes to `CHANGELOG.md`.
Runtime scanning additionally distinguishes source code from prose, so reading
a payment handler that references `process.env.TREASURY_WALLET` beside an RPC
URL is not reported as exfiltration.

Verified additionally against 7 real projects: 0 findings.

## Supported config formats

`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*.mdc`,
`.windsurfrules`, `.windsurf/rules/*.md`,
`.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`.

Permission analysis currently understands Claude Code's `settings.json` best.

## Continuous auditing

```bash
loop/install-cron.sh          # every 6h; --remove to uninstall
```

Silent when nothing changed; logs to `~/.quarantine/logs/` and raises a
notification when a tracked config is modified or a payload appears.
[loop/RESEARCH.md](loop/RESEARCH.md) documents how new rules get added without
eroding the false-positive rate.

## CI

```yaml
- uses: runningoffcode/quarantine@v1
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
    "quarantine": {
      "command": "python3",
      "args": ["-m", "quarantine.mcp_server"],
      "cwd": "/path/to/quarantine"
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
