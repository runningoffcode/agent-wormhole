# Positioning & pitch

## The one-line version

> Your AI agent reads a config file on every start. If something writes to that
> file, your agent runs it — and writes it to the next one. `wormhole` tells
> you when that file changes.

## Why this lands (and what to avoid)

The instinct is to lead with worms. Don't. "AI worm" reads as speculative to a
buyer who has never seen one, and the category is crowded with vendors selling
fear. The demo below converts far better because it is *about them*, verifiable
in ten seconds, and true before any worm exists.

**Lead with the audit, not the threat.** The threat is the reason the audit
matters — it belongs in paragraph two, not the subject line.

## The demo that sells it

Run the scanner on the prospect's own machine, live:

```
$ wormhole scan .

 CRITICAL  Unrestricted shell access granted  [POSTURE-001]
  ~/.claude/settings.json
  `Bash(*)` permits any shell command. The 71 narrower Bash rules in this
  file are therefore decorative — they constrain nothing.
```

That finding is real; it came from this machine, where 71 carefully written
permission rules were silently nullified by one wildcard on line 75. Nearly
every serious agent user has some version of it. It is specific, it is
embarrassing in a *useful* way, and it is fixable in one line — which makes the
tool feel like a colleague rather than a vendor.

Then the second beat:

```
$ wormhole baseline .   # take a fingerprint
$ wormhole verify .

 HIGH  Agent config modified since baseline  [BASELINE-001]
```

Now they understand the product in two commands: *find what's overexposed, and
notice when it changes.*

## Audiences, in order of how well this fits

**1. Individual agent developers — free, and the whole funnel.**
Pitch: "ten seconds, tells you what your agent is actually allowed to do."
Channel: Show HN, the MCP/agent tooling communities, a blog post built around
the `Bash(*)` finding with real numbers. This group will never pay and should
never be asked to. They are how it becomes standard.

**2. Teams running agents in CI — the first real buyers.**
Pitch: "a poisoned AGENTS.md in a PR is an agent instruction with commit
access." `wormhole scan --fail-on high` in a pipeline is a two-line diff and
an obvious control. This is where the money starts, because it is a budget line
that already exists (SAST/secret scanning) and a familiar shape.

**3. Companies operating agent fleets — the actual business.**
Pitch: "you have 200 tenant agents and no idea which of their configs changed
this week." A local CLI cannot answer that. Fleet monitoring, signed audit
trails, and a managed rule feed can. Traccion is a live example of this shape —
worth using as the design partner and the case study.

**4. Compliance / security review — a wedge, not a beachhead.**
Agent deployments are starting to hit security review with no evidence to show.
"Here is our agent posture report and integrity log" is a real artifact. Follows
from (3); don't chase it first.

## Pricing (unchanged from the earlier call, now with the reason sharpened)

| | Free, open source | Team | Enterprise |
|---|---|---|---|
| Scanner, rules, baseline/verify, MCP server | ✓ | ✓ | ✓ |
| CI action | ✓ | ✓ | ✓ |
| Fleet dashboard, cross-repo drift | | ✓ | ✓ |
| Signed audit trail / compliance export | | ✓ | ✓ |
| Managed rule feed | | ✓ | ✓ |
| Containment orchestration, credential rotation hooks | | | ✓ |

Numbers stay guesses until there are users — roughly $0 / low hundreds per
month / custom. **Do not design the product around the pricing table yet.**

The core must stay genuinely free and genuinely complete. A security tool that
inspects your prompts, tool surface, and permissions is asking for real trust,
and nobody grants that to a closed binary from an unknown vendor. Open source
is the trust mechanism, not the marketing strategy — and a crippled free tier
gets forked within a week.

## What makes this defensible

Not the regexes — those are copyable in an afternoon. The moat, in order:

1. **The labelled corpus.** Malicious fixtures paired with benign twins. This
   is the hard part and the most useful thing to publish. Nobody else has one.
2. **The false-positive discipline.** 0 hits across 7 real projects while
   catching 4/4 fixtures. Security tools die of noise; a measured FP rate is a
   sellable claim.
3. **Being early and being default.** Whoever is in the CI templates when the
   first real incident lands, wins the category.

## Honest objections, and the answers

**"Has this actually happened?"** Yes, and you should lead with it. In June
2026 the Miasma worm self-propagated through GitHub and disabled 73 Microsoft
repositories across Azure, Azure-Samples and MicrosoftDocs. It persisted by
writing `.claude/settings.json` and `.gemini/settings.json` SessionStart hooks,
a `.cursor/rules/setup.mdc` always-apply rule, and a `.vscode/tasks.json`
folderOpen task — all pointing at one dropper. It targeted 15 AI coding agents,
and the persistence survives `npm uninstall` and survives reinstalling the
agent, because the settings file outlives both.

Be precise about what is and is not established. Miasma is a confirmed
in-the-wild worm that used agent config files for persistence and propagation.
The *fully autonomous* self-replication described in the AgentWorm paper — a
payload rewriting itself into peers' configs with no package manager involved —
remains demonstrated in a lab, not observed in the wild. Claiming otherwise
loses the only audience that matters. The distinction is also not load-bearing:
the mechanism is the same file, and Miasma proves attackers are already using
it.

**"Can't the model just refuse?"** Sometimes. But the config file is loaded as
*system* instructions, not as untrusted input — that framing is the whole
problem. And detection at the model layer is best-effort; a changed hash is not.

**"Isn't this just a linter?"** Yes, for the content half — and that is fine,
linters are useful. The integrity half is not a linter, and it is the part that
catches payloads no rule anticipated.

## Do not do

- Do not publish working worm payloads. Inert fixtures only. Publishing a
  functional self-replicating prompt would be net-negative regardless of intent,
  and would cost exactly the credibility this depends on.
- Do not claim detection coverage you cannot measure. Cite the corpus numbers.
- Do not let the MCP server perform remediation. Read-only. A security tool an
  agent can ask to modify config is itself an injection target.
