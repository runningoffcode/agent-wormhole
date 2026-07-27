# Fleet management — plan

**Status: PLAN ONLY. Nothing here is built.** Written 2026-07-27 so the paid
tier is designed deliberately rather than assembled from whatever seemed
sellable.

## What this is, and why it is the paid tier rather than text inspection

Selling text inspection as a service is dead. Cloudflare ships injection
filtering free on every plan, AWS cut Bedrock Guardrails 80% to $0.15/1k, Azure
and Google are at $0.38/1k and $0.10/M tokens, and Microsoft Defender hooks
Claude Code through the same `PreToolUse`/`PostToolUse` interface this project
uses — free on E5. Every standalone vendor in the category was acquired between
2024 and 2026, most recently Pangea into CrowdStrike at roughly $260M, and
Pangea's product was almost exactly a self-serve inspect API plus an MCP proxy.
There are no surviving independents. A classifier competing with free has no
pricing power.

What survived the research is narrower and better: **the control in this project
with the best real-world record is the one that blocks a write as it happens.**

In the TrapDoor incident (May 2026) poisoned npm and PyPI packages wrote
invisible instructions into developers' `CLAUDE.md` files, and the real losses
were SSH keys, AWS tokens and wallet keystores. `wormhole guard --block` refuses
that write at the moment it is attempted. A hosted inspection API only helps if
someone later remembers to send the file somewhere. Cloudflare filters traffic
crossing its edge; Defender alerts after the fact. Nothing free blocks the write
at the write.

So the free tool keeps the control that works. **What gets sold is running that
control across a fleet** — which is administration, not detection, and does not
compete with a free hyperscaler feature.

## The problem an operator actually has

A team with fifty agents across thirty repositories cannot answer these
questions today, and each one is a real gap rather than a hypothetical:

- Which repositories have `harden` applied, and which quietly lost it when
  someone ran `chmod` or a fresh clone recreated the files writable?
- Which agents are running the guard hook at all, and which have it installed
  but in warn mode rather than block?
- Has any watched config file changed since it was baselined, anywhere?
- Did the same payload reach more than one agent? **A local scanner has no
  denominator. Propagation is defined over a set of machines, and one host holds
  one sample with nothing to compare it against.**
- When an incident happens, which agents read from the source that was poisoned?

Every sensor needed to answer these already exists and ships free: `scan`,
`harden`, `baseline`, `verify`, `guard`, `readguard`, `outbound`, plus the
`--blast-radius` permission audit. What is missing is a place where their output
lands together.

## What gets built

### Phase 1 — Posture inventory (the minimum real thing)

A reporting agent on each machine and a console that aggregates.

- **Fleet inventory.** Every agent, its configs, hook installation state
  (absent / warn / block), harden state, baseline freshness.
- **Drift alerts.** A watched file changed, a hardened file became writable, a
  hook was removed, an MCP tool definition changed since approval (MCP-001).
- **Coverage gaps.** The single most useful screen: *"9 of 37 agents have no
  guard hook, and 4 have it in warn mode."* Nobody can produce that today.
- **SIEM export.** OCSF/CEF plus Splunk and Sentinel connectors. Without this a
  security team cannot adopt it regardless of how good it is, because their
  workflow lives in the SIEM.

Wire format sends **verdicts, rule IDs, content hashes, byte offsets, path
hashes, agent ID, timestamp**. Never prompt or file plaintext. See the telemetry
section — that constraint is load-bearing and structural.

Priced per agent per month. Real recurring cost: storage, ingestion, alerting.

### Phase 2 — Correlation

The capability a single local scanner structurally cannot provide.

- **Prevalence.** *"Payload X reached 4 of your 37 agents in 52 minutes."*
- **Direction.** `readguard` sees payloads arriving; `outbound` sees them
  leaving. Both ends instrumented on the same fleet means an arrow can be drawn
  from agent A to agent B and patient zero named. No other vendor has sensors on
  both ends of an agent-to-agent hop.
- **Disambiguation.** The same MCP tool-definition hash change across 20 agents
  is a vendor update. On one agent it is tampering. Identical local signal,
  opposite verdict, impossible to resolve on one machine. This demos well
  precisely because the local half is free and commoditized (Vercel's AI SDK
  ships `fingerprintTools`/`detectToolDrift` first-party).
- **Shared-source blast radius.** *"This MCP server is read by 14 agents across
  3 teams."* Immune to payload mutation entirely, because it keys on the source
  rather than the text — and it is what an operator actually asks for during an
  incident: the containment list.

**Known limitation, stated up front:** exact-payload correlation is defeated by
mutation. Our measurements are unambiguous — 200 mutated variants of one payload
produced 200 distinct hashes and zero correlated pairs, and simhash on light
mutation lands at Hamming distance 17–34 against a threshold of 6. Semantic
paraphrase is statistically indistinguishable from unrelated text. **So
correlation must key on destination and source, not on payload identity.** A
paraphrasing worm still writes to `CLAUDE.md` on every host and still comes from
the same poisoned upstream.

A second limitation: correlation recall is capped by local detection. If the
rule does not fire, no record exists, and no threshold recovers it. Rules sit at
roughly 71% under combined paraphrase.

### Phase 3 — Policy and remediation

- Central policy: required hook mode, harden enforcement, allowed MCP servers.
- One-click remediation: re-harden, re-baseline, quarantine across the fleet.
- Role-based access, audit log, SSO/SAML.

Only after Phases 1 and 2 have paying users. Policy engines are where this kind
of product goes to die if built first.

## The telemetry constraint

The free scanner's promise — 100% local, zero telemetry, offline, no account —
is worth more than this product's revenue. If the two blur, the trust that
carries the whole project is gone and no amount of fleet ARR buys it back.

Non-negotiable, and each item is enforcement rather than intent:

1. **Separate product, separate opt-in package, separate privacy page.** The
   free CLI never gains a network call.
2. **A CI gate that fails the build if the free import path opens a socket.** It
   ships before the fleet tier is announced, not after the first accusation.
3. **Zero plaintext by default.** Verdicts, rule IDs, offsets, hashes.
   **Landmine to fix first:** `_excerpt()` is called unconditionally inside
   `scan_text`'s `add()`, so every Finding currently carries ~110 characters of
   plaintext by construction. The reporting path needs a Finding type with **no
   excerpt field at all** — a compile-time guarantee, because a runtime flag
   leaks in a debug build or a panic path.
4. **Never transmit excerpts for the credential-exfil rule class at any tier.**
   WORM-003 fires *on* credential-shaped text; sending excerpts there would
   upload customer secrets. This keeps us out of the secrets-custody business
   entirely.
5. **Hash-only mode as a first-class option.** The customer verifies locally and
   posts only hashes.
6. **Self-host container at standard price.** Air-gapped and regulated buyers
   *should* refuse a hosted console. We agree with them and sell them the
   container — and "the only vendor whose monitoring runs entirely inside your
   perimeter" is a differentiator no acquired incumbent can claim.
7. **Published sub-processor list. No third parties in the data path.** No
   Datadog with bodies, no Sentry with bodies.

## Pricing

Priced in USDC and by card. **$WORM accepted at a discount and gating nothing.**

| Tier | Price | Scope |
|---|---|---|
| Free | $0 | The local tools, forever. Unlimited agents, no account. |
| Team | ~$10/agent/mo, min ~$99 | Inventory, drift alerts, coverage gaps, SIEM export |
| Fleet | ~$8/agent/mo, min ~$499 | Correlation, blast radius, RBAC, SSO |
| Self-host | Standard price | Container, air-gapped, no data leaves |

The token arithmetic, stated so nobody oversells it: at $50k/month revenue with
40% of customers electing to pay in token, that is roughly $16k/month of organic
buy pressure — about **0.08% of a $20M FDV per month.** It will not move a
price. The honest framing is that the token funds infrastructure and research
and earns holders a discount, not that usage pumps it.

## Honest risks

1. **The category is occupied above us.** Microsoft Defender for Endpoint
   already ingests Claude Code hook telemetry, free on E5, and Exabeam and Noma
   ship endpoint agent sensors. **Do not pitch "EDR for AI agents."** The
   defensible primitive is narrower: a named, alertable propagation object —
   *"this payload appeared on N agents"* — which no vendor currently ships, and
   which every published SIEM rule misses because they all key on a single
   `agent_id` and have no payload identity to group by.
2. **The buyer may not exist yet.** This needs a team running enough agents that
   fleet questions hurt. That is a real segment in 2026 but not a large one, and
   **no customer has confirmed they would pay.** One conversation with an
   operator running fifty agents is worth more than any further research.
3. **The brand contradiction, if handled sloppily.** Every item in the telemetry
   section is load-bearing. If zero-plaintext-by-default cannot be held, do not
   ship the hosted path — the scanner's credibility is worth more than the
   console's revenue.

## Kill criterion

Within eight weeks of starting Phase 1: **one operator running ten or more
agents installs the reporting agent, and the coverage-gap screen tells them
something they did not already know.**

Not revenue. Not signups. That screen producing a genuine surprise is the whole
premise. If it does not, the fleet questions were not real and this should stop.

## Build order

- **Phase 0 (before any of it):** the CI socket gate, and the `_excerpt()` fix
  so the reporting path physically cannot carry plaintext.
- **Phase 1:** reporting agent, inventory, drift alerts, coverage-gap screen,
  SIEM export. Priced.
- **Phase 2:** correlation on destination and source. Never on payload hash.
- **Phase 3:** policy and remediation, only after Phase 2 has paying users.
