# Research loop

The detection rules catch payload *shapes* we have already seen. Novel phrasing
will evade them. This loop is how the ruleset stops going stale — it is
report-only, and a human decides what becomes a rule.

## Cadence

| Cadence | Step | Output |
|---|---|---|
| Every 6h (cron) | `loop/audit.sh` on all agent configs | silence, or an alert |
| Weekly | Corpus replay — run the ruleset over `corpus/` | FP/FN count per rule |
| Weekly | Literature sweep (below) | new payload shapes → candidate rules |
| On new rule | Add fixture to `corpus/malicious/`, benign twin to `corpus/benign/` | regression protection |

## The rule that keeps this honest

**Every new detection rule ships with a benign twin.** For each malicious
fixture in `corpus/malicious/`, write a file in `corpus/benign/` that talks
about the same attack without being one — security documentation, a threat
model, this repo's own README. A rule that fires on the twin is rejected.

This is the discipline that produced the current result (0 hits across 7 real
projects, 4 rules on the fixture). It is easy to lose by adding one greedy
regex.

## Literature sweep

Sources worth re-reading for new propagation shapes:

- Morris II / RAG-backdoor line of work — replication via retrieved context
- AgentWorm — supply chain (skills/marketplace) as the highest-yield vector
- OWASP LLM Top 10, LLM01 (prompt injection) revisions
- MCP spec security notes and advisories for popular servers
- Public incident writeups: any real agent-to-agent propagation in the wild

For each: does the payload have a *structural* signature (self-reference,
delivery verb, destination), or is it purely semantic? Structural ones become
regex rules. Semantic ones become posture recommendations instead — we do not
try to out-regex an LLM.

## Open questions to keep pulling on

1. **Cross-agent propagation.** Current rules scan files at rest. A payload
   that lives only in tool output (MCP response, fetched web page) never
   touches disk. Worth a `quarantine watch` mode over agent logs?
2. **Semantic detection.** A classifier catches paraphrase that regex misses,
   but adds a model dependency and a false-positive surface. Probably a paid
   fleet-tier feature, not core.
3. **Corpus sourcing.** The strongest asset here is a labelled corpus of real
   payloads. Public ones are scarce. Building and publishing one may be more
   valuable to the ecosystem than the scanner itself.
4. **Blast-radius scoring.** Findings are currently rated by payload severity.
   Rating by *capability* — what this specific agent could do if infected —
   would rank better. Requires joining posture data to content findings.

## Corpus replay

```bash
# Every malicious fixture must produce >=1 WORM hit.
# Every benign fixture must produce 0.
loop/replay.sh
```

Track the numbers over time. A rule whose FP count creeps up gets tightened or
dropped — coverage is not worth a tool people stop trusting.
