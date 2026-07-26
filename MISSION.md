# Why this exists

## The finding that started it

In March 2026, researchers from Peking University, Sun Yat-sen University,
Wuhan University, Tsinghua University, and Singapore Management University
published the first self-replicating worm against a production-scale agent
framework. They ran 2,250 trials across five models. Three numbers from that
paper define this project's reason for existing:

**82%.** Infection success through skill supply-chain poisoning — the highest
of any vector, and "universally vulnerable" across every model tested. Web
injection managed 51%. Direct instruction replication, 55%.

**0%.** Sandbox isolation was the *only* built-in control that broke the
infection loop, driving attack success to zero across all vectors, payloads,
and models. Across 82 real, publicly indexed agent configurations, the number
with sandbox isolation enabled was zero.

**62%.** The share of those same operators who had enabled gateway
authentication — a control that does not stop propagation.

The gap between those last two numbers is the entire problem. It is not that
the defense is unknown or expensive. It is that operators are defending the
door while the payload arrives through the config file, and nobody has been
telling them which is which.

## What the attack actually does

Agent frameworks load `AGENTS.md` and `CLAUDE.md` into the system prompt at
every session start — as the paper puts it, "loaded unconditionally into the
system prompt at every session start, with no integrity verification or
provenance checking."

AgentWorm exploits this with what the authors call **dual-anchor persistence**:

1. The payload is written into the startup section of `AGENTS.md`, guaranteeing
   execution on every subsequent session.
2. A global interaction rule is injected into the same file's behavioral
   guidelines, so the agent propagates the payload during ordinary work.

Two anchors, two jobs: one survives restart, one spreads. Neither requires the
attacker to be present after the initial message.

## The finding that shaped this tool's design

Execution restriction — the control most operators reach for first — blocked
payload execution completely. It also "left persistence and propagation
approximately unchanged."

The paper names the result: **asymptomatic carriers.** Agents that never run
the payload and infect their neighbours anyway, because propagation happens
through the instruction layer, not the execution layer.

This is why `wormhole` checks *config integrity* rather than trying to catch
malicious commands. An execution allowlist produces an agent that looks clean
by every runtime measure while functioning as a vector. The file is where the
truth is.

It is also why prompt-level defenses are not the answer. The paper tested three
escalating levels of defensive prompting. The best of them reduced attack
success from 65% to 37% — meaningfully better, still more than a third of
attacks succeeding, and the authors call it insufficient. You cannot instruct
your way out of this.

## Our cause

**Close the gap between the defense that works and the defense that gets
deployed.**

Not to invent new detection. The research already identified what stops this:
isolation, integrity verification, provenance checking. The failure is one of
distribution and visibility. Zero percent adoption of a working, already-built
control is not a research problem — it is a tooling problem, and tooling
problems are fixable by shipping something people actually run.

Three commitments follow from that:

**Free, permanently, at the individual layer.** Adoption *is* the mission. A
paywall on the scanner would reproduce the exact failure we exist to fix. The
core stays open source, complete, and uncrippled.

**Report what is verifiable.** Every claim in this repository cites a real
paper with a real arXiv ID and a figure you can check. Security tooling runs
on trust, and trust does not survive one fabricated citation. Where we do not
know, we say so — see LIMITATIONS in the README.

**Never publish a working payload.** Test fixtures in `corpus/malicious/` are
inert by policy: no live endpoints, no functional self-replicating prompts.
Publishing a working worm to demonstrate a worm detector would be a net
negative regardless of intent.

## Scope, honestly stated

`wormhole` does not stop a worm. It tells you that your agent's instructions
changed, and how much damage the agent could do if those instructions turned
hostile. That is a smaller claim than "worm protection," and it is the one we
can actually support.

The control that drives infection to zero is sandbox isolation, and it lives in
your agent framework, not in this tool. Our job is to make its absence
impossible to overlook — and to catch the case where something has already
written to a file that gets loaded, unconditionally, into your system prompt at
every session start.

---

### References

- Zhang, Wei, Luan, Wu, Zhang, Wu, Wu, Chen, Sun, Sun. *AgentWorm:
  Self-Propagating Attacks Across LLM Agent Ecosystems.*
  [arXiv:2603.15727](https://arxiv.org/html/2603.15727v3), NDSS 2026 (v1–v2 titled *ClawWorm*).
- Cohen, Bitton, Nassi. *Here Comes The AI Worm: Unleashing Zero-click Worms
  that Target GenAI-Powered Applications.*
  [arXiv:2403.02817](https://arxiv.org/abs/2403.02817), March 2024. The Morris
  II worm — first demonstration of self-replicating prompts propagating through
  RAG-based agent ecosystems.
