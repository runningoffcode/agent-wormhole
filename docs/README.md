# Documentation

[Integration guide: payment safety, policy, confirmed top-ups and launch attestations](integration.md).

Long-form material that used to live in the README. The
[landing page](../README.md) is the short version; these are the full ones.

| Page | What is in it |
|---|---|
| [Threat model](threat-model.md) | Miasma, the vendor gap, the AgentWorm numbers, prior art, how a payload travels between agents |
| [Rules](rules.md) | The full rule catalogue, what the tool does precisely, the regression suite, the mutation-decay numbers, suppression |
| [Hooks](hooks.md) | `guard` / `readguard` / `outbound` in depth — install JSON, real output, the inbound/outbound asymmetry, `harden` |
| [Scanning](scanning.md) | `scan`, `memos`, `handoffs`, `corpus`, `capture`, `insights`, baselines, CI and SARIF, the MCP server |
| [x402](x402.md) | The payment guard: Solana, EVM, quote text, verdicts and what `abstain` does not mean |
| [Arc](arc.md) | Arc Testnet (verified) and mainnet (explicit only): task-bound payments through a server-side signer, ERC-8004 scans, ERC-8183 funding and release, sealed private delivery, refusal codes |
| [Limits](limits.md) | No warranty, no telemetry, what this tool does not do, supported config formats |

## Runnable examples

Each directory runs and its README contains the actual output.

| Example | Shows |
|---|---|
| [claude-code-hooks](../examples/claude-code-hooks/) | All three hooks in a real `settings.json`, with a blocked write end to end |
| [x402-solana](../examples/x402-solana/) | `guardSigner` around a wallet — a payment that allows and one that refuses |
| [arc-commerce](../examples/arc-commerce/) | The hosted Arc layer: a poisoned quote refused by the signer, a legitimate one confirmed, the same request id replayed |
| [x402-evm](../examples/x402-evm/) | `inspectAuthorization` on an EIP-3009 authorization — allow, refuse and abstain |
| [quote-scanning](../examples/quote-scanning/) | `inspectQuoteText` on a poisoned listing, and the benign twin staying quiet |
| [ci-github-action](../examples/ci-github-action/) | `scan` in CI with `--fail-on` and SARIF upload |
| [agent-fleet](../examples/agent-fleet/) | `harden` + `baseline` + `verify` across several repos |

## Elsewhere in the repo

- [MISSION.md](../MISSION.md) — why this project exists
- [x402-guard/](../x402-guard/) — the payment guard's own API reference
- [corpus/](../corpus/) — the malicious/benign fixture pairs
- [loop/RESEARCH.md](../loop/RESEARCH.md) — how new rules get added without eroding the false-positive rate
- [watchtower/](../watchtower/) — measurement write-ups, including the memo base-rate finding
- [CONTRIBUTING.md](../CONTRIBUTING.md) · [SECURITY.md](../SECURITY.md)
