# Live worm-propagation end-to-end test

Simulates two agents in a shared workspace and drives a controlled worm through
the full kill chain, invoking the REAL shipped hook entrypoints (`readguard`,
`guard`, `outbound`, `scan`) and the `wormhole-x402/evm` payment guard — no
mocks. Every hop asserts on the actual `permissionDecision` / `additionalContext`
the hook returns to Claude Code.

    python3 e2e/worm_propagation.py

Five layers, 17 checks:
1. READ — attacker text (worm / override / invisible Unicode memo) reaches the
   agent as tool output; readguard annotates it as data-not-instruction. A
   benign twin stays silent.
2. WRITE — the agent tries to persist the worm to CLAUDE.md; guard --block
   refuses WORM-001/003, warn mode annotates. Boundary: settings.json is NOT
   content-scanned here (harden/autostart own it) — asserted, not hidden.
3. OUTBOUND — the agent hands the worm to a second agent (subagent task / issue);
   outbound blocks by default. Benign handoff passes.
4. PAYMENT — the injection SUCCEEDS: the agent is fooled into building a payment
   to the attacker. The x402 EVM guard refuses it anyway (X402-101/102/104),
   because the quote said otherwise. The honest quoted payment still allows.
5. PERSISTENCE — an unattended SessionStart hook (the Miasma shape) that content
   rules structurally can't see; scan catches it via AUTOSTART/POSTURE.

The point is not just that it passes — it maps the true product boundary: what
each layer catches, and what it deliberately doesn't.
