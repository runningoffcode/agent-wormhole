# Arc: task-bound agent commerce

Arc is Circle's EVM chain where USDC is the gas token. This document describes
what Agent Wormhole does on Arc, what it verified, and what it does not claim.

Status on 2026-09-15: **Arc Testnet is supported and verified. Arc mainnet is
not.** The official documentation published no mainnet configuration when this
was written, so nothing here guesses one. The hosted deployment enables mainnet
only through explicit operator configuration and refuses to act until the live
chain agrees with that configuration.

## What was verified against the live testnet

| Fact | How it was checked |
| --- | --- |
| Chain id `5042002`, RPC `https://rpc.testnet.arc.io` | `eth_chainId` |
| USDC at `0x3600000000000000000000000000000000000000`, 6 ERC-20 decimals | `decimals()` |
| USDC EIP-712 domain: name `USDC`, version `2` | `DOMAIN_SEPARATOR()` equals the hash of (name, version, chain id, contract) |
| USDC dispatches EIP-3009 | a malformed `transferWithAuthorization` reverts `FiatTokenV2: invalid signature` |
| ERC-8004 identity registry `0x8004A818…` | `ownerOf`, `tokenURI`, `register(string)`, `setAgentURI`, events `Registered`, `URIUpdated`, `MetadataSet` present in the implementation |
| ERC-8183 job contract `0x0747EEf0…` | `getJob`, `paymentToken` (= USDC), `fund(uint256,bytes)`, `complete`, `submit`, `reject`; events match the draft's layout |
| Minimum base fee 20 gwei; log queries limited to roughly 10k blocks | documentation, `eth_getLogs` probing |

Two things the verification does **not** establish: that any contract's
source matches its bytecode, and that any of it has been audited.

## The SDK: Arc Testnet USDC in the trusted-domain table

`wormhole-x402` 0.8.3 adds `5042002:0x3600…` to `TRUSTED_DOMAINS` with the
verified name and version. `inspectAuthorization` now reaches a real verdict
for EIP-3009 authorizations on Arc Testnet instead of abstaining. There is no
Arc mainnet entry, on purpose.

The native USDC balance has 18 decimals; the ERC-20 interface has 6. An x402
quote on Arc quotes ERC-20 base units (micro-USDC). Do not mix the two.

## The hosted layer: five integrations

All of it is behind `dashboard.agentwormhole.com/api/v1/arc/*`. The prose
contract is in `/llms.txt`; the machine contract in `/api/openapi.json`.

1. **Launch guard.** `POST /api/v1/scan` accepts `{"network":"arc","address":"0x…"}`
   and pre-mint bundles with `"network":"arc"`. Same v2 attestation, bound to
   Arc's chain id. A token that does not answer the four metadata getters is
   unchecked, never attested to blanks. Launchpad factories are indexed only
   when the operator lists them (`ARC_LAUNCH_FACTORIES`); none ship by default.

2. **Agent service guard.** `POST /api/v1/arc/agent` reads an ERC-8004
   registration at one block, scans the exact document bytes, lists declared
   endpoints (without fetching them), reports what changed since the last
   scan, and signs evidence bound to registry, agent id, owner, URI, block and
   document hash. Registration is not permission to spend.

3. **Commerce authorization.** The operator creates a **task** in the console:
   one approved recipient, a total budget, a per-payment cap, a gas cap, an
   expiry, and the API key that may use it. `POST /api/v1/arc/pay` takes the
   merchant's quote; the task decides. Permitted payments are signed by a
   server-side key the agent never holds, persisted before broadcast, then
   confirmed against the exact `Transfer` log. The same request id replays
   the same transaction; a different quote under it is a 409.

4. **Job settlement guard.** `POST /api/v1/arc/jobs/fund` funds an ERC-8183 job
   only when the client is the signer, the provider is the task's recipient,
   the evaluator is accepted, there is no hook, the status is Open, the budget
   fits the task, and the job is not expired. It approves exactly the budget,
   then funds. `POST /api/v1/arc/jobs/release` completes a job only from the
   evaluator and only when the presented deliverable hashes (sha256 or
   keccak256) to the `JobSubmitted` deliverable on chain. A matching hash
   binds content, not quality.

5. **Private task gateway.** `POST /api/v1/arc/private/records` seals a record to
   a task; the agent cannot read it back. `POST /api/v1/arc/private/deliver`
   sends it to the operator-approved endpoint with the operator's sealed
   credential and returns a receipt whose digests are keyed and salted. This is
   offchain. Arc's confidential execution is documented as unavailable and no
   receipt here claims that a transfer on Arc hides anything.

## Refusal codes

| Code | Meaning |
| --- | --- |
| ARC-000 | account kill switch engaged |
| ARC-001 | task revoked, expired, missing, or not bound to this key |
| ARC-002 | recipient is not the task's approved recipient |
| ARC-003 | per-payment cap exceeded (or an amount on a non-payment action) |
| ARC-004 | task budget exceeded |
| ARC-005 | estimated gas exceeds the task's gas cap |
| ARC-006 | request id reused for a different request |
| ARC-007 | quote is not on Arc / not Arc USDC |
| ARC-008 | job check failed (client, provider, evaluator, hook, status, budget, expiry, token) |
| ARC-009 | presented deliverable does not match the on-chain deliverable |
| ARC-010 | signer or chain unavailable: abstain, never a partial allow |
| ARC-011–015 | private gateway: key unset, bad record, no endpoint, record not found, delivery limit |

## Mainnet readiness

Enable mainnet by setting `ARC_NETWORK=mainnet` plus every `ARC_MAINNET_*`
variable. Before doing so, read the deployed USDC's `name()`, `version()` and
`DOMAIN_SEPARATOR()` and the job contract's `paymentToken()` on mainnet and
compare them with what you configure. The deployment's `/api/v1/arc/status`
reports the live comparison. Launchpad factories and ERC-8004/8183 mainnet
addresses must come from the deployer, not from a manifest. A launch date is
not a verification.
