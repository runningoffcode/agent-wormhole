# Arc launch layer: research and proposed build scope

Researched September 14, 2026. This is a product and integration proposal, not a claim of shipped Arc support. Research used official documentation, project websites, public source, local code inspection, browser inspection, and read-only Arc Testnet RPC calls. No wallet was connected and no transaction was signed or submitted.

## Recommendation

Extend AgentWormhole's launch screening to Arc, then use the same evidence infrastructure to screen agent service registrations. Add transaction authorization around service purchases as a separate enforcement boundary.

The initial customer is a launchpad or agent platform whose users consume untrusted token or service metadata. The next customer is an agent operator purchasing APIs or hiring other agents with USDC. A token launch scanner offers a concrete entry point; controlling what an agent may buy and sign offers the broader commerce product.

## Verified network status

Arc schedules public mainnet for September 16, 2026. Its announcement describes an existing private mainnet. The public connection and contract-address documentation reviewed here still supplies testnet configuration; the address page explicitly says mainnet addresses are not yet available. Treat partner-supplied mainnet configuration as a claim requiring independent verification. [Launch announcement](https://www.arc.io/blog/arc-mainnet-goes-live-on-september-16-2026), [connection documentation](https://docs.arc.io/arc/references/connect-to-arc), [contract addresses](https://docs.arc.io/arc/references/contract-addresses).

Read-only checks against `https://rpc.testnet.arc.io` returned chain ID `5042002`, a current block, six decimals from USDC at `0x3600000000000000000000000000000000000000`, and nonempty code at the documented identity registry and job contract. Code presence does not establish implementation correctness, source verification, or an audit.

Arc's native USDC uses 18 decimals; its ERC-20 interface uses six. These interfaces expose the same underlying balance. Payment accounting must distinguish the interfaces and avoid double-counting transfers. Arc-specific execution and event behavior requires Arc-aware tests. [EVM differences](https://docs.arc.io/arc/references/evm-differences.md).

Arc Privacy Sector is documented but explicitly marked as unavailable and on the roadmap. An initial privacy product can protect task data, credentials, and invoices offchain; it cannot claim that ordinary Arc transfers hide counterparties or amounts. [Privacy documentation](https://docs.arc.io/arc/concepts/opt-in-privacy).

## Launchpad candidates

| Project | Directly observed | Integration implication |
| --- | --- | --- |
| [UARC](https://uarc.me/) | Rendered UI, machine-readable discovery manifest, and a public source repository. Manifest reports `no_markets_yet`, zero launches, and public launches disabled. | Most concrete adapter candidate found. Verify its current deployment generation before indexing. |
| [Parabola](https://parabola.meme/) | Landing page advertises September 16 launch, USDC bonding-curve trading and graduation. | Relevant launch-day candidate. No factory address or developer integration docs were linked on the reviewed page. |
| [ARCLaunch](https://arclaunch.fun/) | Browser-rendered coming-soon page and social links. | Discovery lead; insufficient material for a factory adapter. |
| [ARC at arc.dating](https://arc.dating/) | Browser-rendered token interface, one displayed token, chain label 5042. | UI observation only; displayed markets were not independently reconciled to chain transactions. |

UARC's [discovery manifest](https://uarc.me/.well-known/uarc-dex-index.v1.json) supplies event layouts, metadata conventions, a factory deployment block, and API paths. Its factory field was `0x8d33b4B0EdBa5Bc95cBd86E2803b64078aF2166e`. The [public repository README](https://github.com/usdcarc/uarc-contracts) instead describes an older generation with factory `0x9AD4259A9a185C8ab417d83863628636af4ACe5c`, and says that factory's source is not included. Public source therefore does not yet verify the manifest's active factory. The site's liquidity-locking claims were not audited in this review.

These are prospective integrations, not partnerships. Directory mentions of other launchpads were not sufficient to establish deployment status.

## What the current code can support

The hosted implementation lives in the sibling `agent-wormhole-dashboard` repository. This repository holds the SDK and integration documentation.

| Existing component | Reuse | Required extension |
| --- | --- | --- |
| Dashboard `lib/launch/attest.ts` | Rule scanning, exact metadata hashes, signed receipts and expiration | Preserve token v2 scope; create a separate schema for agent service evidence. |
| Dashboard `lib/launch/chain.ts` | EVM reads and metadata validation | Replace Robinhood-specific configuration with explicit chain and launchpad adapters. |
| Dashboard `lib/launch/ingest.ts` | Persistent ingestion and rescans | Per-chain/per-factory cursors, vetted event decoding, bounded retries and replay. |
| Dashboard `/api/v1/scan` | Pre-mint and observed-token workflow | Its network selection currently accepts Robinhood/Solana, not Arc. |
| SDK `x402-guard/src/network.ts` | Parsing `eip155:<chainId>` | Parsing an Arc ID does not establish payment support. |
| SDK `x402-guard/src/evm.ts` | Trusted-domain verification | Arc is absent from the trusted domain table. Verify its actual signature scheme and settlement path before adding support. |
| Hosted policy and collection | Budget/velocity checks, approvals, receipts, durable settlement patterns | Task authorization, delegation and Arc collection need dedicated integration work. |

The current token reader expects `name`, `symbol`, `description`, and `logo` contract getters. Each Arc launchpad needs a verified metadata source; missing fields must not silently become a successful scan. Existing attestations cover four token fields, not arbitrary agent manifests, contracts, or economic safety. See the current [integration contract](integration.md).

## Products to build, in order

1. **Arc Launch Guard.** A pre-launch scan API, a receipt bound to the exact metadata, a post-launch check against observed chain identity, and alerts when covered metadata changes. Integrators place the check before metadata reaches agents and before their launch flow proceeds. Charge platforms for scans and monitoring; keep verification reads easy to integrate.

2. **Agent Service Guard.** Inspect ERC-8004 registration documents, service descriptions, endpoint declarations and associated tool schemas. Issue evidence bound to the registry, agent ID, observed owner, resolved document hash, endpoint configuration and expiration. Treat mutable URIs, owner changes, redirects and changed payment destinations as reasons to re-evaluate. Define exactly which external resources were inspected. Arc supplies an [ERC-8004 testnet tutorial](https://docs.arc.io/arc/tutorials/register-your-first-ai-agent); the [standard](https://eips.ethereum.org/EIPS/eip-8004) explicitly recognizes reputation manipulation through fake identities. Registration or a high score is not permission to spend.

3. **Commerce authorization.** Bind an operator-approved task to permitted merchants, contracts, methods, assets, amounts, deadlines, gas limits and delegation limits. Put enforcement at a signer the model cannot bypass. Authenticate quote origin separately from checking payment conformance. Preserve durable idempotency and reconcile reservations with actual settlement. This protects the money boundary even when a content scanner misses an injection.

4. **Job settlement guard.** Check provider, evaluator, escrow contract, allowance and agreed budget before funding; check objective delivery evidence before approving release. Arc's [job tutorial](https://docs.arc.io/arc/tutorials/create-your-first-erc-8183-job) uses `fund(uint256,bytes)`, while the current [ERC-8183 draft](https://eips.ethereum.org/EIPS/eip-8183) specifies an expected-budget parameter. Pin each supported deployment and ABI. Hooks are optional: do not assume a deployed kernel enforces them. Protect the evaluator from untrusted deliverable instructions. A hash proves content binding, not work quality.

5. **Private task gateway.** Keep prompts, credentials and invoice details behind authenticated offchain access; publish only necessary settlement evidence. Account for dictionary attacks before publishing hashes of predictable private data. Integrate Arc's confidential execution only when its availability and interfaces are verified.

The strongest demonstration combines products 2 and 3: an agent is authorized to buy a specific service for at most 5 USDC. A service document injects instructions to use a different recipient or approve unlimited spending. The content layer reports the finding, and the independent signer refuses the unauthorized action even if scanning is bypassed. A legitimate purchase succeeds and produces a settlement-linked receipt.

## First implementation milestone

Build a testnet integration with one explicitly supported metadata adapter, signed scan receipts and a sample consumer that checks freshness and exact content binding. Add a separate agent-manifest schema rather than extending the meaning of token v2 receipts. Ship an integration example demonstrating both accepted content and rejected mutations.

Acceptance cases: wrong chain, wrong registry/token, expired receipt, changed metadata, unavailable RPC, oversized content, redirected metadata fetches, event replay and scanner failure. For payment work, additionally cover altered payees, wrong decimals, excessive allowances, duplicate requests, parallel budget consumption, settlement failure and direct signer bypass.

Mainnet readiness requires independently verified network configuration, each factory's current deployment and metadata schema, documented event sources, and live settlement checks for any enabled payment rail. The launch date alone does not satisfy those requirements. A day-one release can accurately announce available screening integrations or a testnet preview without claiming comprehensive Arc coverage.
