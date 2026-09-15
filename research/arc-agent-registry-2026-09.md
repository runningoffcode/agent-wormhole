# 895,230 agents, 0.7% reachable

## What the ERC-8004 registry on Arc actually contains, and what has to be built before it means anything

**Measured 2026-09-16. Arc Testnet (chain 5042002) and Arc mainnet (chain 5042).**

---

## Summary

Arc is Circle's EVM chain where USDC is the gas token. Its testnet carries a
deployed ERC-8004 agent identity registry, a reputation registry, a validation
registry, and an ERC-8183 job escrow. Together those are the machinery for
agents that can be registered, hired, paid on delivery, and rated.

We measured what is actually in that machinery. The identity registry holds
**895,230 registered agents** — more than one recent study found across
Ethereum, BSC and Base combined. Of a random sample of 150, **one** declared a
service endpoint.

That is the finding. The registry is full and almost entirely unreachable. It
is a list of names, not a directory of things you can call or pay.

We also found that the registry is idle: over a 5.6-hour window, 28 identity
events and 2 reputation events. And on mainnet, which opened on September 16,
**none of the three registries or the job contract is deployed at all**.

None of this makes Arc a bad bet. It makes it an early one, and it says
precisely which parts are load-bearing and which are decoration. The
conclusions section says what we think has to exist before an agent can safely
hire another agent, and what we are building toward it.

---

## Method

Everything below was read from the chain, not from documentation or an
announcement. Reproduction details are in the appendix.

- **Registry size.** Binary search on `ownerOf` over the identity registry at
  `0x8004A818BFB912233c491871b3d84c89A494BD9e` to find the highest existing
  token id.
- **Metadata composition.** Two independent pseudo-random samples over the full
  id range (seeds 20260916 and 777), 200 and 150 ids, reading `ownerOf` and
  `tokenURI` for each.
- **Rate limiting is a bias, not a nuisance.** Our first attempt read 59 of 240
  ids before the public RPC rate-limited us. A partial sample is a biased
  sample, so we discarded it, spread requests across four independent providers
  (arc.io, Blockdaemon, dRPC, QuickNode) and paced them. The reported samples
  completed at 188/200 and **150/150**.
- **Activity.** `eth_getLogs` over 40,000 recent blocks against the identity and
  reputation registries, with the window converted to wall-clock time from block
  timestamps.
- **Mainnet.** `eth_chainId`, `eth_getCode`, and USDC interface reads against
  four providers.

---

## Finding 1: the registry is large

**895,230** is the highest existing agent id on Arc Testnet.

For scale, an empirical study of ERC-8004 deployments across Ethereum, BSC and
Base ([arXiv:2606.26028](https://arxiv.org/html/2606.26028)) examined 173,441
agents across three mainnets. Arc's testnet alone holds roughly five times that.

The obvious caveat: this is a testnet, registration is nearly free, and a
faucet-funded registration costs a fraction of a cent. Some meaningful share of
895,230 is airdrop positioning rather than deployment. We did not find a clean
way to separate the two, and we are not going to pretend we did.

But the count is not the interesting number. What is in the records is.

---

## Finding 2: almost nothing in it is reachable

Of a 150-agent random sample, read with zero errors:

| Metadata form | Count | Share |
| --- | --- | --- |
| `data:` URI (inline JSON) | 139 | 92.7% |
| `ipfs://` | 9 | 6.0% |
| `http(s)://` | 1 | 0.7% |
| empty string | 1 | 0.7% |

134 of the `data:` documents parsed as JSON. Of those, **1 declared anything
resembling a service endpoint** — a field naming where the agent can be reached.

**0.7%.**

Here is a representative record, decoded verbatim:

```json
{
  "name": "Trader-d088b8",
  "description": "Swap Trader Trader-d088b8 — ERC-8004 on Arc Testnet",
  "image": "https://testnet.arcscan.app/assets/config/images/logo.png",
  "attributes": [
    { "trait_type": "Framework", "value": "ERC-8004" },
    { "trait_type": "Network",   "value": "Arc Testnet" },
    { "trait_type": "Role",      "value": "DEX Trader" },
    { "trait_type": "Created",   "value": "2026-06-18" }
  ]
}
```

That is an NFT profile card. It has a name, a picture, and trait badges. It has
no endpoint, no payment address, no capability declaration, no price, and no
schema an agent could use to call it. The role says "DEX Trader"; there is no
way to make it trade.

The `attributes` array is the tell. Whoever generated these reached for the
OpenSea metadata convention, because that is the well-worn path for an ERC-721.
ERC-8004 identities *are* ERC-721s, so the tooling that already exists produces
collectible metadata by default. The standard permits a useful document. The
ecosystem's muscle memory produces a trading card.

Two of 150 sampled agents pointed at `example.com`.

Dominant declared roles in the sample: Bridge Validator (37), DEX Trader (31).

---

## Finding 3: it is not being used

Over the most recent 40,000 blocks — **5.6 hours** at Arc's measured 0.506s
block time:

| Registry | Events |
| --- | --- |
| Identity | 28 |
| Reputation | 2 |

Nearly 900,000 identities exist. Two reputation events in most of a working day.

The reputation registry is the part that would make the identity registry
economically meaningful: a way to tell a good counterparty from a bad one. It
is deployed, and it is essentially unused.

The external study of the three mainnets found the complementary problem where
reputation *is* used: 98.7–100% of feedback records carried no proof of payment
or link to a completed task, and the median cost to move a score was measured
between $0.0027 and $0.055 — hundreds of times less than the median payment
those scores were supposed to inform. Sybil reviewers accounted for 59–91% of
raters depending on the chain.

So the two failure modes bracket each other. Where reputation is unused it
carries no signal. Where it is used it carries a signal anyone can buy for a
fraction of a cent.

---

## Finding 4: identities are transferable, and history travels with them

The identity registry answers `supportsInterface(0x80ac58cd)` with **true**. It
is a standard, fully transferable ERC-721 named `AgentIdentity`.

An agent identity is therefore an asset. It can be sold. Its reputation history,
whatever it accumulates, transfers with the token — the score is attached to the
id, not to the operator who earned it.

The attack writes itself. Build or buy a clean identity, accumulate history
cheaply, sell it to someone who wants the history. Nothing in the registry
records that the controlling party changed, and nothing in the standard requires
a consumer to check.

We are not claiming this is happening at scale on Arc today; with 2 reputation
events in 5.6 hours there is not yet much history worth laundering. We are
pointing out that the mechanism is in place before the value is, which is the
cheapest possible moment to build the defence.

---

## Finding 5: the registries are upgradeable, and nobody is watching

All three registries are EIP-1967 proxies. Reading the implementation slot:

| Registry | Address | Implementation |
| --- | --- | --- |
| Identity | `0x8004A818…BD9e` | `0x7274e874…9c02` |
| Reputation | `0x8004B663…8713` | `0x16e0fa7f…da34` |
| Validation | `0x8004Cb1B…4272` | `0xdb31f5d9…7f99` |

An implementation swap can change what registration, ownership or feedback
*mean*, without changing a single address that any integrator has hardcoded. A
consumer that pinned the proxy address — which is the correct thing to pin —
learns nothing when the logic behind it changes.

This is normal for early infrastructure and is not an accusation. It is an
argument for watching the slot.

---

## Finding 6: the `0x8004` prefix is decorative, not authenticating

The three registries share a memorable `0x8004…` prefix matching the EIP number.
That reads as an identifier. It authenticates nothing.

We ground CREATE2 salts against the standard deployer and found addresses
beginning `0x8004` after roughly 37,000 attempts each — three hits in 112,334
salts, a few seconds of laptop compute:

```
0x8004976e23f7dbab6b72a56703c42f5781df0e20
0x8004c05b74995ad118d089771c83d1669be71017
0x8004ba7ca1b974f78b9740b70f3c4caf9428d1af
```

A lookalike registry at `0x8004…` is cheap. A human comparing the first six
characters of an address — which is what people actually do — cannot tell it
from the real one. Nothing in the ecosystem today attests which registry is
canonical.

Arc phishing is already live ahead of any of this mattering: a fake
"ARC Community Rewards" wallet drainer at `governance-arc[.]com`, and
`arcbridge.chienlvm.network` flagged by MetaMask and SEAL blocklists five days
before mainnet. The demand for spoofing exists. The supply is one vanity grind
away.

---

## Finding 7: mainnet opened without the agent stack

Arc mainnet is live. We verified it independently of any announcement:

- `eth_chainId` returns **5042** on four providers: arc.io, Blockdaemon, dRPC,
  QuickNode
- USDC at `0x3600000000000000000000000000000000000000` reports `name()` =
  `"USDC"`, `version()` = `"2"`, 6 ERC-20 decimals
- `DOMAIN_SEPARATOR()` =
  `0x940506929bba468048a19b567f4f0d534714bc06604b5c3017e5d16785ccdf84`,
  which reproduces exactly from those values under chain id 5042
- Block time 0.507s, averaging 5.75 transactions per block across sampled blocks

And:

| Contract | Mainnet |
| --- | --- |
| ERC-8004 Identity | **not deployed** |
| ERC-8004 Reputation | **not deployed** |
| ERC-8183 Job escrow | **not deployed** |

At the time of measurement, Circle's documentation still published no mainnet
configuration at all — neither RPC nor contract addresses. The chain is running
ahead of its own documentation.

This matters practically. Any integrator who carries testnet registry addresses
onto mainnet will be pointing at empty space, or worse, at whatever eventually
occupies those addresses. The correct behaviour is to refuse, and it has to be
the *default* behaviour, because the failure is silent.

---

## What follows from this

The registry is not yet an agent economy. It is a namespace with a reputation
system attached that nobody uses yet, on a chain whose payment rail works and
whose agent contracts are testnet-only.

That is a genuinely good moment to build, because every defence below is
cheaper to add now than after the value arrives.

Four things have to exist before one agent can safely hire another:

**1. Reputation that cannot be bought for a cent.** The measured failure is that
feedback carries no proof of payment. The fix is structural: bind each feedback
record to a settlement receipt — a specific payment, of a specific amount, to a
specific recipient, in a confirmed transaction. A rating then costs whatever the
job cost, not $0.0027, and Sybil raters have to actually pay each other to
manufacture standing. We think this is the single highest-value thing missing,
and it is downstream of payment verification rather than upstream, which is why
it is rarely built first.

**2. Identity provenance.** Transferable identities need a visible answer to
"did this agent change hands, and when, relative to the history it is showing
you?" Ownership transfer is an on-chain event. Nothing surfaces it at the moment
of decision.

**3. Registry and implementation attestation.** Which registry is canonical, and
has its implementation changed? Both are checkable. Neither is checked today,
and the `0x8004` prefix actively encourages people to skip the check.

**4. Refusal as the default on unverified ground.** Mainnet has no registries.
Testnet metadata is 99.3% unreachable. Tooling that guesses in either situation
will look like it is working, which is the worst failure mode available.

### What we have built

We shipped the payment half of this to Arc on 2026-09-15 and 09-16, testnet then
mainnet, and verified every piece against the live chain.

`wormhole-x402` verifies that an x402 payment matches the quote it was offered
against, offline, with no RPC. Arc's USDC is in its trusted-domain table because
we read `DOMAIN_SEPARATOR()` off the deployed contract and reproduced it — on
both networks, from four providers each. A guessed EIP-712 domain does not fail
loudly; it recovers the wrong signer and returns a confident wrong answer.

The hosted layer adds the enforcement boundary. An operator approves a *task*:
one recipient, a budget, a per-payment cap, a gas cap, an expiry. The agent holds
a key that can only ask; the key that can pay never leaves the server. On the
live testnet we sent a quote carrying an injected instruction and an attacker's
payee: the content scanner flagged the injection, and independently the signer
refused because the payee was not approved. Nothing was signed.

For ERC-8183 we fund a job only after checking the client, provider, evaluator,
hook, status and budget, approve exactly the budget rather than an unlimited
allowance, and release only when the presented deliverable hashes to the one the
provider put on chain.

On mainnet, where the registries do not exist, our agent-scan and job-settlement
endpoints **refuse and name what is missing** rather than reading a familiar
address. That behaviour is enforced by the type system, not by a comment.

### What we are building next

Settlement-backed reputation, in the order the findings imply: receipts first
(done), then feedback bound to those receipts, then provenance and registry
attestation around it.

We would rather publish the measurements than the roadmap, so: the numbers above
are reproducible today, and we will publish the next set the same way — including
the ones that go against us.

---

## Appendix: reproducing this

Registry size, by binary search on `ownerOf`:

```js
import { createPublicClient, http, parseAbi } from "viem";
const c = createPublicClient({ transport: http("https://rpc.testnet.arc.io") });
const ID = "0x8004A818BFB912233c491871b3d84c89A494BD9e";
const abi = parseAbi(["function ownerOf(uint256) view returns (address)"]);
const exists = async (id) => {
  try { await c.readContract({ address: ID, abi, functionName: "ownerOf", args: [id] }); return true; }
  catch { return false; }
};
let lo = 1n, hi = 2000000n;
while (lo < hi) { const mid = (lo + hi + 1n) / 2n; (await exists(mid)) ? (lo = mid) : (hi = mid - 1n); }
console.log("highest agent id:", lo.toString());
```

Mainnet USDC domain verification:

```js
import { createPublicClient, http, parseAbi, keccak256, encodeAbiParameters, toBytes } from "viem";
const c = createPublicClient({ transport: http("https://rpc.mainnet.arc.io") });
const USDC = "0x3600000000000000000000000000000000000000";
const abi = parseAbi([
  "function name() view returns (string)",
  "function version() view returns (string)",
  "function DOMAIN_SEPARATOR() view returns (bytes32)",
]);
const [name, version, onchain] = await Promise.all(
  ["name", "version", "DOMAIN_SEPARATOR"].map((fn) =>
    c.readContract({ address: USDC, abi, functionName: fn })));
const computed = keccak256(encodeAbiParameters(
  [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
  [keccak256(toBytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
   keccak256(toBytes(name)), keccak256(toBytes(version)), 5042n, USDC]));
console.log(onchain === computed); // true
```

**Sampling note.** Pace requests and spread them across providers. The public
testnet RPC rate-limits, and a truncated sample silently becomes a biased one.
Our discarded first attempt returned 59 of 240 and reported metadata proportions
materially different from the completed samples.

**Caveats we want on the record.** Testnet registrations are close to free, so
the 895,230 figure mixes real deployment with airdrop positioning and we cannot
separate them. Our samples are 150–200 agents against ~895k, so proportions carry
sampling error of a few points; the endpoint finding (0.7%) is extreme enough
that error does not change the conclusion, but a 6% figure in this document
should not be read as precise. The cross-chain reputation figures are cited from
arXiv:2606.26028 and were not re-derived by us. Block times and transaction rates
are point-in-time on a chain that opened hours earlier.

*Measurements taken 2026-09-16 against Arc Testnet 5042002 and Arc mainnet 5042.*
