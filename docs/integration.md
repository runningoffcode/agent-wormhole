# Integrate AgentWormhole

Keep the payment signer and its policy outside the model's control. Scan untrusted material before putting it in the agent's context, verify each proposed payment against a quote obtained through a trusted channel, and have the signer enforce the final decision. A conformance check cannot prove that the purchase serves the user's intent. A clean rule scan cannot prove that text is safe.

## Choose the boundary

| Need | Entry point | Enforced by |
| --- | --- | --- |
| Inspect local files, tool output, persistent instructions and handoffs | Python CLI/hooks; [hook guide](hooks.md) | Agent host |
| Inspect a proposed x402 payment offline | `wormhole-x402/verify` | Your signing service |
| Add account-wide budgets, velocity and human approvals | Hosted `POST /api/v1/verify` | Dashboard PostgreSQL plus your signing service |
| Check token metadata before minting or reading it | Hosted `POST /api/v1/scan`, public `GET /api/v1/token/{chainId}/{address}` | Launchpad/agent host |

The changes described here are the source contract for this checkout. Deploy the dashboard and site together; publish the SDK server change before expecting it in a registry install. The hosted route strips untrusted provenance headers independently of that SDK publication.

## Hosted quick start

The API origin is `https://dashboard.agentwormhole.com`. Keep your API key on a server, never in browser code or model-visible prompts.

```sh
# Save the returned api_key securely. Registration without payment starts at zero.
curl --fail-with-body https://dashboard.agentwormhole.com/api/v1/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-agent"}'

# Run on your server with WORMHOLE_API_KEY set. This may return HTTP 402.
curl --fail-with-body https://dashboard.agentwormhole.com/api/v1/scan \
  -H "Authorization: Bearer $WORMHOLE_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"network":"solana","links":false,"bundle":{"name":"Example","symbol":"EX","description":"Example token","logo":""}}'
```

When an endpoint returns 402, read `accepts` and choose one supported payment rail. Validate the quote's origin, payee, asset and amount in your own trusted payment code. Sign once, then retry the original request with the encoded payment in `X-PAYMENT`. That header pays for API credit; the JSON `payload` sent to `/verify` is the separate payment being inspected.

| Response | Client action |
| --- | --- |
| 200 with `decision: "allow"` from `/verify` | Check required receipt/provenance and exact request binding, then let the trusted signer proceed |
| `refuse`, `abstain`, `needs_approval`, missing/unknown decision | Do not sign. For approval, direct the operator to `policy.approve_url`; retry after their decision |
| 402 `insufficient_credit` | Obtain and validate the payment quote |
| 402 `payment_pending` | Retry the **same** signed payment and same account with backoff; do not generate another payment |
| 402 `payment_invalid` | Stop and inspect the finding codes |
| 503 `payment_collection_unavailable` | Retain the same header for retry; no confirmation has been established |
| 429 | Respect `Retry-After` |
| Other HTTP errors, malformed JSON, absent signatures required by your policy | Stop; never treat an error as permission |

An API request can be served from an existing balance while an attached top-up is still pending. A 200 verification response is not proof that the top-up settled. Inspect usage/settlement status and ledger credit separately.

Base USDC collection submits EIP-3009 authorizations and requires a successful receipt with three confirmations, the matching `AuthorizationUsed` event and the exact `Transfer`. A canceled/used nonce alone is not payment evidence. Solana USDC collection requires **all transaction signatures**, submits the transaction, checks the RPC network, and waits for successful `finalized` status. Partially signed facilitator transactions are insufficient for this direct collector. Set a recent blockhash and submit promptly.

Pending submissions are durable. RPC timeouts retain the transaction hash/signature, and a successful retry creates one credit atomically with settlement completion. Identical previously recorded EVM authorizations can resume after expiry. If a Solana blockhash expires before submission, or an EVM authorization expires with no recoverable transaction, inspect the settlement before issuing a replacement. Cron retries do not turn failure into credit.

## Payment verification and provenance

```ts
const response = await fetch(`${origin}/api/v1/verify`, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${process.env.WORMHOLE_API_KEY}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ network, quote, payload }),
});
if (!response.ok) throw new Error(`Verification unavailable: ${response.status}`);
const result = await response.json();
if (result.decision !== "allow") throw new Error("Payment not authorized");
// Verify required receipt signature + request digest here before the signer runs.
// Keep quote provenance and business approval in your own trusted boundary.
```

`X-Quote-Provenance` is not evidence and is ignored. The hosted API currently labels caller-supplied quotes `caller_asserted`. An allow means the submitted payment conforms to that quote; it does not authenticate its merchant. Hosted API usage still has its advertised price; receipt provenance is separate from hosted billing.

For self-hosted `createVerifyHandler`, the server option `resolveQuoteProvenance(request, req)` may return a stronger label only after server-side validation of evidence for that exact quote. It must never echo an incoming label. Resolver failure returns abstain without a receipt. The low-level offline `verify()` option is also a trusted caller assertion: setting `quoteProvenance` does not itself verify a merchant signature.

Policy reads, budget/velocity counters, approval consumption and spend reservation share a transaction locked per tenant. Policy changes and the kill switch use that lock too. Policy storage or commit failure returns `abstain`, `policy.decision: "unavailable"`, and no allow receipt/signature. Spend counts each allowed verification, including retries, conservatively before payment settlement. Unknown monetary assets require human approval when a monetary rule applies. Approval cannot override the budget, velocity ceiling or kill switch.

## Launch integration: pre-mint → observed token

1. Submit the exact `name`, `symbol`, `description`, `logo` strings to `/api/v1/scan` with `links:false` if you only need metadata scanning. Preserve the signed pre-mint attestation.
2. Require HTTP success, `verdict: "clean_by_rules"`, a valid signature, v2 scope and an unexpired attestation before your mint gate proceeds. Failures return `unchecked` without a clean attestation. Findings require your explicit review workflow.
3. After minting, request an on-demand scan with `{chainId:4663,address}` or `{network:"solana",address}`. Compare its signed `metadata_hash` with the pre-mint value. Validate its real chain and token identity separately.
4. Before consuming metadata, fetch the free `/api/v1/token/{chainId}/{address}` result and validate fresh evidence against the exact content you intend to use. A badge is a display, not an authorization primitive. A registry scan is a snapshot, not continuous protection against changes between reads.

v2 has two hashes. They use SHA-256 over UTF-8 `JSON.stringify` output, with the keys in precisely this order:

```js
const metadataHash = sha256(JSON.stringify({
  v: 2, name, symbol, description, logo,
}));
const bundleHash = sha256(JSON.stringify({
  v: 2, chainId,
  address: chainId === 0 ? address : address.toLowerCase(),
  metadataHash,
}));
```

The pre-mint `token` is `"premint"`. Its `metadata_hash` can match an observed token, while its identity-bound `bundle_hash` must differ. Solana addresses preserve case. After decoding native Metaplex NUL padding, no trimming, case folding of metadata, Unicode normalization or silent truncation occurs. UTF-8 limits: name 800 bytes, symbol 240, description 32,768, logo 4,096. Oversize inputs are unchecked.

The signed scope is exactly `name,symbol,description,logo`. On Solana, name/symbol come from Metaplex and description/image from its fetched JSON, with image mapped to logo. The URI itself, extra JSON keys, image contents, linked pages, contract behavior and economics are outside that attestation. Links have separate reports and are not included in the metadata signature. Only changes to the four selected fields count as metadata mutations.

## Verify a launch attestation in Node

Pin the deployment's Ed25519 public key through your trusted configuration. `/api/v1/key` publishes SPKI DER in base64 for initial setup; fetching the key and attestation from the same compromised origin on every call does not establish independent trust.

```js
import { createHash, createPublicKey, verify } from "node:crypto";
const sha256 = value => createHash("sha256").update(value, "utf8").digest("hex");

export function acceptLaunch({ attestation: a, signature }, expected, publicKeyB64) {
  if (!a || a.v !== 2 || a.scope !== "name,symbol,description,logo" ||
      a.verdict !== "clean_by_rules" || !Array.isArray(a.codes) || a.codes.length ||
      typeof signature !== "string") return false;
  const issued = Date.parse(a.issued_at), expires = Date.parse(a.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) ||
      issued > Date.now() || expires <= Date.now() || expires-issued !== 86_400_000) return false;
  const address = expected.chainId === 0 ? expected.address : expected.address.toLowerCase();
  if (a.chain_id !== expected.chainId || a.token !== address) return false;
  const { name, symbol, description, logo } = expected;
  const metadataHash = sha256(JSON.stringify({ v: 2, name, symbol, description, logo }));
  const bundleHash = sha256(JSON.stringify({ v: 2, chainId: expected.chainId, address, metadataHash }));
  if (a.metadata_hash !== metadataHash || a.bundle_hash !== bundleHash) return false;
  const canonical = JSON.stringify({
    v: a.v, metadata_hash: a.metadata_hash, scope: a.scope,
    chain_id: a.chain_id, token: a.token, bundle_hash: a.bundle_hash,
    verdict: a.verdict, codes: a.codes, ruleset: a.ruleset,
    issued_at: a.issued_at, expires_at: a.expires_at,
  });
  try {
    return verify(null, Buffer.from(canonical), createPublicKey({
      key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki",
    }), Buffer.from(signature, "base64"));
  } catch { return false; }
}
```

Expiry is exactly 24 hours from issuance, with no grace period. A valid historical signature may already be expired. Missing, v1, malformed or expired evidence is unchecked; request a fresh scan. v1 → v2 re-attestation does not count the hash-format migration as a metadata mutation.

## Operator rollout and recovery

- Apply the dashboard's additive schema migration before serving collection traffic. New queue entries use `collection_version=2`; existing entries default to 1 because the former collector already granted optimistic credit. Do not manually relabel those old entries as v2: reconcile legacy credits with chain evidence first. This change does not claw back historical balances.
- Configure the existing PostgreSQL and receipt signing variables. Set the matching `RECEIPT_PUBLIC_KEY`. Base collection requires `X402_SETTLER_PRIVATE_KEY` funded for gas; this is a gas wallet, never an agent's wallet. Solana collection requires a configured payout address and a reliable `SOLANA_RPC_URL` on the quoted network. Testnet collection requires `X402_ALLOW_TESTNET=1`.
- Schedule settlement retries and launch ingestion; monitor pending rows and failed jobs. A failed factory log/metadata RPC read leaves the ingestion window uncommitted, so retry it. Unsupported candidates remain unobserved. Oversize metadata fails the window closed and may require operator investigation; it is never silently certified.
- EVM recovery without a stored hash searches approximately 24 hours of Base logs. Older external submissions need operator reconciliation. A webhook delivery failure after a committed payment cannot undo credit.
- Validate locally with `npm test`, `npm run typecheck`, `npm run build`, and dashboard `npm run test:postgres`. The last command requires local PostgreSQL tools, creates a disposable cluster on loopback, and destroys it afterward; it never uses deployment credentials. Chain transport is simulated in tests—no live payment smoke test or deployment is included.

### Compact Drift badge and refresh

Embed the live logo beside the token and link it to its attestation:

```html
<a href="https://dashboard.agentwormhole.com/t/4663/TOKEN_ADDRESS">
  <img src="https://dashboard.agentwormhole.com/api/badge/token/4663/TOKEN_ADDRESS"
       width="28" height="28" alt="AgentWormhole attestation">
</a>
```

The transparent SVG has no visible text. Green represents current evidence with no
findings, amber a recorded metadata change, red findings, and grey unavailable
current evidence. Recorded findings stay red after expiry. The linked page explains
the state; agents must use the JSON endpoint and verify evidence instead of trusting
a color. Animation respects reduced-motion preferences; add `?motion=off` for a
static image.

An observed token's badge, verdict or attestation-page read requests background
refresh after 20 hours. Scheduled ingestion prioritizes scans older than 16 hours
with observed activity in the previous 24 hours. Both are best-effort: limits,
10-minute claim backoff and chain availability can defer work. The triggering
response still contains the existing evidence; no renewal before expiry is promised.
Grey badges cache for 60 seconds; other states up to 300 seconds, with green and
amber capped at attestation expiry. Use a paid on-demand scan for a synchronous
fresh observation. With a funded API key, send the bearer key alone for subsequent
scans; attaching another payment also deposits that payment as credit.
