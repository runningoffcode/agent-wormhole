# x402 payment guard — EVM (EIP-3009)

Checks a signed EIP-3009 `TransferWithAuthorization` against the quote the
merchant actually sent, before it is handed to a facilitator.

The signature is not the thing under suspicion. In every case below the payer
really did sign the message — a signature check alone passes all of them. What
catches the attack is comparing the signed authorization against the quote, and
nothing in a normal agent stack does that.

## What this shows

Four real viem-signed authorizations through `inspectAuthorization()`:

1. **Conforming** → `allow`.
2. **Redirected payee** → `refuse` **X402-101**. Correct amount, attacker's
   address, genuine signature.
3. **Inflated value** → `refuse` **X402-102**. 1000 USDC against a 1 USDC quote.
4. **Optimism USDC** → `abstain`. A real chain and real USDC, but the pair is
   not in the trusted-domain table.

Case 4 is the one worth understanding. To recover a signer you need the exact
EIP-712 domain — `name` and `version` as the deployed contract reports them.
The guard builds that domain **from its own 5-entry table, never from the
quote**, because taking it from the quote would let an attacker supply a domain
that recovers to whatever they like. Guessing at the domain for an unlisted
contract would produce a *confident wrong answer*, so the guard declines to
answer at all.

**`abstain` is not an all-clear.** Nothing was verified. If you treat it as a
pass you have a guard that reports green on every chain it does not cover. Fail
closed on `abstain` unless you have another reason to trust the payment.

The complete table is five entries — Base, Ethereum, Arbitrum, Polygon USDC and
Base Sepolia USDC. Everything else on any chain abstains today. Note Base
Sepolia's test token reports `name` as `"USDC"`, not `"USD Coin"`; it is a
separate entry precisely because using the mainnet name there would recover the
wrong signer.

## What this does NOT show

- **Only EIP-3009 is positively verified.** `permit2` abstains (X402-106) —
  verifying a scoped `PermitWitnessTransferFrom` is out of scope for this
  build. `erc7710` abstains (X402-110) — a redelegatable `permissionContext` is
  opaque and carries no offline destination or amount. Standing-authority
  shapes like `Permit` are refused outright.
- **No network, no chain state.** `recoverTypedDataAddress` is pure
  computation. The guard never checks that the payer holds the balance, that
  the nonce is unused on-chain, or that the contract is what it claims.
  Replay protection here is limited to an optional in-process `seenNonces` set,
  which is not shared across processes.
- **No proof the quote is honest.** A payment matching a malicious quote is
  `allow`. See `examples/quote-scanning/` for scanning the quote's own text.
- **Not shown but present:** X402-104 (recovered signer ≠ `authorization.from`),
  X402-105 (expired window), X402-107 (nonce reuse), X402-103 (payload declares
  a different transfer method than the server quote).

## Notes for integrators

- `inspectAuthorization` is **async**. Await it.
- `viem` is an optional peer dependency needed **only** on this path.
- The server quote's `extra.assetTransferMethod` is authoritative. A payload
  that contradicts it is refused (X402-103) rather than allowed to steer
  verification into a more permissive branch.
- Pass `nowSeconds` to get deterministic results in tests, as this example does.

## Run it

```
npm install wormhole-x402 viem
node example.mjs
```

The private key in the example is viem's well-known public test key. It holds
nothing. Never reuse it.

## Actual output

Verbatim from `node example.mjs`, exit code 0:

```
payer (signer) 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
merchant       0x70997970C51812dc3A010C7d01b50e0d17dc79C8
attacker       0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
quote          {"network":"base","asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","payTo":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8","amount":"1000000","extra":{"assetTransferMethod":"eip3009"}}
parseNetwork('base') -> 8453

========================================================================
1. Conforming authorization — expect ALLOW
Pays the quoted merchant the quoted amount, signed by the payer.
========================================================================
{
  "decision": "allow",
  "findings": []
}

========================================================================
2. Redirected payee — expect REFUSE X402-101
A validly signed authorization for the right amount, to the wrong address.
The signature is genuine — the payer really did sign this — so signature
checking alone would pass it. Only comparison against the quote catches it.
========================================================================
{
  "decision": "refuse",
  "findings": [
    {
      "code": "X402-101",
      "severity": "critical",
      "message": "authorization pays an address other than the quoted payee — this is the substituted-destination attack",
      "expected": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      "actual": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    }
  ]
}

========================================================================
3. Inflated amount — expect REFUSE X402-102
Right merchant, but 1000 USDC instead of the quoted 1.
========================================================================
{
  "decision": "refuse",
  "findings": [
    {
      "code": "X402-102",
      "severity": "critical",
      "message": "authorization value does not match the quoted amount",
      "expected": "1000000",
      "actual": "1000000000"
    }
  ]
}

========================================================================
4. Optimism USDC — expect ABSTAIN, not allow and not refuse
Optimism is a real chain and this is real USDC, but the pair is not in the
5-entry trusted-domain table, so there is no confirmed (name, version) to
recover against. Recovering against a guessed domain would produce a
confident wrong answer, so the guard declines to answer at all.
ABSTAIN IS NOT AN ALL-CLEAR. Nothing was verified. Do not treat it as a pass.
========================================================================
{
  "decision": "abstain",
  "findings": [],
  "reason": "no trusted EIP-712 domain for (chainId 10, asset 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85) — refusing to recover against an unknown domain"
}

trusted domains (the complete table):
   8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913 -> Base USDC
   1:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 -> Ethereum USDC
   42161:0xaf88d065e77c8cc2239327c5edb3a432268e5831 -> Arbitrum USDC
   137:0x3c499c542cef5e3811e1192ce70d8cc03d5c3359 -> Polygon USDC
   84532:0x036cbd53842c5426634e7929541ec2318f3dcf7e -> Base Sepolia USDC

Done. No network calls were made.
```

### Verifying the refusal is real

A refusal is only meaningful if it comes from the quote comparison rather than
an incidentally broken signature. Re-running case 2's **identical signed bytes**
against a quote that names the attacker as the legitimate payee:

```
same signature, quote names attacker as payee -> {"decision":"allow","findings":[]}
```

Same signature, same authorization, opposite verdict. The refusal is the quote
comparison doing its job.
