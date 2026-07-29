# x402 payment guard — Solana

Wraps a Solana keypair in `guardSigner()` so nothing gets signed unless it
matches the quote the merchant actually sent.

The attack this exists for is not a forged signature. It is a payment where
everything the user was shown is true — right merchant, right price — and the
bytes handed to the wallet say something else. The model summarises the quote;
the wallet signs the transaction; nothing compares the two. That gap is where
the Grok/Bankr drain happened, and SlowMist's root cause for it was "loose
coupling between AI outputs and the real asset execution layer".

## What this shows

Four transactions through one guarded wallet:

1. **Conforming payment** → `allow`, wallet signs.
2. **Redirected destination** → `refuse` **X402-001**. Same mint, same amount,
   attacker's ATA.
3. **Token-2022 `TransferCheckedWithFee`** → `refuse` **X402-006**. Correct
   merchant, correct amount, refused anyway.
4. **No quote supplied** → throws. Fails closed.

Case 3 is the interesting one. It is built with the official
`@solana/spl-token` helper and pays the right person the right amount, and it
is still refused. Token-2022 namespaces its extensions: `data[0] = 26` selects
the TransferFee extension group and `data[1] = 1` selects the operation, so a
guard reading only `data[0]` never sees a transfer at all. That was a real
wrong-allow bug in this package — an attacker-destination transfer built by the
official helper rode alongside a conforming payment and the verdict was `allow`
with zero findings. The fix was to make the check an allowlist: the two plain
transfer forms are understood, everything else is refused rather than guessed
at. Expect this to refuse legitimate Token-2022 fee-bearing payments too. That
is the intended trade.

## What this does NOT show

- **No network, no chain state.** The blockhash is a fixed dummy, nothing is
  submitted, no RPC is contacted. Verdicts are computed from transaction bytes
  alone.
- **No proof the merchant is honest.** The guard checks the transaction against
  the quote. If the quote itself came from a malicious merchant, or from text
  the model was tricked into constructing, a matching payment is `allow`. Where
  the quote comes from is your problem — see `examples/quote-scanning/` for the
  quote's *text*.
- **No address-lookup-table support.** A v0 transaction using ALTs abstains,
  because the referenced accounts are not in the message and cannot be resolved
  offline. Not demonstrated here.
- **`allow` is not "this payment is a good idea."** It means the bytes match
  the quote.

## Two traps that will bite a copy-paste

**`guardSigner` returns async methods.** Even when your wallet's
`signTransaction` is synchronous, the guarded one is `async`. You must `await`
it. A synchronous `try/catch` around a guarded call catches *nothing* — the
refusal becomes an unhandled rejection, the next line runs as if signing
succeeded, and the process dies later with a stack trace pointing at the guard.
This example got that wrong on the first run and the fix is in the code now.

**`guardSigner` requires `VersionedTransaction`.** It calls `tx.serialize()`
with no arguments. A legacy `Transaction.serialize()` verifies signatures and
throws `Signature verification failed` on an unsigned transaction, which *looks*
like a guard refusal but is not one. Build with `TransactionMessage(...)
.compileToV0Message()`. (`inspectPayment` itself takes raw bytes or base64 from
either transaction type and is fine.)

Also: the thrown error is a **plain `Error`**. There is no `err.verdict`. The
detail is only in `err.message`. Call `inspectPayment` directly if you need
structured findings.

## Run it

```
npm install wormhole-x402 @solana/web3.js @solana/spl-token
node example.mjs
```

`@solana/web3.js` and `@solana/spl-token` are optional peer dependencies —
needed for this example and for `guardSigner`, not for the EVM or quote-text
paths.

## Actual output

Verbatim from `node example.mjs`, exit code 0:

```
payer     9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj
merchant  5ZgHPb447UcXavVTorgYBr8egi3sw7dXKpX4Frec9rYS
attacker  5rXezEUcPoLLDKATEsDJzUdNojasqE2ekkHntNLfEQtL
quote     {"asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","payTo":"5ZgHPb447UcXavVTorgYBr8egi3sw7dXKpX4Frec9rYS","amount":"1000000"}
merchant ATA (expected destination): AMm8mJhjG1Q6JkbVx4LpFKjFUqg5KGqU96ZdEzWyT4c5

========================================================================
1. Conforming payment — expect ALLOW
1 USDC to the merchant's ATA, exactly the quoted amount.
========================================================================
inspectPayment: {
  "decision": "allow",
  "findings": []
}
guardSigner: SIGNED (wallet.signTransaction calls: 1)

========================================================================
2. Redirected destination — expect REFUSE X402-001
Same amount, same mint, but the destination ATA belongs to the attacker.
This is the attack the package exists for: the quote the agent showed the
user is correct, and the bytes it is about to sign are not.
========================================================================
inspectPayment: {
  "decision": "refuse",
  "findings": [
    {
      "code": "X402-001",
      "severity": "critical",
      "message": "payment destination is not the account derived from the quote",
      "expected": "AMm8mJhjG1Q6JkbVx4LpFKjFUqg5KGqU96ZdEzWyT4c5",
      "actual": "FkyqyPyKfT9ggTaVj4xJYfjGH6czkAoL6jMKQATv2298"
    }
  ]
}
guardSigner: REFUSED, nothing was signed
  x402-guard: refusing to sign (refuse). X402-001: payment destination is not the account derived from the quote
  wallet.signTransaction calls: 0

========================================================================
3. Token-2022 TransferCheckedWithFee — expect REFUSE X402-006
Built with the official @solana/spl-token helper, paying the CORRECT
merchant ATA the CORRECT amount. It is refused anyway, because the guard
allowlists the two plain transfer forms and will not guess at what an
extension instruction does to the payer's funds offline.
Note the instruction is 26/1 — a switch reading only data[0] never sees a
transfer here, which is exactly how this was once a wrong-allow bug.
========================================================================
inspectPayment: {
  "decision": "refuse",
  "findings": [
    {
      "code": "X402-006",
      "severity": "critical",
      "message": "token instruction 26/1 is not one of the transfer forms an exact-scheme payment uses, so what it does to the payer's funds cannot be determined offline",
      "actual": "discriminant 26"
    }
  ]
}
guardSigner: REFUSED, nothing was signed
  x402-guard: refusing to sign (refuse). X402-006: token instruction 26/1 is not one of the transfer forms an exact-scheme payment uses, so what it does to the payer's funds cannot be determined offline
  wallet.signTransaction calls: 0

========================================================================
4. No quote available — expect a throw, not a pass
A guard whose default is 'allow when unconfigured' reports green on all
traffic and nobody notices. Missing quote is a refusal.
========================================================================
guardSigner: REFUSED, nothing was signed
  x402-guard: refusing to sign — no payment quote was supplied, so there is nothing to check this transaction against.
  wallet.signTransaction calls: 0

Done. No network calls were made and no transaction was submitted.
```

`wallet.signTransaction calls: 0` on cases 2, 3 and 4 is the assertion that
matters. The refusal happens *before* the key is reached — not after a
signature already exists.
