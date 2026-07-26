
## devnet-memos-history.json

Eleven real Solana devnet transactions, fetched back from the chain with
`getParsedTransaction` and stored as the RPC returned them. Six carry memo
payloads (worm-style config persistence, instruction override, credential
exfiltration, zero-width smuggling, Unicode tag-block smuggling, concealment);
five carry ordinary payment references that must stay silent. Verified
end-to-end: 6/6 detected, 5/5 clean, FN=0 FP=0.

Kept because the invisible-character cases are the ones worth proving survive a
real round trip through a block explorer's own encoding.
