# Arc commerce demo

Shows the property the Arc layer exists for: the content scanner and the
signer are two independent boundaries, and the signer holds even when the
scanner is bypassed.

The script runs against the hosted API on Arc Testnet and needs:

- `AGENT_WORMHOLE_KEY`: an API key from the dashboard
- `ARC_TASK_ID`: a task created in the console at `/arc` and bound to that key
- `ARC_RECIPIENT`: the task's approved recipient

It performs four steps and prints what happened:

1. Reads `/api/v1/arc/status` and refuses to continue unless the deployment
   reports itself ready on the expected chain.
2. Inspects an ERC-8004 registration (`agentId` 2 on the testnet registry by
   default) and prints its verdict, declared endpoints and changes.
3. Submits a poisoned quote: the merchant text says to pay a different address.
   The scanner reports codes; the signer refuses with `ARC-002`. No transaction.
4. Submits the legitimate quote for a small amount to the approved recipient
   and prints the confirmed transaction hash and the signed evidence.

Then it repeats step 4 with the same request id and shows that the same hash
comes back, not a second payment.

```
AGENT_WORMHOLE_KEY=awk_… ARC_TASK_ID=task_… ARC_RECIPIENT=0x… node demo.mjs
```

Nothing in this example holds a signing key. The payment key lives on the
server behind the task check, which is the point.
