"""Behavioral signals: detection that reads no payload text at all.

Text scanning has a hard ceiling, and the Grok/Bankr drain is the proof. That
theft moved funds with an ordinary ERC-20 `transfer` — no hostile string in the
calldata, no memo, nothing for WORM-001..007 to match. Every rule in the local
package would have returned clean, correctly, because there was nothing to read.
What was anomalous was the SHAPE of the activity, not its content.

So these four signals look only at transfer graph structure and timing:

  BEHAV-001  fan-out burst          narrow sender suddenly sprays counterparties
  BEHAV-002  full-balance sweep     ~everything leaves, to an address with no past
  BEHAV-003  unlimited approve      max allowance to a spender deployed minutes ago
  BEHAV-004  temporal correlation   N unrelated addresses touch one novel contract

The honest framing, which is load-bearing rather than modest:

  NONE OF THESE ARE EVIDENCE OF THEFT. Every one has a benign twin that is far
  more common than the malicious case. An airdrop IS a fan-out burst. A wallet
  migration IS a full-balance sweep. Approving a freshly-deployed DEX router IS
  an unlimited approve to a new spender. A popular mint IS N unrelated addresses
  touching one novel contract. In each pair the benign case is the DOMINANT one
  by volume, probably by three or four orders of magnitude.

That is why every Signal carries `benign_explanations`: the specific ordinary
things that produce this exact shape and that the evidence does NOT rule out.
A signal is a reason to look, never a conclusion. Consistent with the project's
publishing rule, a Signal states facts about transactions ("these 41 transfers
share a sender and occurred within char 90s") and never a verdict about a party
("this address is a drainer"). The address fields exist so a human can go and
verify; they are not an accusation.

Thresholds here are DEFAULTS CHOSEN BY REASONING, NOT BY MEASUREMENT. The
base-rate pass measured memo text; nobody has yet measured how often ordinary
Solana/Base addresses trip these shapes. Until that measurement exists, treat
every constant below as a starting point for tuning, and see `estimate_alert_load`
for the arithmetic on why a plausible-sounding threshold can still be unusable.

No network calls in this module. It is a pure function of transfer records the
caller supplies, which keeps it unit-testable and keeps ingestion swappable.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Sequence

# ------------------------------------------------------------------ input ---


@dataclass(frozen=True)
class Transfer:
    """One value movement. Chain-agnostic on purpose.

    Populated from Solana balance deltas or EVM Transfer logs alike; the signals
    below never ask which chain they are on.

    `amount` is an int in the token's smallest unit (lamports, wei, base units).
    Floats are deliberately not accepted: a sweep test compares a residual
    against a balance, and float error at 18 decimals is how "0.9999999" becomes
    a missed or phantom sweep.
    """

    tx: str
    ts: int  # unix seconds
    sender: str
    recipient: str
    amount: int
    token: str = "native"
    slot: int | None = None


@dataclass(frozen=True)
class Approval:
    """An ERC-20 style allowance grant. EVM-only; Solana has no direct analogue.

    Solana's closest equivalent is a delegate/authority change, which has a
    different shape and is not modelled here rather than being forced into this
    struct.
    """

    tx: str
    ts: int
    owner: str
    spender: str
    amount: int
    token: str


@dataclass(frozen=True)
class AddressFacts:
    """What the caller knows about an address BEFORE the window under test.

    This is the part that cannot be computed from the window alone, and it is
    also the part that carries the most risk of being wrong. `first_seen_ts` from
    a pruned public-node index is a lower bound on age, not the true age: an
    address can look "fresh" purely because the node forgot its history. Callers
    that cannot source this reliably should pass `history_complete=False`, which
    suppresses the freshness-dependent signals rather than letting them fire on
    an artifact of pruning.
    """

    address: str
    first_seen_ts: int | None = None
    distinct_counterparties: int = 0
    tx_count: int = 0
    is_contract: bool = False
    history_complete: bool = True


# ----------------------------------------------------------------- output ---

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Signal:
    """A fact about a set of transactions, plus what would innocently explain it.

    Mirrors `wormhole.rules.injection.Finding` in spirit but is deliberately a
    separate type: a Finding says "this text matches this rule" and is fully
    self-verifying from the text alone. A Signal says "this activity has this
    shape", which is weaker, is contingent on the window and on history the
    caller supplied, and must never be rendered in the same feed as if it had
    the same epistemic weight.
    """

    rule_id: str
    severity: str
    title: str
    detail: str
    subject: str  # the address the shape was observed AROUND, not accused of
    tx_refs: list[str] = field(default_factory=list)
    window_start_ts: int | None = None
    window_end_ts: int | None = None
    evidence: dict = field(default_factory=dict)
    benign_explanations: list[str] = field(default_factory=list)
    needs_adjudication: bool = True

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "subject": self.subject,
            "tx_refs": list(self.tx_refs),
            "window_start_ts": self.window_start_ts,
            "window_end_ts": self.window_end_ts,
            "evidence": dict(self.evidence),
            "benign_explanations": list(self.benign_explanations),
            "needs_adjudication": self.needs_adjudication,
        }


# ------------------------------------------------------- BEHAV-001 fan-out ---

# A "narrow" address is one whose entire history involves at most this many
# distinct counterparties. The spec says <=3. The point is not the exact number
# but the CONTRAST: a wallet that has only ever talked to its owner and a DEX,
# suddenly talking to 30 addresses, is a change in kind.
FANOUT_HISTORIC_MAX_COUNTERPARTIES = 3

# How many NEW counterparties inside the window constitutes a burst.
FANOUT_MIN_NEW_RECIPIENTS = 10

# The burst must be compressed in time. A wallet that pays 12 suppliers over a
# month is a business; 12 in 5 minutes is automation.
FANOUT_WINDOW_SECONDS = 600

FANOUT_BENIGN = [
    "Airdrop or token distribution: one funded address paying many recipients "
    "is the defining shape of an airdrop, and airdrops are enormously more "
    "common than drains.",
    "Exchange or bridge hot wallet processing a batch of withdrawals. These "
    "look narrow historically only if the observation window is short or the "
    "node's index is pruned.",
    "Payroll, grant disbursement, or NFT mint refunds executed as one batch.",
    "A newly-deployed disperse/multisend contract being used for the first "
    "time by a legitimate operator.",
    "Consolidation in reverse: a wallet splitting a balance across its own "
    "fresh addresses for operational or privacy reasons.",
]


def detect_fanout_burst(
    transfers: Sequence[Transfer],
    facts: dict[str, AddressFacts],
    *,
    window_seconds: int = FANOUT_WINDOW_SECONDS,
    min_new_recipients: int = FANOUT_MIN_NEW_RECIPIENTS,
    historic_max: int = FANOUT_HISTORIC_MAX_COUNTERPARTIES,
) -> list[Signal]:
    """BEHAV-001. An address with a narrow past suddenly sending to many.

    RULE
      Sender S has <= `historic_max` distinct counterparties in its history
      before the window, AND sends to >= `min_new_recipients` distinct
      recipients within any `window_seconds` span.

    REQUIRED DATA
      Transfers with sender/recipient/ts, plus per-sender historic counterparty
      counts (AddressFacts.distinct_counterparties). The historic count is the
      whole signal — without it this is just "an address sent to 10 people",
      which is a Tuesday.

    WINDOW
      Sliding, 10 minutes by default.

    THE BENIGN CASE THAT TRIPS IT
      An airdrop. Structurally identical: one source, many fresh destinations,
      compressed in time. This signal cannot distinguish the two from shape
      alone, which is precisely why it is `needs_adjudication` and why the
      airdrop explanation is attached to every emission.
    """
    signals: list[Signal] = []
    by_sender: dict[str, list[Transfer]] = defaultdict(list)
    for t in transfers:
        by_sender[t.sender].append(t)

    for sender, items in by_sender.items():
        known = facts.get(sender)
        # No history means no contrast, and an address that merely LOOKS narrow
        # because we never looked is not evidence. Require an explicit fact.
        if known is None:
            continue
        if known.distinct_counterparties > historic_max:
            continue

        items = sorted(items, key=lambda t: t.ts)
        # Sliding window over send events, counting DISTINCT recipients. Two
        # payments to the same address are one counterparty, not two -- a
        # rebalancing loop between two wallets must not read as fan-out.
        left = 0
        for right in range(len(items)):
            while items[right].ts - items[left].ts > window_seconds:
                left += 1
            span = items[left : right + 1]
            recipients = {t.recipient for t in span}
            # Sending to oneself is not fan-out.
            recipients.discard(sender)
            if len(recipients) < min_new_recipients:
                continue
            signals.append(
                Signal(
                    rule_id="BEHAV-001",
                    severity="medium",
                    title="Fan-out burst from a historically narrow address",
                    detail=(
                        f"{sender} previously transacted with "
                        f"{known.distinct_counterparties} distinct "
                        f"counterparties, then sent to {len(recipients)} "
                        f"distinct recipients within "
                        f"{span[-1].ts - span[0].ts}s."
                    ),
                    subject=sender,
                    tx_refs=sorted({t.tx for t in span}),
                    window_start_ts=span[0].ts,
                    window_end_ts=span[-1].ts,
                    evidence={
                        "historic_counterparties": known.distinct_counterparties,
                        "recipients_in_window": len(recipients),
                        "transfers_in_window": len(span),
                        "window_seconds": span[-1].ts - span[0].ts,
                    },
                    benign_explanations=list(FANOUT_BENIGN),
                )
            )
            break  # One signal per sender per run; the shape is established.

    return signals


# --------------------------------------------------------- BEHAV-002 sweep ---

# What fraction of the pre-transfer balance must leave to count as a sweep.
# Not 1.0: a drainer leaves dust behind, and on EVM the gas token cannot be
# fully sent anyway.
SWEEP_MIN_FRACTION = 0.98

# A destination is "fresh" if first seen this recently before the sweep.
SWEEP_FRESH_DESTINATION_SECONDS = 24 * 3600

SWEEP_BENIGN = [
    "Wallet migration: a user moving to a new seed phrase or a hardware wallet "
    "produces exactly this shape, including the fresh destination.",
    "Upgrading to a smart-contract wallet or multisig, where the destination "
    "was deployed minutes before the move.",
    "Consolidating a burner or throwaway address after it has served its "
    "purpose. Burners are fresh by definition.",
    "Deposit to a freshly-generated exchange deposit address. Exchanges issue "
    "a new address per user per asset, so 'no prior history' is expected.",
    "A bot or keeper rotating its operating wallet on a schedule.",
]


def detect_full_balance_sweep(
    transfers: Sequence[Transfer],
    balances_before: dict[tuple[str, str], int],
    facts: dict[str, AddressFacts],
    *,
    min_fraction: float = SWEEP_MIN_FRACTION,
    fresh_seconds: int = SWEEP_FRESH_DESTINATION_SECONDS,
) -> list[Signal]:
    """BEHAV-002. Substantially the entire balance leaving, to an address with no past.

    RULE
      For (address, token), the total sent in one transaction is >=
      `min_fraction` of the balance immediately before it, AND the destination
      was first seen < `fresh_seconds` before the transfer.

    REQUIRED DATA
      Transfers, pre-transaction balances keyed (address, token), and the
      destination's first-seen timestamp. On Solana the balance is available
      directly from `meta.preTokenBalances`/`preBalances`, so this needs no
      extra indexing; on EVM it needs an archive `balanceOf` at block-1 or a
      running balance reconstruction.

    WINDOW
      Per-transaction, not a time window. Freshness of the destination is
      evaluated over the preceding 24h.

    THE BENIGN CASE THAT TRIPS IT
      A wallet migration, which is the same event with a different intent —
      100% of a balance moving to an address created moments earlier is what a
      user does when rotating a compromised or upgraded wallet. Exchange deposit
      addresses are also fresh by design. Neither is distinguishable here.

    Both conditions are required. Either alone is far too common: emptying a
    wallet to a known exchange is routine, and sending to a fresh address while
    keeping most of the balance is routine.
    """
    signals: list[Signal] = []

    # Aggregate per (tx, sender, token): a drain may split across several
    # transfer events inside one transaction, and testing each event alone
    # would see three 33% moves instead of one 99% sweep.
    grouped: dict[tuple[str, str, str], list[Transfer]] = defaultdict(list)
    for t in transfers:
        grouped[(t.tx, t.sender, t.token)].append(t)

    for (tx, sender, token), items in grouped.items():
        before = balances_before.get((sender, token))
        if not before or before <= 0:
            continue
        total = sum(t.amount for t in items)
        fraction = total / before
        if fraction < min_fraction:
            continue

        ts = min(t.ts for t in items)
        destinations = {t.recipient for t in items}
        destinations.discard(sender)
        if not destinations:
            continue

        fresh: list[str] = []
        for dest in destinations:
            known = facts.get(dest)
            if known is None or known.first_seen_ts is None:
                continue
            # A pruned index makes old addresses look new. Refuse to call an
            # address fresh when the caller has told us history is incomplete.
            if not known.history_complete:
                continue
            if 0 <= ts - known.first_seen_ts < fresh_seconds:
                fresh.append(dest)

        if not fresh:
            continue

        signals.append(
            Signal(
                rule_id="BEHAV-002",
                severity="high",
                title="Full-balance sweep to a freshly-created address",
                detail=(
                    f"{round(fraction * 100, 2)}% of {sender}'s {token} balance "
                    f"({total} of {before}) left in tx {tx}, to "
                    f"{len(fresh)} destination(s) first seen less than "
                    f"{fresh_seconds}s earlier."
                ),
                subject=sender,
                tx_refs=[tx],
                window_start_ts=ts,
                window_end_ts=max(t.ts for t in items),
                evidence={
                    "token": token,
                    "balance_before": before,
                    "amount_sent": total,
                    "fraction_sent": round(fraction, 6),
                    "fresh_destinations": sorted(fresh),
                    "destination_age_seconds": {
                        d: ts - facts[d].first_seen_ts for d in sorted(fresh)
                    },
                },
                benign_explanations=list(SWEEP_BENIGN),
            )
        )

    return signals


# ------------------------------------------------------- BEHAV-003 approve ---

# The canonical "unlimited" allowance, 2**256-1. Many routers instead request
# 2**255 or a large round number, so an exact-equality test misses them; the
# threshold below treats anything above 2**255 as effectively unlimited.
UINT256_MAX = 2**256 - 1
UNLIMITED_APPROVAL_THRESHOLD = 2**255

# How recently the spender must have been deployed to count as "new".
APPROVE_FRESH_SPENDER_SECONDS = 3600

APPROVE_BENIGN = [
    "Standard DEX/aggregator UX: Uniswap, 1inch, CowSwap and most routers "
    "request an unlimited allowance by default to avoid a second approval per "
    "trade. Unlimited approvals are the norm, not the exception.",
    "A legitimate protocol upgrade deploying a new router or vault, which users "
    "then approve within the hour of deployment.",
    "A newly-launched protocol during its first hour of mainnet life, where "
    "EVERY approval is by definition to a recently-deployed spender.",
    "Deterministic (CREATE2) redeployment of an already-audited contract to a "
    "new chain, where deployment time is recent but the code is not novel.",
]


def detect_unlimited_approve_to_new_spender(
    approvals: Sequence[Approval],
    facts: dict[str, AddressFacts],
    *,
    threshold: int = UNLIMITED_APPROVAL_THRESHOLD,
    fresh_seconds: int = APPROVE_FRESH_SPENDER_SECONDS,
) -> list[Signal]:
    """BEHAV-003. Max-value allowance granted to a contract deployed minutes ago.

    RULE
      Approval amount >= `threshold` (effectively unlimited), AND the spender is
      a contract whose deployment was < `fresh_seconds` before the approval.

    REQUIRED DATA
      ERC-20 Approval logs, plus spender contract deployment timestamps
      (AddressFacts.first_seen_ts with is_contract=True). Deployment time comes
      from creation traces; on Dune, `base.creation_traces`.

    WINDOW
      Per-approval; spender age evaluated over the preceding hour.

    THE BENIGN CASE THAT TRIPS IT
      Nearly every DEX interaction ever. Unlimited approval is the DEFAULT in
      mainstream wallet UX, so the "unlimited" half of this rule carries almost
      no information on its own — the load is borne entirely by spender novelty.
      And on the day a legitimate protocol launches, every one of its users
      trips this rule simultaneously. That is not a hypothetical false positive;
      it is a guaranteed daily one, which is why this pairs with BEHAV-004:
      a novel spender collecting approvals from many unrelated addresses is
      either a launch or a worm, and the difference is not visible on chain.

    EVM only. Solana has no allowance primitive of this shape; its delegate
    model differs enough that pretending otherwise would produce nonsense.
    """
    signals: list[Signal] = []
    for ap in approvals:
        if ap.amount < threshold:
            continue
        spender = facts.get(ap.spender)
        if spender is None or spender.first_seen_ts is None:
            continue
        if not spender.history_complete:
            continue
        # Approving an EOA is a different anomaly and not this rule's job; an
        # allowance to a non-contract cannot be pulled by contract logic.
        if not spender.is_contract:
            continue
        age = ap.ts - spender.first_seen_ts
        if not (0 <= age < fresh_seconds):
            continue

        signals.append(
            Signal(
                rule_id="BEHAV-003",
                severity="medium",
                title="Unlimited approval granted to a newly-deployed spender",
                detail=(
                    f"{ap.owner} granted an effectively unlimited {ap.token} "
                    f"allowance to {ap.spender}, a contract deployed {age}s "
                    f"before the approval."
                ),
                subject=ap.owner,
                tx_refs=[ap.tx],
                window_start_ts=ap.ts,
                window_end_ts=ap.ts,
                evidence={
                    "token": ap.token,
                    "spender": ap.spender,
                    "amount": ap.amount,
                    "is_uint256_max": ap.amount == UINT256_MAX,
                    "spender_age_seconds": age,
                },
                benign_explanations=list(APPROVE_BENIGN),
            )
        )
    return signals


# --------------------------------------------------- BEHAV-004 correlation ---

# How many previously-unrelated addresses must touch the same novel contract.
CORRELATION_MIN_ADDRESSES = 5

# The window they must do it in.
CORRELATION_WINDOW_SECONDS = 3600

# A contract is "novel" if deployed this recently.
CORRELATION_NOVEL_CONTRACT_SECONDS = 7 * 24 * 3600

CORRELATION_BENIGN = [
    "A popular NFT mint or token launch. Hundreds of unrelated wallets hitting "
    "one hours-old contract in one hour IS a successful launch, and this is by "
    "far the most common cause.",
    "A viral airdrop claim contract, where unrelated recipients all claim in "
    "the same window because the claim just opened.",
    "A new protocol version going live and its existing userbase migrating.",
    "A trending contract amplified by social media or a bot aggregator, where "
    "the correlation is attention, not compromise.",
    "Copy-trading and MEV bots reacting to the same on-chain event, which "
    "correlates their behaviour without any shared compromise.",
]


def detect_cross_agent_correlation(
    transfers: Sequence[Transfer],
    facts: dict[str, AddressFacts],
    prior_pairs: Iterable[tuple[str, str]] = (),
    *,
    window_seconds: int = CORRELATION_WINDOW_SECONDS,
    min_addresses: int = CORRELATION_MIN_ADDRESSES,
    novel_seconds: int = CORRELATION_NOVEL_CONTRACT_SECONDS,
) -> list[Signal]:
    """BEHAV-004. N previously-unrelated addresses touching one novel contract.

    This is the closest thing to an on-chain fingerprint of self-replication.
    A worm that spreads between agents produces convergence: wallets that have
    never interacted, that share no funding source, independently start talking
    to the same address that did not exist last week. Text scanning cannot see
    this at all, because the shared cause is upstream of the chain.

    RULE
      >= `min_addresses` distinct addresses, pairwise unrelated (no prior
      interaction between them per `prior_pairs`), send to the same contract
      first deployed < `novel_seconds` ago, all within `window_seconds`.

    REQUIRED DATA
      Transfers into contracts, contract deployment timestamps, and a prior
      interaction graph. That last input is the expensive one: it needs
      historical counterparty sets per address, and getting it wrong in the
      permissive direction (assuming unrelated when they are related) inflates
      this signal directly.

    WINDOW
      1 hour, sliding.

    THE BENIGN CASE THAT TRIPS IT
      A successful mint. This is the weakest of the four signals precisely
      because its benign twin is not merely common but is the intended
      behaviour of most new contracts. A worm and a launch look identical here.
      What distinguishes them is not on chain: it is whether the addresses
      involved are agent wallets and whether their owners intended the
      interaction. This signal's job is to produce a small, human-reviewable
      queue — not to make a determination.

    `prior_pairs` is treated as the complete known relation set. Callers who
    cannot supply one get a strictly noisier signal, since every pair then looks
    unrelated; this function does not pretend otherwise.
    """
    related: set[frozenset[str]] = {frozenset(p) for p in prior_pairs if len(set(p)) == 2}

    by_contract: dict[str, list[Transfer]] = defaultdict(list)
    for t in transfers:
        dest = facts.get(t.recipient)
        if dest is None or not dest.is_contract:
            continue
        if dest.first_seen_ts is None or not dest.history_complete:
            continue
        if t.ts - dest.first_seen_ts >= novel_seconds:
            continue
        by_contract[t.recipient].append(t)

    signals: list[Signal] = []
    for contract, items in by_contract.items():
        items = sorted(items, key=lambda t: t.ts)
        left = 0
        for right in range(len(items)):
            while items[right].ts - items[left].ts > window_seconds:
                left += 1
            span = items[left : right + 1]
            senders = sorted({t.sender for t in span})
            if len(senders) < min_addresses:
                continue

            # Keep only a mutually-unrelated subset. A greedy pass is enough:
            # the aim is a defensible lower bound on how many independent
            # parties converged, not a maximum independent set.
            independent: list[str] = []
            for cand in senders:
                if all(frozenset((cand, chosen)) not in related for chosen in independent):
                    independent.append(cand)
            if len(independent) < min_addresses:
                continue

            deployed = facts[contract].first_seen_ts
            signals.append(
                Signal(
                    rule_id="BEHAV-004",
                    severity="medium",
                    title="Unrelated addresses converging on a novel contract",
                    detail=(
                        f"{len(independent)} previously-unrelated addresses sent "
                        f"to {contract} within {span[-1].ts - span[0].ts}s. The "
                        f"contract was first seen {span[0].ts - deployed}s before "
                        f"the first of these transfers."
                    ),
                    subject=contract,
                    tx_refs=sorted({t.tx for t in span}),
                    window_start_ts=span[0].ts,
                    window_end_ts=span[-1].ts,
                    evidence={
                        "distinct_senders": len(senders),
                        "independent_senders": len(independent),
                        "contract_age_seconds": span[0].ts - deployed,
                        "transfers_in_window": len(span),
                    },
                    benign_explanations=list(CORRELATION_BENIGN),
                )
            )
            break  # One signal per contract per run.

    return signals


# ------------------------------------------------------------- aggregation ---


def run_all(
    transfers: Sequence[Transfer] = (),
    approvals: Sequence[Approval] = (),
    facts: dict[str, AddressFacts] | None = None,
    balances_before: dict[tuple[str, str], int] | None = None,
    prior_pairs: Iterable[tuple[str, str]] = (),
) -> list[Signal]:
    """Run every behavioral signal over one batch. Pure; no I/O.

    Returns signals sorted by severity then rule id. Nothing here auto-publishes:
    the output is an adjudication queue, matching stage 3 of the cascade.
    """
    facts = facts or {}
    balances_before = balances_before or {}

    out: list[Signal] = []
    out += detect_fanout_burst(transfers, facts)
    out += detect_full_balance_sweep(transfers, balances_before, facts)
    out += detect_unlimited_approve_to_new_spender(approvals, facts)
    out += detect_cross_agent_correlation(transfers, facts, prior_pairs)

    rank = {s: i for i, s in enumerate(SEVERITIES)}
    out.sort(key=lambda s: (rank.get(s.severity, len(SEVERITIES)), s.rule_id))
    return out


def estimate_alert_load(signals: Sequence[Signal], daily_volume: int, sampled: int) -> dict:
    """Extrapolate a day's alert count from a sample. Deliberately unflattering.

    A signal that fires on 0.01% of activity sounds precise and is unusable at
    10M events/day: that is 1,000 alerts, and a queue nobody can review is the
    same as no detector. This exists so the tuning conversation starts from
    arithmetic instead of from a threshold that merely sounds strict.
    """
    if sampled <= 0:
        return {"error": "sampled must be > 0"}
    per_rule: dict[str, int] = defaultdict(int)
    for s in signals:
        per_rule[s.rule_id] += 1
    scale = daily_volume / sampled
    return {
        "sampled_events": sampled,
        "assumed_daily_volume": daily_volume,
        "signals_in_sample": len(signals),
        "projected_daily_alerts": round(len(signals) * scale, 1),
        "projected_daily_by_rule": {
            k: round(v * scale, 1) for k, v in sorted(per_rule.items())
        },
        "caveat": (
            "Linear extrapolation from one sample. Valid only if the sample is "
            "representative, which for a pruned tip-of-chain walk it may not be."
        ),
    }
