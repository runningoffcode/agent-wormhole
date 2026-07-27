"""Canary addresses: contact is attacker-by-construction.

A canary is an address that appears in NO legitimate payment quote, in no
published document, and in no client configuration. It is planted only where an
attacker would find it -- in bait agent memory files, bait .env fixtures, bait
MCP tool descriptions. Because no honest counterparty has any way to learn the
address, ANY on-chain contact with it is, structurally, evidence that something
read the bait. That is what makes canaries the one signal in this system with
zero false positives by construction rather than by tuning.

WHY THE LIST STAYS PRIVATE. Publishing canary addresses hands worm authors a
free avoidance list -- the countermeasure is one string comparison. So the
registry is loaded from a file that is gitignored, never printed in full, and
never embedded in a Dune query (a Dune query is a publication). Everything this
module emits externally uses a canary LABEL and a truncated fingerprint, never
the address itself.

WHAT THIS IS NOT. Contact with a canary is a fact about a transaction: "tx
<sig> moved value to canary <label>". It is still not a verdict about the
sender's identity or intent -- the sender may itself be a compromised victim
agent relaying someone else's instruction. The alert says what happened, not
who is guilty.

Read-only. Nothing here signs, sends, or funds anything. Canaries are planted
out-of-band by an operator; this module only watches.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

# The registry file is deliberately NOT committed. `.gitignore` carries
# `watchtower/canaries.json` so a careless `git add -A` cannot publish it.
DEFAULT_REGISTRY = Path(__file__).resolve().parent / "canaries.json"

# How much of the address fingerprint is safe to show in an alert. Enough to
# correlate two alerts about the same canary, far too little to brute-force
# back to an address.
FINGERPRINT_CHARS = 12


def fingerprint(address: str) -> str:
    """Stable, non-reversible id for a canary address.

    SHA-256 truncated. An operator holding the registry can map this back to an
    address; a reader of a published alert cannot.
    """
    return hashlib.sha256(address.encode("utf-8")).hexdigest()[:FINGERPRINT_CHARS]


@dataclass(frozen=True)
class Canary:
    """One planted address plus where it was planted.

    `placement` is the bait location (e.g. "bait-agents-md-07"). It matters
    because it tells you WHICH lure was taken, which is the difference between
    "someone scraped a public repo" and "something read a local .env".
    """

    address: str
    label: str
    chain: str = "solana"
    placement: str = ""
    planted_ts: int | None = None

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.address)

    def public_view(self) -> dict:
        """The ONLY representation safe to publish. Note: no `address` key."""
        return {
            "canary_label": self.label,
            "canary_fingerprint": self.fingerprint,
            "chain": self.chain,
            "placement": self.placement,
        }


@dataclass
class CanaryHit:
    """Contact with a canary. A fact about a transaction, not about a party."""

    signature: str
    canary: Canary
    direction: str  # "to-canary" | "from-canary"
    counterparty: str
    amount: int | None = None
    ts: int | None = None
    evidence: dict = field(default_factory=dict)

    @property
    def rule_id(self) -> str:
        return "CANARY-001"

    @property
    def severity(self) -> str:
        # Highest severity in the system: this is the only signal that cannot
        # be explained by a benign coincidence.
        return "critical"

    def as_dict(self) -> dict:
        """Publishable form. The canary address is NEVER included."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": "Contact with canary address",
            "detail": (
                "This transaction touched an address that appears in no "
                "legitimate quote or published document. Contact is only "
                "possible by reading a planted bait, so this is evidence the "
                "bait was read. It is not a claim about who is responsible: "
                "the sender may itself be a compromised agent."
            ),
            "signature": self.signature,
            "direction": self.direction,
            "counterparty": self.counterparty,
            "amount": self.amount,
            "ts": self.ts,
            **self.canary.public_view(),
            "evidence": dict(self.evidence),
        }


class CanaryRegistry:
    """The private set of planted addresses. Never printed in full."""

    def __init__(self, canaries: Iterable[Canary] = ()) -> None:
        self._by_address: dict[str, Canary] = {}
        for c in canaries:
            self.add(c)

    def add(self, canary: Canary) -> None:
        self._by_address[canary.address] = canary

    def __len__(self) -> int:
        return len(self._by_address)

    def __contains__(self, address: str) -> bool:
        return address in self._by_address

    def get(self, address: str) -> Canary | None:
        return self._by_address.get(address)

    def addresses(self) -> frozenset:
        """Internal use only. Do not serialize the result."""
        return frozenset(self._by_address)

    def public_summary(self) -> dict:
        """Safe to publish: counts and fingerprints, never addresses."""
        return {
            "canaries_active": len(self._by_address),
            "fingerprints": sorted(c.fingerprint for c in self._by_address.values()),
            "note": (
                "Canary addresses are withheld deliberately. Publishing them "
                "would let a worm author filter them out in one comparison."
            ),
        }

    @classmethod
    def load(cls, path: str | Path | None = None) -> "CanaryRegistry":
        """Load from the private registry file, or from $WATCHTOWER_CANARIES.

        A missing file is NOT an error: it means no canaries are planted, and a
        watchtower with no canaries should degrade to its other signals rather
        than refuse to start.
        """
        p = Path(path or os.environ.get("WATCHTOWER_CANARIES") or DEFAULT_REGISTRY)
        if not p.exists():
            return cls()
        raw = json.loads(p.read_text(encoding="utf-8"))
        items = raw.get("canaries", raw) if isinstance(raw, dict) else raw
        return cls(
            Canary(
                address=i["address"],
                label=i.get("label", ""),
                chain=i.get("chain", "solana"),
                placement=i.get("placement", ""),
                planted_ts=i.get("planted_ts"),
            )
            for i in items
        )


def scan_transfers(transfers: Sequence, registry: CanaryRegistry) -> list[CanaryHit]:
    """Emit a hit for every transfer touching a canary, either direction.

    `transfers` are `behavioral.Transfer`-shaped (tx/ts/sender/recipient/amount)
    but duck-typed on purpose so this works on any ingest shape.

    Both directions matter. Value moving TO a canary means the bait address was
    used as a payment destination -- something followed a planted instruction.
    Value moving FROM a canary means the key itself was exercised, which only
    happens if the bait leaked a key.
    """
    hits: list[CanaryHit] = []
    if not len(registry):
        return hits
    for t in transfers:
        recipient = getattr(t, "recipient", None)
        sender = getattr(t, "sender", None)
        amount = getattr(t, "amount", None)
        ts = getattr(t, "ts", None)
        sig = getattr(t, "tx", "") or ""
        c = registry.get(recipient) if recipient else None
        if c is not None:
            hits.append(
                CanaryHit(
                    signature=sig,
                    canary=c,
                    direction="to-canary",
                    counterparty=sender or "",
                    amount=amount,
                    ts=ts,
                    evidence={"token": getattr(t, "token", "native")},
                )
            )
            continue
        c = registry.get(sender) if sender else None
        if c is not None:
            hits.append(
                CanaryHit(
                    signature=sig,
                    canary=c,
                    direction="from-canary",
                    counterparty=recipient or "",
                    amount=amount,
                    ts=ts,
                    evidence={"token": getattr(t, "token", "native")},
                )
            )
    return hits


def scan_text_for_canaries(
    text: str, signature: str, registry: CanaryRegistry
) -> list[CanaryHit]:
    """Find a canary address quoted inside carrier text (e.g. a memo).

    This catches the stage BEFORE any value moves: a worm propagating a payment
    instruction has to name the destination, so the canary address appears in
    the memo text itself. Catching it here means catching the instruction in
    flight rather than the theft after settlement.
    """
    hits: list[CanaryHit] = []
    if not text or not len(registry):
        return hits
    for addr in registry.addresses():
        if addr in text:
            c = registry.get(addr)
            assert c is not None
            idx = text.find(addr)
            # Redact the canary out of the excerpt: the excerpt gets published.
            excerpt = (text[:idx] + "<canary>" + text[idx + len(addr):])[:200]
            hits.append(
                CanaryHit(
                    signature=signature,
                    canary=c,
                    direction="quoted-in-carrier",
                    counterparty="",
                    evidence={"excerpt_redacted": excerpt},
                )
            )
    return hits
