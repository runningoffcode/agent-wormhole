"""Blast radius: what an infection here would actually reach.

Severity alone ranks findings by how bad the payload looks. That is the wrong
axis. The same payload in an agent that can only read files is a nuisance; in
an agent with unrestricted shell and network egress it is a breach.

This module scores the *host* — the capability an agent has been granted — and
uses it to weight content findings. The model follows AgentWorm's infection
loop, which needs three things to close:

    execute → persist → propagate

Break any link and the loop stops. The paper's headline result is that sandbox
isolation breaks the persist link and drives attack success to 0%, while
execution restriction alone leaves propagation intact ("asymptomatic carriers").
So we score the links separately rather than summing a single risk number.
"""

from dataclasses import dataclass, field


@dataclass
class BlastRadius:
    execute: int = 0      # 0-10: can it run attacker-controlled code?
    persist: int = 0      # 0-10: can it write where it will be re-read?
    propagate: int = 0    # 0-10: can it reach other agents or hosts?
    factors: list = field(default_factory=list)

    # A link scoring at or below this is residual capability, not a usable
    # step in the infection loop. Scores of 1-2 are the floors assigned when
    # a check finds *nothing*; treating those as "present" would report a
    # closed loop on a host with no agent config and no shell access.
    LINK_THRESHOLD = 3

    @property
    def score(self) -> int:
        """Overall 0-10. The loop is multiplicative: a broken link should pull
        the total down hard, because a broken link stops the worm."""
        links = [self.execute, self.persist, self.propagate]
        if min(links) < self.LINK_THRESHOLD:
            # At least one link is not usable. Cap at the remaining exposure --
            # still nonzero, since a config change can restore the link.
            return min(4, max(links))
        return min(10, round((self.execute + self.persist + self.propagate) / 3))

    @property
    def band(self) -> str:
        s = self.score
        if s >= 8:
            return "severe"
        if s >= 6:
            return "high"
        if s >= 4:
            return "moderate"
        if s >= 2:
            return "limited"
        return "contained"

    @property
    def loop_closed(self) -> bool:
        """True when all three links are usable: the worm can complete a full
        infection cycle without further attacker involvement."""
        return min(self.execute, self.persist,
                   self.propagate) >= self.LINK_THRESHOLD

    @property
    def broken_links(self) -> list:
        """Links too weak to carry an infection. These are the wins."""
        return [n for n, v in (("execute", self.execute),
                               ("persist", self.persist),
                               ("propagate", self.propagate))
                if v < self.LINK_THRESHOLD]


# Rule IDs mapped to the infection-loop link they evidence.
_EXECUTE = {"POSTURE-001"}
_PERSIST = {"POSTURE-004"}
_PROPAGATE = {"POSTURE-002", "POSTURE-005", "POSTURE-006"}


def compute(findings: list) -> BlastRadius:
    """Derive blast radius from posture findings."""
    br = BlastRadius()
    ids = {f.rule_id for f in findings}

    # --- execute -----------------------------------------------------------
    if "POSTURE-001" in ids:
        br.execute = 10
        br.factors.append("unrestricted shell (Bash(*)) — arbitrary code")
    else:
        # Narrower grants still permit execution, just less of it.
        bash_findings = [f for f in findings if f.rule_id == "POSTURE-002"]
        if bash_findings:
            br.execute = 4
            br.factors.append("scoped command execution permitted")
        else:
            br.execute = 2
            br.factors.append("no unrestricted execution grant found")

    # --- persist -----------------------------------------------------------
    writable = [f for f in findings if f.rule_id == "POSTURE-004"]
    if writable:
        n = len(writable)
        br.persist = min(10, 5 + n)
        br.factors.append(
            f"{n} writable agent config(s) — dual-anchor persistence target")
    else:
        br.persist = 1
        br.factors.append("no writable agent config detected")

    # --- propagate ---------------------------------------------------------
    p = 0
    if "POSTURE-002" in ids:
        p += 5
        br.factors.append("network egress permitted — can reach other hosts")
    if "POSTURE-005" in ids:
        p += 3
        br.factors.append("remote MCP servers — untrusted inbound channel")
    if "POSTURE-006" in ids:
        p += 3
        br.factors.append("skills installed — 82% ASR vector present")
    if p == 0:
        p = 1
        br.factors.append("limited outbound reach")
    br.propagate = min(10, p)

    # Absence of deny rules removes the cheapest brake on all three links.
    if "POSTURE-003" in ids:
        br.factors.append("no deny rules — no explicit brake on any link")

    return br


def weight_severity(severity: str, br: BlastRadius) -> str:
    """Escalate a content finding's severity by host capability.

    A payload found in a fully-capable host is worse than the same payload in
    a contained one. We escalate but never de-escalate: a critical finding
    stays critical even in a sandbox, because sandboxes get reconfigured.
    """
    order = ["info", "low", "medium", "high", "critical"]
    if severity not in order:
        return severity
    i = order.index(severity)
    if br.loop_closed and br.score >= 8:
        i += 1
    return order[min(i, len(order) - 1)]


def render(br: BlastRadius, color=None) -> str:
    """Human-readable blast radius block."""
    c = color or {k: "" for k in
                  ("bold", "dim", "r", "critical", "high", "medium", "low", "ok")}
    tone = {"severe": c["critical"], "high": c["high"], "moderate": c["medium"],
            "limited": c["low"], "contained": c["ok"]}[br.band]

    def bar(v):
        return "█" * v + c["dim"] + "░" * (10 - v) + c["r"]

    lines = [
        f"{c['bold']}blast radius{c['r']}  {tone}{br.band}{c['r']} "
        f"{c['dim']}({br.score}/10){c['r']}",
        f"  execute    {bar(br.execute)} {br.execute}",
        f"  persist    {bar(br.persist)} {br.persist}",
        f"  propagate  {bar(br.propagate)} {br.propagate}",
    ]
    if br.loop_closed:
        lines.append(
            f"  {c['critical']} LOOP CLOSED {c['r']} execute → persist → "
            f"propagate are all reachable: an infection here can complete a "
            f"full cycle unassisted.")
    else:
        lines.append(f"  {c['ok']}loop broken at: "
                     f"{', '.join(br.broken_links)}{c['r']}")
    for f in br.factors:
        lines.append(f"  {c['dim']}· {f}{c['r']}")
    return "\n".join(lines)
