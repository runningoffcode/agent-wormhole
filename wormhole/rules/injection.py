"""Detection rules for self-replicating prompt patterns.

The signal these rules look for is *self-reference in an instruction*: text
that tells a reader to reproduce the text itself. That is the property which
separates a worm payload from ordinary malicious instructions, and it is what
makes propagation possible without further attacker involvement.

Rules are deliberately conservative. A config file that discusses prompt
injection (documentation, security notes, this project's own README) must not
trip them, so most rules require a replication cue *and* a delivery or action
cue in proximity.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    rule_id: str
    severity: str  # critical | high | medium | low | info
    title: str
    detail: str
    path: Optional[str] = None
    line: Optional[int] = None
    excerpt: Optional[str] = None
    remediation: str = ""
    references: list = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        return {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
        }.get(self.severity, 5)


# Text that refers to the instruction block itself. A worm payload must
# reference itself in order to copy itself; benign instructions rarely do.
SELF_REFERENCE = re.compile(
    # "this prompt", "this entire skill file", "this Session Startup section"
    r"\bthis\s+(?:entire\s+|whole\s+|full\s+)?"
    r"(?:[A-Z][\w-]*\s+){0,3}"
    r"(?:prompt|instruction|message|paragraph|block|text|rule|rules|"
    r"section|file|skill|config(?:uration)?|content)s?\b"
    r"|\bthe (?:above|preceding|following) (?:instructions?|prompt|text)\b"
    r"|\bthese instructions\b"
    # A bare "this" as the direct object of a propagation verb: "copy this into
    # every project you touch". No noun follows, so the noun-anchored branch
    # above never fires — and this phrasing is the one in every worked example
    # of the attack, including our own README. The verb has to be adjacent, and
    # a destination is still required by the WORM-001 conjunction, so ordinary
    # prose ("copy this file to /tmp") does not reach a finding on its own.
    # A bare "this" as the direct object of a propagation verb, where the
    # destination follows in the same clause: "copy this into every project you
    # touch". No noun follows "this", so the noun-anchored branch above never
    # fires — yet this is the phrasing in every worked example of the attack,
    # including our own README.
    #
    # The destination has to be part of the same phrase rather than merely
    # nearby, because a contributing guide legitimately says "copy this file to
    # .env.local" three lines from "every project in this monorepo". Requiring
    # the preposition binds the verb to its object and keeps that clean.
    r"|\b(?:copy|include|append|insert|embed|add|paste|reproduce|replicate|"
    r"duplicate|propagate|forward)\s+this\s+"
    r"(?:(?:entire|whole|full)\s+)?"
    r"(?:section|block|text|rule|rules|prompt|instruction|instructions|"
    r"paragraph|content|note)?\s*"
    r"(?:in|into|to|onto|within|inside)\s+"
    r"(?:the\s+|your\s+)?"
    r"(?:every|each|any|all)\b"
    # "re-add this section to Y if missing" — self-restoration, a persistence
    # tell. The restored object must itself be self-referential: ordinary docs
    # legitimately say "re-add it to the Makefile if a rebase drops it", and
    # treating the bare verb as self-reference made that a critical finding.
    r"|\bre-?(?:add|insert|write|create)\s+(?:it\s+)?"
    r"(?:this|these|the\s+(?:above|preceding|following))\s+"
    r"(?:entire\s+|whole\s+|full\s+)?"
    r"(?:[A-Z][\w-]*\s+){0,3}"
    r"(?:prompt|instruction|message|paragraph|block|text|rule|rules|"
    r"section|file|skill|config(?:uration)?|content)s?\b",
    re.IGNORECASE,
)

# Verbs that move text somewhere it will be read again.
PROPAGATION_VERB = re.compile(
    r"\b(copy|repeat|reproduce|include|append|insert|embed|forward|"
    r"replicate|duplicate|propagate|pass (?:it |this )?(?:on|along)|"
    r"write|add)\b",
    re.IGNORECASE,
)

# Destinations that constitute a new host for the payload.
PROPAGATION_TARGET = re.compile(
    r"\b(every|each|all)\s+(?:subsequent |future |outgoing |following )?"
    r"(response|reply|message|email|output|file|commit|answer|request)|"
    # "every project you touch", "each repository you open" — the destination
    # in the canonical worked example of this attack. The trailing relative
    # clause is load-bearing: a project the agent *acts on* is a new host,
    # whereas bare "every project" is ordinary documentation prose ("every
    # project in this monorepo shares the eslint config") and matching it
    # produced a false positive on a real contributing guide.
    r"\b(every|each|any|all)\s+(?:new |other |subsequent )?"
    r"(project|repo|repository|codebase|workspace)s?\s+"
    r"(?:you|it|the agent)\s+"
    r"(?:touch|open|work|visit|edit|encounter|see|read|clone|enter)|"
    r"\b(outgoing|future|subsequent)\s+(messages?|emails?|responses?)|"
    r"\b(AGENTS?\.md|CLAUDE\.md|\.cursorrules|system prompt)\b|"
    # A spawned agent is a new host as surely as a file is. The parent writes
    # the child's whole context, and the child never sees where it came from,
    # so no hop in the tree is positioned to notice a payload riding along.
    r"\b(task description|system prompt|context handoff)\b|"
    r"\b(every|each|any)\s+(?:new |outgoing |spawned |child |sub-?)?"
    r"(agent|worker|subagent|task|delegate)s?\b",
    re.IGNORECASE,
)

# Attempts to displace prior instructions — the classic injection opener.
INSTRUCTION_OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override|discard|bypass)\s+"
    r"(?:all\s+|any\s+|the\s+|your\s+|previous\s+|prior\s+|earlier\s+|"
    r"above\s+|preceding\s+|system\s+){1,3}"
    r"(instructions?|prompts?|rules?|directives?|guidelines?|context)",
    re.IGNORECASE,
)

# Exfiltration: reading secrets and sending them outward.
SECRET_NOUN = re.compile(
    r"\b(password|passwd|credential|api[_ -]?key|secret|token|"
    r"private[_ -]?key|ssh[_ -]?key|\.env|env(?:ironment)? (?:file|var)|"
    r"seed phrase|mnemonic|wallet)\b",
    re.IGNORECASE,
)

EXFIL_VERB = re.compile(
    r"\b(send|email|post|upload|transmit|exfiltrate|leak|forward|"
    r"curl|wget|fetch|report)\b",
    re.IGNORECASE,
)

EXTERNAL_DEST = re.compile(
    r"(https?://(?!localhost|127\.0\.0\.1)[^\s\"'<>)]+|"
    r"\b[\w.+-]+@[\w-]+\.[\w.]+\b)",
    re.IGNORECASE,
)

# Destinations that only ever appear in documentation. RFC 2606 reserves
# example.com/.net/.org and .invalid/.test precisely for this purpose.
PLACEHOLDER_DEST = re.compile(
    r"(example\.(?:com|net|org)|\.invalid\b|\.test\b|\.local\b|"
    r"evil\.com|attacker\.com|malicious\.|your-?server|<[^>]+>|"
    r"\{\{[^}]+\}\}|YOUR_|PLACEHOLDER|TODO)",
    re.IGNORECASE,
)

# Text engineered to be invisible to a human reviewing the file.
# Bounded rather than `<!--(.*?)-->`. A lazy quantifier under DOTALL with no
# closing delimiter rescans to end-of-string from every start position, which
# is quadratic: 40KB of bare "<!--" took 1.9s, 156KB took 28s, 256KB took 76s.
# Since guard and outbound run on every tool call, that is both a denial of
# service and an uninstall trigger. `[^-]` plus a bounded repeat keeps a real
# comment matchable while refusing to backtrack across the whole document.
HIDDEN_HTML_COMMENT = re.compile(r"<!--([^>]{0,8000}?)-->", re.DOTALL)
ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")
# Unicode tag block — renders as nothing, reads as ASCII to a model.
UNICODE_TAGS = re.compile(r"[\U000e0000-\U000e007f]")

# Instructing the reader to conceal activity *from the operator*.
#
# The distinction that matters: "never show pricing in the public README" is a
# publishing preference and must not fire. "do not tell the user" is an attempt
# to blind the person supervising the agent, and must. So the negated verb has
# to take the operator as its object, either explicitly or by ellipsis
# ("do not mention this") — never a public/third-party audience.
CONCEALMENT = re.compile(
    r"\b(?:do not|don't|never|avoid)\s+"
    r"(?:mention(?:ing)?|tell(?:ing)?|inform(?:ing)?|reveal(?:ing)?|"
    r"disclos(?:e|ing)|report(?:ing)?|notify(?:ing)?|alert(?:ing)?|"
    r"log(?:ging)?|warn(?:ing)?)\s+"
    r"(?:this |that |it |any(?:thing)? (?:of )?(?:this|that) )?"
    r"(?:to )?(?:the )?(?:user|human|operator|owner|admin|anyone|"
    r"the person|them)\b"
    r"|"
    r"\b(?:silently|covertly|discreetly|surreptitiously)\b"
    r"|"
    r"\bwithout (?:the )?(?:user|human|operator|anyone|their)(?:'s)?\s+"
    r"(?:knowledge|awareness|consent|permission|noticing|approval)\b",
    re.IGNORECASE,
)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _excerpt(text: str, pos: int, width: int = 110) -> str:
    start = max(0, pos - width // 3)
    end = min(len(text), pos + width)
    frag = text[start:end].replace("\n", " ").strip()
    frag = re.sub(r"\s+", " ", frag)
    return ("..." if start > 0 else "") + frag + ("..." if end < len(text) else "")


# Prose that *describes* an attack rather than issuing one. Security
# documentation, this project's own rules file, threat models and incident
# reports all discuss worms in detail and must not be flagged. The tell is
# framing: a describing sentence attributes the behaviour to someone else
# ("attackers may try to...") or hedges it ("we detect ... where a key is
# sent"), whereas a payload addresses the reader directly in the imperative.
DESCRIPTIVE_FRAME = re.compile(
    r"\b(attackers?|adversar(?:y|ies)|threat actors?|malicious|worm|payload|"
    r"injection|exploit|vulnerabilit(?:y|ies)|CVE|proof[- ]of[- ]concept|"
    r"research(?:ers)?|we detect|detects?|detection|example|e\.g\.|"
    r"for instance|such as|may try|might try|could try|would try|"
    r"attempts? to|designed to|known as|referred to as|this rule|"
    r"false positive|test (?:case|fixture)|do not flag)\b",
    re.IGNORECASE,
)


def _is_descriptive(text: str, pos: int, window: int = 320) -> bool:
    """True when the surrounding prose reads as describing an attack.

    Deliberately biased toward suppression near explicit security vocabulary:
    a missed finding in a file that is visibly a threat-model document costs
    far less than a false positive that trains the operator to ignore output.
    """
    lo = max(0, pos - window)
    hi = min(len(text), pos + window)
    return bool(DESCRIPTIVE_FRAME.search(text, lo, hi))


def _near(text: str, a: re.Pattern, b: re.Pattern, window: int = 240):
    """Yield positions where a match of `a` has a match of `b` within `window`
    characters. Proximity stands in for 'part of the same instruction'."""
    for ma in a.finditer(text):
        lo = max(0, ma.start() - window)
        hi = min(len(text), ma.end() + window)
        if b.search(text, lo, hi):
            yield ma


# Beyond this, scanning is truncated. Every rule here is a regex over the whole
# blob, and several can backtrack superlinearly on adversarial input -- a page
# of bare "<!--" took 76s at 256KB before this cap. Since `guard`, `outbound`
# and `readguard` run on every tool call, an attacker who controls a fetched
# page could hang the agent by serving a large enough one. A payload that only
# appears past 256KB of a config file is not a realistic delivery mechanism;
# an unbounded scan on every tool call is a realistic denial of service.
MAX_SCAN_BYTES = 262144


def scan_text(text: str, path: str = None) -> list:
    """Run all content rules over a blob of text."""
    findings = []
    if text and len(text) > MAX_SCAN_BYTES:
        text = text[:MAX_SCAN_BYTES]

    def add(rule_id, severity, title, detail, pos, remediation, refs=None):
        findings.append(Finding(
            rule_id=rule_id, severity=severity, title=title, detail=detail,
            path=path, line=_line_of(text, pos), excerpt=_excerpt(text, pos),
            remediation=remediation, references=refs or [],
        ))

    # WORM-001: the defining signature. Self-reference + copy verb + a
    # destination that will be read again = a replication loop.
    for m in _near(text, SELF_REFERENCE, PROPAGATION_VERB, window=160):
        lo, hi = max(0, m.start() - 300), min(len(text), m.end() + 300)
        if PROPAGATION_TARGET.search(text, lo, hi):
            if _is_descriptive(text, m.start()):
                continue
            add("WORM-001", "critical",
                "Self-replicating instruction pattern",
                "Text refers to itself, uses a copy/forward verb, and names a "
                "destination that will be read by another agent. This is the "
                "structure of a worm payload: it instructs its own reproduction.",
                m.start(),
                "Remove this text. If the file is version controlled, check the "
                "commit that introduced it and audit any agent that has already "
                "read this file.",
                ["arXiv:2403.02817 (Morris II)", "arXiv:2603.15727 (AgentWorm)"])
            break  # one finding per file is enough to condemn it

    # WORM-002: instruction override.
    for m in INSTRUCTION_OVERRIDE.finditer(text):
        if _is_descriptive(text, m.start()):
            continue
        add("WORM-002", "high",
            "Instruction-override phrasing",
            "Text attempts to displace previously supplied instructions. This is "
            "the standard opening move of an indirect prompt injection.",
            m.start(),
            "Remove the text. Legitimate configuration never needs to countermand "
            "the system prompt.")
        break

    # WORM-003: exfiltration. Needs a secret, a send verb, and somewhere to send.
    for m in _near(text, SECRET_NOUN, EXFIL_VERB, window=200):
        lo, hi = max(0, m.start() - 300), min(len(text), m.end() + 300)
        dest = EXTERNAL_DEST.search(text, lo, hi)
        if dest:
            # Only suppress when the destination is itself a documentation
            # placeholder. A real host means the sentence is operative
            # regardless of how the surrounding prose is framed — the cost of
            # missing live exfiltration outweighs the cost of a false alarm.
            if PLACEHOLDER_DEST.search(dest.group(0)) and \
                    _is_descriptive(text, m.start()):
                continue
            add("WORM-003", "critical",
                "Credential exfiltration instruction",
                f"Text pairs a secret with a transmission verb and an external "
                f"destination ({dest.group(0)[:60]}).",
                m.start(),
                "Remove immediately and rotate any credential reachable from this "
                "agent. Assume exposure until proven otherwise.")
            break

    # WORM-004: hidden text. A model reads what a human reviewer will not see.
    for m in HIDDEN_HTML_COMMENT.finditer(text):
        body = m.group(1)
        if len(body.strip()) < 12:
            continue
        if INSTRUCTION_OVERRIDE.search(body) or CONCEALMENT.search(body) or (
            SELF_REFERENCE.search(body) and PROPAGATION_VERB.search(body)
        ):
            add("WORM-004", "critical",
                "Instructions concealed in HTML comment",
                "An HTML comment contains directive language. Comments are "
                "invisible when the file is rendered but are read by the model.",
                m.start(),
                "Delete the comment. Treat any agent that loaded this file as "
                "potentially compromised.")
            break

    if ZERO_WIDTH.search(text):
        m = ZERO_WIDTH.search(text)
        add("WORM-005", "high",
            "Zero-width characters present",
            "Zero-width characters render as nothing but are tokenized by the "
            "model. They are used to hide payloads and to break up keywords so "
            "they evade naive filters.",
            m.start(),
            "Strip with: perl -CSD -pe 's/[\\x{200b}-\\x{200d}\\x{2060}\\x{feff}]//g'")

    if UNICODE_TAGS.search(text):
        m = UNICODE_TAGS.search(text)
        add("WORM-006", "critical",
            "Unicode tag-block smuggling",
            "Unicode tag characters (U+E0000-U+E007F) are invisible in every "
            "renderer but decode to readable ASCII for the model. There is no "
            "legitimate use for them in a configuration file.",
            m.start(),
            "Delete the file's hidden characters and audit its provenance.")

    # WORM-007: concealment directives.
    for m in CONCEALMENT.finditer(text):
        lo, hi = max(0, m.start() - 250), min(len(text), m.end() + 250)
        if EXFIL_VERB.search(text, lo, hi) or SECRET_NOUN.search(text, lo, hi) \
                or PROPAGATION_VERB.search(text, lo, hi):
            if _is_descriptive(text, m.start()):
                continue
            add("WORM-007", "high",
                "Concealment directive",
                "Text instructs the agent to withhold information from the user "
                "while performing an action. Legitimate instructions do not need "
                "the user kept unaware.",
                m.start(),
                "Remove. Any instruction requiring secrecy from the operator is "
                "hostile by construction.")
            break

    return findings
