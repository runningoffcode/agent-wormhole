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
#
# Deliberately not a regex. `<!--(.*?)-->` under DOTALL is quadratic on input
# with no closing delimiter (256KB of bare "<!--" took 76s). Bounding the
# quantifier to `<!--([^>]{0,8000}?)-->` removed the quadratic term but left a
# punishing constant: measured 4.8 us/byte at 4KB rising to 19.1 us/byte at
# 256KB -- 5.0 seconds at the scan cap, still superlinear, because every one of
# the 65,536 `<!--` starts re-walks up to 8000 characters before failing.
#
# guard, readguard and outbound run on the tool-call path, so an attacker
# serving a large fetched page stalls the agent for seconds. MAX_SCAN_BYTES
# caps the blast radius; it does not remove it, and a hook that costs five
# seconds once is a hook the operator uninstalls.
#
# str.find is a memchr-backed C loop: each scan starts where the previous one
# ended, so the whole document is walked at most twice. Same matches, ~1000x
# faster in the adversarial case.
_COMMENT_OPEN = "<!--"
_COMMENT_CLOSE = "-->"
_COMMENT_MAX_BODY = 8000


class _CommentMatch:
    """Minimal re.Match stand-in: the call sites need start() and group(1)."""

    __slots__ = ("_start", "_body")

    def __init__(self, start: int, body: str):
        self._start = start
        self._body = body

    def start(self) -> int:
        return self._start

    def group(self, n: int = 0) -> str:
        if n == 1:
            return self._body
        return _COMMENT_OPEN + self._body + _COMMENT_CLOSE


def iter_html_comments(text: str):
    """Yield each `<!-- ... -->` comment, linear in len(text).

    Bodies longer than _COMMENT_MAX_BODY are skipped rather than searched
    further, matching the bound the previous regex enforced.
    """
    pos = 0
    n = len(text)
    while pos < n:
        open_at = text.find(_COMMENT_OPEN, pos)
        if open_at < 0:
            return
        body_at = open_at + len(_COMMENT_OPEN)
        close_at = text.find(_COMMENT_CLOSE, body_at)
        if close_at < 0:
            return
        if close_at - body_at <= _COMMENT_MAX_BODY:
            yield _CommentMatch(open_at, text[body_at:close_at])
            pos = close_at + len(_COMMENT_CLOSE)
        else:
            # Over-long body: skip past this opener and keep scanning. Never
            # re-examine the region already walked.
            pos = body_at
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
#
# Split into two tiers, because vocabulary alone is not evidence. A single
# noun near the match is trivially plantable: appending "attackers hate this"
# to a live worm silenced WORM-001 outright while the instruction stayed
# operative. Words in ATTRIBUTED_FRAME carry grammatical attribution or
# hedging that a payload cannot adopt without ceasing to be an instruction;
# words in TOPIC_VOCAB merely indicate the subject matter and are therefore
# only corroborating, never sufficient on their own.
# Attribution proper: a third-party subject paired with a verb of intent or
# capability, or first-person framing about detection. The pairing is what
# matters -- the bare noun "attackers" is one word an attacker appends, while
# "attackers may try to" is a clause a payload cannot carry and still read as
# an instruction to the model.
_THIRD_PARTY = r"(?:attackers?|adversar(?:y|ies)|threat actors?|a worm|worms|malware)"
_INTENT_VERB = (r"(?:may|might|could|would|will|can|often|typically|sometimes|"
                r"try|tries|tried|attempts?|attempted|use[sd]?|abuse[sd]?|"
                r"plant(?:s|ed)?|inject(?:s|ed)?|do(?:es)? this|did this)")
ATTRIBUTED_FRAME = re.compile(
    rf"\b({_THIRD_PARTY}\s+(?:\w+\s+){{0,3}}?{_INTENT_VERB}|"
    r"we (?:detect|flag|scan for|look for)|this rule (?:detects|flags|matches)|"
    r"detects? (?:when|text|files?|the)|detection (?:rule|logic|pattern)|"
    r"(?:is|are) (?:designed to|known as|referred to as)|"
    r"false positive|test (?:case|fixture))\b",
    re.IGNORECASE,
)

TOPIC_VOCAB = re.compile(
    r"\b(malicious|worm|payload|injection|exploit|vulnerabilit(?:y|ies)|CVE|"
    r"proof[- ]of[- ]concept|research(?:ers)?|example|e\.g\.|for instance|"
    r"such as|attackers?|adversar(?:y|ies)|threat actors?)\b",
    re.IGNORECASE,
)

# Structure that only documentation has: a fenced block, an inline-code span,
# a blockquote, a numbered reference, or a docs path. An operative payload
# planted in a config file to be obeyed does not wrap itself in these.
DOC_STRUCTURE = re.compile(
    r"(```|~~~|^\s{4,}\S|^\s*>|`[^`\n]{3,}`|\b(?:docs?|documentation|"
    r"threat[- ]model|README|CONTRIBUTING|polic(?:y|ies)|guidelines?)\b|"
    r"\barXiv:|\bRFC\s?\d)",
    re.IGNORECASE | re.MULTILINE,
)

# Prohibitive guidance — a policy telling the reader NOT to do the dangerous
# thing. The inverse of a payload, which always instructs the reader to do it.
# Short policy files carry no fenced blocks or docs paths, so this stands in
# as the corroborating signal for them.
PROHIBITIVE_FRAME = re.compile(
    r"\b(?:do not|don't|never|avoid|refuse to|must not|should not|"
    r"rather than acting on|without acting on)\s+"
    r"(?:\w+\s+){0,2}?"
    r"(?:commit|send|include|share|expose|reveal|paste|forward|transmit|"
    r"upload|post|email|leak|act|obey|follow|comply|execute|run)\b",
    re.IGNORECASE,
)

# Imperative second-person address, which is how a payload speaks to the model
# it is trying to recruit. Its presence overrides descriptive framing: prose
# that tells *you* to do the thing is not describing someone else doing it.
IMPERATIVE_ADDRESS = re.compile(
    r"\b(you must|you should|you need to|your task|from now on|going forward|"
    r"always (?:copy|append|include|add|forward|write)|"
    r"never (?:mention|reveal|tell|disclose|log)|do not (?:mention|reveal|"
    r"tell|disclose|inform)|be sure to|make sure (?:to|you)|"
    # A bare imperative aimed at the reader: a copy/propagation verb at the
    # start of a sentence with no subject. "Copy this into every CLAUDE.md"
    # is an order; "attackers copy this into every CLAUDE.md" is a report.
    r"(?:^|(?<=[.!?]\s)|(?<=[.!?]\n)|^\s*[-*]\s*)"
    r"(?:copy|append|add|include|forward|paste|insert|write|propagate|"
    r"replicate|reproduce)\s+(?:this|these|the following|it)\b|"
    # A bare override imperative with no third-party subject in front of it.
    # "Ignore all previous instructions" addresses the model; a report says
    # "attackers try to make an agent ignore all previous instructions", where
    # the verb sits inside a clause governed by its subject.
    #
    # The preceding boundary must be a real sentence end, the very start of
    # the text, or a list/heading marker -- deliberately NOT a bare newline.
    # Prose wraps mid-sentence, and treating a line break as a boundary made
    # the threat-model fixture read as imperative on its second line.
    r"(?:\A|(?<=[.!?][ \t\n])|(?<=[.!?])|(?:^|\n)[ \t]*[-*>#]+[ \t]*)"
    r"(?:ignore|disregard|forget|override|discard|bypass)\s+"
    r"(?:all|any|the|your|previous|prior|earlier|above|preceding|system)\b)",
    re.IGNORECASE | re.MULTILINE,
)


def _is_descriptive(text: str, pos: int, window: int = 320) -> bool:
    """True when the surrounding prose reads as describing an attack.

    Suppression requires one of three things, never a bare keyword:

    - grammatical attribution to a third party ("attackers may try to..."),
    - prohibitive guidance ("never send credentials to an external service"),
      which is a policy forbidding the act rather than commanding it,
    - topic vocabulary corroborated by documentation structure: a fenced
      block, a blockquote, a docs path, an arXiv or RFC reference.

    Topic vocabulary alone is not enough. It is one word an attacker appends
    to an otherwise operative instruction, which turned every rule consulting
    this helper into an opt-out: appending "attackers hate this" to a live
    worm silenced WORM-001 while the instruction stayed fully operative.

    Direct imperative address to the reader overrides suppression entirely.
    A sentence commanding *you* to copy something is not a sentence
    describing somebody else copying it, however much security vocabulary
    surrounds it.
    """
    lo = max(0, pos - window)
    hi = min(len(text), pos + window)
    frame = text[lo:hi]

    if IMPERATIVE_ADDRESS.search(frame):
        return False
    if ATTRIBUTED_FRAME.search(frame):
        return True
    if PROHIBITIVE_FRAME.search(frame):
        return True
    return bool(TOPIC_VOCAB.search(frame) and DOC_STRUCTURE.search(frame))


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


# Inline suppression: `wormhole:ignore RULE-ID[,RULE-ID...]` on the same line
# as a finding, or on the line immediately above it.
#
# Nobody enables --fail-on in CI without an escape hatch for the one false
# positive they hit, and the alternative to a narrow one is `|| true` on the
# whole step, which disables every rule silently and forever. Requiring
# explicit rule IDs keeps the exemption auditable and grep-able in review:
# a bare "ignore everything" directive is deliberately not supported.
#
# The tradeoff is real and worth naming: an attacker who can already write to
# an instruction file can also write a suppression comment. That is not a new
# capability -- the same write deletes the payload's own tell -- and the
# directive is far more conspicuous in a diff than a rephrased payload. It is
# reported by `wormhole insights` for exactly that reason.
SUPPRESSION = re.compile(
    r"wormhole:\s*ignore\s+([A-Z][A-Z0-9]*-\d{3}(?:\s*,\s*[A-Z][A-Z0-9]*-\d{3})*)",
    re.IGNORECASE,
)


def _suppressed_rules(text: str, line_no: int) -> set:
    """Rule IDs suppressed for a 1-indexed line: same line, or the one above."""
    if not line_no:
        return set()
    lines = text.splitlines()
    out = set()
    for idx in (line_no - 1, line_no - 2):  # same line, then the line above
        if 0 <= idx < len(lines):
            for m in SUPPRESSION.finditer(lines[idx]):
                out.update(r.strip().upper() for r in m.group(1).split(","))
    return out


def scan_text(text: str, path: str = None) -> list:
    """Run all content rules over a blob of text."""
    findings = []
    if text and len(text) > MAX_SCAN_BYTES:
        text = text[:MAX_SCAN_BYTES]

    def add(rule_id, severity, title, detail, pos, remediation, refs=None):
        line_no = _line_of(text, pos)
        if rule_id.upper() in _suppressed_rules(text, line_no):
            return
        findings.append(Finding(
            rule_id=rule_id, severity=severity, title=title, detail=detail,
            path=path, line=line_no, excerpt=_excerpt(text, pos),
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
    for m in iter_html_comments(text):
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
