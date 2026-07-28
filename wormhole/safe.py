"""Plaintext-incapable findings, for any path that leaves the machine.

`Finding` (wormhole/rules/injection.py) carries an `excerpt`: roughly 110
characters of verbatim source text, attached unconditionally by `_excerpt()`
inside the `add()` closure. That is the right shape for a local report — an
operator reading `wormhole scan` output needs to see the offending line, and
the text never leaves the terminal it was printed to.

It is the wrong shape for anything that transmits. The excerpt is a slice of
whatever was scanned: a prompt, a config file, a fetched page, tool output. A
reporting path built on `Finding` exfiltrates customer content by construction,
and it does so for every rule at once, silently, with no bug required.

So the transmitting path does not use `Finding`. It uses `SafeFinding`, which
has no excerpt field at all.

Why a separate type instead of a `redact=True` flag on the existing one:

    A flag is a runtime property, and every runtime property has a path that
    misses it. A debug build that dumps the object, an exception handler that
    reprs it into a log line, a `json.dumps(asdict(f))` added by someone who
    did not know about the flag, a `copy()` that carries the field forward.
    Each of those is one commit away, and none of them fails a test.

    A missing field is a structural property. `SafeFinding` is a NamedTuple:
    its fields are fixed at class-creation time, `_fields` enumerates them
    exhaustively, and there is no `excerpt` attribute for any code path to
    read, print, serialise or copy — not in a debug build, not in a traceback,
    not in a `repr`. `to_safe()` cannot copy the excerpt across because there
    is nowhere to put it. Getting plaintext into a `SafeFinding` requires
    editing this file, which is a reviewable event.

NamedTuple rather than a frozen dataclass with `__slots__` for two reasons:
the tuple layout is genuinely immutable rather than immutable-by-convention
(no `object.__setattr__` escape), and `slots=True` on a dataclass is Python
3.10+ while this package supports 3.8.

WHAT THIS DOES NOT PROTECT AGAINST — read this before quoting it as a
guarantee:

  - A `path_hash` is a hash of a filesystem path, and paths are low-entropy.
    `/Users/alice/work/acme-secrets/CLAUDE.md` hashed is not recoverable in
    general, but an attacker holding the ciphertext and a guess ("is this
    /home/bob/.claude/CLAUDE.md?") can confirm the guess. Path hashes are
    correlation keys, not secrets. They are salted per-installation (see
    `PathHasher`) so that a guess must be mounted against one customer at a
    time rather than precomputed once against everybody.
  - `content_hash` covers the whole scanned artifact, not the matched span.
    Hashing the ~110-character span would be hash-crackable for short spans
    and would leak span length. Hashing the artifact leaks whether two
    machines hold byte-identical files, which is the point of having it.
  - `line` and `offset` are structural metadata about where in a file a rule
    fired. A determined adversary with the file already in hand learns
    nothing; an adversary without it learns that a file has >= N lines. That
    is the residual leak and it is accepted deliberately, because a finding
    with no location is not actionable.
  - Byte offsets are NOT included. Offsets plus a rule's regex narrow the
    matched text considerably, and the reporting path has no use for them
    that `line` does not already serve.

Nothing in this module imports anything outside the standard library, and
nothing in it opens a socket. It is the conversion layer only. Transmission
lives in a separate, opt-in package that is not part of this distribution.
"""

import hashlib
import hmac
import os
from typing import NamedTuple, Optional, Sequence, Tuple

# Rule classes whose findings are NEVER represented off-machine, not even as a
# hash.
#
# WORM-003 fires *on credential-shaped text*: the matched region is, by the
# rule's own definition, near a secret noun, a transmission verb and an
# external destination. The excerpt is the thing we are trying to protect.
#
# It is tempting to think a hash is safe here. It is not. A hash of a
# 20-character API key is a hash of a 20-character string drawn from a known
# alphabet in a known format — `sk-` plus 48 base62 characters, `ghp_` plus 36,
# an AWS pair with a fixed prefix. That is a brute-forceable keyspace against
# a known-plaintext-format target, which is the exact situation offline
# password cracking was built for. Publishing such a hash to an ingestion
# endpoint moves a crackable secret off the customer's machine.
#
# There is no version of "send a redacted form of the credential finding" that
# is worth the risk, because the useful signal — *this machine has a
# credential-exfiltration finding* — survives as a plain count with no
# per-finding record at all. So the conversion drops them and returns the
# count separately.
#
# Any future rule that matches on secret-shaped text must be added here. The
# test suite asserts the set is non-empty and that WORM-003 is in it; it
# cannot assert about rules that do not exist yet, so this comment is the
# handoff.
NEVER_REPORTED = frozenset({"WORM-003"})

# Severity ranking, duplicated from Finding.severity_rank on purpose. This
# module must stay importable and useful without pulling in the rules engine,
# and the mapping is five entries that have not changed.
_SEVERITY_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


class SafeFinding(NamedTuple):
    """A finding stripped to facts about an artifact.

    There is deliberately no `excerpt`, no `detail`, and no `title`.

    `detail` and `title` are omitted as well as `excerpt`, which is worth
    stating because they look harmless: they are rule-authored strings, but
    WORM-003's detail interpolates the matched destination
    (`f"...destination ({dest.group(0)[:60]})"`, injection.py:566) and any
    future rule may do the same. A receiver that wants prose for a rule ID
    looks it up from the rule catalogue, which is public, versioned, and does
    not travel with customer data.

    Fields:
      rule_id       e.g. "WORM-001". From the public rule catalogue.
      severity      critical|high|medium|low|info. Rule-assigned constant.
      content_hash  salted digest of the FULL scanned artifact, or None when
                    the scan had no artifact (a pending write, a fetched page).
      path_hash     salted digest of the artifact path, or None when unpathed.
      line          1-indexed line the rule fired on, or None.
      line_count    total lines in the artifact, or None. Present so a
                    receiver can render "line 40 of 512" without asking for
                    content; also bounds what `line` alone implies.
    """

    rule_id: str
    severity: str
    content_hash: Optional[str] = None
    path_hash: Optional[str] = None
    line: Optional[int] = None
    line_count: Optional[int] = None

    @property
    def severity_rank(self) -> int:
        return _SEVERITY_RANK.get(self.severity, 5)


# Asserted at import time rather than in a test, so that adding a plaintext
# field to SafeFinding fails on `import wormhole.safe` — in the reporting
# agent, in CI, in a REPL — rather than only under `unittest discover`. A
# test can be skipped or not run; an import cannot.
_FORBIDDEN_FIELDS = frozenset({
    "excerpt", "detail", "title", "text", "content", "snippet", "fragment",
    "match", "matched", "body", "remediation", "source", "raw",
})
_overlap = _FORBIDDEN_FIELDS.intersection(SafeFinding._fields)
if _overlap:  # pragma: no cover - structural guard, cannot be reached in a
    #                              build that imports successfully
    raise AssertionError(
        "SafeFinding gained a field that can carry plaintext: "
        + ", ".join(sorted(_overlap))
        + ". The reporting path depends on this type being structurally "
        "incapable of carrying content. Do not add the field; add a "
        "hash of it instead."
    )


class PathHasher:
    """Salted hashing for paths and content.

    The salt is per-installation and never transmitted. Without it, a path
    hash is a global rainbow-table lookup: there are not many plausible values
    of `~/.claude/CLAUDE.md` across all Unix systems, and an ingestion
    database of unsalted path hashes would be trivially reversible into a list
    of usernames and project names.

    With a per-installation salt, hashes still correlate *within* one
    installation — which is the whole purpose, since "this file changed" and
    "these two agents read the same file" are the questions being asked — but
    do not correlate across customers and cannot be attacked with a
    precomputed table.

    HMAC rather than salt-prepend-then-sha256 because HMAC is the construction
    designed for keyed digests and costs nothing extra here.

    The salt is generated once and kept by the caller. This class does not
    read or write the filesystem; where the salt is stored is the reporting
    agent's decision, and it is deliberately not this package's business.
    """

    __slots__ = ("_salt",)

    def __init__(self, salt: bytes):
        if not isinstance(salt, (bytes, bytearray)):
            raise TypeError("salt must be bytes")
        if len(salt) < 16:
            # 16 bytes is the floor at which guessing the salt is harder than
            # guessing the path, which is the only thing the salt has to beat.
            raise ValueError("salt must be at least 16 bytes")
        self._salt = bytes(salt)

    @staticmethod
    def new_salt(n: int = 32) -> bytes:
        return os.urandom(n)

    def hash_text(self, text: str) -> str:
        return hmac.new(self._salt, text.encode("utf-8", "surrogatepass"),
                        hashlib.sha256).hexdigest()

    def hash_bytes(self, data: bytes) -> str:
        return hmac.new(self._salt, data, hashlib.sha256).hexdigest()


def to_safe(
    findings: Sequence,
    hasher: PathHasher,
    *,
    text: Optional[str] = None,
) -> Tuple[Tuple[SafeFinding, ...], int]:
    """Convert `Finding`s into `SafeFinding`s.

    Returns `(safe_findings, withheld_count)`.

    `withheld_count` is the number of findings dropped because their rule is
    in NEVER_REPORTED. It is a count and nothing else — no rule ID breakdown,
    no line numbers — because NEVER_REPORTED currently has one member, so a
    breakdown would be the same information as the count with extra steps, and
    a per-finding record is what we are refusing to produce.

    `text` is the artifact that was scanned. When supplied, `content_hash` and
    `line_count` are derived from it. When omitted, both are None: a finding
    from a pending write or a fetched page has no artifact identity worth
    reporting, and inventing one from the excerpt is exactly the mistake this
    module exists to prevent.

    This function reads only `rule_id`, `severity`, `path` and `line` off each
    input. It never touches `.excerpt`, `.detail` or `.title`. That is checked
    by a test that passes in an object which raises on attribute access to
    those names.
    """
    if not isinstance(hasher, PathHasher):
        raise TypeError("hasher must be a PathHasher")

    content_hash = hasher.hash_text(text) if text is not None else None
    # `count("\n") + 1` matches `_line_of` in the rules engine, so a reported
    # line is always <= line_count for the same text.
    line_count = (text.count("\n") + 1) if text is not None else None

    safe = []
    withheld = 0
    for f in findings:
        rule_id = getattr(f, "rule_id", None)
        if rule_id is None:
            continue
        if rule_id.upper() in NEVER_REPORTED:
            withheld += 1
            continue
        path = getattr(f, "path", None)
        safe.append(SafeFinding(
            rule_id=rule_id,
            severity=getattr(f, "severity", "info"),
            content_hash=content_hash,
            path_hash=hasher.hash_text(str(path)) if path is not None else None,
            line=getattr(f, "line", None),
            line_count=line_count,
        ))
    return tuple(safe), withheld


def safe_dict(sf: SafeFinding) -> dict:
    """Serialise a SafeFinding for the wire.

    Built from `_fields` rather than a hand-written literal so that a field
    added to the type cannot be silently omitted here, and — more to the point
    — so that this function has no field list of its own to drift out of sync
    with the import-time forbidden-field assertion above.
    """
    return {name: getattr(sf, name) for name in SafeFinding._fields}
