"""Runtime detection over agent session transcripts.

The static scanner reads files at rest. That misses the highest-yield vector
AgentWorm measured: skill supply-chain poisoning at 82% attack success. A
poisoned skill, an MCP tool response, or a fetched web page reaches the model's
context without ever being written to a config file the scanner would inspect.

This module reads session transcripts and applies the same content rules to
untrusted inbound channels — tool results, fetched pages, skill content. It is
detection after the fact, not prevention: the value is knowing an injection
attempt reached your agent, and when.

Transcript format (Claude Code, ~/.claude/projects/<slug>/<session>.jsonl):
newline-delimited JSON, one record per line. Records with type 'user' carry
tool_result blocks in message.content; type 'assistant' carries the model's
own output. We scan inbound channels only — flagging the model's own text
would report our own rule descriptions back at us.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from ..rules.injection import Finding, scan_text

TRANSCRIPT_ROOT = Path.home() / ".claude" / "projects"

# Inbound channels: content the agent did not author, which lands in context.
# tool_result covers MCP responses, file reads, web fetches, and skill output.
INBOUND_BLOCK_TYPES = {"tool_result"}

# "   142\tconst x = 1" — the shape Read/Edit tool output uses.
_LINE_NUMBERED = re.compile(r"^\s*\d+\t")


@dataclass
class Hit:
    session: str
    path: str
    timestamp: str
    channel: str
    tool: str
    finding: Finding


def _iter_records(jsonl: Path):
    try:
        with open(jsonl, "r", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield lineno, json.loads(line)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def _blocks(record):
    """Yield (channel, tool_id, text) for untrusted inbound content."""
    msg = record.get("message") or {}
    content = msg.get("content")
    if isinstance(content, str):
        return
    if not isinstance(content, list):
        return
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype not in INBOUND_BLOCK_TYPES:
            continue
        body = block.get("content")
        # tool_result content is usually a string, sometimes a block list.
        if isinstance(body, list):
            body = "\n".join(
                b.get("text", "") for b in body
                if isinstance(b, dict) and b.get("type") == "text")
        if not isinstance(body, str) or not body.strip():
            continue
        yield btype, block.get("tool_use_id", "?"), body


def _looks_like_source_code(text: str) -> bool:
    """Distinguish source code from prose instructions.

    Reading a file that handles credentials is normal engineering work: a
    payment handler referencing process.env.TREASURY_WALLET next to an RPC URL
    trips the exfiltration rule even though nothing is instructing the agent to
    do anything. Those rules were written for prose, and applying them to code
    produces noise that would get this tool uninstalled.

    We look for syntax density rather than keywords, so it holds across
    languages without maintaining a keyword list per ecosystem.
    """
    sample = text[:4000]
    lines = [ln for ln in sample.split("\n") if ln.strip()]
    if len(lines) < 3:
        return False

    code_markers = sum(sample.count(t) for t in
                       ("();", ");", "{", "}", "=>", "const ", "def ", "import ",
                        "function ", "return ", "</", "/>", "::", "&&"))
    density = code_markers / max(len(lines), 1)

    # Read/Edit tool output is line-numbered ("   123\tcontent"). That used to
    # be sufficient on its own, which made it a one-line off switch: prefixing
    # prose with fake line numbers suppressed every rule in readguard and
    # outbound at once, and attacker-controlled content (a web page, an issue
    # body, `cat -n` output) can carry that prefix trivially. Numbering is now
    # only corroborating evidence -- the body still has to look like code.
    numbered = sum(1 for ln in lines[:40] if _LINE_NUMBERED.match(ln))
    if numbered >= max(3, len(lines[:40]) // 2):
        return density > 0.4

    return density > 1.5


# Rules that describe *instructions* and therefore only make sense in prose.
# Structural rules (hidden comments, unicode smuggling) stay active in code,
# because there is no benign reason for them to appear there either.
_PROSE_ONLY_RULES = {"WORM-002", "WORM-003", "WORM-007"}


def scan_transcript(jsonl: Path, max_bytes: int = 200_000) -> list:
    """Apply content rules to untrusted inbound content in one transcript."""
    hits = []
    session = Path(jsonl).stem
    for lineno, rec in _iter_records(jsonl):
        if rec.get("type") != "user":
            continue
        ts = rec.get("timestamp", "")
        for channel, tool, text in _blocks(rec):
            # Very large tool results are usually file dumps or build logs.
            # Scan the head; a payload wants to be read, so it sits near the top.
            if len(text) > max_bytes:
                text = text[:max_bytes]
            is_code = _looks_like_source_code(text)
            for f in scan_text(text, path=f"{jsonl}:{lineno}"):
                # WORM-005 (zero-width) fires constantly on terminal output
                # and emoji sequences in logs. Too noisy for this channel.
                if f.rule_id == "WORM-005":
                    continue
                # Prose rules on source code are false positives, not findings.
                if is_code and f.rule_id in _PROSE_ONLY_RULES:
                    continue
                hits.append(Hit(session=session, path=str(jsonl),
                                timestamp=ts, channel=channel,
                                tool=str(tool), finding=f))
    return hits


def find_transcripts(project_dir: Path = None, limit: int = None) -> list:
    """Locate session transcripts, newest first."""
    root = Path(project_dir) if project_dir else TRANSCRIPT_ROOT
    if not root.is_dir():
        return []
    files = [p for p in root.rglob("*.jsonl") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:limit] if limit else files


def scan_sessions(project_dir: Path = None, limit: int = 20) -> list:
    """Scan the most recent sessions for injection attempts in tool output."""
    hits = []
    for t in find_transcripts(project_dir, limit=limit):
        hits.extend(scan_transcript(t))
    return hits


def to_findings(hits: list) -> list:
    """Convert runtime hits into Findings for uniform rendering."""
    out = []
    for h in hits:
        f = h.finding
        out.append(Finding(
            rule_id=f"RUNTIME-{f.rule_id.split('-')[-1]}",
            severity=f.severity,
            title=f"{f.title} (in tool output)",
            detail=(
                f"{f.detail}\n      Detected in untrusted tool output reaching "
                f"the agent's context, not in a file at rest. This is the "
                f"channel skill supply-chain poisoning uses — the vector "
                f"AgentWorm measured at 82% attack success.\n"
                f"      session {h.session} at {h.timestamp or 'unknown time'}"),
            path=f.path,
            line=f.line,
            excerpt=f.excerpt,
            remediation=(
                "Identify which tool or skill produced this output and review "
                "its provenance. If it is an MCP server or marketplace skill, "
                "treat it as compromised until shown otherwise. Then run "
                "`wormhole verify` to confirm no config was written."),
            references=["arXiv:2603.15727 (Vector B: 82% ASR)"],
        ))
    return out
