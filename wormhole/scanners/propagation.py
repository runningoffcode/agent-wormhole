"""Propagation between agents, and poisoning of retrieved documents.

These are the two vectors this project can see least well, and the honest thing
is to say why before saying what is covered.

MULTI-AGENT PROPAGATION. When a parent agent spawns a child, it composes a task
description in memory and hands it over. There is no file, no config, and in
most frameworks no interception point -- the child receives a fresh context
assembled from a parent-authored string and never sees where it came from. No
hop in the tree is positioned to notice, which is exactly what makes it a good
carrier. What *is* observable, after the fact, is the transcript: the parent's
own tool call recorded the task description it sent. So this covers detection,
not prevention, and only for frameworks that write a transcript.

RETRIEVAL POISONING. A poisoned document retrieved into context is a worm with
no file to scan -- the payload lives in a vector store keyed by embedding, and
there is no standard format to read. Scanning every store is not achievable.
Scanning documents *before* they are embedded is, and it is the only point in
the pipeline where the text is still text. That is the covered case: point this
at a corpus directory before it is ingested.

Neither of these is complete. They are the parts that can be done without
inventing a standard or installing a daemon, and the gaps are stated in the
findings themselves so an operator is not misled about coverage.
"""

import json
import re
from pathlib import Path

from ..rules.injection import Finding, scan_text
from .runtime import TRANSCRIPT_ROOT, _looks_like_source_code

# Tool calls that hand work to another agent. The task description travels in
# the parameters, so that is where a propagating payload would sit.
SPAWN_TOOLS = {"Task", "Agent", "SendMessage", "Workflow", "dispatch_agent"}

# Fields that carry the child's instructions.
TASK_FIELDS = ("prompt", "description", "task", "instructions", "message",
               "input", "content")

# Documents that get embedded. Anything a retriever would index as prose.
CORPUS_SUFFIXES = (".md", ".markdown", ".txt", ".rst", ".mdx", ".html")


def _iter_transcript(path: Path, limit: int = 4000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= limit:
                    return
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    except OSError:
        return


def _task_text(tool_input) -> str:
    if isinstance(tool_input, str):
        return tool_input
    if not isinstance(tool_input, dict):
        return ""
    parts = []
    for f in TASK_FIELDS:
        v = tool_input.get(f)
        if isinstance(v, str):
            parts.append(v)
    return "\n".join(parts)


def scan_handoffs(root: Path = None, limit: int = 30) -> list:
    """Findings for task descriptions a parent sent to a child agent.

    Detection after the fact. The value is knowing a payload travelled between
    agents at all -- a single infected config is ambiguous, the same payload
    appearing in successive handoffs is not.
    """
    root = Path(root) if root else TRANSCRIPT_ROOT
    if not root.is_dir():
        return []

    files = sorted(
        (p for p in root.rglob("*.jsonl") if p.is_file()),
        key=lambda p: p.stat().st_mtime, reverse=True)[:limit]

    findings = []
    seen = set()

    for f in files:
        for rec in _iter_transcript(f):
            msg = rec.get("message") or {}
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "tool_use":
                    continue
                if block.get("name") not in SPAWN_TOOLS:
                    continue

                text = _task_text(block.get("input"))
                if not text.strip() or _looks_like_source_code(text):
                    continue

                for hit in scan_text(text, path=f"handoff:{f.stem[:12]}"):
                    key = (hit.rule_id, text[:120])
                    if key in seen:
                        continue
                    seen.add(key)
                    hit.rule_id = f"PROPAGATE-{hit.rule_id}"
                    hit.title = f"Agent handoff: {hit.title}"
                    hit.detail = (
                        f"{hit.detail} This text was sent from one agent to "
                        f"another as a task description. A child agent receives "
                        f"a fresh context assembled by its parent and never sees "
                        f"the originating file, so no hop in the tree is "
                        f"positioned to notice a payload riding along.")
                    hit.remediation = (
                        "Find what put this in the parent's context: check the "
                        "agent configs and any skill the parent loaded. The "
                        "handoff is the symptom, not the source.")
                    findings.append(hit)

    return findings


def scan_corpus(root: Path) -> list:
    """Findings for documents before they are embedded into a vector store.

    Once a document is embedded there is no standard artifact left to scan, so
    this is the last point at which the text is still text. Intended to run in
    an ingestion pipeline, not against a live store.
    """
    root = Path(root)
    if not root.is_dir():
        return []

    findings = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in CORPUS_SUFFIXES:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _looks_like_source_code(text):
            continue

        for hit in scan_text(text, path=str(p)):
            hit.rule_id = f"CORPUS-{hit.rule_id}"
            hit.title = f"Retrievable document: {hit.title}"
            hit.detail = (
                f"{hit.detail} This document is in a corpus destined for "
                f"retrieval. Once embedded it has no file for a scanner to "
                f"read, and it will be pulled into the context of every agent "
                f"whose query matches it.")
            hit.remediation = (
                "Remove the text before ingestion. If this corpus is already "
                "embedded, re-index it after cleaning -- deleting the source "
                "file does not remove the vector.")
            findings.append(hit)

    return findings
