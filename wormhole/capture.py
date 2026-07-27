"""The Wormhole: isolate payloads instead of deleting them.

Deletion is the wrong default for three reasons. It destroys the evidence
needed to answer the only questions that matter after an infection -- what
wrote this, when, and did it spread. It is irreversible, so a false positive
becomes data loss and people stop running the tool. And it throws away the
sample, when a labelled corpus of real payloads is the most useful thing this
project can accumulate.

So: excise the payload, keep the file working, and store the original plus a
full provenance record under ~/.wormhole/captured/.

Every captured item can be restored. The Wormhole is chmod 700 and payload files are
stored with a .quarantined suffix and no execute bit, so nothing in it is
loaded by an agent or run by accident.
"""

import hashlib
import json
import shutil
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from .baseline import sha256, _write_atomic
from .rules.injection import scan_text

WORMHOLE_DIR = Path.home() / ".wormhole" / "captured"
WORMHOLE_INDEX = WORMHOLE_DIR / "index.json"


@dataclass
class WormholeEntry:
    id: str
    source_path: str
    captured_at: str
    rule_ids: list
    severity: str
    line: int
    excerpt: str
    original_sha256: str
    cleaned_sha256: str
    payload_file: str
    restored: bool = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_index() -> list:
    if not WORMHOLE_INDEX.exists():
        return []
    try:
        return json.loads(WORMHOLE_INDEX.read_text()).get("entries", [])
    except (OSError, json.JSONDecodeError):
        return []


def _save_index(entries: list):
    WORMHOLE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    WORMHOLE_DIR.chmod(0o700)
    _write_atomic(WORMHOLE_INDEX, json.dumps(
        {"version": 1, "updated": _now(), "entries": entries}, indent=2))


def _entry_id(path: Path, digest: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{stamp}-{digest[:8]}-{path.name}"


def excise_until_clean(text: str, max_passes: int = 5) -> tuple:
    """Excise repeatedly until a rescan finds nothing, or we give up.

    A single pass is not enough. Rules report one finding per file by design
    (one is enough to condemn it), and a payload can occupy several separate
    blocks -- AgentWorm's dual-anchor design uses exactly two. Excising only
    what the first scan pointed at leaves the second anchor live while making
    the file look treated, which is worse than not treating it at all.

    So: excise, rescan, repeat. Returns (cleaned, removed, clean) where `clean`
    is False if payloads remain after max_passes, in which case the caller must
    not claim the file was cleaned.
    """
    cleaned = text
    removed = []
    for _ in range(max_passes):
        findings = [f for f in scan_text(cleaned)
                    if f.rule_id.startswith("WORM")]
        if not findings:
            return cleaned, removed, True
        nxt, chunks = excise(cleaned, findings)
        if nxt == cleaned:
            # Excision made no progress; stop rather than spin.
            return cleaned, removed, False
        cleaned = nxt
        removed.extend(chunks)
    residual = [f for f in scan_text(cleaned) if f.rule_id.startswith("WORM")]
    return cleaned, removed, not residual


def excise(text: str, findings: list) -> tuple:
    """Remove flagged regions from text.

    Returns (cleaned_text, removed_snippets). We remove whole lines that a
    finding points at, plus any HTML comment a finding sits inside, because a
    payload split across a comment must come out as a unit -- excising one line
    of it would leave a syntactically broken comment and a partial payload.
    """
    lines = text.split("\n")
    doomed = set()
    removed = []

    for f in findings:
        if not f.line:
            continue
        idx = f.line - 1
        if not (0 <= idx < len(lines)):
            continue

        start = end = idx
        before = "\n".join(lines[:idx + 1])

        # An HTML comment is a self-delimiting unit: take exactly the comment
        # and nothing around it. The delimiters bound the payload precisely,
        # so widening to the paragraph would delete adjacent legitimate text.
        #
        # A line can sit inside a comment while containing neither delimiter,
        # and the closing line carries only "-->". Check both directions:
        # an unclosed "<!--" above, or an unopened "-->" at or below.
        after = "\n".join(lines[idx:])
        opens_above = before.rfind("<!--") > before.rfind("-->")
        closes_below = (after.find("-->") != -1 and
                        (after.find("<!--") == -1 or
                         after.find("-->") < after.find("<!--")))
        if opens_above or closes_below:
            while start > 0 and "<!--" not in lines[start]:
                start -= 1
            while end < len(lines) - 1 and "-->" not in lines[end]:
                end += 1
        else:
            # Prose: take the whole paragraph. A payload is a sentence or
            # several, and sentences wrap across lines -- removing only the
            # matched line truncates the text mid-clause and can leave the
            # rest of the payload live. Paragraph boundaries are blank lines
            # and markdown headings, which is where an instruction block ends.
            while start > 0:
                prev = lines[start - 1].strip()
                if not prev or prev.startswith("#"):
                    break
                start -= 1
            while end < len(lines) - 1:
                nxt = lines[end + 1].strip()
                if not nxt or nxt.startswith("#"):
                    break
                end += 1

        for i in range(start, end + 1):
            doomed.add(i)

    if not doomed:
        return text, removed

    kept = []
    run = []
    for i, ln in enumerate(lines):
        if i in doomed:
            run.append(ln)
        else:
            if run:
                removed.append("\n".join(run))
                run = []
            kept.append(ln)
    if run:
        removed.append("\n".join(run))

    cleaned = "\n".join(kept)
    # Collapse the blank-line gap the excision leaves behind.
    while "\n\n\n" in cleaned:
        cleaned = cleaned.replace("\n\n\n", "\n\n")
    return cleaned, removed


def swallow(path: Path, findings: list, dry_run: bool = False) -> dict:
    """Excise payloads from one file, preserving the original in the jail."""
    path = Path(path)
    original = path.read_text(encoding="utf-8", errors="replace")
    worm_findings = [f for f in findings if f.rule_id.startswith("WORM")]
    if not worm_findings:
        return {"status": "no_payload", "path": str(path)}

    cleaned, removed, fully_clean = excise_until_clean(original)
    if cleaned == original:
        return {"status": "nothing_excised", "path": str(path)}

    result = {
        "status": "would_swallow" if dry_run else "swallowed",
        "path": str(path),
        "rules": sorted({f.rule_id for f in worm_findings}),
        "lines_removed": original.count("\n") - cleaned.count("\n"),
        "snippets": removed,
        "fully_clean": fully_clean,
    }
    if dry_run:
        return result

    WORMHOLE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    WORMHOLE_DIR.chmod(0o700)

    orig_digest = sha256(path)
    entry_id = _entry_id(path, orig_digest)
    payload_file = WORMHOLE_DIR / f"{entry_id}.quarantined"

    # Preserve the complete original, not just the excised fragment: the
    # surrounding context is what tells you how the payload was delivered.
    # Preserved copy first, atomically, and verified readable before the
    # source is touched: a truncated quarantine file plus an excised original
    # loses the payload permanently, and the payload is the evidence.
    _write_atomic(payload_file, original, mode=0o400)

    # The source rewrite is the one write in the codebase that destroys
    # operator data if it is interrupted. os.replace makes it all-or-nothing.
    _write_atomic(path, cleaned, mode=path.stat().st_mode & 0o777)

    entry = WormholeEntry(
        id=entry_id,
        source_path=str(path.resolve()),
        captured_at=_now(),
        rule_ids=sorted({f.rule_id for f in worm_findings}),
        severity=min((f.severity for f in worm_findings),
                     key=lambda s: ["critical", "high", "medium", "low",
                                    "info"].index(s)),
        line=worm_findings[0].line or 0,
        excerpt=(worm_findings[0].excerpt or "")[:300],
        original_sha256=orig_digest,
        cleaned_sha256=hashlib.sha256(cleaned.encode()).hexdigest(),
        payload_file=str(payload_file),
    )
    entries = _load_index()
    entries.append(asdict(entry))
    _save_index(entries)

    result["wormhole_id"] = entry_id
    result["payload_file"] = str(payload_file)
    return result


def list_entries(include_restored: bool = False) -> list:
    return [e for e in _load_index()
            if include_restored or not e.get("restored")]


def restore(entry_id: str) -> dict:
    """Pull a captured file back out exactly as it was. For false positives."""
    entries = _load_index()
    for e in entries:
        if e["id"] != entry_id:
            continue
        if e.get("restored"):
            return {"status": "already_restored", "id": entry_id}
        payload = Path(e["payload_file"])
        if not payload.is_file():
            return {"status": "payload_missing", "id": entry_id}
        target = Path(e["source_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(payload, target)
        e["restored"] = True
        e["restored_at"] = _now()
        _save_index(entries)
        return {"status": "restored", "id": entry_id, "path": str(target)}
    return {"status": "not_found", "id": entry_id}


def export_corpus(dest: Path) -> dict:
    """Export captured payloads as corpus fixtures for rule development.

    Exported samples are what make the next version of the rules better. They
    are written inert -- filenames carry a .sample suffix so nothing loads them
    as agent config -- and the index records provenance for each.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    entries = _load_index()
    exported = []
    for e in entries:
        src = Path(e["payload_file"])
        if not src.is_file():
            continue
        out = dest / f"{e['id']}.sample"
        shutil.copyfile(src, out)
        out.chmod(0o400)
        exported.append({"id": e["id"], "rules": e["rule_ids"],
                         "file": str(out), "captured_at": e["captured_at"]})
    _write_atomic(dest / "manifest.json", json.dumps(
        {"exported": _now(), "samples": exported}, indent=2), mode=0o644)
    return {"count": len(exported), "dest": str(dest)}
