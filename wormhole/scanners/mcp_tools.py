"""Integrity for MCP tool definitions.

Every other file this tool watches sits on disk, so hashing it is enough. MCP
tool definitions do not. The agent asks a server for `tools/list` at connect
time and the server answers over the wire; the name, description and input
schema it returns are injected verbatim into the model's context, where they
read as instructions. Nothing in the protocol signs that response, and nothing
requires the client to re-validate it. A server can therefore answer one way on
the day you review it and another way a week later, and no file changed.

That is a rug-pull, and it is the gap this module closes. It is also the
mechanism behind tool poisoning (Invariant Labs, 2025), where instructions were
hidden in a description field, invisible in the client UI and fully visible to
the model.

The approach is deliberately the same one that already works elsewhere here:
hash what you saw, store it outside the tree, and report when it changes.
Hashing does not care how a description is phrased, so it survives the
rewording that defeats rules.

Two things this does NOT do, stated because overclaiming is worse than a gap:

  - It does not connect to remote servers. Speaking MCP to an arbitrary
    endpoint means executing whatever handshake that endpoint wants, from a
    security tool, on a machine that may already be compromised. Definitions
    are read from the local files the client itself uses, and from a cache the
    operator can populate deliberately.
  - It cannot see a description that only ever existed in a server's runtime
    response and was never recorded. The first `record` is trust-on-first-use.
"""

import hashlib
import json
from pathlib import Path

from ..baseline import BASELINE_DIR, _now, _write_atomic
from ..rules.injection import Finding, scan_text

# Where a client keeps its MCP server definitions. Tool definitions themselves
# live on the server, so these are read for the server list and for any tools
# declared inline.
MCP_CONFIGS = (
    ".claude.json",
    ".claude/settings.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
)

TOOLS_FILE = BASELINE_DIR / "mcp-tools.json"


def _canonical(tool: dict) -> str:
    """A stable string for one tool definition.

    Name, description and schema are the three fields the model actually
    reads. Ordering is normalised so a server reformatting its JSON does not
    read as a change, while any edit to the text does.
    """
    return json.dumps(
        {
            "name": tool.get("name", ""),
            "description": tool.get("description", "") or "",
            "inputSchema": tool.get("inputSchema") or tool.get("input_schema") or {},
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def fingerprint(tool: dict) -> str:
    return hashlib.sha256(_canonical(tool).encode("utf-8")).hexdigest()


def tools_from_config(path: Path) -> list:
    """Extract any tool definitions declared inline in a client config.

    Most servers declare tools at runtime, not in the client config, so this
    finds the subset that is statically visible. It is the honest half of the
    picture and needs no network access.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    out = []

    def walk(servers, scope):
        if not isinstance(servers, dict):
            return
        for server, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            for tool in cfg.get("tools") or []:
                if isinstance(tool, dict) and tool.get("name"):
                    out.append((f"{scope}{server}", tool))

    walk(data.get("mcpServers"), "")
    for proj, pdata in (data.get("projects") or {}).items():
        if isinstance(pdata, dict):
            walk(pdata.get("mcpServers"), f"{Path(proj).name}/")

    return out


def find_mcp_configs(root: Path) -> list:
    root = Path(root)
    found = [root / rel for rel in MCP_CONFIGS if (root / rel).is_file()]
    home = Path.home()
    found.extend(home / rel for rel in MCP_CONFIGS if (home / rel).is_file())
    return sorted(set(found))


def collect(root: Path) -> list:
    """Every statically visible tool definition, as (server, tool) pairs."""
    pairs = []
    for cfg in find_mcp_configs(root):
        pairs.extend(tools_from_config(cfg))
    return pairs


def load_tools() -> dict:
    if not TOOLS_FILE.exists():
        return {}
    try:
        return json.loads(TOOLS_FILE.read_text()).get("tools", {})
    except (OSError, json.JSONDecodeError):
        return {}


def save_tools(entries: dict) -> None:
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    _write_atomic(TOOLS_FILE, json.dumps({"tools": entries}, indent=2))


def record(root: Path) -> dict:
    """Fingerprint the tool definitions currently visible. Trust on first use."""
    entries = load_tools()
    for server, tool in collect(root):
        key = f"{server}::{tool.get('name')}"
        entries[key] = {
            "sha256": fingerprint(tool),
            "description": (tool.get("description") or "")[:400],
            "recorded": _now(),
        }
    save_tools(entries)
    return entries


def verify(root: Path) -> list:
    """Compare visible tool definitions against what was recorded."""
    stored = load_tools()
    findings = []
    seen = set()

    for server, tool in collect(root):
        name = tool.get("name")
        key = f"{server}::{name}"
        seen.add(key)
        current = fingerprint(tool)
        entry = stored.get(key)

        # A description is an instruction the model will read. Run the same
        # content rules over it that run over an agent config file.
        for f in scan_text(tool.get("description") or "", path=f"mcp:{key}"):
            f.rule_id = f"MCP-{f.rule_id}"
            f.title = f"Tool description: {f.title}"
            findings.append(f)

        if entry is None:
            findings.append(Finding(
                rule_id="MCP-002", severity="medium",
                title=f"MCP tool not in baseline: {name}",
                detail=(
                    f"`{key}` was not recorded when the baseline was taken. A "
                    "tool definition is injected into the model's context and "
                    "read as instruction, so a new one is new instruction."),
                path=f"mcp:{key}",
                remediation=("Read the description, then run "
                             "`wormhole baseline --mcp` to adopt it.")))
            continue

        if entry.get("sha256") != current:
            findings.append(Finding(
                rule_id="MCP-001", severity="high",
                title=f"MCP tool definition changed: {name}",
                detail=(
                    f"`{key}` no longer matches what was recorded "
                    f"({entry.get('recorded')}). Nothing in the MCP protocol "
                    "signs a tool definition or requires a client to "
                    "re-validate one, so a server can present a benign "
                    "description at review time and a different one later. The "
                    "model reads the new text as instruction."),
                path=f"mcp:{key}",
                remediation=(
                    "Compare the description against what you approved. If you "
                    "did not expect this change, disconnect the server before "
                    "the next session and treat anything it could reach as "
                    "exposed."),
                references=["MCP tool poisoning (Invariant Labs, 2025)"]))

    for key, entry in stored.items():
        if key not in seen:
            findings.append(Finding(
                rule_id="MCP-003", severity="low",
                title=f"Recorded MCP tool no longer present: {key.split('::')[-1]}",
                detail=("A tool that was under integrity monitoring is no "
                        "longer declared. This is normal if you removed the "
                        "server."),
                path=f"mcp:{key}",
                remediation="Re-run `wormhole baseline --mcp` if intended."))

    return findings
