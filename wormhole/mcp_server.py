"""MCP server — lets an agent audit its own posture.

Deliberately read-only. Every tool here reports; none of them writes, deletes,
or reconfigures anything. That constraint is a security property, not a
limitation of the implementation: this server is reachable by the agent, and
anything reachable by the agent is reachable by a payload that has compromised
it. A worm that can ask the security tool to rewrite a config, disable a rule,
or re-baseline a tampered file would use the defense as its own tooling.

Remediation stays in the CLI, where a human runs it.

Speaks MCP over stdio using JSON-RPC 2.0 with no third-party dependencies, so
it can be run from a checkout without installing anything.
"""

import json
import sys
from pathlib import Path

from .baseline import verify as verify_baseline
from . import scoring
from .cli import gather
from .scanners.runtime import scan_sessions, to_findings

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "wormhole", "version": "0.1.0"}

TOOLS = [
    {
        "name": "scan_agent_configs",
        "description": (
            "Scan a directory's agent configuration files (AGENTS.md, "
            "CLAUDE.md, .cursorrules) for self-replicating prompt payloads and "
            "permission overreach. Read-only."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Directory to scan. Defaults to cwd."},
                "include_global": {
                    "type": "boolean",
                    "description": "Also check global settings, MCP servers, "
                                   "and installed skills. Default true."},
            },
        },
    },
    {
        "name": "check_integrity",
        "description": (
            "Compare agent config files against their recorded baseline "
            "hashes to detect modification. Reports drift; does not "
            "re-baseline. Read-only."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Directory to verify. Defaults to cwd."},
            },
        },
    },
    {
        "name": "blast_radius",
        "description": (
            "Score what an infection of this agent could reach, across the "
            "execute/persist/propagate links of the worm infection loop. "
            "Returns a 0-10 score per link and whether the loop is closed."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Directory to assess. Defaults to cwd."},
            },
        },
    },
    {
        "name": "scan_session_history",
        "description": (
            "Scan recent agent session transcripts for prompt-injection "
            "attempts arriving through tool output — the skill supply-chain "
            "channel. Read-only."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer",
                          "description": "Recent sessions to scan. Default 20."},
            },
        },
    },
]


def _finding_dict(f):
    return {
        "rule_id": f.rule_id, "severity": f.severity, "title": f.title,
        "path": f.path, "line": f.line, "excerpt": f.excerpt,
        "remediation": f.remediation, "references": f.references,
    }


def _summarize(findings):
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _call_tool(name, args):
    args = args or {}
    path = Path(args.get("path") or Path.cwd()).resolve()

    if name == "scan_agent_configs":
        findings, configs = gather(
            path, include_global=args.get("include_global", True))
        return {
            "scanned_files": [str(c) for c in configs],
            "summary": _summarize(findings),
            "findings": [_finding_dict(f) for f in findings],
        }

    if name == "check_integrity":
        from .scanners.posture import find_agent_configs
        configs = find_agent_configs(path)
        findings = verify_baseline([str(p) for p in configs] if configs else None)
        modified = [f for f in findings if f.rule_id == "BASELINE-001"]
        return {
            "modified_since_baseline": len(modified),
            "findings": [_finding_dict(f) for f in findings],
            "note": ("Baselines are recorded with the CLI (`wormhole "
                     "baseline`). This tool only reads them."),
        }

    if name == "blast_radius":
        findings, _ = gather(path, include_global=True)
        br = scoring.compute(findings)
        return {
            "score": br.score, "band": br.band,
            "execute": br.execute, "persist": br.persist,
            "propagate": br.propagate,
            "loop_closed": br.loop_closed,
            "factors": br.factors,
            "interpretation": (
                "loop_closed means execute, persist, and propagate are all "
                "reachable, so an infection could complete a full cycle "
                "unassisted. Sandbox isolation is the control that breaks it "
                "(arXiv:2603.15727)."),
        }

    if name == "scan_session_history":
        hits = scan_sessions(None, limit=int(args.get("limit", 20)))
        findings = to_findings(hits)
        return {
            "sessions_scanned": int(args.get("limit", 20)),
            "summary": _summarize(findings),
            "findings": [_finding_dict(f) for f in findings],
        }

    raise ValueError(f"unknown tool: {name}")


def _respond(req_id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": req_id}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def serve():
    """Read JSON-RPC requests from stdin until EOF."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        req_id = req.get("id")

        if method == "initialize":
            _respond(req_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            })
        elif method == "tools/list":
            _respond(req_id, {"tools": TOOLS})
        elif method == "tools/call":
            params = req.get("params") or {}
            try:
                result = _call_tool(params.get("name"), params.get("arguments"))
                _respond(req_id, {
                    "content": [{"type": "text",
                                 "text": json.dumps(result, indent=2)}],
                })
            except Exception as e:  # report, never crash the server
                _respond(req_id, {
                    "content": [{"type": "text", "text": f"error: {e}"}],
                    "isError": True,
                })
        elif method and method.startswith("notifications/"):
            continue  # notifications carry no id and expect no reply
        elif req_id is not None:
            _respond(req_id, error={"code": -32601,
                                    "message": f"method not found: {method}"})


if __name__ == "__main__":
    serve()
