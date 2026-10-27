"""standbox audit - append-only JSONL record of every gate decision.

The gate itself is bash; it cannot import Python. So the MCP server appends
after it *runs* the gate (standbox_check / generate-tests), and the gate can
also write via a shared file if STANDBOX_AUDIT_LOG is set. This module owns
the write/read path so `standbox_audit` always reflects reality.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def bundle_audit_path(bundle_root: str, name: str) -> str:
    return os.path.join(bundle_root, name, "audit.jsonl")


def append(bundle_root: str, name: str, record: dict[str, Any]) -> str:
    """Append one record; returns the path written (for error messages)."""
    path = bundle_audit_path(bundle_root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rec = {
        "ts": _now(),
        "sandbox": name,
        **record,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return path


def append_path(path: str, record: dict[str, Any]) -> None:
    """Append to an explicit path (used by the gate's STANDBOX_AUDIT_LOG)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def query(bundle_root: str, name: str, limit: int = 200,
          blocked_only: bool = False) -> list[dict[str, Any]]:
    """Read the last `limit` records for a sandbox."""
    path = bundle_audit_path(bundle_root, name)
    if not os.path.exists(path):
        return []
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if blocked_only and rec.get("action") != "BLOCK":
                continue
            out.append(rec)
    return out[-limit:]


def render(records: list[dict[str, Any]]) -> str:
    """Compact human-readable rendering for the MCP tool."""
    lines = []
    for r in records:
        cmd = r.get("command", "")
        action = r.get("action", "?")
        agent = r.get("agent", r.get("sandbox", "?"))
        reason = r.get("reason", "")
        lines.append(
            f"{r.get('ts', '')}  {action:5}  {agent}: {cmd}"
            + (f"   [{reason}]" if reason else "")
        )
    return "\n".join(lines) if lines else "(no records)"
