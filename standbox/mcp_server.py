#!/usr/bin/env python3
"""standbox MCP server.

The COMPILER: you describe a sandbox in natural language; it generates the
enforcing artifact + policy + report. Schema-driven - supports any CLI that
has a schema (kubectl, docker; add more in schema.py). The generated gate is
self-contained (bash), has NO external binary, no other project's code, and
is deterministic (no LLM at runtime).

Tools:
  standbox_generate(use_case, cli, name?) -> report markdown (+ writes bundle)
  standbox_check(command, sandbox)         -> ALLOW/BLOCK + reason
  standbox_audit(sandbox)                  -> decisions logged for a sandbox
  standbox_list()                          -> generated sandboxes
  standbox_parse(use_case, cli)            -> structured constraints (review)
"""

import json
import os
import subprocess
import sys

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("error: `pip install mcp` to run this server", file=sys.stderr)
    sys.exit(1)

try:
    from . import schema  # package import
    from .internal import audit
    from .report import build_report
except ImportError:  # direct-script / legacy path
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import schema  # type: ignore # noqa: E402
    from internal import audit  # type: ignore # noqa: E402
    from report import build_report  # type: ignore # noqa: E402

# Bundles land in the CWD where claude was launched (not next to the server).
BUNDLE_ROOT = os.environ.get("STANDBOX_BUNDLES") or os.path.join(os.getcwd(), "bundles")

mcp = FastMCP("standbox")


def _sanitize_name(name):
    return "".join(ch for ch in name if ch.isalnum() or ch in "-_").strip("-_")


@mcp.tool()
def standbox_generate(use_case: str, cli: str = "kubectl", name: str = "agent",
                      constraints: str = "{}") -> str:
    """Generate a sandbox from a plain-English use case for ANY supported CLI.

    Args:
        use_case: what the agent may do, e.g.
            "kubectl: only namespace mfsada, CRUD on pods + deployments,
             port-forward allowed, no jobs but cronjobs allow, no secrets"
            or "docker: no persistent mounts, read-only rootfs, no network"
            or "git: only read (status/log/diff) in this repo, no push"
        cli: which CLI to sandbox (kubectl, docker; schema.py adds more)
        name: bundle name (default 'agent')
        constraints: (advanced) JSON dict {"verbs":[...],"resources":[...],
            "namespaces":[...],"deny":[...]} - overrides naive parsing; the
            LLM front-end should pass this when it has precise understanding.

    Returns a markdown report (use cases, denials, raw docker commands,
    use cases TESTED against the gate) and writes the enforcing artifact to
    bundles/<name>/<cli>/.
    """
    name = _sanitize_name(name or "agent")
    c = None
    if constraints and constraints.strip() not in ("{}", ""):
        try:
            c = json.loads(constraints)
        except Exception as e:  # noqa: BLE001
            return f"constraints must be valid JSON: {e}"
    try:
        report_dict = build_report(name, cli, use_case, BUNDLE_ROOT, c)
    except Exception as e:  # noqa: BLE001
        return f"error generating sandbox: {e}"
    out_dir = report_dict["out_dir"]

    md_path = os.path.join(out_dir, "sandbox.md")
    with open(md_path, "w") as f:
        f.write(report_dict["markdown"])

    return report_dict["markdown"] + (
        f"\nWrote bundle + report to: `{out_dir}` (relative to cwd)\n"
        f"Report file: `{md_path}`\n"
    )


@mcp.tool()
def standbox_check(command: str, sandbox: str = "agent") -> str:
    """Dry-run: what would the sandbox do with this command? ALLOW or BLOCK + reason.

    Args:
        command: the exact command, e.g. "kubectl get secrets -n mfsada"
        sandbox: bundle name
    """
    name = _sanitize_name(sandbox)
    bundle = os.path.join(BUNDLE_ROOT, name)
    # find the gate file: bundles/<name>/<cli>/gate/<binary>
    gate = None
    for sub in os.listdir(bundle) if os.path.isdir(bundle) else []:
        g = os.path.join(bundle, sub, "gate")
        if os.path.isdir(g):
            for f in os.listdir(g):
                p = os.path.join(g, f)
                if os.path.isfile(p) and not f.endswith((".yaml", ".yml")):
                    gate = p
                    break
        if gate:
            break
    if not gate:
        return f"no sandbox '{name}' (try standbox_generate first)"
    env = dict(os.environ)
    env["STANDBOX_REAL_BIN"] = "/bin/echo"
    try:
        args = command.split()
        # The gate expects verb-first ("get pods"), not the full command
        # ("kubectl get pods") - strip a leading CLI-binary token if present.
        if args and args[0] in ("kubectl", "git", "gh", "aws", "docker", "podman",
                                 "terraform", "helm", "npm", "gcloud", "psql"):
            args = args[1:]
        proc = subprocess.run(
            [gate, *args], env=env, capture_output=True, text=True, timeout=5)
        verdict = "ALLOW" if proc.returncode == 0 else "BLOCK"
        reason = "" if proc.returncode == 0 else (proc.stderr or proc.stdout).strip()
        audit.append(BUNDLE_ROOT, name, {
            "action": verdict,
            "command": command,
            "reason": reason,
            "gate": os.path.basename(gate),
        })
        if verdict == "ALLOW":
            return f"✅ ALLOW\n→ would run: {command}"
        return f"⛔ BLOCK (exit {proc.returncode})\n{reason}"
    except Exception as e:  # noqa: BLE001
        return f"check failed: {e}"


@mcp.tool()
def standbox_audit(sandbox: str = "agent", limit: int = 200,
                   blocked_only: bool = False) -> str:
    """Real audit trail: every gate decision recorded with ts/command/verdict.

    Args:
        sandbox: bundle name
        limit: max records to return (default 200)
        blocked_only: only show BLOCKs (what the agent tried and got denied)
    """
    name = _sanitize_name(sandbox)
    recs = audit.query(BUNDLE_ROOT, name, limit=limit, blocked_only=blocked_only)
    if not recs:
        return f"no audit records for '{name}' (generate + run standbox_check to populate)."
    return audit.render(recs)


@mcp.tool()
def standbox_list() -> str:
    """List generated sandboxes."""
    if not os.path.isdir(BUNDLE_ROOT):
        return "no sandboxes yet."
    rows = []
    for d in sorted(os.listdir(BUNDLE_ROOT)):
        md = os.path.join(BUNDLE_ROOT, d, "sandbox.md")
        if os.path.exists(md):
            first = open(md).read().splitlines()[1].strip("# ") if os.path.getsize(md) else ""
            rows.append(f"- **{d}** - {first}")
        else:
            rows.append(f"- **{d}**")
    return "```\n" + "\n".join(rows) + "\n```"


@mcp.tool()
def standbox_parse(use_case: str, cli: str = "kubectl") -> str:
    """Show the structured policy an LLM would extract from a use case.
    Useful for review before generating."""
    c = schema.parse_use_case(cli, use_case)
    if c is None:
        return f"unsupported cli: {cli} (supports: {', '.join(schema.all_clis())})"
    return json.dumps(c, indent=2)


def main() -> None:
    """Console entry point (`standbox` command / `python -m standbox.mcp_server`)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
