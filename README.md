# standbox

> **Describe a sandbox in plain English. Get a per-agent permission gate +
> a human-readable report - no cluster-wide RBAC, no server-side changes.**

![standbox demo](docs/standbox-demo.gif)

*<sub>If the gif doesn't render here, run `make-demo.sh` to regenerate it (see
[#Demo](README.md#demo)).</sub>*

---

## What it does

You're a cluster admin. An AI agent (like Claude Code) needs to work on
deployments - but only in `mfsada`, only on `pods`/`deployments`, with
`port-forward` allowed and **no** `secrets`.

With standbox, inside Claude Code you say:

```
/standbox kubectl: only namespace mfsada, CRUD on pods and deployments,
        port-forward allowed, no jobs but cronjobs ok, no secrets
```

and immediately get:

1. **A generated gate** (`bundles/<name>/<cli>/gate/<cli>`) - a deterministic
   bash policy script that sits on PATH and blocks anything outside the
   policy (verb / resource / namespace / sub-resource, plus hard-denies like
   `--raw`, `-A`, `--as`, shell metacharacters).
2. **A report** (`bundles/<name>/sandbox.md`) with:
   - **use cases TESTED against the gate** (each row is a real gate run:
     ALLOW or BLOCK with the reason),
   - **what it CANNOT do** (explicit denials + hard-denied flags),
   - **ONE command** to run it in a Docker container where the gated binary
     is the *only* binary on PATH,
   - an honest **"what `kubectl` ACTUALLY runs"** section distinguishing the
     gate (real enforcement) from the stub target (show-only) and the real
     cluster mode (mount your real binary + kubeconfig).

### Demo

<a href="docs/standbox-demo.gif"><img src="docs/standbox-demo.gif" width="640" alt="standbox demo"></a>

The demo shows: generate → report → gate ALLOW/BLOCK → docker one-command.

---

## Why this exists

The gap: server-side RBAC needs cluster-admin and ServiceAccount/Role management
(and sometimes a cluster you don't control). Prompting an LLM with "be careful"
is not enforcement. standbox is a **client-side, per-agent** gate: the policy
lives on your machine, is enforced by a generated script, and is *auditable*.

- **Not** a system sandbox (no seccomp/namespaces).
- **Is** a policy gate on the *natural* path: whatever `kubectl` (or any
  supported CLI) you or your agent types through the gate gets checked first.

---

## Threat model (read this - honest)

standbox enforces the **natural path**: `kubectl ...` through the gate.

It does **NOT** stop:
- `/usr/local/bin/kubectl` (absolute path) or `curl` straight to the apiserver,
- an agent with the same user's file access that reads your real kubeconfig,
- a fully hostile root-like process on the same machine.

The container mode narrows this: the image contains **only** the gated binary,
so `/usr/local/bin/kubectl` *is* the gate and there is nothing else to run.

See [SECURITY.md](SECURITY.md) for the full model and what we are / aren't.

---

## Install

```bash
# from this repo
pip install .
# dependencies: mcp>=1,<2 ; pyyaml
```

### Register with Claude Code (MCP)

```jsonc
// .mcp.json (project) or ~/.claude.json (user)
{
  "mcpServers": {
    "standbox": {
      "command": "python",
      "args": ["-m", "standbox.mcp_server"],
      "env": { "PYTHONDONTWRITEBYTECODE": "1" }
    }
  }
}
```

(Install as a package once, then `python -m standbox.mcp_server` works anywhere
with no absolute paths.)

---

## Quick start

```bash
# 1. start a session in the target project (identity = this project)
claude

# 2. in Claude Code:
#    /standbox kubectl: only namespace mfsada, crud on pods+deployments,
#        port-forward allowed, no jobs but cronjobs ok, no secrets

# 3. inspect the report
cat bundles/agent/sandbox.md

# 4. run the gate locally
export PATH="$PWD/bundles/agent/kubectl/gate:$PATH"
kubectl get deployments -n mfsada   # ALLOWED (gate checks, then execs real kubectl)
kubectl get secrets -n mfsada       # BLOCKED with reason

# 5. or in a container (gated kubectl is the ONLY kubectl)
bash bundles/agent/kubectl/container/run.sh
```

---

## Supported CLIs

kubectl · docker · git · gh · aws · terraform · helm · npm · gcloud · psql (SQL: SELECT/WITH/SHOW only)

**Adding a CLI = adding a schema dict** in `standbox/schema.py` (verbs/resources/subcommands, hard-denies). The engine, gate templates, and report are generic.

---

## Architecture

```
 natural language "use case"
        │
   ┌────▼─────┐   schema.py (CLI grammar data)
   │ MCP tool │──► constraints {verbs, resources, namespaces, deny}
   │ generate │
   └────┬─────┘
        ├──► gate script (deterministic bash policy: verb×resource×ns×subres, hard-denies)
        ├──► policy.yaml  +  container/ (Dockerfile, run.sh, staged gate)
        ├──► sandbox.md   (use cases TESTED - each row a real gate run)
        └──► audit.jsonl  (ts, sandbox, command, verdict, reason)
```

Enforcement is a **generated script**, never an LLM. The LLM only drafts the
constraints from your English use case (you can pass exact `constraints` JSON
to bypass the naive parser).

---

## CLI reference (MCP tools)

| Tool | What it does |
|---|---|
| `standbox_generate(use_case, cli, name?, constraints?)` | Build the bundle + report |
| `standbox_check(command, sandbox)` | Dry-run: ALLOW/BLOCK + reason (audited) |
| `standbox_audit(sandbox, limit?, blocked_only?)` | Real audit trail |
| `standbox_list()` | Which sandboxes exist |
| `standbox_parse(use_case, cli)` | Preview parsed constraints |

---

## Demo

To (re)generate the demo gif:

```bash
brew install asciinema    # or npm i -g asciinema-player
./make-demo.sh            # records docs/standbox-demo.gif
```

The script drives a real `claude`/MCP session through: generate → report →
gate ALLOW/BLOCK → container one-command, then converts the asciinema cast to
a gif with `agg` (if installed) or leaves the `.cast` for
`asciinema play`.

---

## Status

Prototype → hardening. See [SHORTCOMINGS.md](SHORTCOMINGS.md) for the honest
gap list and the production-readiness plan. Not yet: signed gates, Windows
support, native package upload.

## License

[MIT](LICENSE)

## Security

[SECURITY.md](SECURITY.md) - threat model + reporting.
