# Security Policy

## Threat model

standbox is a **client-side policy gate**, not a system sandbox.

### What it protects against
- Accidental / AI-misguided `kubectl` (or any supported CLI) commands that
  exceed the intended scope: wrong namespace, forbidden resource, forbidden
  verb/subresource, `-A` all-namespaces, `--raw`, `--as`, shell metacharacters,
  compound commands, CTE-wrapped SQL DML, manifest-file includes (`-f`), etc.
- The "AI did something I didn't tell it to" problem: enforcement is a
  **generated deterministic script**, never an LLM judgment.

### What it does NOT protect against
- `/usr/local/bin/kubectl` (or any absolute path) invoked directly, bypassing
  the gate.
- `curl` / direct requests to the Kubernetes API server with the user's real
  credentials.
- An agent that reads the user's real `~/.kube/config` and uses it directly.
- A fully hostile process running as the same user (no OS sandboxing).

The **container mode** narrows the gap: the image contains ONLY the gated
binary, so `/usr/local/bin/kubectl` IS the gate and there is no other kubectl
in the image. But bind-mounting your real kubectl + kubeconfig (REAL mode)
re-introduces the absolute-path caveat - documented in the generated report.

### Reported / accepted in v0.1
- Generated gates are bash (editable by an agent with file access). We
  checksum them in the report; signing is future work.
- The upstream CLI itself can have its own post-gate behavior (e.g. `apply`
  with unknown flags); we hard-deny the flags we know are dangerous.

## Reporting a vulnerability

Please open a private issue or email the maintainer. Include:
- The CLI + use case + generated gate (or reproduce with `standbox_generate`)
- The exact command that bypassed/over-blocked
- Expected vs actual verdict

We treat "bypass" (allowed but should be blocked) as high priority;
"over-block" (blocked but should be allowed) as normal priority.
