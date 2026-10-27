"""Generic sandbox generator for standbox - schema-driven.

This module has ZERO CLI-specific hardcoding. It takes a schema (from
schema.py: verbs/resources/namespaces for kubectl-like CLIs, flags for
docker-like CLIs) and a constraint dict, and produces:
  - a generic gate script / wrapper (parameterized by the schema)
  - a policy.yaml
  - a container (Dockerfile + run.sh) with the gated binary as the ONLY one
  - a report with use cases + denials + raw commands + TESTED results
"""

import os
import subprocess
import tempfile

from . import schema

# ---------------------------------------------------------------- gates

# Generic gate for "verb_resource_name" CLIs (git, kubectl, gh, ...):
# argv = verb followed by resource/name, checked against an allow-list.
GATE_VERB_RESOURCE = r"""#!/usr/bin/env bash
# standbox gate - sandbox: @@NAME@@ (cli: @@CLI@@)
# Deny-by-default. Only the verbs/resources/namespaces below pass.
set -euo pipefail

VERBS_ALLOWED="@@VERBS@@"
RESOURCES_ALLOWED="@@RES@@"
NAMESPACES_ALLOWED="@@NS@@"

VERB="${1:-}"
shift || true

NS=""
RES=""
REST=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace)
      if [[ $# -lt 2 ]]; then echo "BLOCKED: -n needs a value" >&2; exit 3; fi
      NS="$2"; shift 2;;
    @@NSFLAGS@@) echo "BLOCKED: '$1' not allowed" >&2; exit 3;;
    @@HARDDENY@@) echo "BLOCKED: '$1' not allowed" >&2; exit 3;;
    *)
      if [[ -z "$RES" ]]; then RES="$1"; else REST+=("$1"); fi
      shift;;
  esac
done

case " $VERBS_ALLOWED " in
  *" $VERB "*) ;;
  *) echo "BLOCKED: verb '$VERB' not allowed" >&2; exit 3;;
esac

# Resource check. For port-forward/logs/exec, the RES is a TARGET like
# svc/x (port-forward) - validate the base resource (svc/pod) instead.
# Map short aliases (svc->services, po->pods, deploy->deployments) so
# `svc/x` matches allowed `services`.
base="${RES%%/*}"
case "$base" in
  svc) base="services";;
  po|pod) base="pods";;
  deploy) base="deployments";;
  cm) base="configmaps";;
  sts) base="statefulsets";;
  cj) base="cronjobs";;
  ns) base="namespaces";;
esac
check_res() {
  local ok=""
  for allowed in $RESOURCES_ALLOWED; do
    if [[ "$base" == "$allowed" || "$base" == "${allowed%s}" ]]; then ok=1; break; fi
  done
  [[ -n "$ok" ]] || { echo "BLOCKED: resource/target '$1' not allowed" >&2; exit 3; }
}
check_res "$RES"

if [[ -z "$NS" ]]; then NS="${NAMESPACES_ALLOWED%% *}"; fi
case " $NAMESPACES_ALLOWED " in
  *" $NS "*) ;;
  *) echo "BLOCKED: namespace '$NS' not allowed" >&2; exit 3;;
esac

exec "${STANDBOX_REAL_BIN:-@@BIN@@.real}" "$VERB" "$RES" "${REST[@]}"
"""

# Generic gate for "subcommand" CLIs (gh, aws, terraform, helm, npm, gcloud...):
# argv[0]=subcommand, argv[1:]=the rest. We check the FIRST word against
# ALLOWED single tokens ("plan"), and the first two words against ALLOWED
# two-token pairs ("pr list"), and the first three against three-token
# ("compute instances list"). Allow if ANY prefix is allowed.
GATE_SUBCOMMAND = r"""#!/usr/bin/env bash
# standbox gate - sandbox: @@NAME@@ (cli: @@CLI@@, subcommand model)
set -euo pipefail
# SINGLE = one-word verbs (terraform plan); MULTI = multi-word tokens
# (gh pr list, gcloud compute instances list). Matching is EXACT, never
# subcommand-prefix matching.
SINGLE_ALLOWED=@@SINGLE@@
MULTI_ALLOWED=@@MULTI@@
HARDDENY=@@HARDDENY@@
NSFLAGS=@@NSFLAGS@@

# hard-deny flags (schema-driven, e.g. -auto-approve, --force)
for arg in "$@"; do
  case " $HARDDENY " in
    *" $arg "*) echo "BLOCKED: '$arg' not allowed" >&2; exit 3;;
  esac
  case " $NSFLAGS " in
    *" $arg "*) echo "BLOCKED: '$arg' not allowed" >&2; exit 3;;
  esac
  # shell metacharacters: an agent cannot inject compound commands
  case "$arg" in
    *';'*|*'&'*|*'|'*|*'`'*|*'$('*) echo "BLOCKED: shell metacharacter in '$arg'" >&2; exit 3;;
  esac
done

SUB="${1:-}"
JOINED="$*"
# MULTI entries: match if the joined argv STARTS WITH an allowed multi-word
# verb token (extra positional args/flags after the verb pass through).
# MULTI is stored pipe-delimited ("compute instances list|pr list") so each
# entry is a whole token, not a space-split word.
ALLOWED_ARG=0
IFS='|' read -ra ENTRIES <<< "$MULTI_ALLOWED"
for entry in "${ENTRIES[@]}"; do
  [[ -n "$entry" ]] || continue
  case "$JOINED" in
    "$entry "*) ALLOWED_ARG=1; break;;
    "$entry")   ALLOWED_ARG=1; break;;
  esac
done
if [[ "$ALLOWED_ARG" == "1" ]]; then
  :
elif case " $SINGLE_ALLOWED " in *" $SUB "*) true ;; *) false ;; esac; then
  :
else
  echo "BLOCKED: '$*' not allowed" >&2; exit 3
fi

exec "${STANDBOX_REAL_BIN:-@@BIN@@.real}" "$@"
"""

# Generic gate for "sql" CLIs (psql): inspect -c/--command and stdin for
# destructive statements. Only read-only SQL (SELECT/WITH/SHOW/...) passes.
GATE_SQL = r"""#!/usr/bin/env bash
# standbox gate - sandbox: @@NAME@@ (cli: @@CLI@@, SQL read-only model)
set -euo pipefail
READ_OK="@@SQLREAD@@"
DENY_KW="@@SQLDENY@@"

# gather SQL: from -c/--command args, or stdin (if piped)
SQL=""
check_arg() {
  local arg="$1"
  if [[ "$arg" == "-c" || "$arg" == "--command" ]]; then
    local nxt="${2:-}"
    SQL="$SQL $nxt"
  elif [[ "$arg" == --command=* ]]; then
    SQL="$SQL ${arg#--command=}"
  fi
}

args=("$@")
i=0
while [[ $i -lt ${#args[@]} ]]; do
  a="${args[$i]}"
  case "$a" in
    -c|--command) SQL="$SQL ${args[$((i+1))]:-}"; i=$((i+2));;
    --command=*) SQL="$SQL ${a#--command=}"; i=$((i+1));;
    *) i=$((i+1));;
  esac
done

# if no -c given, read stdin (psql reads SQL from stdin)
if [[ -z "$SQL" && ! -t 0 ]]; then
  SQL="$(cat 2>/dev/null || true)"
fi

if [[ -z "$SQL" ]]; then
  # no SQL provided - allow psql interactive metadata like \l, \d? Deny to be safe
  echo "BLOCKED: no SQL statement provided; use -c 'SELECT ...'" >&2
  exit 3
fi

# strip comments and normalize
STMT="$(printf '%s' "$SQL" | tr 'A-Z' 'a-z' | tr -d '\n\r')"
STMT="${STMT%%--*}"
# normalize punctuation to spaces so keyword scan catches (delete), ;drop, delete, etc.
STMT="$(printf '%s' "$STMT" | sed 's/[(),;]/ /g')"
# trim leading whitespace (the -c gather adds a leading space)
STMT="${STMT#"${STMT%%[![:space:]]*}"}"

# read-only first-word check
FIRST="${STMT%% *}"
case " $READ_OK " in
  *" $FIRST "*) : ;;
  *) echo "BLOCKED: SQL statement starting with '$FIRST' is not allowed (read-only SELECT/WITH/SHOW only)" >&2; exit 3;;
esac

# destructive keywords anywhere
for kw in $DENY_KW; do
  case " $STMT " in
    *" $kw "*) echo "BLOCKED: SQL contains forbidden keyword '$kw'" >&2; exit 3;;
  esac
done

exec "${STANDBOX_REAL_BIN:-@@BIN@@.real}" "$@"
"""

# Generic wrapper for "flags_inject" CLIs (docker/podman): refuse deny-flags,
# inject sandbox flags on `run`.
WRAPPER_FLAGS = r"""#!/usr/bin/env bash
# standbox wrapper - sandbox: @@NAME@@ (cli: @@CLI@@)
DENY_FLAGS=(@@DENY@@)
for arg in "$@"; do
  for d in "${DENY_FLAGS[@]}"; do
    if [[ "$arg" == "$d"* ]]; then
      echo "BLOCKED: standbox sandbox does not allow '$arg'" >&2; exit 3
    fi
  done
done
if [[ "${1:-}" == "run" ]]; then
  shift
  exec "${STANDBOX_REAL_BIN:-@@BIN@@}" run @@FLAGS@@ "$@"
fi
exec "${STANDBOX_REAL_BIN:-@@BIN@@}" "$@"
"""


def render_gate(sch, name, c):
    """Render the gate/wrapper script for a schema+constraints."""
    if sch.get("arg_model") == "flags_inject":
        # merge schema hard_deny (--privileged etc.) with parsed deny (mounts)
        deny = sorted(set(sch.get("hard_deny") or []) | set(c.get("deny") or []))
        return (WRAPPER_FLAGS
                .replace("@@NAME@@", name)
                .replace("@@CLI@@", sch["cli"])
                .replace("@@DENY@@", " ".join(deny))
                .replace("@@FLAGS@@", " ".join(sch.get("sandbox_flags", [])))
                .replace("@@BIN@@", sch.get("default_binary", "docker")))
    if sch.get("arg_model") == "subcommand":
        # split into single-word (terraform plan) vs multi-word (pr list)
        singles = [v for v in c["verbs"] if " " not in v]
        multis = [v for v in c["verbs"] if " " in v]
        hard = sch.get("hard_deny") or []
        nsflags = sch.get("all_namespaces_flags") or []
        return (GATE_SUBCOMMAND
                .replace("@@NAME@@", name)
                .replace("@@CLI@@", sch["cli"])
                .replace("@@SINGLE@@", '"' + " ".join(singles) + '"')
                .replace("@@MULTI@@", '"' + "|".join(multis) + '"')
                .replace("@@HARDDENY@@", '"' + " ".join(hard) + '"')
                .replace("@@NSFLAGS@@", '"' + " ".join(nsflags) + '"')
                .replace("@@BIN@@", sch.get("default_binary", "gh")))
    if sch.get("arg_model") == "sql":
        return (GATE_SQL
                .replace("@@NAME@@", name)
                .replace("@@CLI@@", sch["cli"])
                .replace("@@SQLREAD@@", " ".join(sch.get("sql_read", ["select", "with", "show"])))
                .replace("@@SQLDENY@@", " ".join(sch.get("sql_deny", [
                    "drop", "delete", "update", "insert", "truncate", "alter", "create"])))
                .replace("@@BIN@@", sch.get("default_binary", "psql")))
    # verb_resource_name
    ns_flags = sch.get("all_namespaces_flags") or ["-A", "--all-namespaces"]
    hard = (sch.get("hard_deny") or []) + ["--raw"]
    return (GATE_VERB_RESOURCE
            .replace("@@NAME@@", name)
            .replace("@@CLI@@", sch["cli"])
            .replace("@@VERBS@@", " ".join(c["verbs"]))
            .replace("@@RES@@", " ".join(c["resources"]))
            .replace("@@NS@@", " ".join(c["namespaces"]))
            .replace("@@NSFLAGS@@", "|".join(ns_flags))
            .replace("@@HARDDENY@@", "|".join(f"'{x}'" for x in hard))
            .replace("@@BIN@@", sch.get("default_binary", "kubectl")))


# -------------------------------------------------------------- run tests

def run_gate(src, argv):
    """Run the gate with a stub real binary; returns (code, output)."""
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as tf:
        tf.write(src)
        p = tf.name
    os.chmod(p, 0o755)
    env = dict(os.environ)
    env["STANDBOX_REAL_BIN"] = "/bin/echo"
    try:
        r = subprocess.run([p] + argv, capture_output=True, text=True,
                           timeout=10, env=env)
        return r.returncode, (r.stdout + r.stderr).strip()
    finally:
        os.unlink(p)


# ------------------------------------------------------------- reporting

def _fence(s):
    return "```\n" + s + "\n```"


def build_report(name, cli, text, out_root, constraints=None):
    """Main entry: generate + test + report for ANY CLI in the registry.

    constraints: optional dict (verb/resources/namespaces/deny) - when given,
    it's used verbatim. This is how the LLM front-end passes precise policy,
    bypassing the naive text parser.
    """
    sch = schema.schema_for(cli)
    if sch is None:
        raise ValueError(
            f"unsupported cli '{cli}' - supports: {', '.join(schema.all_clis())}")
    c = constraints or schema.parse_use_case(cli, text)
    c["cli"] = sch["cli"]
    sch_cli = sch["cli"]

    out = os.path.join(out_root, name)
    os.makedirs(out, exist_ok=True)

    gate_src = render_gate(sch, name, c)
    gate_path = os.path.join(out, sch_cli, "gate")
    os.makedirs(gate_path, exist_ok=True)
    gate_file = os.path.join(gate_path, sch.get("default_binary", "cli"))
    with open(gate_file, "w") as f:
        f.write(gate_src)
    os.chmod(gate_file, 0o755)
    policy_path = os.path.join(gate_path, "policy.yaml")
    schema.write_policy(policy_path, name, c)

    # use cases TESTED against the gate (really run, not described)
    cases = []
    def add(label, argv, expect):
        code, out_text = run_gate(gate_src, argv)
        got = "ALLOW" if code == 0 else "BLOCK"
        ok = "✅" if got == expect else "❌"
        cases.append(f"| {ok} | `{' '.join(argv)}` | **{got}** | {label} |")
        return got == expect

    all_ok = True
    if sch.get("arg_model") == "sql":
        # psql: test SQL statements through the gate
        all_ok &= add("SELECT (read)", ["-c", "SELECT * FROM users"], "ALLOW")
        all_ok &= add("WITH (read)", ["-c", "WITH t AS (SELECT 1) SELECT * FROM t"], "ALLOW")
        all_ok &= add("SHOW (read)", ["-c", "SHOW tables"], "ALLOW")
        all_ok &= add("DROP (deny)", ["-c", "DROP TABLE users"], "BLOCK")
        all_ok &= add("DELETE (deny)", ["-c", "DELETE FROM users WHERE id=1"], "BLOCK")
        all_ok &= add("UPDATE (deny)", ["-c", "UPDATE users SET x=1"], "BLOCK")
        all_ok &= add("INSERT (deny)", ["-c", "INSERT INTO users VALUES (1)"], "BLOCK")
        all_ok &= add("ALTER (deny)", ["-c", "ALTER TABLE users ADD c"], "BLOCK")
    elif sch.get("arg_model") == "flags_inject":
        all_ok &= add("default run", ["run", "--rm", "-it", "img", "cmd"], "ALLOW")
        all_ok &= add("deny mount", ["run", "-v", "/host:/c", "img"], "BLOCK")
        all_ok &= add("deny privileged", ["run", "--privileged", "img"], "BLOCK")
    elif sch.get("arg_model") == "subcommand":
        # verb entries are "sub action" pairs, e.g. "pr list"
        for v in c["verbs"]:
            sub, _, action = v.partition(" ")
            if action:
                all_ok &= add(f"{v}", [sub, action], "ALLOW")
            else:
                all_ok &= add(f"{v}", [sub, "list"], "ALLOW")
        # tested denials
        for d in c.get("deny", []):
            sub, _, action = d.partition(" ")
            if action:
                all_ok &= add(f"denied {d}", [sub, action], "BLOCK")
            else:
                all_ok &= add(f"denied {d}", [d, "delete"], "BLOCK")
    else:
        ns0 = c["namespaces"][0]
        seen = set()
        def once(label, add_argv, expect):
            key = tuple(add_argv)
            if key in seen:
                return True
            seen.add(key)
            return add(label, add_argv, expect)

        verified_pf = "port-forward" in c["verbs"]
        for res in c["resources"]:
            if res == "services" and verified_pf:
                continue  # services is only a port-forward target here
            for verb in c["verbs"]:
                if verb in ("get", "list", "watch", "describe"):
                    once(f"{verb} {res}", ["get", res, "-n", ns0], "ALLOW")
                elif verb == "port-forward":
                    once("port-forward svc", ["port-forward", "svc/x", "8080:80", "-n", ns0], "ALLOW")
                elif verb == "logs":
                    once("logs pod", ["logs", "pod/x", "-n", ns0, "--tail=10"], "ALLOW")
                elif verb in ("create", "apply", "patch", "update", "delete"):
                    once(f"{verb} {res}", ["patch", res + "/x", "-n", ns0, "-p", "{}"], "ALLOW")
        # real deny cases
        for d in c.get("deny", []):
            once(f"denied {d}", ["get", d, "-n", ns0], "BLOCK")
        once("denied secrets", ["get", "secrets", "-n", ns0], "BLOCK")
        once("denied wrong ns", ["get", "deployments", "-n", "prod"], "BLOCK")
        once("denied --raw", ["get", "--raw", "/api"], "BLOCK")
        once("denied -A", ["get", "pods", "-A"], "BLOCK")
        if verified_pf:
            once("port-forward svc on wrong ns", ["port-forward", "svc/x", "8080:80", "-n", "prod"], "BLOCK")
        if "cronjobs" in c["resources"] and "jobs" in c.get("deny", []):
            once("cronjobs allowed", ["get", "cronjobs", "-n", ns0], "ALLOW")

    table = "\n".join(cases)
    verified = "**verified by running the gate**" if all_ok else "**⚠ some cases not as expected**"

    # docker container with the gated binary as the ONLY one
    cont = os.path.join(out, sch_cli, "container")
    os.makedirs(cont, exist_ok=True)
    with open(os.path.join(cont, "standbox-gate"), "w") as f:
        f.write(gate_src)
    os.chmod(os.path.join(cont, "standbox-gate"), 0o755)
    binname = sch.get("default_binary", "cli")
    with open(os.path.join(cont, "Dockerfile"), "w") as f:
        f.write(f"""FROM ubuntu:22.04
# standbox sandbox: {name} - the gated {binname} is the ONLY one here.
COPY standbox-gate /usr/local/bin/{binname}
RUN chmod +x /usr/local/bin/{binname} \\
  && printf '#!/bin/sh\\necho "[STUB-ONLY show: {binname} would receive] $@"\\n' > /usr/local/bin/{binname}.real \\
  && chmod +x /usr/local/bin/{binname}.real
ENV STANDBOX_REAL_BIN=/usr/local/bin/{binname}.real
ENTRYPOINT ["/usr/local/bin/{binname}"]
""")
    with open(os.path.join(cont, "run.sh"), "w") as f:
        f.write(f"""#!/usr/bin/env bash
# standbox sandbox: {name} - one-command container launch.
# Gives you a SHELL (--entrypoint bash). Inside, `{binname}` is the GATE.
# By default it runs a STUB (show-only). See sandbox.md 'REAL kubectl' section
# for mounting a real binary.
set -euo pipefail
CDIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
docker build -q -t {name} "$CDIR"
exec docker run --rm -it --entrypoint bash \\
  --network none --cap-drop ALL --security-opt no-new-privileges \\
  --read-only --tmpfs /tmp --tmpfs /run \\
  {name}
""")
    os.chmod(os.path.join(cont, "run.sh"), 0o755)

    # Displayed paths are RELATIVE to the bundle parent (bundles/) so the
    # report is portable - no /Users/... absolute paths leak into READMEs.
    rel_cont = os.path.join(name, sch_cli, "container")
    rel_gate = os.path.join(name, sch_cli, "gate")
    one = f'bash "{rel_cont}/run.sh"'
    raw = f"""# SHELL mode (gate is /usr/local/bin/{binname}; STUB target by default)
docker build -q -t {name} "{rel_cont}"
docker run --rm -it --entrypoint bash \\
  --network none --cap-drop ALL --security-opt no-new-privileges \\
  --read-only --tmpfs /tmp --tmpfs /run {name}

# REAL cluster output - the gate's target is /usr/local/bin/{binname}.real.
# On macOS your host {binname} is Mach-O; the container is Linux, so you MUST
# download a LINUX {binname} and mount it at EXACTLY that path:
mkdir -p bin
curl -fsSL https://dl.k8s.io/release/v1.36.3/bin/linux/arm64/{binname} -o bin/{binname}-linux-arm64
chmod +x bin/{binname}-linux-arm64
docker run --rm -it --entrypoint bash \\
  --network none --cap-drop ALL --security-opt no-new-privileges \\
  --read-only --tmpfs /tmp --tmpfs /run \\
  -v "$PWD/bin/{binname}-linux-arm64:/usr/local/bin/{binname}.real:ro" \\
  -v "$HOME/.kube/config:/root/.kube/config:ro" \\
  {name}
# (then inside: kubectl get pods -n mfsada -> the gate ALLOWs and the REAL
#  Linux kubectl actually queries your cluster; BLOCKs still enforced.)
"""
    container_section = f"""### Run it in a container where the gated {sch_cli} is the ONLY one (ONE command)

**⚠️ What `{binname}` ACTUALLY runs inside this container (read this):**

- `/usr/local/bin/{binname}` = **THE GATE** (a bash policy script). It checks
  every invocation against this sandbox's policy and either ALLOWs (execs the
  target) or BLOCKs with the reason. **This is the real enforcement.**
- `/usr/local/bin/{binname}.real` = the gate's **TARGET**. **By default it is a
  STUB that only prints** `[STUB-ONLY show: ...]` - it does NOT talk to any
  cluster. **So an `ALLOW` line is the gate saying "allowed" - it is NOT real
  `{binname}` output.** (This is intentional: no real cluster, no credentials
  in the isolated image.)
- To get REAL {binname} output (actual cluster), use the **REAL cluster** mount
  command below. IMPORTANT: the container is LINUX and your host {binname} is
  macOS (Mach-O) - you must download/point at a **LINUX {binname}** and mount
  it at **exactly** `/usr/local/bin/{binname}.real` (the target the gate execs).
  Then the gate STILL enforces, but ALLOWs now reach your real cluster.

{_fence(one)}

{_fence(raw)}

> Verify the gate is real: the **BLOCK** lines (e.g. `BLOCKED: verb ...` /
> `BLOCKED: resource ...`) are produced by the gate script, never by the stub.
"""
    ns_disp = ", ".join(c["namespaces"])
    res_disp = ", ".join(c["resources"])
    verbs_disp = ", ".join(c["verbs"])
    bin_disp = sch.get("default_binary", "cli")
    # pre-rendered "run it locally" snippet (nested f-strings are not portable
    # to python 3.10, so build it out here instead of inline)
    if sch.get("arg_model") == "sql":
        local_run = _fence(
            "export PATH=" + rel_gate + ":$PATH\n"
            + bin_disp + " -c 'SELECT * FROM users'        # ALLOWED\n"
            + bin_disp + " -c 'DROP TABLE users'           # BLOCKED")
    elif sch.get("arg_model") == "subcommand":
        local_run = _fence(
            "export PATH=" + rel_gate + ":$PATH\n"
            + bin_disp + " " + (c["verbs"][0] if c["verbs"] else "help")
            + "        # ALLOWED\n"
            + bin_disp + " " + (c.get("deny") or ["(denied)"])[0]
            + "        # BLOCKED")
    else:
        local_run = _fence(
            "export PATH=" + rel_gate + ":$PATH\n"
            + bin_disp + " get deployments -n " + (c["namespaces"][0] if c["namespaces"] else "default")
            + "   # ALLOWED\n"
            + bin_disp + " get secrets -n " + (c["namespaces"][0] if c["namespaces"] else "default")
            + "       # BLOCKED")

    if sch.get("arg_model") == "sql":
        md = f"""## ✅ Sandbox: **{name}**

**CLI:** {sch_cli} (SQL read-only model) · **Allowed statements:** {", ".join(c["verbs"])}

### What it CAN do (use cases)
- `psql -c "SELECT ..."` - read-only queries
- `psql -c "WITH ... SELECT ..."`, `SHOW`, `EXPLAIN`, `DESCRIBE`
- any SQL that starts with a read keyword and contains no DML/DDL

### What it CANNOT do
- `DROP`, `DELETE`, `UPDATE`, `INSERT`, `TRUNCATE`, `ALTER`, `CREATE`,
  `GRANT`, `REVOKE`, `CALL`, `DO` - any destructive statement
- `\\copy` / `COPY` / `\\i` / `\\o` - file/command escapes

### Use cases TESTED against the gate ({verified})
| OK | Command | Verdict | Why |
|---|---|---|---|
{table}

### Run it locally
{local_run}

{container_section}
"""
    elif sch.get("arg_model") == "subcommand":
        md = f"""## ✅ Sandbox: **{name}**

**CLI:** {sch_cli} (subcommand model) · **Allowed:** {verbs_disp}

### What it CAN do (use cases)
- {chr(10).join("- `" + v + "`" for v in c["verbs"])}
- the gated binary `{bin_disp}` is first on PATH

### What it CANNOT do
{chr(10).join("- `" + d + "`" for d in c.get("deny", []))}
- hard-denied flags: {", ".join(sch.get("hard_deny", []))}

### Use cases TESTED against the gate ({verified})
| OK | Command | Verdict | Why |
|---|---|---|---|
{table}

### Run it locally
{local_run}

{container_section}
"""
    else:
        md = f"""## ✅ Sandbox: **{name}**

**CLI:** {sch_cli} · **Namespace(s):** `{ns_disp}` · **Resources:** {res_disp} · **Verbs:** {verbs_disp}

### What it CAN do (use cases)
- {verbs_disp} on {res_disp} -n {ns_disp}
- the gated binary `{bin_disp}` is first on PATH

### What it CANNOT do
{chr(10).join("- " + d for d in c.get("deny", []))}
- hard-denied: {", ".join(sch.get("hard_deny", []))}

### Use cases TESTED against the gate ({verified})
| OK | Command | Verdict | Why |
|---|---|---|---|
{table}

### Run it locally
{local_run}

{container_section}
"""
    return {"markdown": md, "artifacts": {"gate": gate_file, "container": cont},
            "run_commands": [one, raw], "out_dir": out}
