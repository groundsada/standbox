#!/usr/bin/env bash
# standbox demo: same flow, several different CLIs.
# Runs in a scratch dir. Gate targets are /bin/echo, so nothing touches a real
# cluster, repo, or database.
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}"

GREEN=$'\033[32m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
type_cmd() { printf '%s$ %s%s\n' "$GREEN" "$1" "$OFF"; sleep 0.7; }
pause() { sleep "${1:-1}"; }

WORK=$(mktemp -d)
cd "$WORK" || exit 1
export STANDBOX_REAL_BIN=/bin/echo

# cli | use case
CASES=(
  "kubectl|only namespace mfsada, crud on pods and deployments, port-forward allowed, no jobs but cronjobs ok, no secrets"
  "terraform|read-only: plan, validate, state list only. no apply, no destroy, no -auto-approve"
  "git|read-only: status log diff. no push, no commit, no reset"
  "psql|READ-ONLY SQL: allow SELECT, WITH, SHOW. DENY: DROP, DELETE, UPDATE, INSERT, TRUNCATE"
)

# probe | expect
PROBES_kubectl=(
  "get deployments -n mfsada|0"
  "get secrets -n mfsada|3"
  "get pods -A|3"
)
PROBES_terraform=(
  "plan|0"
  "state list|0"
  "apply|3"
  "plan -auto-approve|3"
)
PROBES_git=(
  "status|0"
  "log|0"
  "push|3"
  "commit -m x|3"
)
PROBES_psql=(
  "-c 'SELECT * FROM users'|0"
  "-c 'DROP TABLE users'|3"
  "-c 'DELETE FROM users WHERE id=1'|3"
)

clear
printf '%sstandbox%s  per-agent client-side permission gates for CLIs\n' "$BOLD" "$OFF"
printf '%sone generator, any CLI: describe the policy in English, get an enforced gate%s\n\n' "$DIM" "$OFF"
pause 2

for entry in "${CASES[@]}"; do
  cli="${entry%%|*}"
  use_case="${entry#*|}"

  printf '\n%s=== %s ===%s\n' "$BOLD" "$cli" "$OFF"
  type_cmd "standbox_generate \"$use_case\""
  python3 - "$cli" "$use_case" <<'PY'
import sys
from standbox.report import build_report
cli, use_case = sys.argv[1], sys.argv[2]
r = build_report("agent", cli, use_case, "bundles")
rows = [l for l in r["markdown"].splitlines() if l.startswith("| ")]
print("wrote", r["out_dir"] + "/sandbox.md")
for line in rows[:7]:
    print(line)
PY
  pause 2

  export PATH="$WORK/bundles/agent/$cli/gate:$PATH"
  var="PROBES_$cli"
  eval "probes=(\"\${${var}[@]}\")"
  for p in "${probes[@]}"; do
    cmd="${p%|*}"
    printf '%s$ %s %s%s\n' "$GREEN" "$cli" "$cmd" "$OFF"
    # probes are our own literal strings, so eval is safe and preserves
    # quoting for things like psql -c 'SELECT * FROM users'
    eval "$cli $cmd" 2>&1
    pause 1.2
  done
  pause 1
done

printf '\n%s--- one command per CLI, container where the gate is the only binary ---%s\n' "$BOLD" "$OFF"
for entry in "${CASES[@]}"; do
  cli="${entry%%|*}"
  printf '  bash bundles/agent/%s/container/run.sh\n' "$cli"
  pause 0.4
done
pause 2
