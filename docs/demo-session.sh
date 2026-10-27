#!/usr/bin/env bash
# standbox demo: generate -> report -> gate ALLOW/BLOCK -> container command.
# Runs against a scratch dir. Never touches a real cluster (gate target = echo).
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}"

GREEN=$'\033[32m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
type_cmd() { printf '%s$ %s%s\n' "$GREEN" "$1" "$OFF"; sleep 0.8; }
pause() { sleep "${1:-1}"; }

WORK=$(mktemp -d)
cd "$WORK" || exit 1
USE_CASE='only namespace mfsada, crud on pods and deployments, port-forward allowed, no jobs but cronjobs ok, no secrets'

clear
printf '%sstandbox%s  per-agent client-side permission gates for CLIs\n' "$BOLD" "$OFF"
printf '%sdescribe a sandbox in plain English, get an enforced gate + report%s\n\n' "$DIM" "$OFF"
pause 2

type_cmd "standbox_generate \"$USE_CASE\""
python3 - "$USE_CASE" <<'PY'
import sys
from standbox.report import build_report
r = build_report("agent", "kubectl", sys.argv[1], "bundles")
print("wrote", r["out_dir"] + "/sandbox.md")
PY
pause 2

printf '\n%s--- use cases tested against the gate (real gate runs) ---%s\n' "$BOLD" "$OFF"
python3 - "$USE_CASE" <<'PY'
import sys
from standbox.report import build_report
md = build_report("agent", "kubectl", sys.argv[1], "bundles")["markdown"]
i = md.find("## Use cases")
print(md[i:i + 1200] if i >= 0 else "(section not found)")
PY
pause 3

printf '\n%s--- run the gate directly ---%s\n' "$BOLD" "$OFF"
export PATH="$WORK/bundles/agent/kubectl/gate:$PATH"
export STANDBOX_REAL_BIN=/bin/echo
for c in "get deployments -n mfsada" \
         "port-forward svc/web 8080:80 -n mfsada" \
         "get secrets -n mfsada" \
         "get jobs -n mfsada" \
         "get pods -n prod" \
         "get pods -A"; do
  type_cmd "kubectl $c"
  kubectl $c
  pause 1.5
done

printf '\n%s--- one command to run it in a container ---%s\n' "$BOLD" "$OFF"
python3 - "$USE_CASE" <<'PY'
import sys
from standbox.report import build_report
md = build_report("agent", "kubectl", sys.argv[1], "bundles")["markdown"]
i = md.find("docker build")
j = md.find("\n\n", i)
print(md[i:j] if i >= 0 else "(container command not found)")
PY
printf '\n%s(the gated kubectl is the ONLY kubectl in that image)%s\n' "$DIM" "$OFF"
pause 3
