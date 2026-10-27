"""Gate enforcement tests - run the generated bash gates against a matrix of
ALLOW/BLOCK cases (including adversarial)."""
import os
import shutil
import tempfile

import pytest

from standbox.report import build_report, run_gate

SCENARIOS = {
    "kubectl": {
        "use_case": "only namespace mfsada, crud on pods and deployments, port-forward allowed, no jobs but cronjobs ok, no secrets",
        "cases": [
            (["get", "pods", "-n", "mfsada"], 0),
            (["patch", "deployments/x", "-n", "mfsada", "-p", "{}"], 0),
            (["port-forward", "svc/x", "8080:80", "-n", "mfsada"], 0),
            (["get", "cronjobs", "-n", "mfsada"], 0),
            (["get", "secrets", "-n", "mfsada"], 3),
            (["get", "jobs", "-n", "mfsada"], 3),
            (["get", "pods", "-n", "prod"], 3),
            (["get", "--raw", "/api"], 3),
            (["get", "pods", "-A"], 3),
        ],
    },
    "docker": {
        "use_case": "no persistent mounts, read-only rootfs, no network",
        "cases": [
            (["run", "--rm", "-it", "img", "cmd"], 0),
            (["run", "-v", "/host:/c", "img"], 3),
            (["run", "--privileged", "img"], 3),
        ],
    },
    "git": {
        "use_case": "read-only: status log diff, no push, no commit",
        "cases": [(["status"], 0), (["push"], 3), (["commit", "-m", "x"], 3)],
    },
    "gh": {
        "use_case": "read-only issues and prs, no release create",
        "cases": [
            (["pr", "list"], 0),
            (["issue", "view", "1"], 0),
            (["release", "create"], 3),
            (["pr", "create"], 3),
        ],
    },
    "aws": {
        "use_case": "read-only s3 ls and ec2 describe, no s3 rb",
        "cases": [
            (["s3", "ls", "s3://b"], 0),
            (["ec2", "describe-instances", "--region", "us-east-1"], 0),
            (["s3", "rb", "s3://b"], 3),
            (["ec2", "terminate-instances"], 3),
        ],
    },
    "terraform": {
        "use_case": "read-only: plan, validate, state list only. no apply, no destroy, no -auto-approve",
        "cases": [
            (["plan"], 0),
            (["plan", "-input=false"], 0),
            (["state", "list"], 0),
            (["apply"], 3),
            (["destroy"], 3),
            (["plan", "-auto-approve"], 3),
            (["plan", ";", "echo", "x"], 3),  # shell metachar
            (["plan", "&&", "terraform", "apply"], 3),  # compound
        ],
    },
    "helm": {
        "use_case": "read-only: list, get, history, repo list. NO install, NO upgrade, no uninstall",
        "cases": [
            (["list", "-n", "dev"], 0),
            (["get", "all", "rel", "--no-hooks"], 0),
            (["list", "-A"], 3),  # all-namespaces
            (["install", "x", "chart"], 3),
            (["upgrade", "x", "chart"], 3),
        ],
    },
    "npm": {
        "use_case": "read-only: run, ls, view, audit. NO install, NO uninstall, NO publish, NO exec, NO ci, NO --force",
        "cases": [
            (["run", "build"], 0),
            (["ls", "--depth=0"], 0),
            (["install", "--force", "x"], 3),
            (["publish"], 3),
            (["exec", "rm"], 3),
            (["ci"], 3),
        ],
    },
    "gcloud": {
        "use_case": "read-only: compute instances list/describe, config list ONLY. NO ssh, NO start, NO stop, NO delete, NO create, NO deploy",
        "cases": [
            (["compute", "instances", "list"], 0),
            (["compute", "instances", "describe", "x"], 0),
            (["compute", "instances", "list", "--filter=name:foo"], 0),
            (["compute", "instances", "ssh", "x"], 3),
            (["compute", "instances", "delete", "x"], 3),
            (["storage", "rm", "-r", "gs://b"], 3),
            (["iam", "roles", "create", "r"], 3),
        ],
    },
    "psql": {
        "use_case": "READ-ONLY SQL: allow SELECT, WITH, SHOW, EXPLAIN. DENY: DROP, DELETE, UPDATE, INSERT, TRUNCATE, ALTER, CREATE, GRANT, COPY, \\copy",
        "cases": [
            (["-c", "SELECT * FROM users"], 0),
            (["-c", "WITH x AS (SELECT 1) SELECT * FROM x"], 0),
            (["-c", "DROP TABLE users"], 3),
            (["-c", "DELETE FROM users WHERE id=1"], 3),
            (["-c", "UPDATE users SET x=1"], 3),
            (["-c", "INSERT INTO users VALUES (1)"], 3),
            (["-c", "WITH x AS (DELETE FROM t RETURNING 1) SELECT 1"], 3),  # CTE DML
            (["-c", "SELECT 1; DROP TABLE t"], 3),  # multi-statement
            (["-f", "/tmp/evil.sql"], 3),  # file include
        ],
    },
}


@pytest.mark.parametrize("cli", list(SCENARIOS.keys()))
def test_gate_matrix(cli):
    sc = SCENARIOS[cli]
    tmp = tempfile.mkdtemp()
    try:
        r = build_report("t", cli, sc["use_case"], tmp)
        gate = os.path.join(r["out_dir"], cli, "gate", cli)
        src = open(gate).read()
        for argv, expect in sc["cases"]:
            code, _ = run_gate(src, argv)
            assert code == expect, (
                f"{cli} {' '.join(argv)!r} -> {code}, expected {expect}")
    finally:
        shutil.rmtree(tmp)
