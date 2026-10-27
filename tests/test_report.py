"""Report integrity tests: every generated sandbox.md must have the tested
table, the docker one-command, and the stub-vs-real distinction."""
import os
import shutil
import tempfile

import pytest

from standbox.report import build_report

CLIS = ["kubectl", "docker", "git", "gh", "aws", "terraform", "helm", "npm", "gcloud", "psql"]


@pytest.mark.parametrize("cli", CLIS)
def test_report_has_required_sections(cli):
    tmp = tempfile.mkdtemp()
    try:
        r = build_report("t", cli, "read-only, no write", tmp)
        md = r["markdown"]
        assert "TESTED against the gate" in md, f"{cli}: missing tested table"
        assert "ONE command" in md or "one-command" in md.lower(), f"{cli}: missing docker one-command"
        assert "ACTUALLY runs" in md, f"{cli}: missing stub-vs-real distinction"
        assert "docker build" in md, f"{cli}: missing raw docker build"
        assert ".real" in md, f"{cli}: missing real target mount note"
    finally:
        shutil.rmtree(tmp)


@pytest.mark.parametrize("cli", CLIS)
def test_report_generates_bundle_files(cli):
    tmp = tempfile.mkdtemp()
    try:
        r = build_report("t", cli, "read-only, no write", tmp)
        out = r["out_dir"]
        assert os.path.isfile(os.path.join(out, cli, "gate", cli)), f"{cli}: gate missing"
        assert os.path.isfile(os.path.join(out, cli, "container", "Dockerfile")), f"{cli}: Dockerfile missing"
        assert os.path.isfile(os.path.join(out, cli, "container", "run.sh")), f"{cli}: run.sh missing"
        assert os.path.isfile(os.path.join(out, cli, "container", "standbox-gate")), f"{cli}: staged gate missing"
    finally:
        shutil.rmtree(tmp)


@pytest.mark.parametrize("cli,use_case", [
    ("git", "read-only: status log diff. no push, no commit"),
    ("terraform", "read-only: plan, validate, state list. no apply, no destroy"),
])
def test_subcommand_tested_rows_use_real_commands(cli, use_case):
    """Single-word subcommands must be tested bare (`git status`), not with a
    fabricated `list` argument."""
    tmp = tempfile.mkdtemp()
    try:
        md = build_report("t", cli, use_case, tmp)["markdown"]
        assert " status list " not in md, f"{cli}: fabricated 'status list' test row"
        assert " plan list " not in md, f"{cli}: fabricated 'plan list' test row"
    finally:
        shutil.rmtree(tmp)
