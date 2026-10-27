"""Tests for schema.parse_use_case - includes every regression bug we hit."""

from standbox import schema


def verbs(cli, text):
    return schema.parse_use_case(cli, text)["verbs"]


def resources(cli, text):
    return schema.parse_use_case(cli, text)["resources"]


def deny(cli, text):
    return schema.parse_use_case(cli, text)["deny"]


def namespaces(cli, text):
    return schema.parse_use_case(cli, text)["namespaces"]


# ---- regression: "no jobs but cronjobs ok" must NOT drop cronjobs ----
def test_cronjobs_survives_but_jobs():
    c = schema.parse_use_case(
        "kubectl",
        "only namespace mfsada, crud on pods and deployments, port-forward allowed, no jobs but cronjobs ok, no secrets")
    assert "cronjobs" in c["resources"]
    assert "jobs" not in c["resources"]
    assert "jobs" in c["deny"]
    assert "secrets" in c["deny"]
    assert "port-forward" in c["verbs"]


# ---- regression: "no s3 rb" denies only s3 rb, keeps s3 ls ----
def test_aws_s3_rb_denies_pair_not_service():
    c = schema.parse_use_case("aws", "read-only describe/list on s3 and ec2, no delete, no s3 rb")
    assert "s3 ls" in c["verbs"]
    assert "s3 rb" in c["deny"]
    assert "ec2 describe-instances" in c["verbs"]


# ---- regression: "ns mfsada" abbreviation parsed ----
def test_ns_abbreviation():
    c = schema.parse_use_case("kubectl", "ns mfsada, get pods, no secrets")
    assert "mfsada" in c["namespaces"]


# ---- regression: "no namespaces list" must not leak "list" as namespace ----
def test_no_namespaces_does_not_leak():
    c = schema.parse_use_case("kubectl", "read only deployments, no namespaces list")
    assert "list" not in c["namespaces"]


# ---- regression: "read-only" (hyphenated) must not imply write ----
def test_read_only_hyphen_detected():
    c = schema.parse_use_case("gh", "read-only issues and prs, no release create")
    assert "pr list" in c["verbs"]
    assert "release create" in c["deny"]


# ---- regression: "no create" must not set wants_write ----
def test_no_create_not_write_trigger():
    c = schema.parse_use_case("kubectl", "read only deployments, no create, no exec, no port-forward")
    assert "create" not in c["verbs"]
    assert "exec" not in c["verbs"]
    assert "port-forward" not in c["verbs"]
    # genuinely read-only verb set
    assert {"get", "list", "watch"} <= set(c["verbs"])


# ---- subcommand models ----
def test_terraform_single_word():
    c = schema.parse_use_case("terraform", "read-only: plan and validate only, no apply, no destroy")
    assert "plan" in c["verbs"]
    assert "apply" in c["deny"]
    assert "destroy" in c["deny"]


def test_gcloud_three_level():
    c = schema.parse_use_case("gcloud", "read-only: compute instances list/describe, no ssh, no delete, no iam roles create")
    assert "compute instances list" in c["verbs"]
    assert "compute instances ssh" in c["deny"]
    assert "iam roles create" in c["deny"]


def test_npm_run_allowed_exec_absent():
    c = schema.parse_use_case("npm", "read-only: run and ls only, no install, no publish")
    assert "run" in c["verbs"]
    assert "install" in c["deny"]


# ---- psql returns sql model ----
def test_psql_read_only():
    c = schema.parse_use_case("psql", "READ-ONLY SQL: SELECT WITH SHOW only. DENY DROP DELETE UPDATE INSERT")
    assert c["verbs"]  # read keywords present
    assert "drop" in c["deny"]


# ---- unsupported CLI ----
def test_unsupported():
    assert schema.parse_use_case("git-unknown", "x") is None
