# Changelog

All notable changes to standbox are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); version follows SemVer.

## [Unreleased]

### Added
- Production hardening sprint: SHORTCOMINGS.md gap list + plan
- README with embedded demo gif (docs/standbox-demo.gif via make-demo.sh)
- LICENSE (MIT), CHANGELOG, SECURITY (threat model)
- pyproject.toml packaging + `standbox` console entry point
- Real audit logging (internal/audit.py: append/query/render; standbox_audit now reads real records)
- Test suite: parser regressions, 10-CLI gate matrices (incl. adversarial), report integrity (41 tests)

### Fixed
- parser: "no jobs but cronjobs ok" no longer drops cronjobs
- parser: "no s3 rb" denies the pair, not the whole service
- parser: "ns mfsada" abbreviation parsed; "no namespaces list" no longer leaks `list`
- parser: read-only hyphenated + negation-phrase (conjunction-aware)
- gate: subcommand prefix-matching (gcloud `describe x` / `list --filter` now allowed)
- gate: single-word verbs with args (npm run build), exact-match (no false allow)
- gate: shell metachar/compound hard-deny; `-A`, `--privileged`, `-auto-approve` hard-denied
- gate: SQL keyword scan normalizes punctuation (CTE-wrapped DML blocked); -f blocked
- report: stub-vs-real distinction, Linux-kubectl REAL mode (macOS Mach-O cannot run in Linux containers)
- report: container one-command uses `--entrypoint bash` (no more `BLOCKED: verb 'bash'`)
- schema: git moved from verb_resource_name to subcommand (verb-only CLIs didn't need a resource positional)
- server: PYTHONDONTWRITEBYTECODE (no stale .pyc) ; removed proto `kubegate-*` binaries from repo
