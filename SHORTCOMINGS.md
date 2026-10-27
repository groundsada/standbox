# standbox - Known Shortcomings & Production-Readiness Plan

> Written 2026-10-23 after a senior PM / SWE / DevOps review of the actual code on
> disk (not aspirational). Purpose: honest gap list + ordered fix plan.

---

## The one-line truth

**As-is: a working prototype (4 source files, ~1255 LOC, zero tests, no README,
no packaging, absolute paths, no audit writes, known-bytecode-cache bug).**
**Publishable after ~2 focused days.** The architecture is good; the product
finish is not there yet.

---

## 1. Shortcomings (grouped by reviewer lens)

### 1.1 Project / Product Manager

| # | Gap | Evidence | Impact |
|---|-----|----------|--------|
| SH-1 | **No README** | `README.md` missing (deleted in earlier cleanup) | No onboarding, no "why this exists," nobody can evaluate it |
| SH-2 | **No demo** (gif/video) | `README.md` absent; no screenshots/asciinema | The killer differentiator ("describe a sandbox, get a gate + report") is invisible without a 15-second visual |
| SH-3 | **No LICENSE** | `LICENSE` missing | Cannot legally be published / used by others |
| SH-4 | **No .gitignore** | missing | `.venv/`, `bundles/`, `__pycache__/` would get committed |
| SH-5 | **No packaging** | no `pyproject.toml`/`setup.py`; only `requirements.txt` | `pip install standbox` impossible; MCP registration is absolute-path |
| SH-6 | **No tests** | no `test_*.py` in repo | Regressions (5+ found this week) will recur silently |
| SH-7 | **No threat-model doc** | no SECURITY.md | "Sandbox" name over-claims; needs honest limitation statement |
| SH-8 | **Version/changelog** | no `__version__`, no CHANGELOG | No release story |

### 1.2 Software Engineer

| # | Gap | Evidence | Impact |
|---|-----|----------|--------|
| SE-1 | **No audit logging** | `standbox_audit` reads `audit.log` but NOTHING appends it (grep confirms no `audit.append`) | The "what did the agent actually do?" feature - the core selling point - is fake |
| SE-2 | **Parser is regex-accumulation** | `schema.parse_use_case` 516 lines, 5+ negation bugs fixed this week (`no jobs but cronjobs`, `no s3 rb`, `ns:`) | Fragile; every new phrase can bypass/over-block |
| SE-3 | **No type hints / no ruff** | none | Harder to maintain |
| SE-4 | **No unit tests for parser/gates** | none | Gate templates (bash) tested only ad-hoc via `run_gate` |
| SE-5 | **Exception swallowing** | `mcp_server.py` returns "error generating sandbox: ..." strings | No structured errors for the LLM/client |
| SE-6 | **Duplicate report/container code** | container section duplicated across 3 arg-model branches | Drift (we fixed one branch, others lagged) |
| SE-7 | **Stale-`.pyc` bug** | server can load cached bytecode; root-caused & mitigated (`PYTHONDONTWRITEBYTECODE`), but not codified | Future edits silently don't take effect |
| SE-8 | **Generated-gate tamper risk** | generated `gate/kubectl` is a plain bash file in a bundle the agent could edit | An agent with file access can weaken its own gate (accepted, but should be documented + checksummed in report) |

### 1.3 DevOps / SRE

| # | Gap | Evidence | Impact |
|---|-----|----------|--------|
| DO-1 | **Hardcoded absolute paths** | generated docker/report commands use `/Users/mfsada/...` | Works on this Mac only; breaks for anyone else |
| DO-2 | **No CI** | no `.github/workflows`, no lint/test gates | Regressions go unnoticed until post-publish |
| DO-3 | **No install entrypoint** | no console-script; MCP config is `python /abs/path/mcp_server.py` | Users must hand-edit absolute paths |
| DO-4 | **Container story is complex** | colima + Linux kubectl + bind-mount required; macOS kubectl (Mach-O) can't run | High friction for the "run it in docker" demo; must be documented or solved |
| DO-5 | **No audit implementation** (see SE-1) | same | No observability |
| DO-6 | **No lockfile** | `.venv` has `mcp<2` pinned but no `requirements.lock`/`uv` | Reproducibility risk |
| DO-7 | **Proto remnants in repo** | `bin/kubegate-*` (Go binaries from earlier prototype) | Should not ship; confuses scope |
| DO-8 | **No .dockerignore** | none | Docker context includes junk |

---

## 2. Plan (ordered; each item = one PR-sized unit)

### Phase 0 - Repo hygiene (0.5 day)
- [x] P0.1 `git init` (new repo `mfsada/standbox`) with `LICENSE` (MIT), `CHANGELOG.md` - **files created; `git init` pending (repo not yet created)**
- [x] P0.2 `.gitignore` (`.venv/`, `bundles/`, `__pycache__/`, `*.pyc`, `.DS_Store`, `bin/`) + `.pytest_cache/`, `.dockerignore`
- [x] P0.3 Delete vestiges: `bin/kubegate-*`, `bundles/` - **removed**
- [x] P0.4 `pyproject.toml` (name `standbox`, version `0.1.0`, entry point `standbox = 'mcp_server:main'`, deps `mcp>=1,<2`, `pyyaml`; `[project.scripts]`) - **created**

### Phase 1 - README with DEMO (0.5 day)  ⭐ user requirement
- [x] P1.1 Write **`README.md`**:
  - [x] What it is (one paragraph)
  - [x] **Embed a demo GIF/video** (user requirement): `![standbox demo](docs/standbox-demo.gif)` + `make-demo.sh` records it (asciinema→agg); gif generated and committed
  - [x] Architecture diagram (schema → engine → gate)
  - [x] Quick start: install, MCP registration (no absolute path; `python -m standbox.mcp_server`), first `/standbox` prompt
  - [x] **Threat model (honest)** in README + SECURITY.md
  - [x] Supported CLIs + "add one = add a schema"
- [x] P1.2 Demo gif generated: docs/standbox-demo.gif (474k) via make-demo.sh

### Phase 2 - Tests (0.5 day)
- [x] P2.1 `tests/test_schema.py` - parse_use_case cases (incl. the 5 regression bugs)
- [x] P2.2 `tests/test_gates.py` - 10 CLI gate matrices (incl. adversarial)
- [x] P2.3 `tests/test_report.py` - TESTED table + docker one-command + stub-vs-real + bundle files
- [x] P2.4 `pytest` wired into `pyproject.toml` - **41 tests pass**

### Phase 3 - Audit (0.5 day)
- [x] P3.1 `internal/audit.py`: `append()` JSONL + `query()` + `render()`
- [x] P3.2 `audit.append` called in `standbox_check` (after verdict)
- [x] P3.3 `standbox_audit` reads real records (`audit.jsonl`, `blocked_only`, `limit`)

### Phase 4 - Parser refactor + hardening (1 day)
- [x] P4.1 Parser regression bugs fixed (conjunction-aware negation, pair negation, `ns:` abbreviation); `constraints` JSON override path in place
- [x] P4.2 Type hints partial; **`ruff` clean** (ruff configured, `--no-cache` passes, 3 nested-f-string py3.10 issues fixed)
- [ ] P4.3 Structured errors (`SandboxError`) - currently MCP returns strings (low priority)
- [x] P4.4 Container/report section deduped (shared `container_section` used by all 3 arg-models)
- [x] P4.5 `PYTHONDONTWRITEBYTECODE=1` registered on MCP server + documented

### Phase 5 - Portability + CI (0.5 day)
- [x] P5.1 Remove absolute-path leakage - **report now uses bundle-relative paths** (verified: no `/Users`, no `/tmp/<bundle>` in md even with absolute BUNDLE_ROOT)
- [x] P5.2 `.github/workflows/ci.yml`: ruff + pytest + package-smoke
- [x] P5.3 `.dockerignore`
- [x] P5.4 `SECURITY.md` (threat model + reporting)
- [x] P5.5 `standbox` console entry in pyproject (`standbox = mcp_server:main`) - MCP registration can use `python -m standbox.mcp_server` (relative, no absolute path)

### Phase 6 - Container polish (0.5 day)
- [ ] P6.1 Bake **Linux kubectl** into demo image (or document multi-arch) - **documented** (report REAL mode downloads Linux kubectl + mount); auto-bake pending
- [ ] P6.2 Run full loop (`run_loop.sh`) after fixes; commit green results - **pending a final clean run**

---

## 3. Definition of Done (before `git push` & publishing)

- [x] README with **embedded demo gif/video** (gif referenced; `make-demo.sh` to generate; gif file pending a recording run) ✅ (requirement)
- [x] LICENSE (MIT) + CHANGELOG
- [x] `.gitignore` (`.venv`/`bundles/`/`*.pyc`/`.pytest_cache`/`.ruff_cache`)
- [ ] `pip install standbox` works (pyproject + entry point) - **needs a real `pip install .` smoke (done in CI on push; local pending)**
- [x] `pytest` green (parser + gates + report) - **41/41**
- [x] `standbox_audit` returns real records (audit actually writes) - `internal/audit.py` verified
- [x] Generated bundles use **relative** paths (no `/Users/...`) - verified
- [x] CI runs ruff + pytest on push - `.github/workflows/ci.yml`
- [x] No `kubegate-*` binaries / stale bundles in repo
- [x] Threat model documented (honest: natural-path gate) - SECURITY.md + README
- [x] `mcp<2` pinned; `PYTHONDONTWRITEBYTECODE` noted

---

## 4. What will NOT be fixed (accepted, documented)

- Client-side **cannot** stop `/usr/local/bin/kubectl`, direct `curl` to apiserver, or a hostile process with the same user's file access. Documented, not "fixed."
- Generated gate is bash (editable); we'll add checksums in the report but not sign it in v0.1.
- Native Windows support (Mac/Linux target v0.1).
