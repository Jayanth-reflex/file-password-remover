# Project dependency graph

The build was run as a directed graph of nodes. A node could not start until
its prerequisites had produced their artifacts, and every edge carries an
explicit validation, failure condition and recovery path. This document is the
map; [node-ledger.md](node-ledger.md) is the record of what actually happened
at each one, including the failures.

## Legend

| Field | Meaning |
| --- | --- |
| **In** | artifact(s) the node consumes |
| **Out** | artifact(s) the node must produce |
| **Validate** | the command or review that decides pass/fail |
| **Fail if** | the condition that makes the node red |
| **Recover** | what happens on failure |

Owners are the agent roles from the brief: Research, Architecture, Product,
Implementation, Security, Test, Release, Review.

```
 1 audit ──┬─> 2 research ──┬─> 3 scope ──> 4 boundaries ──┐
           │                │                              │
           └────────────────┴─> 5 stack ──> 6 structure ───┼─> 7 core
                                                           │      │
                                     ┌─────────────────────┘      v
                                     │            ┌──────────> 8 adapters ──┐
                                     │            │                 │        │
                                    12 secure-io ─┘                 v        v
                                                              9 CLI    10 desktop
                                                                 │        │
                                          11 mobile (design only)─┴────────┤
                                                                           v
                              13 fixtures ──> 14 tests ──> 15 CI ──> 16 build ──> 17 review
                                                    ^                               │
                                                    └────────── 18 fix loop ────────┘
                                                                                    v
                                                                    19 docs ──> 20 sign-off
```

## Nodes

### 1. Discover and audit the repository — Research
- **In**: working directory, host toolchain
- **Out**: `docs/research/evidence/` (toolchain inventory), decision to start a
  new repository rather than extend an existing one
- **Validate**: `ls`, `python3 -V`, per-tool `--version` sweep
- **Fail if**: no Python ≥ 3.10, or no network for dependency resolution
- **Recover**: fall back to a vendored-dependency design (not needed)

### 2. Research open-source implementations — Research
- **In**: node 1
- **Out**: [`docs/research/00-open-source-landscape.md`](../research/00-open-source-landscape.md),
  [`01-dependency-license-analysis.md`](../research/01-dependency-license-analysis.md),
  [`02-format-notes.md`](../research/02-format-notes.md),
  `docs/research/evidence/{pypi-metadata.json,osv-scan-deps.json}`
- **Validate**: every candidate has a cited source; release dates and licences
  read from PyPI's own JSON API and the installed wheels, not from memory;
  advisories queried from OSV
- **Fail if**: a candidate's licence is incompatible, or has unresolved
  high-severity advisories
- **Recover**: reject the candidate and record why (done for unrar; py7zr
  moved to an optional extra over LGPL)

### 3. Product scope and format matrix — Product
- **In**: node 2
- **Out**: [`docs/product/requirements.md`](../product/requirements.md),
  [`format-matrix.md`](../product/format-matrix.md)
- **Validate**: every row in the matrix maps to either a tested adapter or an
  explicit "unsupported, because"
- **Fail if**: a format is listed as supported with no implementation behind it
- **Recover**: demote the row to unsupported/experimental

### 4. Security, privacy, legal and abuse boundaries — Security
- **In**: node 3
- **Out**: [`docs/security/threat-model.md`](../security/threat-model.md),
  [`abuse-cases.md`](../security/abuse-cases.md), `src/fpr/policy.py`
- **Validate**: `pytest tests/security` — each abuse case has a test that
  proves the tool refuses
- **Fail if**: any abuse case is unmitigated and untested
- **Recover**: implement the refusal, or document the residual risk with an ID

### 5. Stack comparison and selection — Architecture
- **In**: nodes 2, 4
- **Out**: [ADR-0001](../adr/0001-language-and-runtime.md) …
  [ADR-0010](../adr/0010-no-mobile-app-this-release.md)
- **Validate**: each ADR states alternatives, consequences and a reversal cost
- **Fail if**: a decision has no recorded alternative

### 6. Repository structure and module contracts — Architecture
- **In**: node 5
- **Out**: `pyproject.toml`, package layout, `src/fpr/adapters/base.py`
- **Validate**: `mypy --strict`, `ruff check`
- **Fail if**: type checking fails, or an adapter can bypass the engine

### 7. Shared processing core — Implementation
- **In**: node 6
- **Out**: `engine.py`, `types.py`, `errors.py`, `registry.py`, `policy.py`
- **Validate**: `pytest tests/unit tests/integration/test_engine.py`
- **Fail if**: an output is published without verification
- **Recover**: scrub the output, raise `VerificationError` (exit 9)

### 8. Format adapters — Implementation
- **In**: nodes 7, 13
- **Out**: `adapters/{pdf,ooxml,zipfiles,sevenzip,legacy_office}.py`
- **Validate**: `pytest tests/integration`
- **Fail if**: a round trip loses content, or a wrong password is misreported
- **Recover**: fix the adapter, re-run the adapter's suite *and* the engine and
  security suites (see node 18)

### 9. CLI — Implementation
- **In**: node 7
- **Out**: `cli/{main,output,password_input}.py`, [`docs/ops/cli.md`](../ops/cli.md)
- **Validate**: `pytest tests/integration/test_cli.py` (exit codes tested in a
  real child process)
- **Fail if**: a password can reach `argv`, or an exit code is wrong

### 10. Desktop applications — Implementation
- **In**: nodes 7, 9
- **Out**: `src/fpr_gui/app.py`, PyInstaller specs, packaging scripts
- **Validate**: `pytest -m gui`, `scripts/build_desktop.sh`, screenshot
- **Fail if**: the window cannot complete a removal, or a control is
  unreachable from the keyboard

### 11. Mobile — Product / Architecture
- **In**: nodes 3, 5
- **Out**: [`mobile/README.md`](../../mobile/README.md) — a design and a
  **negative result**: no mobile app ships in this release
- **Validate**: review against "no unverified platform claims"
- **Fail if**: the repository implies a mobile build exists
- **Recover**: n/a — the honest outcome is the deliverable

### 12. Secure file, password, memory and temp handling — Security
- **In**: node 6
- **Out**: `secret.py`, `securefs.py`, `logging_setup.py`
- **Validate**: `pytest tests/unit/test_secret.py tests/unit/test_securefs.py
  tests/security`
- **Fail if**: a secret survives `close()`, or a temp file outlives a failure

### 13. Fixtures and test specification — Test
- **In**: nodes 2, 3
- **Out**: `src/fpr/testing/{cfb,ooxml_agile,zipcrypto,fixtures}.py`
- **Validate**: fixtures are accepted by an *independent* reader (olefile,
  msoffcrypto, pyzipper, stdlib zipfile)
- **Fail if**: a fixture cannot be produced for a claimed format
- **Recover**: mark the format experimental (done for legacy Office decryption)

### 14. Automated tests — Test
- **In**: nodes 8–13
- **Out**: `tests/`, `artifacts/coverage.xml`
- **Validate**: `pytest -q --cov`
- **Fail if**: any test fails, or coverage of the removal path regresses

### 15. CI/CD, static analysis, dependency and secret scanning — Release
- **In**: node 14
- **Out**: `.github/workflows/{ci,security,release}.yml`
- **Validate**: workflow syntax check; the same commands run locally
- **Fail if**: a gate is present in CI but cannot be run locally

### 16. Build and package every target — Release
- **In**: nodes 14, 15
- **Out**: `dist/` wheel + sdist, PyInstaller bundles, checksums
- **Validate**: `scripts/build_all.sh`, `shasum -c`, install-into-clean-venv smoke test
- **Fail if**: a claimed platform does not build
- **Recover**: mark that platform "built in CI only" or "not built" — never
  claim it (see the platform table in the verification report)

### 17. Compatibility, performance, accessibility, security review — Security / Test / Review
- **In**: node 16
- **Out**: [`docs/reports/`](../reports/)
- **Validate**: `pytest -m slow`, `bandit`, `pip-audit`, accessibility checklist
- **Fail if**: an unresolved high-severity finding exists

### 18. Fix and re-verify — all
- **In**: any red node
- **Out**: the fix, plus a re-run of the failing node **and every node
  downstream of it**
- **Validate**: the original failing command, then the full suite
- **Fail if**: a fix is made without re-running dependents

### 19. Release documentation and artifacts — Release
- **In**: nodes 16, 17
- **Out**: `CHANGELOG.md`, install/uninstall, release notes, checksums

### 20. Independent production-readiness review — Review
- **In**: everything
- **Out**: [`docs/reports/production-readiness.md`](../reports/production-readiness.md),
  [`independent-review.md`](../reports/independent-review.md)
- **Validate**: a pass that re-runs the gates from the documentation alone,
  without trusting the implementer's summary
- **Fail if**: documentation and implementation disagree
