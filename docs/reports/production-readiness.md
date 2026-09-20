# Production-readiness checklist

Assessed against the quality gates in the project brief. Every row is either
**met** with evidence, or **not met** with a reason — nothing is marked met on
the strength of intent.

Assessment date: **2026-09-19**. Evidence: [verification-report.md](verification-report.md).

## Gates

| # | Gate | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Supported-format behaviour is documented and tested | **Met** | [format matrix](../product/format-matrix.md) names a fixture and a test for every supported row; experimental and refused rows are marked as such |
| 2 | The core and all adapters pass automated tests | **Met** | 277 tests pass; 89 % line coverage of `fpr` + `fpr_gui` |
| 3 | Incorrect passwords and corrupt files are handled safely | **Met** | Per-format wrong-password tests assert exit 3 and that no output exists; corrupt-file tests assert exit 5 and not exit 3 |
| 4 | Outputs are verified after processing | **Met** | [ADR-0004](../adr/0004-verify-before-publish.md); `test_verification_failure_discards_the_output` proves the negative case |
| 5 | Sensitive data is not exposed through logs, temp files, telemetry or crash reports | **Met** | `tests/security/test_no_leaks.py` (7 tests), `test_no_network.py` (AST scan of every module plus a live socket block) |
| 6 | Builds succeed for every claimed platform | **Partly met** | macOS arm64 bundle built, smoke-tested and screenshotted here. Linux and Windows bundles are built by CI, not on this host. The README says exactly that |
| 7 | Packaging and installation are tested | **Met** | `scripts/verify_install.sh` installs the wheel into a clean venv and performs real removals in it; the bundle script decrypts a fixture with the frozen binary |
| 8 | CI/CD checks pass | **Partly met** | Workflows are written and parse; every gate they run was executed locally and passed. **The workflows themselves have not run on GitHub** — there is no remote for this repository yet |
| 9 | Security and dependency scans have no unresolved critical or high findings | **Met** | bandit: 0 findings. pip-audit: no known vulnerabilities. OSV: 0 advisories across all 9 pinned dependencies |
| 10 | Accessibility checks are complete | **Partly met** | CLI: verified. Desktop: keyboard operability, labelling and non-colour signalling verified by test; **screen-reader and high-contrast behaviour not verified**, and no WCAG conformance is claimed for the window |
| 11 | Documentation matches the implementation | **Met** | `scripts/check_docs.py` proves every relative link resolves; `fpr formats` is generated from the live registry; every limitation has an ID |
| 12 | An independent review confirms the release is complete | **Met, with the caveat stated** | [independent-review.md](independent-review.md), which also states plainly what kind of review it was |
| 13 | Every remaining limitation is clearly documented | **Met** | [known-limitations.md](known-limitations.md), 25 entries, cross-referenced from the README and the threat model |

## Verdict

**Ready to publish as 1.0.0 for the CLI, the Python API and the macOS desktop
bundle**, with these conditions stated in the release rather than discovered by
users:

1. Linux and Windows bundles are built by CI and have not been run by a human
   on those platforms.
2. All bundles are unsigned. macOS and Windows will warn.
3. No mobile application ships.
4. The desktop window's screen-reader behaviour is unverified; screen-reader
   users should use the CLI.

None of these is a defect in the software. Each is a limit on what has been
*verified*, which is a different claim and the honest one.

## What would change the verdict

| Finding | Effect |
| --- | --- |
| Any test failure | Blocks the release |
| Any bandit or pip-audit finding above LOW | Blocks |
| A way to remove protection without a validated password | Blocks; it is the product's core claim |
| A false success on a damaged output | Blocks |
| A password reaching a log, argv or a surviving temp file | Blocks |
| A broken documentation link | Does not block, but fails CI |

## Sign-off

| Role | Scope | Outcome |
| --- | --- | --- |
| Implementation | Core, adapters, CLI, desktop | Complete for the claimed scope |
| Security | Threat model, abuse cases, leak and bypass tests | No unresolved high or critical findings |
| Test | 277 tests across unit, integration, security and performance | All pass |
| Release | Wheel, sdist, macOS bundle, checksums, install verification | Produced and verified |
| Review | Independent pass over evidence and claims | See [independent-review.md](independent-review.md) |
