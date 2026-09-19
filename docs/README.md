# Documentation map

| | |
| --- | --- |
| **Start here** | [Product requirements](product/requirements.md) · [Supported-format matrix](product/format-matrix.md) |
| **Using it** | [CLI reference](ops/cli.md) · [Install](ops/install.md) · [Uninstall](ops/uninstall.md) |
| **Design** | [Architecture decision records](adr/) · [Project graph](graph/project-graph.md) · [Node ledger](graph/node-ledger.md) |
| **Security** | [Threat model](security/threat-model.md) · [Security design](security/security-design.md) · [Abuse cases](security/abuse-cases.md) |
| **Research** | [Open-source landscape](research/00-open-source-landscape.md) · [Dependency licences](research/01-dependency-license-analysis.md) · [Format notes](research/02-format-notes.md) |
| **Quality** | [Verification report](reports/verification-report.md) · [Production readiness](reports/production-readiness.md) · [Independent review](reports/independent-review.md) · [Known limitations](reports/known-limitations.md) · [Performance](reports/performance.md) |
| **Inclusion** | [Accessibility](product/accessibility.md) · [Localization](product/localization.md) |
| **Building** | [Build](ops/build.md) · [Release](ops/release.md) |
| **Mobile** | [Why no mobile app ships](../mobile/README.md) |

## If you are here to check a claim

| Claim | Where it is proved |
| --- | --- |
| "It never uploads anything" | `tests/security/test_no_network.py` — an AST scan of every module, plus a live socket block during a real removal |
| "It never claims success without checking" | [ADR-0004](adr/0004-verify-before-publish.md); `test_pdf.py::test_verification_failure_discards_the_output` |
| "It refuses to bypass protection" | [ADR-0008](adr/0008-owner-restriction-policy.md); `tests/security/test_no_bypass.py` |
| "It does not leak the password" | `tests/security/test_no_leaks.py` |
| "The dependencies are clean" | [licence analysis](research/01-dependency-license-analysis.md) + `docs/research/evidence/*.json` |
| "This format really works" | [format matrix](product/format-matrix.md) names the fixture and the test for each row |
| "What it does *not* do" | [known limitations](reports/known-limitations.md), 25 entries |
