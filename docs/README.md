<div align="center">

# Documentation

**[← Back to the README](../README.md)**

</div>

---

## Start here

| I want to… | Read |
| :--- | :--- |
| Install it | [install.md](ops/install.md) — pip, pipx, Docker, standalone bundles |
| Use the command line | [cli.md](ops/cli.md) — every flag, exit code and recipe |
| Know whether my file is supported | [format-matrix.md](product/format-matrix.md) |
| Know what it refuses to do, and why | [format-matrix.md](product/format-matrix.md) and [abuse-cases.md](security/abuse-cases.md) |
| Remove it again | [uninstall.md](ops/uninstall.md) |

## Verify a claim rather than trust it

Every promise in the README has something you can run or read.

| Claim | Proof |
| :--- | :--- |
| "It never uploads anything" | [`tests/security/test_no_network.py`](../tests/security/test_no_network.py) — parses every module for networking imports, then blocks `socket.connect` and performs a real removal |
| "It never claims success without checking" | [ADR-0004](adr/0004-verify-before-publish.md) · `test_pdf.py::test_verification_failure_discards_the_output` |
| "It refuses to bypass protection" | [ADR-0008](adr/0008-owner-restriction-policy.md) · [`tests/security/test_no_bypass.py`](../tests/security/test_no_bypass.py) |
| "It does not leak the password" | [`tests/security/test_no_leaks.py`](../tests/security/test_no_leaks.py) |
| "The dependencies are clean" | [Licence analysis](research/01-dependency-license-analysis.md) + [raw evidence](research/evidence/) |
| "This format really works" | [Format matrix](product/format-matrix.md) names the fixture and the test for every row |
| "Here is what it does *not* do" | [Known limitations](reports/known-limitations.md) — 25 entries, each with an ID |

## By area

<table>
<tr><th align="left">Product</th><th align="left">Design</th></tr>
<tr valign="top"><td>

- [Requirements](product/requirements.md)
- [Supported-format matrix](product/format-matrix.md)
- [Accessibility](product/accessibility.md)
- [Localization](product/localization.md)

</td><td>

- [Architecture decision records](adr/) — 10
- [Project dependency graph](graph/project-graph.md)
- [Build ledger](graph/node-ledger.md) — every failure and fix

</td></tr>
<tr><th align="left">Security</th><th align="left">Research</th></tr>
<tr valign="top"><td>

- [Threat model](security/threat-model.md) — assets, adversaries, R-01…R-16
- [Security design](security/security-design.md)
- [Abuse cases](security/abuse-cases.md) — AB-01…AB-14
- [Privacy statement](../PRIVACY.md)
- [Reporting a vulnerability](../SECURITY.md)

</td><td>

- [Open-source landscape](research/00-open-source-landscape.md)
- [Dependency licences and advisories](research/01-dependency-license-analysis.md)
- [Format notes and upstream findings](research/02-format-notes.md)
- [Raw evidence](research/evidence/) — PyPI and OSV responses

</td></tr>
<tr><th align="left">Quality</th><th align="left">Operations</th></tr>
<tr valign="top"><td>

- [Verification report](reports/verification-report.md)
- [Production-readiness checklist](reports/production-readiness.md)
- [Independent review](reports/independent-review.md)
- [Known limitations](reports/known-limitations.md)
- [Performance](reports/performance.md)

</td><td>

- [CLI reference](ops/cli.md)
- [Install](ops/install.md) · [Uninstall](ops/uninstall.md)
- [Build](ops/build.md)
- [Release process](ops/release.md)

</td></tr>
</table>

## The four documents worth reading even if you never use the tool

1. **[Format notes](research/02-format-notes.md)** — nine things about PDF,
   OOXML and ZIP encryption that are not obvious from the specifications, each
   with a reproduction. Including an upstream encryptor that writes a malformed
   container, and why a PDF with an empty *owner* password is not protected at
   all.
2. **[ADR-0004](adr/0004-verify-before-publish.md)** — why "the write call
   returned" is not the same as "the file is good", and what it costs to
   actually check.
3. **[ADR-0008](adr/0008-owner-restriction-policy.md)** — the line between
   removing a password you hold and stripping a restriction you cannot
   authenticate against. This is the decision the product is built on.
4. **[Build ledger](graph/node-ledger.md)** — sixteen failures, what caused
   each one, and what was re-run after the fix. A build record with no failures
   in it was written afterwards.

## Conventions used here

- **Limitations have IDs** (`L-04`), **risks have IDs** (`R-08`), **abuse cases
  have IDs** (`AB-03`), and **policy rules have IDs** (`R1`–`R5`). They are
  referenced across documents so a claim can be traced.
- **"Not verified" means not verified.** Where something was not tested, the
  documents say so rather than implying coverage — see the closing section of
  the [verification report](reports/verification-report.md).
- **Every relative link is checked in CI** by
  [`scripts/check_docs.py`](../scripts/check_docs.py).
