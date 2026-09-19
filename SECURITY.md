# Security policy

## Reporting a vulnerability

Open a [private security advisory](https://github.com/Jayanth-reflex/file-password-remover/security/advisories/new)
on GitHub. Please do not open a public issue for anything that affects the
confidentiality of a password or a decrypted document.

Include: the version (`fpr version`), your OS, what you did, what happened, and
a file that reproduces it **only if it contains nothing you mind sharing** —
please generate one with `fpr.testing.fixtures` rather than sending a real
document.

What to expect: acknowledgement within 3 working days, an assessment within 10,
and a fix released before public disclosure for anything rated high or above.
Credit in the release notes unless you ask otherwise.

## What counts as a vulnerability here

The obvious ones — memory corruption, a path that writes outside the chosen
output, a way to read another user's password — and three that are specific to
this project:

1. **A policy bypass.** A way to make the tool remove protection without a
   validated password, or to strip PDF permission restrictions without the
   owner password. This is a vulnerability in this project even though it
   exposes nobody's data, because the policy layer *is* the product. See
   [ADR-0008](docs/adr/0008-owner-restriction-policy.md).
2. **A false success.** A way to make the tool report a verified removal over
   an output that is damaged, incomplete, or still protected. See
   [ADR-0004](docs/adr/0004-verify-before-publish.md).
3. **A leak.** Any route by which a password or decrypted content reaches a
   log, a temp file that survives, a crash report, an environment variable, or
   a command line.

## What is not a vulnerability

- **The tool decrypts a file for someone with the password.** That is the
  product. Software cannot tell whether the holder of a password is entitled to
  it.
- **The tool refuses to remove something.** Refusals are deliberate; see the
  [format matrix](docs/product/format-matrix.md).
- **A parser crash on a deliberately malformed file**, unless it is exploitable.
  Please still report it — a crash on hostile input is a bug worth fixing, just
  not a security advisory.
- **Weakness of the formats themselves.** ZipCrypto is broken and RC4-40 is
  broken; the tool says so in its output rather than pretending otherwise.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No |

## How the project defends itself

| Control | Where |
| --- | --- |
| No network code in the package, enforced by a test | `tests/security/test_no_network.py` |
| Password never on argv, enforced by a test | `tests/integration/test_cli.py` |
| Leak tests over logs, output, tracebacks and temp files | `tests/security/test_no_leaks.py` |
| Abuse cases with a refusal test each | `tests/security/test_no_bypass.py` |
| `bandit` static analysis, zero findings | CI, every push |
| `pip-audit` + OSV advisory query | CI, every push and weekly |
| Dependency licences and provenance recorded per release | `docs/research/01-dependency-license-analysis.md` |
| Secret scanning (gitleaks) | CI, every push |

Full analysis: [threat model](docs/security/threat-model.md),
[security design](docs/security/security-design.md),
[abuse cases](docs/security/abuse-cases.md).
