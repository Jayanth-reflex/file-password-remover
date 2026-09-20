## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The problem, not the patch. -->

## Checklist

- [ ] `make check` passes locally (lint, `mypy --strict`, tests, bandit, pip-audit)
- [ ] New behaviour has a test; a bug fix has a test that failed before it
- [ ] Documentation updated if behaviour changed — including `docs/product/format-matrix.md` for a format change
- [ ] `make docs-check` passes (no broken links)

### If this touches a security control

Name the control and the test that covers it. The rules in
[CONTRIBUTING.md](../CONTRIBUTING.md#the-rules-that-are-not-negotiable) are not
style preferences:

- [ ] No password guessing, retries, or fallbacks were added
- [ ] Nothing removes protection without the format's own verifier accepting a password
- [ ] No network code was added to `src/`
- [ ] Any new adapter verifies its output by re-reading it from disk

### If this adds a format

- [ ] A fixture generator produces a valid protected sample
- [ ] Round trip preserves content; wrong password writes nothing; a corrupt file is not misreported as a wrong password
- [ ] A row in `docs/product/format-matrix.md` naming the fixture and the test
- [ ] Any new dependency is recorded in `docs/research/01-dependency-license-analysis.md` with its licence and OSV status
