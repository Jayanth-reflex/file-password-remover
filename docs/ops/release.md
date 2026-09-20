# Release process

## Overview

Tagging `v*` triggers `.github/workflows/release.yml`, which builds the wheel
and sdist, builds a desktop bundle on each of macOS/Linux/Windows, smoke-tests
every one of them, writes checksums, and opens a **draft** release. Nothing is
published without a human pressing the button.

## Before tagging

```bash
make check                 # lint, types, tests, bandit, pip-audit
make test-slow             # performance suite
make evidence              # refresh dependency licence + advisory JSON
make build checksums
bash scripts/verify_install.sh
make bundle                # and run the bundle yourself
python scripts/gui_screenshot.py artifacts/gui-$(uname -s).png --completed
```

Then the paperwork, which is part of the release and not an afterthought:

- [ ] `CHANGELOG.md` has an entry with today's date
- [ ] `pyproject.toml` version and `fpr/__init__.py::__version__` agree
- [ ] `docs/reports/verification-report.md` regenerated from this run
- [ ] `docs/reports/known-limitations.md` still true
- [ ] `docs/research/01-dependency-license-analysis.md` matches
      `make evidence` output
- [ ] Every platform claim in `README.md` is backed by evidence — including
      the rows that say *not built*
- [ ] `make docs-check` passes

### Dry-run the artifact pipeline first

Running the release workflow by hand builds the wheel and all three desktop
bundles and smoke-tests each one, without creating anything public — the
publish job requires a tag, so a manual run skips it.

```bash
gh workflow run release.yml --ref main
gh run watch "$(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Do this before tagging. Discovering that the Windows bundle job is broken
halfway through a release is worse than spending ten minutes proving it is not.

### Then tag

```bash
git tag -a v1.0.0 -m "1.0.0"
git push origin v1.0.0
```

## Signing

**The published bundles are unsigned.** This is stated in the install guide and
in the draft release body rather than left for users to discover. The steps
below are for whoever holds the identities.

### macOS

```bash
# 1. Sign every Mach-O in the bundle, inside out.
codesign --force --options runtime --timestamp \
         --sign "Developer ID Application: NAME (TEAMID)" \
         dist/file-password-remover/fpr \
         dist/file-password-remover/fpr-gui

# 2. Notarise.
ditto -c -k --keepParent dist/file-password-remover fpr-macos.zip
xcrun notarytool submit fpr-macos.zip \
      --apple-id "APPLE_ID" --team-id "TEAMID" --password "APP_SPECIFIC_PASSWORD" \
      --wait

# 3. Staple, so it validates offline.
xcrun stapler staple dist/file-password-remover/fpr-gui
xcrun stapler validate dist/file-password-remover/fpr-gui
```

Needs: an Apple Developer Program membership, a Developer ID Application
certificate in the keychain, and an app-specific password. The hardened runtime
(`--options runtime`) is required for notarisation.

### Windows

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
         /f codesign.pfx /p $env:CERT_PASSWORD `
         dist\file-password-remover\fpr.exe dist\file-password-remover\fpr-gui.exe
signtool verify /pa /v dist\file-password-remover\fpr.exe
```

Needs an OV or EV code-signing certificate. An EV certificate is what actually
clears SmartScreen quickly; an OV one builds reputation slowly.

### Linux

No signing convention for a tarball. If you publish a `.deb` or `.rpm`, sign
the repository metadata with `debsign` / `rpm --addsign`. A detached GPG
signature over `SHA256SUMS` is a reasonable minimum:

```bash
gpg --armor --detach-sign --output dist/SHA256SUMS.asc dist/SHA256SUMS
```

## Publishing to PyPI

The `pypi` job in the release workflow does this with **Trusted Publishing**,
so no API token is stored in the repository. It is skipped until the one-time
setup below is done, so a release never fails on a publisher that does not
exist yet.

### One-time setup (needs the PyPI account)

1. Sign in to PyPI and open
   [Publishing → Add a new pending publisher](https://pypi.org/manage/account/publishing/).
2. Fill in:
   - **PyPI project name**: `file-password-remover`
   - **Owner**: `Jayanth-reflex`
   - **Repository**: `file-password-remover`
   - **Workflow name**: `release.yml`
   - **Environment name**: `pypi`
3. In the GitHub repository, create the `pypi` environment
   (*Settings → Environments → New environment*). Add a required reviewer if
   you want a human gate on every publish.
4. Set the repository variable that arms the job:
   ```bash
   gh variable set PYPI_PUBLISH --body true
   ```
5. Remove the "not on PyPI yet" notes from `README.md` and
   `docs/ops/install.md`. They exist so the documented install is one that
   actually works; leaving them behind after publishing is its own kind of
   wrong.

After that, pushing a `v*` tag publishes the wheel and sdist with
[PEP 740 attestations](https://peps.python.org/pep-0740/) proving they were
built by this workflow.

### Manually, if you must

```bash
python -m twine check dist/*
python -m twine upload dist/*.whl dist/*.tar.gz
```

Only the wheel and sdist go to PyPI. The desktop bundles are release assets,
and the container image goes to GHCR from `container.yml`.

## App stores

Not used. The Mac App Store requires sandbox entitlements that would make
arbitrary file access awkward for a tool whose entire job is arbitrary file
access, and the Microsoft Store adds a packaging format for no benefit here.
Neither is a technical blocker; both are a deliberate scope decision.

## Verifying a published release

```bash
shasum -a 256 -c SHA256SUMS
python -m pip download file-password-remover==1.0.0 --no-deps -d /tmp/check
shasum -a 256 /tmp/check/*.whl
codesign --verify --deep --strict --verbose=2 file-password-remover/fpr-gui   # once signed
spctl --assess --type execute --verbose file-password-remover/fpr-gui
```

## Rollback

Releases are immutable on PyPI: a bad release is **yanked**, not deleted, and
replaced by a patch version.

```bash
# mark 1.0.0 as yanked on PyPI (web UI or twine), then
git tag -a v1.0.1 -m "1.0.1 - fix <thing>"
git push origin v1.0.1
```

Delete the GitHub release assets for the bad version and say why in the
changelog. Users who already downloaded it keep working software, which is
exactly why yanking beats deleting.

## Human steps that cannot be automated

| Step | Why | Needed for |
| --- | --- | --- |
| Apple Developer membership + Developer ID certificate | Apple issues them to identified people | macOS bundles without a Gatekeeper warning |
| Notarisation credentials | Tied to that account | Stapled macOS bundles |
| Windows code-signing certificate | A CA must vet the organisation | Windows bundles without SmartScreen |
| PyPI project ownership | Account-bound | Publishing |
| Release approval | Judgement | Every release |
