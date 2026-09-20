# Installation

## From PyPI (recommended)

```bash
pip install file-password-remover
```

Gives you `fpr` (command line) and `fpr-gui` (desktop window). Python 3.10 or
newer.

With 7-Zip support — a separate extra because `py7zr` is LGPL-2.1-or-later and
the default install stays permissive
([ADR-0006](../adr/0006-optional-lgpl-sevenzip-extra.md)):

```bash
pip install "file-password-remover[sevenzip]"
```

### Isolated, if you only want the command

```bash
pipx install file-password-remover
pipx install "file-password-remover[sevenzip]"
```

### Hash-pinned, for a locked-down environment

```bash
pip install --require-hashes -r requirements.lock
```

Generate the lock file yourself — do not trust one you did not produce:

```bash
pip install pip-tools
pip-compile --generate-hashes --output-file requirements.lock pyproject.toml
```

## Docker

The image exists because the [threat model](../security/threat-model.md)'s R-08
says the parsers are not sandboxed and recommends processing untrusted files in
a container. This is that container.

```bash
docker pull ghcr.io/jayanth-reflex/file-password-remover:latest
```

Pass `--user` so the output belongs to you rather than to the image's uid, and
mount the directory you are working in:

```bash
# Inspect -- no password needed, nothing written
docker run --rm -v "$PWD:/data" --user "$(id -u):$(id -g)" \
  ghcr.io/jayanth-reflex/file-password-remover inspect /data/report.pdf

# Remove -- the password goes in over stdin, never in argv
printf '%s' "$PASSWORD" | docker run --rm -i -v "$PWD:/data" \
  --user "$(id -u):$(id -g)" \
  ghcr.io/jayanth-reflex/file-password-remover \
  remove /data/report.pdf --password-stdin
```

Add `--network none` to make the "it never uploads anything" claim something
the kernel enforces rather than something you take on trust:

```bash
docker run --rm --network none -v "$PWD:/data" --user "$(id -u):$(id -g)" \
  ghcr.io/jayanth-reflex/file-password-remover inspect /data/report.pdf
```

The image runs as a non-root user, contains no build toolchain, and
deliberately omits `py7zr`, so `.7z` is not supported inside it
([ADR-0006](../adr/0006-optional-lgpl-sevenzip-extra.md)). If you need it:

```dockerfile
FROM ghcr.io/jayanth-reflex/file-password-remover
USER root
RUN pip install --no-cache-dir py7zr
USER fpr
```

### Verifying the image

Images are built, run and *tested* before they are pushed — the workflow
decrypts a PDF, a DOCX and a ZIP inside the image and checks that a wrong
password still exits 3 — then signed with cosign keyless signing:

```bash
cosign verify ghcr.io/jayanth-reflex/file-password-remover:latest \
  --certificate-identity-regexp '^https://github.com/Jayanth-reflex/file-password-remover/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Standalone bundle (no Python needed)

Download the archive for your platform from the
[releases page](https://github.com/Jayanth-reflex/file-password-remover/releases),
then **verify it before running it**:

```bash
shasum -a 256 -c SHA256SUMS      # macOS / Linux
certutil -hashfile file-password-remover-Windows-X64.zip SHA256   # Windows
```

| Platform | Archive | Unpack to |
| --- | --- | --- |
| macOS (Apple silicon / Intel) | `…-macOS-ARM64.tar.gz` / `…-macOS-X64.tar.gz` | `~/Applications` or anywhere |
| Linux (glibc 2.28+) | `…-Linux-X64.tar.gz` | `~/.local/opt` |
| Windows 10+ | `…-Windows-X64.zip` | `%LOCALAPPDATA%\Programs` |

```bash
tar xzf file-password-remover-macOS-ARM64.tar.gz
./file-password-remover/fpr version
./file-password-remover/fpr-gui        # the desktop window
```

Put it on your `PATH` if you want to type `fpr` from anywhere:

```bash
mkdir -p ~/.local/bin
ln -s "$PWD/file-password-remover/fpr" ~/.local/bin/fpr
```

### The bundles are not signed

They are built by GitHub Actions and are **not** code-signed or notarised.
Signing needs an Apple Developer identity and a Windows code-signing
certificate, which this project does not hold; the steps are written up in
[release.md](release.md) for anyone who does.

Practical consequences:

- **macOS** shows *"cannot be opened because the developer cannot be
  verified"*. Right-click → **Open** once, or
  `xattr -d com.apple.quarantine file-password-remover/*`, after you have
  checked the SHA-256.
- **Windows** shows a SmartScreen warning. *More info* → *Run anyway*, after
  checking the hash.

If that is not acceptable in your environment — and it is a reasonable position
— use `pip install`, which verifies the package through PyPI instead.

## From source

```bash
git clone https://github.com/Jayanth-reflex/file-password-remover
cd file-password-remover
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,sevenzip]"
make check
```

## Checking it works

```bash
fpr version     # version, platform, and every decryption dependency
fpr formats     # what is supported, what is refused, and the policy rules
```

End to end, with a file the tool generates itself so you are not testing with
anything of your own:

```bash
python - <<'PY'
from pathlib import Path
from fpr.testing import fixtures as F
Path("demo.pdf").write_bytes(F.make_pdf(F.PdfSpec(user="demo-pw", owner="demo-owner")))
PY
printf 'demo-pw' | fpr remove demo.pdf --password-stdin
```

You should see a `verified encrypted=false, pages=3, …` line and a
`demo-unprotected.pdf` beside the original.

## Platform notes

**Linux.** Some distributions ship Python without Tk. If `fpr-gui` reports
`No module named 'tkinter'`, install it: `sudo apt install python3-tk`
(Debian/Ubuntu), `sudo dnf install python3-tkinter` (Fedora). The `fpr` command
does not need it.

**macOS.** The system Python at `/usr/bin/python3` works. If `fpr-gui` looks
wrong or fails to start, use a python.org or Homebrew Python — Apple's build of
Tk has historically lagged.

**Windows.** Use the official python.org installer or `winget install
Python.Python.3.12`. The Microsoft Store build sandboxes file access in ways
that make choosing files awkward.

## Removing it

See [uninstall.md](uninstall.md).
