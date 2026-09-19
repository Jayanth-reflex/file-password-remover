# Building

## Prerequisites

Python 3.10+, `make`, and a C toolchain only if a dependency has no wheel for
your platform (in practice pikepdf, lxml and cryptography all ship wheels for
macOS, Linux and Windows on x86-64 and arm64).

```bash
make venv install
make check          # lint, types, tests, bandit, pip-audit
```

## Targets

| Command | What it does |
| --- | --- |
| `make check` | Everything CI runs. Green here means green there |
| `make test` | Fast suite, skipping the performance tests |
| `make test-all` | Everything, with coverage into `artifacts/` |
| `make test-slow` | Only the performance tests |
| `make lint` / `make format` | ruff check / ruff fix + format |
| `make typecheck` | `mypy --strict` over `src/` |
| `make security` | bandit, JSON report into `artifacts/` |
| `make audit` | `pip-audit` |
| `make evidence` | Refresh dependency licence and advisory evidence (needs network) |
| `make build` | Wheel and sdist into `dist/` |
| `make bundle` | Standalone desktop bundle for the current platform |
| `make checksums` | SHA-256 for everything in `dist/`, verified immediately |
| `make docs-check` | Every relative Markdown link resolves |

## The Python distribution

```bash
make build
python -m twine check dist/*
bash scripts/verify_install.sh
```

`verify_install.sh` is the one that matters. It creates a **clean** virtualenv,
installs the built wheel, confirms both console scripts exist, asserts that
`py7zr` is *absent* (it must stay an optional extra), generates protected PDF,
DOCX and ZIP fixtures, removes protection from each, and checks that a wrong
password still exits 3 without writing anything. Building a wheel proves
nothing; running it in an environment that has never seen the source tree
proves something.

## The desktop bundle

```bash
make bundle
```

Runs PyInstaller against `packaging/pyinstaller/fpr.spec`, which produces one
directory containing both entry points (`fpr` and `fpr-gui`) sharing their
dependencies via `MERGE`.

The script then smoke-tests what it built: it runs `version` and `formats` from
the *bundle*, generates an encrypted PDF with the *source tree*, removes the
protection with the bundle, and verifies the output independently. A bundle
that builds but cannot decrypt is not a successful build, and the script exits
non-zero to say so.

Two things in the spec are load-bearing:

- **`copy_metadata`** for pikepdf, msoffcrypto-tool, pyzipper, cryptography,
  olefile and lxml. `fpr version` reads dependency versions through
  `importlib.metadata`, and pikepdf's `dist-info` carries the IJG licence text
  that libjpeg-turbo's terms require to accompany redistribution. Dropping the
  metadata breaks the command *and* creates a licence problem.
- **`excludes=["py7zr", …]`** keeps the LGPL dependency out of the binary; see
  [ADR-0006](../adr/0006-optional-lgpl-sevenzip-extra.md).

The frozen entry points are `packaging/pyinstaller/entry_cli.py` and
`entry_gui.py`. They exist because PyInstaller runs its entry script as
`__main__`, which breaks relative imports if you point it at a module inside
the package.

### Expected size

Around 70 MiB unpacked on macOS arm64, most of it CPython, Tk and libqpdf.

## Reproducibility

Builds are **not** bit-for-bit reproducible today. PyInstaller embeds
timestamps and paths, and wheel metadata varies with the build environment. The
mitigation is checksums published with each release and a
`scripts/verify_install.sh` run that anyone can repeat. Making the wheel
reproducible (`SOURCE_DATE_EPOCH`) would be a small change; the bundle would
need more work.

## Cross-building

Not attempted. Each platform's bundle is built on that platform, by the
`bundles` job in `.github/workflows/release.yml`. Cross-building CPython
bundles with native extensions is possible and fragile, and CI runners make it
unnecessary.

## Troubleshooting

**`No module named 'tkinter'`** — install the Tk package for your Python
(`python3-tk`, `python3-tkinter`), or use the CLI, which does not need it.

**PyInstaller cannot find `fpr`** — build from the repository root; the spec's
paths are relative to it.

**The bundle starts but cannot open PDFs** — `copy_metadata` was probably
dropped from the spec, so pikepdf's data files did not make it in.

**The GUI tests hang on macOS** — you are creating more than one `Tk()` root in
one process. `tests/integration/test_gui.py` uses a session-scoped root for
exactly this reason.
