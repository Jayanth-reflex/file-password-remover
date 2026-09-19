# Contributing

## Getting set up

```bash
git clone https://github.com/Jayanth-reflex/file-password-remover
cd file-password-remover
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,sevenzip]"
make check          # everything CI runs
```

`make check` is `ruff check` + `ruff format --check` + `mypy --strict` +
`pytest` + `bandit` + `pip-audit`. If it passes locally it passes in CI; if it
does not, that is a bug in the Makefile worth reporting.

## The rules that are not negotiable

These are not style preferences. A pull request that breaks one of them will be
declined however good the rest of it is.

1. **No password guessing.** No candidate loops, no wordlists, no "try the
   empty password first", no retry after a rejection. One attempt per
   invocation.
2. **No bypasses.** Protection is removed only after the *format's own*
   verifier accepts the password. Permission restrictions on unencrypted
   content need the owner password and an explicit flag — see
   [ADR-0008](docs/adr/0008-owner-restriction-policy.md).
3. **No network code in `src/fpr/` or `src/fpr_gui/`.** A test enforces this by
   parsing every module.
4. **No success without verification.** If you add an adapter, `verify()` must
   re-open the written file and compare invariants. "It did not raise" is not
   verification.
5. **No claiming a capability that is not tested.** An untested path is
   experimental, is gated, and says so where the user can see it.

## Adding a format

Six steps, in this order:

1. **A fixture generator** in `src/fpr/testing/` that produces a *valid*
   protected file. Prefer an implementation independent of the library that
   will read it — see [ADR-0009](docs/adr/0009-own-fixture-generators.md).
   Never commit a binary sample, and never a real document.
2. **The adapter**: `sniff` / `detect` / `remove` / `verify` in
   `src/fpr/adapters/`. Register it in `registry.py`, most specific first.
3. **Tests**: round trip preserving content, wrong password writes nothing,
   corrupt file is not misreported as a wrong password, verification failure
   discards the output.
4. **The matrix**: a row in `docs/product/format-matrix.md` naming the fixture
   and the test.
5. **Licences**: if it needs a new dependency, add it to
   `docs/research/01-dependency-license-analysis.md` with its licence, latest
   release date and OSV status. Anything copyleft goes behind an optional
   extra.
6. **`fpr formats`** should describe it correctly with no extra work — that
   output is generated from the registry.

## Writing style for user-facing text

Error messages are the product's main documentation. They should say what
happened, why, and what the person can do instead. Compare:

> ✗ Error: decryption failed

> ✗ This PDF can already be opened without a password; it only carries
> permission restrictions, and the password you supplied is not its owner
> password.
>   Supply the owner password together with --remove-restrictions. This tool
>   will not strip restriction flags from a document you cannot prove you own.

Comments follow the same principle: explain the *why* that the code cannot.
`# increment i` is noise; `# qpdf recovers truncated files silently, so a
successful open is not evidence the document is intact` is the reason the next
line exists.

## Commit and PR conventions

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
`chore:`). One logical change per commit. A PR that touches a security control
must say which one and which test covers it.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).
