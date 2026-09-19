# Independent review

## What kind of review this is

An adversarial pass over the repository whose job was to find places where the
claims and the code disagree. It re-ran the gates from the documentation rather
than from the implementer's summary, and it read the tests looking for ones
that cannot fail.

**It was not a third-party audit.** No external security firm, no second
organisation, no human reviewer other than the project's own. Saying so is part
of the review: a reader deciding how much weight to give this needs to know
what produced it. Treat it as a structured self-review with a hostile brief.

## Method

1. Re-ran `bash scripts/run_verification.sh` from a clean `dist/`.
2. Took every capability claim in `README.md` and traced it to a test or a
   documented limitation.
3. Read `tests/security/` asking: *could this test pass against a broken
   implementation?*
4. Grepped for the failure modes the brief names — fake integrations, empty
   implementations, placeholders, unverified platform claims.
5. Checked each ADR against the code it describes.

## Findings

### F-1 — A test that could not fail *(fixed)*

`test_every_control_is_reachable_from_the_keyboard` walked the focus ring of a
**withdrawn** window. ttk's `takefocus` handler reports that a widget declines
focus while it is not viewable, so the assertion would have passed just as
happily against a window containing no controls at all.

Fixed: the window is deiconified for the walk. Ledger 10.3.

### F-2 — A build step that reported success over a broken artifact *(fixed)*

PyInstaller printed *"Build complete!"* for a bundle whose entry point raised
`ImportError` on first run. Had the build script stopped at PyInstaller's exit
code, the release would have shipped a binary that cannot start.

Fixed: the build script now runs the artifact, decrypts a generated fixture
with it, and verifies the output with an independent check. Ledger 16.1.

### F-3 — A security control weaker than its docstring *(fixed)*

`reveal_in_file_manager` invoked `explorer` and `xdg-open` by bare name,
resolved through `PATH` — which anything running as the user can write. Found
by bandit (B603/B607).

Fixed by resolving absolute paths per platform and returning `None` when none
is found, rather than by suppressing the warning. Ledger 17.1.

### F-4 — A memory assertion that measured nothing *(fixed)*

`test_large_zip_streams_rather_than_buffering` built its 200 MiB fixture in a
`BytesIO` and *then* read `ru_maxrss` as a baseline. Since `ru_maxrss` is a
high-water mark, the baseline already contained the spike the test was supposed
to detect, so the assertion was unfalsifiable.

Fixed: the fixture is written straight to disk. Noted in
[performance.md](performance.md) because it is an easy mistake to reintroduce.

### F-5 — A documentation claim that was wrong *(fixed)*

The format matrix said qpdf "declines to write R5" PDFs, which was an
assumption, not a measurement. qpdf does write them, with a deprecation
warning. The claim was removed and R5 was added to the parametrised revision
test instead — turning a wrong sentence into a passing test.

### F-6 — Coverage that flatters *(accepted, documented)*

`legacy_office.py` sits at 60 % and `ooxml.py` at 77 %. Both gaps are real
untested code: legacy decryption and the ECMA-376 *standard* branch. No
coverage threshold is enforced, which is the right call — a threshold would
invite tests written to hit it — but it means the number needs the table in
the [verification report](verification-report.md) beside it to be meaningful.
Recorded as [L-04](known-limitations.md) and [L-05](known-limitations.md).

### F-7 — CI has never run *(open, disclosed)*

Three workflows exist, parse, and run commands that were each executed locally.
None has ever executed on GitHub, because the repository has no remote. A
reader could reasonably assume otherwise from the presence of
`.github/workflows/`.

Disclosed in the verification report's *Not verified* section and in the
production-readiness checklist (gate 8, "partly met"). Not fixable from here.

### F-8 — "Verified" is narrower than it sounds *(accepted, documented)*

The success line reads `verified encrypted=false, pages=12, …`. That proves the
output matches the *input*. It does not prove the input was complete — and qpdf
silently recovers truncated PDFs with fewer pages, so a truncated source
produces a faithful, successful-looking decryption of a truncated document.

The engine cannot do better without the missing bytes. Documented as
[L-10](known-limitations.md) and in
[ADR-0004](../adr/0004-verify-before-publish.md) under *What this does and does
not prove*, which is the right place for it.

## Checks against the brief's explicit prohibitions

| Prohibition | Verdict |
| --- | --- |
| No password cracking, brute force or bypass | **Clean.** No candidate loop exists; a test asserts no symbol matching `crack`/`bruteforce`/`wordlist`/`guess`; one attempt per invocation, asserted |
| No fake integrations or placeholders | **Clean.** No stub mobile project, no empty adapter, no TODO standing in for a feature. `grep -rn "TODO\|FIXME\|NotImplementedError" src/` returns nothing |
| No unverified platform claims | **Clean.** The README platform table distinguishes "built and tested here", "built in CI", and "not shipped" |
| Nothing marked complete without tests and evidence | **Clean**, with the deliberate exception of legacy Office decryption, which is marked *experimental* precisely because it has none |
| No unsupported case hidden behind a generic success | **Clean.** Every refusal names the rule and the reason; `NotProtectedError`, `UnsupportedFormatError` and `PolicyRefusedError` are distinct exit codes |
| All platform limitations documented | **Clean.** 25 entries in known-limitations, cross-referenced |

## Spot checks

| Check | Result |
| --- | --- |
| Does a wrong password ever leave an output file? | No, across every format — asserted per adapter |
| Does a verification failure leave an output file? | No — asserted, including a forced-failure test that writes a marker and greps the whole temp tree for it |
| Can the tool be made to open a PDF with `""` and write? | No — the empty-password open exists only in `detect()` and the classification check, both read-only, and a test asserts the file is untouched by it |
| Is `py7zr` really absent from the default install? | Yes — `verify_install.sh` asserts it, and CI has a job for it |
| Do the docs link to files that exist? | Yes — `scripts/check_docs.py`, 122 links |
| Is the version consistent? | Yes — `pyproject.toml`, `fpr.__version__` and `fpr version` all report 1.0.0 |

## Conclusion

The implementation matches its documentation, and where it falls short of the
brief it says so in the place a reader would look. Four defects were found and
fixed during the review (F-1 to F-5); three limitations were confirmed as
accurately disclosed rather than fixed (F-6 to F-8).

The single most important caveat is **F-7**: the CI configuration has never
run. Everything else has been executed and its output preserved.
