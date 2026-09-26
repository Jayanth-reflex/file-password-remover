# Threat model

Scope: `fpr` 1.1.0 — the CLI, the desktop app, the Python API and the iOS and
Android apps, running on a user's own device against files that user chose.

## What we are protecting

| Asset | Why it matters |
| --- | --- |
| **A-1** The user's password | Usually reused. Losing it costs more than losing the file. |
| **A-2** The decrypted content | The point of the exercise, and often the reason the file was encrypted. |
| **A-3** The original file | Irreplaceable. Corrupting it is the worst outcome this tool can produce. |
| **A-4** The fact that a particular file was processed | Metadata is data. Log lines and temp file names leak it. |
| **A-5** The user's trust in the success message | A false "done" leads to deleting the only good copy. |

## Trust boundaries

```
  user ──(argv, stdin, tty, GUI)──> fpr process ──(read)──> source file
                                        │
                                        ├──(write 0600)──> temp file ──(os.replace)──> output
                                        └──(stderr)──────> logs

  ✗ no network boundary exists: there is no socket in the package
```

Inside the process, the password crosses into third-party C extensions
(pikepdf/qpdf, pycryptodome, cryptography) as a `str` or `bytes`. That is a
trust boundary we can describe but not enforce; see R-07.

## Adversaries

| | Capability | In scope |
| --- | --- | --- |
| **T-1** Another local user | Read `/proc`, `ps`, world-readable files and temp directories | Yes |
| **T-2** Another process of the same user | Read the environment, argv, temp files, memory via debugger | Partly |
| **T-3** A malicious input file | Arbitrary bytes crafted to exploit a parser or exhaust resources | Yes |
| **T-4** Someone who later gets the disk | Forensic recovery of deleted temp files | Partly (see R-05) |
| **T-5** A supply-chain attacker | Malicious release of a dependency | Partly |
| **T-6** The tool's own operator | Trying to use it to bypass protection they are not entitled to | Yes — see [abuse-cases.md](abuse-cases.md) |
| **T-7** Someone with root / kernel access | — | **Out of scope.** Nothing user-space can defend against this. |

## Risks and controls

| ID | Risk | Control | Status |
| --- | --- | --- | --- |
| **R-01** | Password visible in `ps` / `/proc/<pid>/cmdline` | `--password VALUE` is refused outright; `--password-fd`, `--password-stdin`, `--password-file`, prompt | Mitigated — [ADR-0007](../adr/0007-no-password-on-argv.md) |
| **R-02** | Password written to shell history | No argv route exists | Mitigated |
| **R-03** | Password in logs or crash output | No code path logs it; a `RedactionFilter` scrubs credential-shaped text as defence in depth; `Secret.__repr__` and friends return a placeholder; pickling and copying raise | Mitigated — `tests/security/test_no_leaks.py` |
| **R-04** | Password persists in memory after use | `Secret` holds a `bytearray` zeroed on `close()` and again by `weakref.finalize` | **Partly** — see R-07 |
| **R-05** | Decrypted temp data recoverable from disk | Temp files are `0600` in a `0700` directory on the destination's own filesystem, overwritten with zeros then unlinked, scrubbed on every failure path | **Partly** — overwriting does not reliably erase on SSDs, APFS/Btrfs/ZFS, or journalled filesystems. Full-disk encryption is the real control. Documented, not papered over. |
| **R-06** | Output world-readable | Output inherits the temp file's `0600`, **not** the source's mode | Mitigated — `test_engine.py::test_output_is_not_world_readable_even_if_the_source_was` |
| **R-07** | Password copied into an unwipeable `str` | Unavoidable: every decryption API takes `str`/`bytes`. `Secret.expose()` keeps the window as narrow as the call. No `mlock` — it needs privileges, fails silently in containers, and would be security theatre. | **Accepted** |
| **R-08** | Malicious file exploits a parser | Attack surface is qpdf, pycryptodome, lxml and CPython's `zipfile`. Pinned, audited (OSV + pip-audit, weekly), and re-checked at release. No sandbox. | **Partly accepted** — see the note below |
| **R-09** | Telemetry or crash reports leak passwords/paths | None exists; enforced by an AST test over the whole package | Mitigated — [ADR-0002](../adr/0002-local-only-no-backend.md) |
| **R-10** | Decompression bomb exhausts disk or memory | 16 GiB total and 2000:1 per-entry ceilings on ZIP, checked while streaming | Mitigated — `test_zip.py::test_decompression_bomb_is_refused` |
| **R-11** | An unmaintained dependency stops receiving fixes | pyzipper had a four-year gap; replacing WinZip AES with our own code on top of `cryptography` is a few hundred lines if needed | **Accepted, monitored** |
| **R-12** | PDF and 7z fixtures share an implementation with the reader under test | Mitigated for Office and ZipCrypto (independent writers). For PDF, content invariants are compared rather than "it opened". | **Accepted** — [ADR-0009](../adr/0009-own-fixture-generators.md) |
| **R-13** | Path traversal from a crafted archive | 7z entry names are checked for absolute paths and `..` **before** extraction; ZIP output is written through `zipfile`, which does not extract to disk | Mitigated |
| **R-14** | Source file corrupted by the tool | The source is opened read-only. Output goes to a temp file and is published with `os.replace`; `--in-place` is opt-in and still goes through verification first | Mitigated — `test_engine.py` |
| **R-15** | False success on a damaged output | Post-write verification re-reads from disk and compares invariants; failure scrubs the output and exits 9 | Mitigated — [ADR-0004](../adr/0004-verify-before-publish.md) |
| **R-16** | Supply-chain compromise of a dependency | Pinned upper bounds, OSV + pip-audit in CI and weekly, licence and provenance recorded per release | **Partly** — no signature verification of wheels; `--require-hashes` installs are documented in [release.md](../ops/release.md) |

### On R-08, honestly

This tool parses hostile input for a living. It does not sandbox the parsers.
Doing it properly — seccomp/Landlock on Linux, App Sandbox on macOS, AppContainer
on Windows — is a real piece of work and platform-specific. What we do instead
is keep the dependency set small, pin it, scan it continuously, and never run
as a service or with elevated privileges. A user processing files from an
untrusted source should run the tool in a container or a VM. That is a
mitigation we are asking the user to apply, which is worth stating plainly
rather than burying.

## Adding protection

`fpr protect` runs the tool in the opposite direction, and it introduces a risk
class the rest of the tool does not have: software that encrypts a user's files
and controls the only key is, structurally, what ransomware does. The difference
has to be built in rather than promised.

| ID | Risk | Control | Status |
| --- | --- | --- | --- |
| **R-17** | A file is locked with a key the user never receives | The password is surfaced only *after* the output exists, so a failure between the two cannot produce a locked file with no key; `--json` returns a generated password so an automated caller keeps it too. Output streams replace characters the console cannot encode instead of raising, and if the report fails for any other reason the password is written to stderr before anything else. *Until 1.1.0 a file name the console could not encode -- a redirected `fpr protect 税务.pdf --generate` on Windows -- crashed the report before its last line, which is where the password was; found by the end-to-end suite* | Mitigated — `tests/integration/test_cli_protect.py`, `tests/e2e/test_features.py` |
| **R-18** | The original is destroyed along with access to it | There is no in-place mode for `protect`. The output is always a new file and the original is never written to | Mitigated — `test_protect_refuses_to_write_over_its_own_source` |
| **R-19** | A batch produces more passwords than anyone can keep | `protect` refuses more than one file per run | Mitigated |
| **R-20** | Two passwords end up nested on one file | Protecting an already-encrypted file is refused; the existing protection must be removed first | Mitigated |
| **R-21** | A generated password is predictable | `secrets` (Python), `SecRandomCopyBytes` with rejection sampling (Swift), `SecureRandom` (Kotlin); ~99 bits, and anything under 90 is refused | Mitigated — `tests/unit/test_passwords.py` |
| **R-22** | A generated password sits in terminal scrollback | `--password-out FILE` writes it to a `0600` file instead; on Android the clipboard copy is flagged `IS_SENSITIVE` | **Partly** — printing to a terminal is still the default, because a password nobody sees is worse |
| **R-24** | `--password-out` is not owner-only on Windows | The mode passed to `os.open` only sets the read-only flag there, so the file inherits the directory's ACLs. Stated in the `--password-out` help rather than implied by the POSIX behaviour | **Open** — choose the directory accordingly, or keep the password elsewhere |
| **R-25** | A chosen password is mistyped behind a mask | Every interface asks for a chosen password twice -- the CLI prompt, the desktop window, and both apps -- and protecting stays disabled until the two agree; the view models re-check before acting. *Until 1.1.0 the desktop, iOS and Android apps took one masked field, so a single wrong key produced a file nobody could open* | Mitigated — `tests/e2e/test_desktop.py`, `ios/UITests/JourneyUITests.swift`, `DocumentScreenJourneyTest.kt` |
| **R-23** | The file is encrypted but no longer holds the original content | The output is re-opened *with the password* and its content compared against the source before success is reported. "It is encrypted" alone would be satisfied by an empty encrypted file | Mitigated |

The honest residual: **this tool cannot get you back into a file whose password
you lost.** That is the same property that makes it safe — it has no cracking
code — and it is stated wherever a password is generated, not buried here.

## Explicitly out of scope

- A compromised operating system, kernel or root user (T-7).
- Hardware attacks: cold boot, DMA, side channels.
- The user choosing to publish the decrypted output.
- The user losing a password this tool generated and showed them. There is no
  recovery path, by design.
- Whether the user is *entitled* to the file. The tool enforces that they hold
  the password, which is the only thing software can check.

## Residual risk summary

| Severity | Open |
| --- | --- |
| Critical | none |
| High | none |
| Medium | R-05 (temp scrubbing on modern storage), R-08 (no parser sandbox) |
| Low | R-07, R-11, R-12, R-16, R-22, R-24 |

Every medium item is documented in the README or
[known-limitations.md](../reports/known-limitations.md) so a user can make
their own call.
