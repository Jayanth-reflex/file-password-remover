# CLI reference

```
fpr [--json] [-v|-q] COMMAND [options] FILE...
```

Five commands: `inspect`, `remove`, `protect`, `formats`, `version`.

---

## `fpr`

Run with no command, `fpr` prints the menu: every command, what it does, and
what it does to your files. The effect of each command is written in words as
well as carried in colour, so it reads the same in a CI log, in a terminal with
`NO_COLOR` set, and to a screen reader.

```
$ fpr
  FPR  1.1.0
  Remove or add password protection. Everything happens on this machine.

  ◆ inspect FILE  what protection is on this file?      reads only
  ◆ remove  FILE  write an unlocked copy                unlocks
  ◆ protect FILE  write a locked copy                   locks
  ◇ formats       what is supported, and what is not
  ◇ version       versions of everything involved

  TRY
  fpr inspect report.pdf
  fpr remove report.pdf
  fpr protect taxes.pdf --generate

  ──────────────────────────────────────────────
  fpr COMMAND --help for every option. Your original file is never changed.
  This tool never guesses, recovers or cracks a password.
```

The exit code is `2` (`USAGE`): no command ran. `fpr --help` still prints the
full option listing, and `fpr COMMAND --help` the options for one command.

---

## `fpr inspect FILE...`

Report what protection a file carries. **Never asks for a password and never
writes anything.** Use it to find out what you are holding before typing a
secret, or to plan a batch.

```
$ fpr inspect report.pdf
report.pdf
  format       PDF (pdf)
  protection   user-password
  algorithm    AES-256 (PDF 2.0, R6)
  removable    removable
  note         Encrypted. Supply the open (user) password or the owner password.
```

| Option | Meaning |
| --- | --- |
| `-r`, `--recursive` | Descend into directories |
| `--pattern GLOB` | Filter directory contents; repeatable; default `*` |

Identification is by content, not by extension. A `.docx` renamed to `.zip` is
still reported as an Office package, with `the file extension does not match
its contents` added.

---

## `fpr remove FILE...`

Decrypt with the password you supply and write an unprotected copy. The
original is never modified unless you ask for `--in-place`.

```
$ fpr remove report.pdf
Password:
✓ /home/you/report-unprotected.pdf
  removed      user-password
  algorithm    AES-256 (PDF 2.0, R6)
  size         2.3 MiB -> 2.2 MiB in 0.41s
  verified     encrypted=false, pages=12, content_digest=3f2a1c9d8e7b4a05, content_scope=all 12 page(s)
  original     /home/you/report.pdf (unchanged)
```

The `verified` line is not decoration. It is the result of re-opening the
written file from disk and comparing it against invariants captured from the
source; without it, no success is reported.

### Output

| Option | Meaning |
| --- | --- |
| `-o`, `--output PATH` | Exact output path. Single input only |
| `--output-dir DIR` | Directory for the copies; created if missing |
| `--suffix TEXT` | Suffix on the stem (default `-unprotected`) |
| `--overwrite` | Replace an existing output. Off by default |
| `--in-place` | Replace the original. Off by default, and still verified first |
| `--no-preserve-timestamps` | Do not copy the source's mtime onto the output |

The output is created with mode `0600` — it does **not** inherit a source file
that happened to be world-readable.

### Behaviour

| Option | Meaning |
| --- | --- |
| `--remove-restrictions` | Also clear PDF permission flags. Requires the owner password; see [ADR-0008](../adr/0008-owner-restriction-policy.md) |
| `--experimental` | Enable format support with no automated test coverage (legacy Office decryption) |
| `-r`, `--recursive` | Descend into directories |
| `--pattern GLOB` | Filter directory contents; repeatable |
| `--stop-on-error` | Abort a batch at the first failure instead of continuing |

### Password

Pick one. With none of these, the tool prompts on the terminal.

| Option | Exposure | Use when |
| --- | --- | --- |
| `--password-fd N` | none | scripting — the parent writes into a pipe |
| `--password-stdin` | none | shell pipelines |
| `--password-file PATH` | a file on disk (warns if group/world readable) | the password already lives in a protected file |
| *(nothing)* | none | interactive use |
| `--password-env VAR` | environment — **warns** | last resort; environments leak into crash dumps |

There is no `--password VALUE`. Command lines are readable by every process on
the machine and are saved in shell history, so the option is refused with an
explanation. See [ADR-0007](../adr/0007-no-password-on-argv.md).

---

## `fpr protect FILE`

Encrypt a file that has no password yet and write a protected copy. Supported
for PDF and ZIP; every other adapter refuses rather than writing an
unencrypted copy under a name that suggests otherwise.

```
$ fpr protect notes.pdf --generate
✓ PROTECTED  notes-protected.pdf
  applied      user-password
  algorithm    AES-256 (PDF 2.0, R6)
  size         48.2 KiB -> 49.1 KiB · 0.09s

  ENCRYPTED  DIGEST            PAGES
  true       3f2a1c9d8e7b4a05  12
  ──────────────────────────────────────────────
  saved to     /home/you/notes-protected.pdf
  original     /home/you/notes.pdf (unchanged)

  PASSWORD
  kwvzq-8mhtn-3pdxr-jc4bs-9vgqy
  Save this now. It is shown once, and this tool cannot recover it.
```

| Option | Meaning |
| --- | --- |
| `-o`, `--output PATH` | Exact output path (single input only) |
| `--output-dir DIR` | Directory for the protected copies |
| `--suffix TEXT` | Suffix added to the stem (default `-protected`) |
| `--overwrite` | Replace an existing output file |
| `--generate` | Generate a strong password instead of asking for one |
| `--password-out FILE` | Write the generated password to a file instead of printing it |

Password input otherwise follows the same routes as `remove`, and `--generate`
cannot be combined with a password you supply.

### Why there is no `--in-place`

Every other destructive option in this tool can be undone by reaching for the
original. Encrypting in place cannot: the tool refuses, by design, to crack a
password back open, so a lost password means a lost file. Four rules follow
from that, and all four are enforced:

- The password is surfaced only **after** the encrypted file exists on disk, so
  a crash between the two cannot leave a locked file whose password was never
  shown.
- `--generate` is refused for a batch. One password shown once, for several
  files, loses most of them.
- A file that is already protected is refused; remove the existing protection
  first.
- `--json` includes `generated_password`, because an agent that cannot read the
  password back out of the response has destroyed the file it was securing.

`--password-out` creates the file owner-only (`0600`) on macOS and Linux. On
Windows the mode argument only sets the read-only flag, so the file inherits
the directory's permissions — choose the directory accordingly.

---

## `fpr formats`

Everything the tool supports, everything it refuses, and the policy rules,
printed from the live registry rather than from a document that can drift.

## `fpr version`

Version, Python, platform, and the resolved version of every decryption
dependency including the bundled libqpdf. Attach this to bug reports.

---

## Global options

| Option | Meaning |
| --- | --- |
| `--json` | One machine-readable JSON object instead of prose |
| `-v`, `-vv` | More detail on stderr (info, then debug) |
| `-q`, `--quiet` | Errors only |
| `--version` | Print the version and exit |

`NO_COLOR` disables colour, as does any non-TTY stdout. `FPR_FORCE_COLOR`
turns it back on for a pipe. On Windows, virtual terminal processing is enabled
on the console handle at startup, so the same colour appears in `cmd.exe` and
PowerShell as in a macOS or Linux terminal; where the console refuses the mode
change, output falls back to plain text rather than printing escape bytes.

---

## Exit codes

Stable, and part of the contract. Anything other than `0` means nothing was
written.

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `OK` | Success, verified |
| 1 | `UNEXPECTED` | A bug — please report it |
| 2 | `USAGE` | Bad arguments |
| 3 | `WRONG_PASSWORD` | The format's verifier rejected the password |
| 4 | `UNSUPPORTED_FORMAT` | Not a format, or not a protection, that this tool handles |
| 5 | `CORRUPT_FILE` | Structurally damaged or truncated |
| 6 | `NOT_PROTECTED` | Nothing to remove |
| 7 | `OUTPUT_EXISTS` | Refusing to clobber; pass `--overwrite` |
| 8 | `IO_ERROR` | Permissions, disk, unreadable path |
| 9 | `VERIFICATION_FAILED` | The output failed its read-back check and was discarded |
| 10 | `POLICY_REFUSED` | Would be a bypass, not a removal |
| 11 | `DEPENDENCY_MISSING` | An optional extra is needed (e.g. `[sevenzip]`) |
| 12 | `PARTIAL_FAILURE` | A batch where at least one item failed |
| 130 | `INTERRUPTED` | Ctrl-C |

```bash
fpr remove secret.pdf --password-fd 3 3<<<"$PW"
case $? in
  0)  echo "done" ;;
  3)  echo "wrong password" ;;
  10) echo "refused: that would be a bypass" ;;
  *)  echo "failed with $?" ;;
esac
```

---

## Recipes

**A folder, one password, machine-readable:**
```bash
fpr --json remove ~/archive --recursive --pattern '*.docx' --output-dir ./clean
```

**Without the password touching argv, the environment or the disk:**
```bash
printf '%s' "$PASSWORD" | fpr remove book.pdf --password-stdin
```

**Plan first, act second:**
```bash
fpr --json inspect ~/archive -r | jq -r '.results[] | select(.removability=="removable") | .path'
```

**A PDF you own that only carries printing restrictions:**
```bash
fpr remove scan.pdf --remove-restrictions        # prompts for the OWNER password
```

**In a batch, tell apart "skipped" from "failed":**
```bash
fpr --json remove ./docs -r | jq '.items[] | select(.outcome=="failed")'
```
