# agents.md — File Password Remover, for AI agents

This file is for an AI agent (or the person prompting one) that needs to use
`fpr` — either by shelling out to it, or by wrapping it as a tool. It is
generated from the same source of truth as the human docs and kept in sync;
nothing here is aspirational. Human docs: <https://github.com/Jayanth-reflex/file-password-remover>.

## What this is

`fpr` removes password protection from a file **after being given the
correct password**. It runs entirely on the local machine: no network code
exists in the package (enforced by a test that parses every module and blocks
`socket.connect`), so nothing about the file or the password can be exfiltrated
by this tool, by design, not by configuration you could disable.

**It does not crack, guess, brute-force, or bypass anything.** There is no
retry loop, no dictionary, no flag that makes it try candidate passwords. This
is a hard boundary, not a missing feature — do not build a retry loop around
it. A wrong password fails once, cleanly, with a distinct exit code.

## Install (non-interactive, for a sandbox or CI)

```bash
pipx install git+https://github.com/Jayanth-reflex/file-password-remover
# or, without pipx:
pip install "file-password-remover[sevenzip] @ git+https://github.com/Jayanth-reflex/file-password-remover"
```

Or run it in a container with no host install at all:

```bash
docker run --rm -v "$PWD:/data" --user "$(id -u):$(id -g)" \
  ghcr.io/jayanth-reflex/file-password-remover inspect /data/report.pdf
```

Not yet on PyPI — the `git+` form above is required until it is (the release
workflow is wired for PyPI Trusted Publishing but not yet activated). Do not
trust a PyPI package of this name appearing before the project's README says
otherwise.

## The two commands you need

### `fpr inspect FILE` — read-only, no password required

Tells you what kind of protection a file has before you decide what to do.
Always call this before `remove` if you are deciding programmatically.

```bash
fpr --json inspect report.pdf
```

```json
{
  "ok": true,
  "results": [
    {
      "ok": true,
      "path": "/abs/path/report.pdf",
      "format": "pdf",
      "format_name": "PDF",
      "protection": "user-password",
      "removability": "removable",
      "algorithm": "AES-256 (PDF 2.0, R6)",
      "extension_mismatch": false,
      "detail": "Encrypted. Supply the open (user) password or the owner password."
    }
  ]
}
```

`removability` is the field to branch on: `removable`, `restrictions-only`
(needs the owner password and `--remove-restrictions`, see below), or
`refused` (DRM/IRM — this tool will not touch it, and neither should your
agent try another way).

### `fpr remove FILE --password-stdin` — the only way to pass a password

```bash
printf '%s' "$PASSWORD" | fpr --json remove report.pdf --password-stdin
```

```json
{
  "ok": true,
  "source": "/abs/path/report.pdf",
  "output": "/abs/path/report-unprotected.pdf",
  "format": "pdf",
  "protection_removed": "user-password",
  "algorithm": "AES-256 (PDF 2.0, R6)",
  "bytes_in": 3091,
  "bytes_out": 2422,
  "duration_s": 0.019,
  "verification": {
    "encrypted": "false",
    "pages": "3",
    "content_digest": "456cf7bce5ff12ef",
    "content_scope": "all 3 page(s)",
    "docinfo_keys": "/Producer,/Title",
    "has_xmp": "true"
  },
  "warnings": []
}
```

**`ok: true` alone is not the strongest signal available — the `verification`
block is.** It is a re-read of the file from disk after writing, not a copy of
what the tool intended to do. If your agent's next step depends on the output
being trustworthy (attaching it, forwarding it, deleting the original), check
`verification`, not just the exit code.

**There is no `--password VALUE` flag, on purpose** — command-line arguments
are visible to every process on the machine via `ps`, and land in shell
history. Give an agent the password only through one of these:

| Flag | Use when |
| :--- | :--- |
| `--password-stdin` | The password is already in a variable in your process |
| `--password-fd N` | You're forking and can hand over an open file descriptor |
| `--password-file PATH` | The password is in a `0600` file (warns if it isn't) |

Never construct a shell command that interpolates the password as a literal
argument. If your tool-calling framework only supports passing a fixed argv
list without stdin, use `--password-file` against a temp file you create with
mode `0600` and delete immediately after.

## Adding protection

`fpr protect` locks a file that has no password yet. It is the inverse of
`remove`, and the rules are stricter because a generated password is the only
copy that will ever exist -- this tool refuses to crack, so losing it destroys
the file.

```bash
fpr --json protect notes.pdf --generate
```

The generated password comes back in the JSON, because an agent that cannot
read it back has destroyed the file it just made:

```json
{
  "ok": true,
  "output": "/abs/path/notes-protected.pdf",
  "protection_applied": "user-password",
  "algorithm": "AES-256 (PDF 2.0, R6)",
  "verification": {
    "encrypted": "true",
    "opens": "true",
    "pages": "3",
    "content_digest": "456cf7bce5ff12ef"
  },
  "generated_password": "w5zd-mzy4-d6g8-s4g5-npvk"
}
```

**Store `generated_password` before you do anything else.** Use
`--password-out FILE` to have it written to a `0600` file instead of stdout if
your transcript is logged.

To set a password the user chose, pipe it in as usual -- it is not echoed back:

```bash
printf '%s' "$PASSWORD" | fpr --json protect notes.pdf --password-stdin
```

What it refuses, and why arguing will not help:

- **More than one file per run.** A batch of generated passwords is how people
  lose them.
- **An already-encrypted file.** Nesting two passwords means two things to lose.
  Remove the existing protection first.
- **Writing over the original.** There is no in-place mode. If the only key were
  lost, the file would be gone.
- **Formats other than PDF and ZIP.** Office and 7-Zip can be *opened* but not
  locked. The refusal says so; do not fall back to writing an unencrypted copy.

## Exit codes — branch on these, not on stdout text

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `OK` | Success, verified |
| 1 | `UNEXPECTED` | A bug in the tool — do not retry, surface it |
| 2 | `USAGE` | Bad arguments — a prompting/wiring bug on your side |
| 3 | `WRONG_PASSWORD` | The password was rejected. **Do not retry with variations; ask the user.** |
| 4 | `UNSUPPORTED_FORMAT` | Not a format, or not a protection type, this tool handles |
| 5 | `CORRUPT_FILE` | Structurally damaged or truncated input |
| 6 | `NOT_PROTECTED` | Nothing to remove — the file was never encrypted |
| 7 | `OUTPUT_EXISTS` | Refusing to overwrite; pass `--overwrite` if that's actually intended |
| 8 | `IO_ERROR` | Permissions, disk, unreadable path |
| 9 | `VERIFICATION_FAILED` | The write happened but the read-back check failed; output was discarded. **Treat as a failure even though a file may have briefly existed — nothing usable was left behind.** |
| 10 | `POLICY_REFUSED` | What you asked for would be a bypass, not a removal (see below) |
| 11 | `DEPENDENCY_MISSING` | An optional extra is needed, e.g. `pip install ...[sevenzip]` |
| 12 | `PARTIAL_FAILURE` | Batch mode: at least one item in the batch failed |
| 130 | `INTERRUPTED` | Ctrl-C / SIGINT |

## Boundaries your agent should not try to route around

If any of these produce a refusal, that is the correct, final answer — do not
retry with a different flag, a different tool, or a shell one-liner that
reimplements the removal:

- **`POLICY_REFUSED` (10)** — asking to strip PDF permission flags (printing,
  copying, editing disabled) without the *owner* password. Supplying the owner
  password and `--remove-restrictions` explicitly is the only legitimate path;
  there is no way to do this with only the user password, and there should not
  be — that is the difference between removing protection and bypassing it.
- **DRM / IRM / certificate-based encryption** — `inspect` reports these and
  `remove` refuses them outright. There is no flag that overrides this.
- **A wrong password (`WRONG_PASSWORD`, 3)** — is not evidence the *right*
  password is close; do not iterate over candidate strings.

## Batch and scripting

```bash
fpr --json remove ~/inbox --recursive --pattern '*.pdf' --output-dir ./clean \
  | jq '.items[] | select(.outcome=="failed")'
```

```bash
fpr --json inspect ~/inbox -r | jq -r '.results[] | select(.removability=="removable") | .path'
```

## Formats

| Format | Protection handled |
| :--- | :--- |
| `.pdf` | Standard security handler R2–R6 (RC4-40/128, AES-128/256) |
| `.docx` `.xlsx` `.pptx` (+12 more) | ECMA-376 agile (2010+) and standard (2007) |
| `.zip` | WinZip AES-128/192/256, legacy ZipCrypto |
| `.7z` | AES-256, incl. encrypted headers (needs the `sevenzip` extra) |
| `.doc` `.xls` `.ppt` | RC4/CryptoAPI — **experimental**, needs `--experimental` |

Full matrix: <https://github.com/Jayanth-reflex/file-password-remover/blob/main/docs/product/format-matrix.md>

## Not available

- **No PyPI package yet.** Install via `git+` as shown above.
- **No iOS or Android app**, and no APK — deliberate, see
  [ADR-0010](https://github.com/Jayanth-reflex/file-password-remover/blob/main/docs/adr/0010-no-mobile-app-this-release.md).
  Don't fabricate a mobile install path for a user who asks; point them at the
  CLI running under Termux/a-Shell, or at the desktop build.
- **No API server, no webhook, no hosted endpoint.** This is a local binary.
  If a task implies "send this file to a service to unlock it," that service
  is not this project, and running one that receives files and passwords is
  exactly the pattern this tool exists to avoid.

## Full reference

- CLI reference (every flag): <https://github.com/Jayanth-reflex/file-password-remover/blob/main/docs/ops/cli.md>
- Threat model: <https://github.com/Jayanth-reflex/file-password-remover/blob/main/docs/security/threat-model.md>
- Verification design (what `verification` in the JSON actually proves): <https://github.com/Jayanth-reflex/file-password-remover/blob/main/docs/adr/0004-verify-before-publish.md>
- Machine-summary index: <https://file-password-remover.vercel.app/llms.txt>
