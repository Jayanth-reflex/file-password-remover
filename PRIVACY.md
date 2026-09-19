# Privacy

## The short version

File Password Remover does not collect, store or transmit anything.

It reads the file you point it at, writes the output you ask for, and exits.
There is no account, no licence check, no update check, no analytics, no crash
reporting, and no network code in the package at all.

## What the software touches

| | |
| --- | --- |
| **Reads** | the input file you select; a password file, pipe or environment variable, if you choose one of those |
| **Writes** | the output file you asked for; a temporary file in the output's directory, which is deleted when the run ends |
| **Sends** | nothing |
| **Stores** | nothing between runs — no config file, no cache, no history, no recent-files list |

## Why you can check this rather than trust it

`tests/security/test_no_network.py` parses every module in the installed
package and fails the build if any of them imports a networking library. A
second test replaces `socket.socket.connect` with something that raises and
then performs a real removal. If either could be made to fail, the release
would not ship.

```bash
grep -rn "import socket\|urllib\|requests\|httpx" $(python -c "import fpr,os;print(os.path.dirname(fpr.__file__))")
```

The only file in the repository that uses the network is
`scripts/audit_dependencies.py`, a developer tool that refreshes the dependency
advisory evidence. It is not part of the installed package.

## Passwords

Your password is held in a buffer that is overwritten with zeros when the
operation finishes. It is never written to disk, never logged, and cannot be
passed on the command line — the tool refuses `--password VALUE` because
command lines are visible to other processes and are saved in shell history.

The honest caveat: Python strings cannot be wiped, and every decryption library
takes one. During the moment of decryption a copy exists that we cannot erase,
and the operating system may page it to swap. Full-disk encryption is the
control for that. This is written up as risk R-07 in the
[threat model](docs/security/threat-model.md).

## Temporary files

Decryption happens in a file created with mode `0600` inside a directory the
tool creates with mode `0700`, on the same filesystem as your output. When the
run ends — successfully or not — that file is overwritten with zeros and
deleted.

On SSDs and on copy-on-write filesystems (APFS, Btrfs, ZFS), overwriting a file
does not reliably erase the physical blocks. That is a property of the storage,
not of this tool. If it matters to you, use full-disk encryption.

## Logs

Nothing is logged by default beyond warnings and errors on stderr. With `-v` or
`-vv` the tool prints progress information that includes file paths — because
you asked for it, on your terminal. A redaction filter scrubs anything
credential-shaped before any handler can write it.

## Third-party components

The libraries that do the decryption — pikepdf/qpdf, msoffcrypto-tool, pyzipper
and optionally py7zr — are listed in [NOTICE](NOTICE). None of them performs
network access in the code paths this tool uses.

## Children and sensitive data

The software has no age gate because it collects nothing to gate. It is a local
file utility.

## Changes

Any change to this document ships in a release and is listed in
[CHANGELOG.md](CHANGELOG.md). A change that introduced any form of data
collection would be a major version bump and would say so in the first line of
the release notes.

## Contact

Privacy or security questions: see [SECURITY.md](SECURITY.md).
