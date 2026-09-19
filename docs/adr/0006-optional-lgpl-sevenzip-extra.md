# ADR-0006: py7zr is an optional extra, not a default dependency

**Status**: Accepted · **Date**: 2026-09-19 · **Owner**: Architecture / Release

## Context

`py7zr` is the only maintained pure-Python 7-Zip implementation and it handles
AES-256 including encrypted headers. It is **LGPL-2.1-or-later**. This project
is Apache-2.0 and ships frozen binaries built with PyInstaller.

LGPL §6 lets a work that merely *uses* the library stay under its own terms,
provided the user can replace the library with a modified version. A pip-installed
distribution satisfies that comfortably. A PyInstaller one-file bundle does
not, without shipping the object files or a relinking mechanism — an obligation
worth taking on for a core capability, and not worth it for one optional format.

## Decision

- `py7zr` is **not** a default dependency. It is
  `pip install "file-password-remover[sevenzip]"`.
- It is **not** bundled into any released binary. The PyInstaller spec excludes
  it explicitly.
- `fpr/registry.py` treats `ImportError` from `adapters/sevenzip.py` as "this
  adapter is not available", and the CLI explains how to enable it.
- Every 7z removal emits a warning naming the licence, so a user redistributing
  their own build knows what is in it.

## Consequences

*Good*: the default install and every signed binary are permissive-only, with
no copyleft obligations to propagate. Users who want 7z opt in knowingly and
get a separately installed, user-replaceable library — the arrangement LGPL is
designed for.

*Bad*: 7z support is invisible until someone reads the docs, and the CI matrix
gains a job that runs *without* the extra to prove the registry degrades
gracefully.

## Alternatives considered

**Bundle it and comply.** Possible — ship the object files or use a mechanism
that permits relinking — but it complicates every release for one format.

**Shell out to the `7z` binary.** Moves the licence problem onto the user's
machine, adds a fragile subprocess interface, and makes password handling worse
(argv exposure).

**Write our own 7z AES reader.** The container format is substantial; this
would be a project in itself, and a worse one than py7zr.

## Reversal cost

Low in either direction: promoting it to a default dependency is a one-line
change to `pyproject.toml` plus a compliance review of the bundles.
