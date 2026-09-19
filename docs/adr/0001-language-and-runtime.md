# ADR-0001: Python 3.10+ as the single implementation language

**Status**: Accepted · **Date**: 2026-09-19 · **Owner**: Architecture

## Context

The tool has to parse four unrelated container formats and implement three
different cryptographic schemes correctly. Getting cryptography and container
parsing *right* matters far more than raw throughput, and every mature,
maintained, permissively licensed implementation of all four formats happens to
live in the same ecosystem.

## Decision

Python ≥ 3.10, one language for core, CLI, GUI and fixtures. No second runtime.

## Alternatives considered

**Rust.** Excellent for this domain and a smaller attack surface. Rejected
because the format coverage is not there: PDF encryption crates do not
approach qpdf's revision coverage, and there is no maintained ECMA-376 agile
decryptor. We would be writing the cryptography ourselves — which is precisely
the part you should not write yourself.

**Go.** `pdfcpu` is good and Apache-2.0, but it covers only PDF; Office and 7z
would still need a second implementation.

**C++ on qpdf directly.** Best PDF story, worst everything else: a build
toolchain per platform, and no Office or archive support.

**Polyglot** (Rust core + Python glue, or per-format binaries). Rejected: the
build and signing matrix multiplies for no user-visible benefit.

## Consequences

*Good*: qpdf via pikepdf gives PDF R2–R6 for free; msoffcrypto and pyzipper
cover the rest; Tkinter gives a GUI with no new dependency; `mypy --strict`
across the whole codebase; tests and the product share one language.

*Bad*: start-up time is the interpreter's; distribution needs PyInstaller
rather than a static binary; per-entry throughput is bounded by the underlying
C extensions, which is fine since they do the actual work.

*Floor*: 3.10 for `X | Y` unions and structural pattern availability; it is
also the floor pikepdf and msoffcrypto already set.

## Reversal cost

High for the core, low for the front ends. The adapter contract
(ADR-0003) is language-neutral, so a future Rust core could be introduced
adapter by adapter behind the same four methods.
