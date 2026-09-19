# ADR-0003: Format adapters behind a four-method contract

**Status**: Accepted · **Date**: 2026-09-19 · **Owner**: Architecture

## Context

Five container families with almost nothing in common. The risk in this shape
of program is that policy decisions — *may we do this?* — end up scattered
across format code, where each adapter quietly invents its own answer.

## Decision

Every format implements `fpr.adapters.base.Adapter`:

| Method | Password? | Responsibility |
| --- | --- | --- |
| `sniff(head, path)` | no | "are these bytes mine?" |
| `detect(path)` | **no** | describe the protection |
| `remove(src, dst, secret, options)` | yes | decrypt into a temp file, return evidence |
| `verify(output, evidence)` | no | prove the written file is readable and unprotected |

The engine owns everything else: policy checks, output naming, atomic writes,
temp-file scrubbing, timestamps, error mapping. An adapter cannot publish a
file, cannot decide whether an operation is allowed, and cannot report success.

## Why `detect` must not take a password

Three reasons, in order of importance:

1. **Refuse before prompting.** A user asked for a secret and then told
   "refused" has been made to type a password for nothing.
2. **Inspection is useful on its own.** `fpr inspect` over a folder plans a
   batch without any secret in the room.
3. **It keeps the policy check honest.** Policy runs on a password-free
   detection, so it cannot accidentally depend on having the key.

## Why `verify` is separate from `remove`

If the same code that wrote the file also declared it good, the check would
share every assumption of the writer. `verify` re-opens the file *from disk*,
through the format's own reader, and compares against invariants captured
before the write. See [ADR-0004](0004-verify-before-publish.md).

## Alternatives considered

**One class per format with free rein.** Simpler; discarded because it is how
the policy gets quietly bypassed six months from now.

**A plugin system with entry points.** Third-party adapters would be able to
sidestep the policy layer. If it is added later it must run behind the same
contract and the same engine.

## Consequences

*Good*: a new format is one file plus a fixture plus tests. The security tests
assert properties of the engine and get the adapters for free.

*Bad*: some duplication across adapters (each writes its own digest-comparison
loop). Accepted — the alternative is a shared abstraction that fits none of
them.

## Reversal cost

Low. The contract is four methods.
