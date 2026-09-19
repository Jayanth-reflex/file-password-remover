# ADR-0008: Restriction removal requires the owner password and an explicit flag

**Status**: Accepted · **Date**: 2026-09-19 · **Owner**: Security / Product

## Context

A PDF can be encrypted with an **empty user password** and a non-empty **owner
password**. Anyone can open and read it; the permission flags merely ask
software not to print, copy or edit. qpdf opens such a file with `""` and will
happily re-save it with the flags gone. Every "free PDF unlocker" on the web is
exactly that one call.

The same shape exists in Office as `<w:documentProtection>` and sheet/workbook
protection: content unencrypted, a password stored only as a hash, and
"removal" meaning *delete an XML element*.

This is a different act from decryption. In decryption, the password is the
key: without it there is no content. In restriction removal, there is no key —
only a request that software behave, and the "password" is a check you can
skip entirely.

## Decision

**R3** in `fpr/policy.py`:

> Permission restrictions on content that is not encrypted may be removed only
> by someone holding the **owner** password, and only when they ask for it
> explicitly with `--remove-restrictions`.

Implementation:

- The PDF adapter classifies a run as restriction-only when the document opens
  with an empty password **and** the supplied password did not match as the
  *user* password. In that case, qpdf must have accepted it as the **owner**
  password — the format itself does the authentication, and a wrong password
  never gets in at all.
- Without the flag, the run is refused with exit code 10 and a message that
  explains what the file actually is.
- Office editing restrictions are refused outright, with or without the flag,
  because there is nothing to authenticate against. The message points at the
  application's own *Stop Protection* command, which is the correct answer.

## Why not just do it, like everyone else

Because the product's value is being the tool that does not. The line between
"remove the password I own" and "strip protection off a document I found" is
exactly this distinction, and a tool that blurs it has no defensible position
when asked what it is for.

## What we deliberately do **not** do

- Never open a document with `""` in order to write something. The empty-password
  open exists only in `detect()` and in the classification check; both are
  read-only, and there is a test that asserts the file is untouched by it.
- Never try a second password, an empty password, or any fallback after a
  rejection. One attempt per invocation, asserted by
  `tests/security/test_no_bypass.py::test_a_wrong_password_is_never_retried`.

## Consequences

*Good*: a bright line, enforced in code and covered by tests. A user with a
legitimate restricted PDF and its owner password is one flag away.

*Bad*: a document whose owner password is genuinely lost cannot be unlocked by
this tool, and other tools will do it. That is the intended outcome, and the
refusal message says what the file actually is so the user can decide.

*Edge case*: a PDF with a real user password and an **empty** owner password
opens with `""`, so detection cannot see the user password and asks for the
flag. Supplying the flag and the real open password works and reports a normal
decryption. Covered by
`test_pdf.py::test_empty_owner_password_still_decrypts_with_the_real_open_password`.

## Reversal cost

Deliberately high; see ADR-0002's closing note.
