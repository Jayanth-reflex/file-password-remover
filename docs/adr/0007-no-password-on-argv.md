# ADR-0007: The CLI refuses passwords on the command line

**Status**: Accepted · **Date**: 2026-09-19 · **Owner**: Security

## Context

Almost every comparable tool accepts `--password VALUE`. It is convenient and
it is a straightforward credential disclosure:

- On Linux, `/proc/<pid>/cmdline` is world-readable by default, so any local
  user can read another process's arguments for as long as it runs.
- On macOS, `ps -ef` shows the arguments of other users' processes.
- Interactive shells write the whole command line to history — `~/.bash_history`,
  `~/.zsh_history` — in plaintext, indefinitely.
- CI systems log commands, and those logs outlive the job.

## Decision

`--password VALUE` is parsed and then **refused** with an explanation and a
list of alternatives. It is parsed rather than omitted so that a user who tries
it gets a useful answer instead of "unrecognised argument".

Supported routes, best first:

| Route | Exposure |
| --- | --- |
| `--password-fd N` | None: the parent writes into a pipe |
| `--password-stdin` | None beyond the pipe |
| `--password-file PATH` | A file on disk; the tool warns if it is group/world readable |
| interactive prompt (default) | `getpass`, no echo, no shell history |
| `--password-env VAR` | Environment; **warns loudly**, because environments leak into crash dumps and child processes |

## Consequences

*Good*: the most common accidental disclosure in this category of tool is
impossible. A scripted caller is pushed toward `--password-fd`, which is
genuinely the safest option and about as easy.

*Bad*: one-liners copied from other tools fail. That failure is the point, and
the error text is written to teach rather than scold.

## Verification

`tests/integration/test_cli.py::test_password_on_argv_is_refused_with_a_reason`
runs the real entry point in a child process and asserts both the exit code and
that the message names an alternative.
`tests/security/test_no_leaks.py::test_password_never_reaches_argv_of_a_child_process`
asserts the password is absent from `argv` on the working path.

## Reversal cost

None. Adding the option back is deleting a check — which is exactly why the
check has a test with a name that says what it is for.
