# ADR-0002: No backend, and no network code at all

**Status**: Accepted · **Date**: 2026-09-19 · **Owner**: Architecture / Security

## Context

The entire category this tool sits in — "remove PDF password online" — works by
having the user upload a confidential document **and its password** to a
stranger's server. That is the threat the product exists to displace. A privacy
promise that depends on a configuration flag is not a promise.

## Decision

The package contains no network code. Not disabled by default, not behind a
flag: absent. There is no telemetry, no crash reporting, no update check, and
no licence check.

## How it is enforced

`tests/security/test_no_network.py` parses every module in the package with
`ast` and fails if any of them imports `socket`, `ssl`, `http`, `urllib`,
`requests`, `httpx`, `ftplib`, `smtplib`, `aiohttp` or friends. A separate test
monkeypatches `socket.socket.connect` to raise and then performs a real
removal, so an indirect connection through a dependency would fail the suite
too.

The one script that does use the network —
`scripts/audit_dependencies.py`, which refreshes the licence and advisory
evidence — lives outside the package and is not installed.

## Alternatives considered

**Optional cloud processing for big files.** Rejected: it would make the
privacy claim conditional, and the local path is fast enough.

**An update check.** Rejected: it is a phone-home, it leaks usage timing, and
package managers already solve it.

**Anonymous crash reporting.** Rejected: crash reports from a tool that handles
passwords and confidential documents are exactly the payload you do not want
leaving the machine. See risk R-09 in the threat model.

## Consequences

*Good*: the privacy claim is structural. A reviewer can verify it with one
grep. No server to run, breach, or subpoena.

*Bad*: no usage data, so prioritisation is guesswork; no automatic update
notification; users must find out about security fixes through their package
manager or the release feed.

## Reversal cost

Deliberately high. Adding network code means deleting a test that exists to say
no, which is a conversation rather than a commit.
