# Architecture decision records

One file per decision that would be expensive to reverse. Each states the
alternatives that were actually considered, what the decision costs, and how
hard it would be to undo.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-language-and-runtime.md) | Python 3.10+ as the single implementation language | Accepted |
| [0002](0002-local-only-no-backend.md) | No backend, no network code at all | Accepted |
| [0003](0003-adapter-architecture.md) | Format adapters behind a four-method contract | Accepted |
| [0004](0004-verify-before-publish.md) | Never publish an output that has not been re-read and verified | Accepted |
| [0005](0005-desktop-toolkit.md) | Tkinter for the desktop window | Accepted |
| [0006](0006-optional-lgpl-sevenzip-extra.md) | py7zr as an optional extra, not a default dependency | Accepted |
| [0007](0007-no-password-on-argv.md) | Refuse passwords on the command line | Accepted |
| [0008](0008-owner-restriction-policy.md) | Restriction removal requires the owner password and an explicit flag | Accepted |
| [0009](0009-own-fixture-generators.md) | Generate protected fixtures ourselves, independently of the readers under test | Accepted |
| [0010](0010-no-mobile-app-this-release.md) | Ship no mobile app rather than an unverified one | Accepted |
