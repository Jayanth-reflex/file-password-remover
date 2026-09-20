# ADR-0010: Ship no mobile app rather than an unverified one

**Status**: Superseded by [ADR-0011](0011-ship-mobile-apps-verified-not-published.md) · **Date**: 2026-09-19 · **Owner**: Product / Release

> This decision was correct for the host it was written on, which had no
> Android SDK, no Gradle and no signing identity. Those are now present, and
> [ADR-0011](0011-ship-mobile-apps-verified-not-published.md) ships the apps.
> The reasoning below is kept because the *standard* it applies -- do not
> claim a platform you have not built and run -- is the standard ADR-0011
> is held to as well.

## Context

The brief asks for iOS and Android support "where feasible", and separately
forbids fake integrations and unverified platform claims. Those two
instructions resolve each other.

What a real mobile release needs, beyond code:

- **iOS**: an Xcode project, a Swift implementation of PDF/Office/ZIP
  decryption (CPython on iOS is possible from 3.13 but not a supported
  distribution path for this stack), a Share Extension and a
  `UIDocumentBrowser` integration, an Apple Developer account, a provisioning
  profile, a signing identity, and App Review — which has a documented history
  of rejecting tools in this category until the "you must own the file"
  framing is argued.
- **Android**: the Android SDK, Gradle, a Chaquopy/Kotlin implementation, a
  Storage Access Framework integration, a signing keystore, and a Play Console
  account.

On this build host: Xcode is present, but there is **no Android SDK and no
Gradle**, no signing identity for either platform, and no device or store
account. Anything "shipped" would be unbuilt, unsigned and untested.

## Decision

No mobile application ships in 1.0.0. In its place:

- [`mobile/README.md`](../../mobile/README.md) documents the architecture a
  mobile port would use, the platform integration points, the per-platform
  feasibility of each format, and the human credentials required.
- The README's platform table says **"Not shipped"** for iOS and Android.
- The repository contains no stub Xcode project, no empty Gradle module, and no
  placeholder that could be mistaken for progress.

## What *is* offered to mobile users today

The CLI runs anywhere Python does, including iSH and a-Shell on iOS and Termux
on Android, with the usual caveat that those are unofficial environments. That
is documented as what it is — a workaround — not as mobile support.

## Consequences

*Good*: nothing in the repository claims a capability that has not been built
and run. The design work is preserved for whoever picks it up.

*Bad*: the product has no mobile story in 1.0.0, which is a real gap for a tool
whose users often receive protected files on a phone.

## Reversal cost

Zero for the decision; large for the work. The design document exists so the
next attempt does not start from nothing.
