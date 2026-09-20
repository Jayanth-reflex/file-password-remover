# ADR-0011: Ship mobile apps built and verified here, not published to the stores

**Status**: Accepted · **Date**: 2026-09-20 · **Owner**: Product / Release
**Supersedes**: [ADR-0010](0010-no-mobile-app-this-release.md)

## Context

ADR-0010 refused to ship a mobile app, and the reasoning was about evidence
rather than ambition: on the build host at the time there was no iOS signing
identity, no Android SDK, no Gradle, and no device. Anything called an "app"
would have been an unbuilt, unsigned, untested project directory.

That is no longer the state of the world. On the host this release was produced
on:

| Requirement | ADR-0010 | Now |
| --- | --- | --- |
| Xcode / Swift | present | Xcode 27, Swift 6.4 |
| iOS simulators | — | 8 available |
| iOS signing identity | **absent** | Apple Development identity present |
| Android SDK | **absent** | platform 35, build-tools 35, platform-tools |
| Gradle | **absent** | 8.13 |
| Android emulator | **absent** | present |
| Apple Developer Program membership | absent | **still absent** |
| Play Console account / upload keystore | absent | **still absent** |

The two rows that did not change are the ones that decide distribution.

## Decision

Ship iOS and Android apps, built and verified on this host, and distribute them
as artifacts rather than through the stores.

**What "verified" means here.** The engine is reimplemented in Swift and in
Kotlin -- it cannot be shared, because the original is Python and leans on qpdf.
Three independent implementations of the same specifications is a good way to
end up with three different bugs, so all three are tested against one corpus:
`fpr.testing.vectors` writes the generated fixtures to disk with a manifest
recording each file's password and the SHA-256 of every member's *plaintext*.
The Swift and Kotlin suites decrypt those files and compare digests, so a port
that reports success without actually recovering the content fails.

That corpus has already earned its keep. It caught a 16-bit truncation in the
Swift ZipCrypto keystream, a wrong PKWARE seed constant, and PDFKit silently
re-encrypting R2-R4 documents on save.

**What is not claimed.** No App Store or Play listing exists, because the
accounts to create one do not. The iOS build is signed with a development
identity, which runs on the Simulator and on a device the developer owns; it is
not a distribution build. The Android APK is debug-signed. Both say so.

## Format coverage, which is not equal

| Format | CLI | Android | iOS |
| --- | --- | --- | --- |
| PDF (R2-R6) | yes | yes | yes |
| OOXML agile | yes | yes | yes |
| ZIP (AES-128/192/256, ZipCrypto) | yes | yes | yes |
| 7-Zip (AES-256, incl. encrypted header) | yes | yes | **no** |
| Legacy Office (.doc/.xls) | detection only | detection only | detection only |

Android reaches parity because Apache Commons Compress (Apache-2.0) implements
the 7-Zip container, its AES-256/SHA-256 derivation and LZMA. iOS has no
equivalent: shipping 7-Zip there means hand-writing an LZMA decoder and a 7z
header parser in Swift. That is real work with real bug risk, and pretending
otherwise by shipping an untested version would be the exact failure mode
ADR-0010 existed to prevent. The iOS app therefore reports 7-Zip as unsupported
and points at the CLI, and this gap is listed wherever platform support is
described.

## Consequences

*Good*: the product has a mobile story. The three implementations check each
other through a shared corpus rather than by inspection.

*Bad*: users must sideload, which is friction on iOS especially. Three
implementations is three times the maintenance, and a format added to the CLI is
now a format missing from two other places until it is ported.

*Still open*: store distribution needs a paid Apple Developer Program membership
and a Play Console account. 7-Zip on iOS needs an LZMA decoder.
