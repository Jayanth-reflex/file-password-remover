# Design system

## Where this comes from

This tool's distinguishing behaviour is not that it opens files. It is that it
**refuses to guess a password**, and that after writing an output file it
**re-reads that file from disk** and checks the content against the input before
reporting success. The `verification` block is the product:

```
encrypted=false · pages=3 · digest=456cf7bc · scope=all 3 page(s)
```

So the visual language is not padlocks, shields or vaults — those belong to
tools that break into things. It is **hallmarking**: the small punched marks
struck into precious metal to certify purity, maker and assay office. Compact,
precise, authoritative, and every mark carries a specific claim that someone
staked their name on.

That is the same shape as the verification block, and it is the idea the whole
interface is built around.

## Signature: the hallmark row

The one element the product is remembered by. After a file is cleared, the
verification data appears as a row of small monospace marks separated by
hairlines, each under a tiny caption:

```
 ENCRYPTED      PAGES        DIGEST         SCOPE
 false          3            456cf7bc       all 3 pages
 ────────────────────────────────────────────────────
```

Rules:

- It **only** appears after a verified success. It is never a placeholder, never
  shown speculatively, and never populated with anything but real data returned
  by the engine.
- Marks are monospace and aligned. Captions are uppercase, small, wide-tracked.
- Brass is used here and almost nowhere else, so the eye learns that brass means
  "this was checked".

Everything else on screen stays quiet so this can be loud.

## Colour

Cool graphite ground with one warm metal. Cool ground against warm metal is the
actual language of luxury hardware, and it avoids both the cream/serif/terracotta
and the black/acid-green looks that generic "premium" interfaces settle into.

| Token | Dark | Light | Used for |
| :-- | :-- | :-- | :-- |
| `ink` | `#121417` | `#F7F7F5` | Window ground |
| `surface` | `#1A1D21` | `#FFFFFF` | Raised cards |
| `line` | `#2A2E34` | `#E4E4E0` | Hairlines, dividers |
| `mist` | `#8B9198` | `#6B6F76` | Captions, secondary text |
| `platinum` | `#ECEEF0` | `#15171A` | Primary text |
| `brass` | `#C6A664` | `#9A7B3A` | The hallmark row, focus rings |
| `patina` | `#5E9C86` | `#3F7A63` | Verified state |
| `oxide` | `#A8564B` | `#94433A` | Refusals and errors |

Brass never fills a large area. It is a hairline, a caption, a focus ring, a
single rule under the hallmark row. The moment it becomes a big button it stops
reading as metal and starts reading as a warning.

`patina` and `oxide` carry state, but state is **never colour alone** — every
one of them is paired with a word, because the existing accessibility test
(`test_no_state_is_conveyed_by_colour_alone`) requires it and because that is
simply correct.

## Type

Platform system faces, set deliberately. This is what Apple's HIG and Material
both want, it is what Dynamic Type and font scaling need to work, and it means
no font files ship in the binaries.

| Role | iOS | Android | Desktop | CLI / Web |
| :-- | :-- | :-- | :-- | :-- |
| Display | SF Pro, tight tracking | Roboto Medium | System sans | — |
| Body | SF Pro Text | Roboto Regular | System sans | — |
| Marks | SF Mono | Roboto Mono | Platform mono | Terminal mono |

Scale (relative): display 28 / title 20 / body 15 / caption 12 / mark 13.
Captions are uppercase with wide tracking (~0.08em); everything else is sentence
case with normal tracking.

## Structure

The old interface numbered its sections `1.` `2.` `3.`. Numbering should encode
real sequence information, and here **progressive disclosure does that job
better**: there is no password field until there is a file to unlock, and no
hallmark row until something has been verified. The interface reveals exactly as
much as is true right now, which is also the honest thing for a security tool to
do.

Three states, one surface:

1. **Waiting** — a single invitation, nothing else.
2. **Examined** — what this file actually is: format, protection, algorithm.
   This is a statement of fact, not a promise.
3. **Cleared** — the hallmark row, and the output.

## Where the platforms differ

Stated here because the interface shows it rather than hiding it: protecting a
PDF on iOS produces **AES-128 (R4)**, not the AES-256 (R6) the CLI and the
Android app produce. PDFKit does not expose the encryption revision. The
hallmark row prints the algorithm for exactly this reason -- the user can see
what they got, and it is a fact read back out of the file rather than a claim.

## Quality floor

Not negotiable, and not announced in the UI:

- Contrast at least 4.5:1 for body text, 3:1 for large text and UI edges.
- Visible keyboard focus everywhere, using `brass` at 2px.
- Touch targets at least 44pt (iOS) / 48dp (Android).
- Respect reduced motion: transitions collapse to instant.
- Respect the system light/dark appearance.
- Every state that uses colour also uses words.
