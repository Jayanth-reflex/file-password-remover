"""Generating a password for a file this tool is about to protect.

This is the one place in the codebase that *creates* a secret rather than
consuming one, and it is security-critical for an unusual reason: the tool
refuses to crack passwords, so a generated password is the only copy that will
ever exist. If the user loses it, the file is gone, and this tool is
specifically the wrong tool to get it back.

Two consequences shape the design:

* Randomness comes from :mod:`secrets`, never :mod:`random`. The latter is
  seeded predictably and is not fit for anything anyone has to keep.
* The alphabet excludes characters people misread. A password that cannot be
  transcribed off a screen is not usable, and an unusable password is one the
  user will replace with something weak.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass

from .secret import Secret

__all__ = ["ALPHABET", "MINIMUM_BITS", "PassphraseStrength", "generate"]

# Lowercase letters and digits, minus the pairs that get confused in most
# faces: i/l/1 and o/0. 31 symbols, about 4.95 bits each.
ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"

# Below this a generated password is not worth generating. 90 bits is far past
# anything brute-forceable and still only 20 typed characters.
MINIMUM_BITS = 90.0


@dataclass(frozen=True)
class PassphraseStrength:
    """How much entropy a given shape actually carries."""

    groups: int
    group_size: int
    bits: float

    @classmethod
    def of(cls, *, groups: int, group_size: int) -> PassphraseStrength:
        symbols = groups * group_size
        return cls(
            groups=groups,
            group_size=group_size,
            bits=symbols * math.log2(len(ALPHABET)),
        )


def generate(*, groups: int = 5, group_size: int = 4) -> Secret:
    """Return a new random password, grouped with hyphens for transcription.

    The default is five groups of four -- ``k7fq-2mxp-9rtv-wc4h-3jns`` -- which
    is about 99 bits. Hyphens are separators for the eye and are not part of
    the entropy calculation.
    """
    if groups < 1 or group_size < 1:
        raise ValueError("groups and group_size must both be at least 1")

    strength = PassphraseStrength.of(groups=groups, group_size=group_size)
    if strength.bits < MINIMUM_BITS:
        raise ValueError(
            f"that shape carries {strength.bits:.0f} bits of entropy; this tool will not "
            f"generate a password below {MINIMUM_BITS:.0f}. Use at least "
            f"{math.ceil(MINIMUM_BITS / math.log2(len(ALPHABET)))} characters."
        )

    chunks = ["".join(secrets.choice(ALPHABET) for _ in range(group_size)) for _ in range(groups)]
    return Secret.from_text("-".join(chunks))
