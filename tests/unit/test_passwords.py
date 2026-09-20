"""The generated-password path.

A password this tool generates is the only copy that will ever exist: the tool
refuses to crack, so if the user loses it the file is gone. That makes the
generator security-critical in a way the rest of the code is not.
"""

from __future__ import annotations

import math
import re

import pytest

from fpr.passwords import ALPHABET, PassphraseStrength, generate


def test_generated_password_is_grouped_for_transcription() -> None:
    with generate().expose() as text:
        assert re.fullmatch(r"[a-z0-9]{4}(-[a-z0-9]{4}){4}", text), text


def test_alphabet_excludes_characters_people_confuse() -> None:
    """A password nobody can read back off a screen is not usable."""
    for confusable in "ilo01":
        assert confusable not in ALPHABET, f"{confusable!r} is easy to misread"


def test_two_generated_passwords_differ() -> None:
    with generate().expose() as first, generate().expose() as second:
        assert first != second


def test_strength_reports_real_entropy() -> None:
    strength = PassphraseStrength.of(groups=5, group_size=4)
    expected = 20 * math.log2(len(ALPHABET))

    assert strength.bits == pytest.approx(expected, abs=0.5)
    assert strength.bits >= 90, "a generated password must be far past guessable"


def test_generated_password_is_a_secret_that_does_not_leak_in_logs() -> None:
    secret = generate()
    assert "-" not in repr(secret), "the material must not appear in repr"
    with secret.expose() as text:
        assert text not in repr(secret)


def test_a_shorter_password_can_be_asked_for_but_not_a_weak_one() -> None:
    with pytest.raises(ValueError, match="entropy"):
        generate(groups=1, group_size=2)
