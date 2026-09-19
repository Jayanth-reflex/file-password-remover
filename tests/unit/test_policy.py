"""The authorisation rules are enforced before a password is ever requested."""

from __future__ import annotations

from pathlib import Path

import pytest

from fpr import inspect, policy
from fpr.errors import NotProtectedError, PolicyRefusedError, UnsupportedFormatError
from fpr.types import Detection, FormatId, Protection, Removability


def _detection(removability: Removability, detail: str = "detail") -> Detection:
    return Detection(
        path=Path("x"),
        format_id=FormatId.PDF,
        format_name="PDF",
        protection=Protection.USER_PASSWORD,
        removability=removability,
        detail=detail,
    )


def test_removable_passes() -> None:
    policy.check(_detection(Removability.REMOVABLE))


def test_unprotected_is_rejected_with_its_own_error() -> None:
    with pytest.raises(NotProtectedError):
        policy.check(_detection(Removability.NOT_PROTECTED))


def test_unsupported_is_rejected() -> None:
    with pytest.raises(UnsupportedFormatError):
        policy.check(_detection(Removability.UNSUPPORTED))


def test_bypass_shaped_requests_are_refused() -> None:
    with pytest.raises(PolicyRefusedError):
        policy.check(_detection(Removability.REFUSED_BY_POLICY))


def test_restriction_removal_needs_the_explicit_flag() -> None:
    with pytest.raises(PolicyRefusedError) as exc:
        policy.check(_detection(Removability.REMOVABLE_WITH_OWNER_PASSWORD))
    assert "--remove-restrictions" in (exc.value.remediation or "")
    policy.check(
        _detection(Removability.REMOVABLE_WITH_OWNER_PASSWORD),
        allow_restriction_removal=True,
    )


def test_real_restricted_pdf_is_refused_by_default(pdf_restricted: Path) -> None:
    with pytest.raises(PolicyRefusedError):
        policy.check(inspect(pdf_restricted))


def test_policy_rules_are_published() -> None:
    ids = {ident for ident, _ in policy.POLICY_RULES}
    assert ids == {"R1", "R2", "R3", "R4", "R5"}
