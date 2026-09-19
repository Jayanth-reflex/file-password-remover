"""The authorisation rules, in one place.

These are the rules that make this tool a *password remover* and not a
*protection bypass*. They are enforced here, before a password is ever
requested, and again inside each adapter at the point of decryption.

R1  A removal requires a password, and the password must be validated by the
    format's own verifier. No dictionary, no brute force, no "try empty
    first", no recovery of a forgotten password.
R2  Content encryption may be removed by anyone holding a valid password.
R3  Permission/owner restrictions on content that is *not* encrypted may only
    be removed by someone holding the **owner** password, and only when they
    explicitly ask for it (``--remove-restrictions``). Without that, the tool
    refuses -- clearing flags you cannot authenticate against is a bypass.
R4  Protection whose key is not derived from a password (DRM, IRM,
    certificate/public-key security) is never touched.
R5  The source file is never modified unless the user explicitly asks
    (``--in-place``), and even then only via an atomic replace of a verified
    output.
"""

from __future__ import annotations

from .errors import NotProtectedError, PolicyRefusedError, UnsupportedFormatError
from .types import Detection, Removability

__all__ = ["check", "POLICY_RULES"]

POLICY_RULES: tuple[tuple[str, str], ...] = (
    ("R1", "A correct password, validated by the format's own verifier, is required."),
    ("R2", "Content encryption is removable by a holder of a valid password."),
    (
        "R3",
        "Permission restrictions are removable only with the owner password and an "
        "explicit --remove-restrictions flag.",
    ),
    ("R4", "DRM, IRM and certificate-based protection are never removed."),
    ("R5", "The source file is preserved unless --in-place is given."),
)


def check(detection: Detection, *, allow_restriction_removal: bool = False) -> None:
    """Raise if the requested removal is not permitted, before prompting.

    Succeeds silently when the operation may proceed.
    """
    r = detection.removability
    if r is Removability.NOT_PROTECTED:
        raise NotProtectedError(
            f"{detection.path.name} is not protected: {detection.detail}",
            remediation="There is nothing to remove. Use the file as it is.",
        )
    if r is Removability.UNSUPPORTED:
        raise UnsupportedFormatError(detection.detail or "Unsupported protection.")
    if r is Removability.REFUSED_BY_POLICY:
        raise PolicyRefusedError(detection.detail or "Refused by policy.")
    if r is Removability.REMOVABLE_WITH_OWNER_PASSWORD and not allow_restriction_removal:
        raise PolicyRefusedError(
            detection.detail
            or "This file only carries permission restrictions; removing them needs the "
            "owner password.",
            remediation="Re-run with --remove-restrictions and supply the owner password.",
        )
