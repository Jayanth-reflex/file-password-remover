"""Build ECMA-376 *agile*-encrypted OOXML documents, for test fixtures only.

This is an independent implementation of the encryption side of
[MS-OFFCRYPTO] section 2.3.4.10 (Agile Encryption), written against the
specification rather than against the library we use to decrypt. That
independence is the point: a round-trip test that encrypts and decrypts with
the same code proves very little, whereas encrypting here and decrypting with
``msoffcrypto`` exercises two implementations against one file format.

Parameters are fixed to what Office 2013+ writes and what our adapter claims to
support: AES-256 in CBC mode, SHA-512, 16-byte salts, 100 000 spin iterations.

References
----------
* [MS-OFFCRYPTO] 2.3.4.10-2.3.4.15 -- agile key derivation, verifier, payload
* [MS-OFFCRYPTO] 2.1.4-2.1.8      -- the ``\\x06DataSpaces`` structures
* Block-key constants are specification values, reproduced below.

Nothing in the removal path imports this module.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from collections.abc import Callable
from struct import pack

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import cfb

__all__ = ["encrypt_agile", "AgileParams"]

# [MS-OFFCRYPTO] 2.3.4.12 -- block keys used to diversify the derived key.
BLK_VERIFIER_HASH_INPUT = bytes([0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79])
BLK_VERIFIER_HASH_VALUE = bytes([0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E])
BLK_KEY_VALUE = bytes([0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6])
BLK_INTEGRITY_KEY = bytes([0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6])
BLK_INTEGRITY_VALUE = bytes([0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33])

SEGMENT_LENGTH = 4096
BLOCK_SIZE = 16
KEY_BITS = 256
HASH_SIZE = 64
SALT_SIZE = 16


class AgileParams:
    """Knobs a fixture may want to vary. Defaults match Office 2013+."""

    def __init__(self, spin_count: int = 100_000) -> None:
        self.spin_count = spin_count


def _aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _pad_block(data: bytes, block: int = BLOCK_SIZE) -> bytes:
    """Zero-pad to the cipher block size, as agile encryption specifies.

    Note this is *not* PKCS#7: [MS-OFFCRYPTO] stores the true length separately
    (in the payload header, or implicitly by hash size) and pads with zeros.
    """
    rem = len(data) % block
    return data + b"\x00" * (block - rem) if rem else data


def _iterated_hash(password: str, salt: bytes, spin_count: int) -> bytes:
    """H_n = SHA512(LE32(n) || H_{n-1}), starting from SHA512(salt || UTF16LE(pw))."""
    h = hashlib.sha512(salt + password.encode("utf-16-le")).digest()
    for i in range(spin_count):
        h = hashlib.sha512(pack("<I", i) + h).digest()
    return h


def _derive(h: bytes, block_key: bytes) -> bytes:
    return hashlib.sha512(h + block_key).digest()[: KEY_BITS // 8]


def _encrypt_payload(plaintext: bytes, secret_key: bytes, key_data_salt: bytes) -> bytes:
    """8-byte little-endian plaintext length, then AES-CBC segments of 4096 bytes."""
    out = bytearray(pack("<Q", len(plaintext)))
    for i in range(0, max(len(plaintext), 1), SEGMENT_LENGTH):
        chunk = plaintext[i : i + SEGMENT_LENGTH]
        if not chunk:
            break
        iv = hashlib.sha512(key_data_salt + pack("<I", i // SEGMENT_LENGTH)).digest()[:BLOCK_SIZE]
        out += _aes_cbc_encrypt(_pad_block(chunk), secret_key, iv)
    return bytes(out)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _descriptor(
    *,
    key_data_salt: bytes,
    encrypted_hmac_key: bytes,
    encrypted_hmac_value: bytes,
    spin_count: int,
    password_salt: bytes,
    encrypted_verifier_hash_input: bytes,
    encrypted_verifier_hash_value: bytes,
    encrypted_key_value: bytes,
) -> bytes:
    xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password" xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">
  <keyData saltSize="{SALT_SIZE}" blockSize="{BLOCK_SIZE}" keyBits="{KEY_BITS}" hashSize="{HASH_SIZE}" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="{_b64(key_data_salt)}"/>
  <dataIntegrity encryptedHmacKey="{_b64(encrypted_hmac_key)}" encryptedHmacValue="{_b64(encrypted_hmac_value)}"/>
  <keyEncryptors>
    <keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
      <p:encryptedKey spinCount="{spin_count}" saltSize="{SALT_SIZE}" blockSize="{BLOCK_SIZE}" keyBits="{KEY_BITS}" hashSize="{HASH_SIZE}" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="{_b64(password_salt)}" encryptedVerifierHashInput="{_b64(encrypted_verifier_hash_input)}" encryptedVerifierHashValue="{_b64(encrypted_verifier_hash_value)}" encryptedKeyValue="{_b64(encrypted_key_value)}"/>
    </keyEncryptor>
  </keyEncryptors>
</encryption>"""
    # 2-byte major, 2-byte minor, 4-byte flags (0x40 = AES + agile).
    return pack("<HHI", 4, 4, 0x40) + xml.encode("utf-8")


# --------------------------------------------------------------------------
# \x06DataSpaces structures. [MS-OFFCRYPTO] 2.1.4 - 2.1.8.
# Built field by field from the spec so the bytes are auditable, rather than
# copied as an opaque blob from another project.
# --------------------------------------------------------------------------
def _lp_utf16(text: str) -> bytes:
    """UNICODE-LP-P4: 4-byte byte-length, UTF-16LE data, padded to 4 bytes."""
    raw = text.encode("utf-16-le")
    return pack("<I", len(raw)) + raw + b"\x00" * ((-len(raw)) % 4)


def _version_stream() -> bytes:
    # FeatureIdentifier, then Reader/Updater/Writer version pairs (major, minor).
    return _lp_utf16("Microsoft.Container.DataSpaces") + pack("<HHHHHH", 1, 0, 1, 0, 1, 0)


def _data_space_map() -> bytes:
    entry = (
        pack("<I", 1)  # ReferenceComponentCount
        + pack("<I", 0)  # ReferenceComponentType: 0 = stream
        + _lp_utf16("EncryptedPackage")
        + _lp_utf16("StrongEncryptionDataSpace")
    )
    entry = pack("<I", len(entry) + 4) + entry  # Length includes itself
    return pack("<II", 8, 1) + entry  # HeaderLength, EntryCount


def _strong_encryption_data_space() -> bytes:
    return pack("<II", 8, 1) + _lp_utf16("StrongEncryptionTransform")


def _primary() -> bytes:
    header = (
        pack("<I", 1)  # TransformType: 1 = encryption
        + _lp_utf16("{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}")
        + _lp_utf16("Microsoft.Container.EncryptionTransform")
        + pack("<HHHHHH", 1, 0, 1, 0, 1, 0)
    )
    header = pack("<I", len(header) + 4) + header
    encryption_transform_info = (
        pack("<I", 0)  # EncryptionName: empty
        + pack("<I", 0)  # EncryptionBlockSize
        + pack("<I", 0)  # EncryptionCipherMode
        + pack("<I", 4)  # Reserved, must be 4
    )
    return header + encryption_transform_info


def encrypt_agile(
    plaintext: bytes,
    password: str,
    *,
    params: AgileParams | None = None,
    rng: Callable[[int], bytes] | None = None,
) -> bytes:
    """Return a complete encrypted OOXML container for ``plaintext``.

    ``plaintext`` is the unencrypted .docx/.xlsx/.pptx ZIP, byte for byte.
    ``rng`` is injectable so a test can produce a deterministic fixture.
    """
    params = params or AgileParams()
    rng = rng or os.urandom
    key_data_salt = rng(SALT_SIZE)
    password_salt = rng(SALT_SIZE)
    secret_key = rng(KEY_BITS // 8)
    verifier = rng(SALT_SIZE)
    hmac_key = rng(HASH_SIZE)

    h = _iterated_hash(password, password_salt, params.spin_count)
    key_vhi = _derive(h, BLK_VERIFIER_HASH_INPUT)
    key_vhv = _derive(h, BLK_VERIFIER_HASH_VALUE)
    key_kv = _derive(h, BLK_KEY_VALUE)

    encrypted_verifier_hash_input = _aes_cbc_encrypt(_pad_block(verifier), key_vhi, password_salt)
    verifier_hash = hashlib.sha512(verifier).digest()
    encrypted_verifier_hash_value = _aes_cbc_encrypt(
        _pad_block(verifier_hash), key_vhv, password_salt
    )
    encrypted_key_value = _aes_cbc_encrypt(_pad_block(secret_key), key_kv, password_salt)

    encrypted_package = _encrypt_payload(plaintext, secret_key, key_data_salt)

    iv1 = hashlib.sha512(key_data_salt + BLK_INTEGRITY_KEY).digest()[:BLOCK_SIZE]
    iv2 = hashlib.sha512(key_data_salt + BLK_INTEGRITY_VALUE).digest()[:BLOCK_SIZE]
    encrypted_hmac_key = _aes_cbc_encrypt(_pad_block(hmac_key), secret_key, iv1)
    hmac_value = hmac.new(hmac_key, encrypted_package, hashlib.sha512).digest()
    encrypted_hmac_value = _aes_cbc_encrypt(_pad_block(hmac_value), secret_key, iv2)

    encryption_info = _descriptor(
        key_data_salt=key_data_salt,
        encrypted_hmac_key=encrypted_hmac_key,
        encrypted_hmac_value=encrypted_hmac_value,
        spin_count=params.spin_count,
        password_salt=password_salt,
        encrypted_verifier_hash_input=encrypted_verifier_hash_input,
        encrypted_verifier_hash_value=encrypted_verifier_hash_value,
        encrypted_key_value=encrypted_key_value,
    )

    return cfb.write(
        [
            cfb.storage(
                "\x06DataSpaces",
                [
                    cfb.stream("Version", _version_stream()),
                    cfb.stream("DataSpaceMap", _data_space_map()),
                    cfb.storage(
                        "DataSpaceInfo",
                        [cfb.stream("StrongEncryptionDataSpace", _strong_encryption_data_space())],
                    ),
                    cfb.storage(
                        "TransformInfo",
                        [
                            cfb.storage(
                                "StrongEncryptionTransform",
                                [cfb.stream("\x06Primary", _primary())],
                            )
                        ],
                    ),
                ],
            ),
            cfb.stream("EncryptedPackage", encrypted_package),
            cfb.stream("EncryptionInfo", encryption_info),
        ]
    )
