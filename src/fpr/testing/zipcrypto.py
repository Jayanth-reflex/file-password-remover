"""Write ZipCrypto-encrypted ZIP archives, for test fixtures only.

ZipCrypto (APPNOTE.TXT section 6.1, "traditional PKWARE encryption") is the
scheme this project supports for backwards compatibility and warns about
loudly. To test that support we have to *produce* such archives, and no Python
library writes them -- ``pyzipper`` reads them but only writes AES.

The whole cipher is here because it is tiny: three 32-bit keys stirred with
CRC-32, a 12-byte random header, and a one-byte password check. That one byte
is exactly why the format is unsafe, and why the ZIP adapter refuses to treat a
passing check as proof that a password was right.

Implemented from APPNOTE.TXT 6.3.10 section 6.1. Fixture code only; never
imported by the removal path.
"""

from __future__ import annotations

import os
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass

__all__ = ["ZipEntry", "build_zipcrypto_archive", "ZipCryptoKeys"]

_KEY0, _KEY1, _KEY2 = 0x12345678, 0x23456789, 0x34567890
_MASK = 0xFFFFFFFF


class ZipCryptoKeys:
    """The three-word key schedule from APPNOTE 6.1.5."""

    __slots__ = ("k0", "k1", "k2")

    def __init__(self, password: bytes) -> None:
        self.k0, self.k1, self.k2 = _KEY0, _KEY1, _KEY2
        for byte in password:
            self.update(byte)

    def update(self, byte: int) -> None:
        self.k0 = zlib.crc32(bytes([byte]), self.k0 ^ _MASK) ^ _MASK
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & _MASK
        self.k1 = (self.k1 * 134775813 + 1) & _MASK
        self.k2 = zlib.crc32(bytes([(self.k1 >> 24) & 0xFF]), self.k2 ^ _MASK) ^ _MASK

    def stream_byte(self) -> int:
        temp = (self.k2 | 2) & 0xFFFF
        return ((temp * (temp ^ 1)) >> 8) & 0xFF

    def encrypt(self, plain: bytes) -> bytes:
        out = bytearray(len(plain))
        for i, byte in enumerate(plain):
            out[i] = byte ^ self.stream_byte()
            self.update(byte)
        return bytes(out)


@dataclass(frozen=True)
class ZipEntry:
    name: str
    data: bytes
    deflate: bool = True


def _encrypt_entry(
    payload: bytes, password: bytes, crc: int, rng: Callable[[int], bytes] = os.urandom
) -> bytes:
    """12-byte header (11 random + CRC check byte) followed by the ciphertext."""
    keys = ZipCryptoKeys(password)
    header = bytearray(rng(11))
    header.append((crc >> 24) & 0xFF)
    return keys.encrypt(bytes(header)) + keys.encrypt(payload)


def build_zipcrypto_archive(
    entries: list[ZipEntry],
    password: str,
    *,
    comment: bytes = b"",
    rng: Callable[[int], bytes] = os.urandom,
) -> bytes:
    """Assemble a complete ZIP file whose entries use ZipCrypto."""
    pw = password.encode("utf-8")
    out = bytearray()
    central = bytearray()
    count = 0

    for entry in entries:
        raw = entry.data
        crc = zlib.crc32(raw) & _MASK
        if entry.deflate:
            compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
            body = compressor.compress(raw) + compressor.flush()
            method = 8
        else:
            body = raw
            method = 0
        encrypted = _encrypt_entry(body, pw, crc, rng=rng)

        name = entry.name.encode("utf-8")
        offset = len(out)
        flags = 0x1  # bit 0: encrypted. Bit 3 (data descriptor) deliberately unset,
        # which is what makes the check byte the high byte of the CRC.
        local = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            flags,
            method,
            0,
            0,
            crc,
            len(encrypted),
            len(raw),
            len(name),
            0,
        )
        out += local + name + encrypted

        central += (
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                flags,
                method,
                0,
                0,
                crc,
                len(encrypted),
                len(raw),
                len(name),
                0,
                0,
                0,
                0,
                0,
                offset,
            )
            + name
        )
        count += 1

    cd_offset = len(out)
    out += central
    out += (
        struct.pack(
            "<IHHHHIIH",
            0x06054B50,
            0,
            0,
            count,
            count,
            len(central),
            cd_offset,
            len(comment),
        )
        + comment
    )
    return bytes(out)
