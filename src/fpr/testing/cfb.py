"""A minimal writer for Compound File Binary (CFB / OLE2) containers.

Why this exists
---------------
Encrypted OOXML documents are not ZIPs: ECMA-376 wraps the package in a CFB
container holding ``EncryptionInfo`` and ``EncryptedPackage`` streams. To test
our *decryption* path we need encrypted sample files, and to have any
confidence in those tests the samples must come from an implementation other
than the one under test.

``olefile`` -- the library everything in this space uses for reading -- cannot
write (upstream issue decalage2/olefile#6), and the writer bundled with
msoffcrypto 6.0.0 produces containers whose directory entries point at the
wrong sectors (see docs/research/02-format-notes.md). So this module writes the
container itself, from the specification.

Scope and limits
----------------
* Version 3 containers only: 512-byte sectors, 64-byte mini sectors, 4096-byte
  mini-stream cutoff. That is what Office writes and what every reader accepts.
* The DIFAT is confined to the 109 slots in the header, which caps a container
  at roughly 7 MiB of payload. Fixtures are small; :func:`write` raises a clear
  error rather than silently producing a corrupt file if that is exceeded.
* Red-black colouring is not maintained. Sibling trees are built balanced from
  a sorted list and every node is coloured black, which readers accept because
  a perfectly balanced all-black tree satisfies the red-black invariants.

This module is *test/fixture* infrastructure. Nothing in the removal path
imports it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from struct import pack

__all__ = ["CfbNode", "storage", "stream", "write", "CfbTooLargeError"]

MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
MINI_STREAM_CUTOFF = 4096
DIFAT_HEADER_SLOTS = 109
FAT_ENTRIES_PER_SECTOR = SECTOR_SIZE // 4
MINIFAT_ENTRIES_PER_SECTOR = SECTOR_SIZE // 4
DIR_ENTRIES_PER_SECTOR = SECTOR_SIZE // 128

MAXREGSECT = 0xFFFFFFFA
DIFSECT = 0xFFFFFFFC
FATSECT = 0xFFFFFFFD
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
NOSTREAM = 0xFFFFFFFF

TYPE_EMPTY = 0
TYPE_STORAGE = 1
TYPE_STREAM = 2
TYPE_ROOT = 5

COLOR_BLACK = 1


class CfbTooLargeError(ValueError):
    """The container would need DIFAT sectors, which this writer does not emit."""


@dataclass
class CfbNode:
    """One storage (directory) or stream (file) in the container."""

    name: str
    is_storage: bool
    data: bytes = b""
    children: list[CfbNode] = field(default_factory=list)

    def __post_init__(self) -> None:
        # 31 UTF-16 code units plus the terminator is the hard limit of the
        # 64-byte name field in a directory entry.
        if len(self.name.encode("utf-16-le")) > 62:
            raise ValueError(f"CFB entry name too long: {self.name!r}")


def storage(name: str, children: list[CfbNode]) -> CfbNode:
    return CfbNode(name=name, is_storage=True, children=children)


def stream(name: str, data: bytes) -> CfbNode:
    return CfbNode(name=name, is_storage=False, data=data)


def _sort_key(node: CfbNode) -> tuple[int, str]:
    """CFB sibling order: shorter names first, then case-insensitive ordinal."""
    return (len(node.name.encode("utf-16-le")) + 2, node.name.upper())


@dataclass
class _Entry:
    name: str
    kind: int
    left: int = NOSTREAM
    right: int = NOSTREAM
    child: int = NOSTREAM
    start: int = 0
    size: int = 0
    data: bytes = b""


def _build_directory(root_children: list[CfbNode]) -> list[_Entry]:
    """Flatten the node tree into directory entries with sibling links."""
    entries: list[_Entry] = [_Entry(name="Root Entry", kind=TYPE_ROOT)]

    def add(node: CfbNode) -> int:
        idx = len(entries)
        entries.append(
            _Entry(
                name=node.name,
                kind=TYPE_STORAGE if node.is_storage else TYPE_STREAM,
                data=b"" if node.is_storage else node.data,
                size=0 if node.is_storage else len(node.data),
            )
        )
        if node.children:
            entries[idx].child = _link(node.children)
        return idx

    def _link(siblings: list[CfbNode]) -> int:
        """Insert a sibling group as a balanced tree; return the root index."""
        ordered = sorted(siblings, key=_sort_key)
        indices = [add(n) for n in ordered]

        def build(lo: int, hi: int) -> int:
            if lo > hi:
                return NOSTREAM
            mid = (lo + hi) // 2
            idx = indices[mid]
            entries[idx].left = build(lo, mid - 1)
            entries[idx].right = build(mid + 1, hi)
            return idx

        return build(0, len(indices) - 1)

    if root_children:
        entries[0].child = _link(root_children)
    return entries


def _chain(fat: list[int], sectors: list[int]) -> None:
    for a, b in zip(sectors, sectors[1:], strict=False):
        fat[a] = b
    if sectors:
        fat[sectors[-1]] = ENDOFCHAIN


def _pad(data: bytes, size: int) -> bytes:
    rem = len(data) % size
    return data + b"\x00" * (size - rem) if rem else data


def write(children: list[CfbNode]) -> bytes:
    """Serialise ``children`` (the contents of the root storage) to CFB bytes."""
    entries = _build_directory(children)

    # ---- split streams into mini-stream residents and full-sector residents
    mini_payload = bytearray()
    mini_chains: dict[int, list[int]] = {}
    big: list[int] = []
    for i, e in enumerate(entries):
        if e.kind != TYPE_STREAM:
            continue
        if e.size < MINI_STREAM_CUTOFF:
            first = len(mini_payload) // MINI_SECTOR_SIZE
            blob = _pad(e.data, MINI_SECTOR_SIZE)
            count = len(blob) // MINI_SECTOR_SIZE
            mini_payload.extend(blob)
            mini_chains[i] = list(range(first, first + count))
            e.start = first
        else:
            big.append(i)

    # ---- lay out sectors: big streams, mini stream, MiniFAT, directory, FAT
    next_sector = 0
    sector_blobs: list[bytes] = []

    def allocate(blob: bytes) -> list[int]:
        nonlocal next_sector
        padded = _pad(blob, SECTOR_SIZE)
        count = len(padded) // SECTOR_SIZE
        ids = list(range(next_sector, next_sector + count))
        next_sector += count
        for c in range(count):
            sector_blobs.append(padded[c * SECTOR_SIZE : (c + 1) * SECTOR_SIZE])
        return ids

    big_chains = {i: allocate(entries[i].data) for i in big}
    for i, ids in big_chains.items():
        entries[i].start = ids[0] if ids else ENDOFCHAIN

    mini_container = allocate(bytes(mini_payload)) if mini_payload else []
    entries[0].start = mini_container[0] if mini_container else ENDOFCHAIN
    entries[0].size = len(mini_payload)

    minifat_len = len(mini_payload) // MINI_SECTOR_SIZE
    minifat = [FREESECT] * (
        max(1, -(-minifat_len // MINIFAT_ENTRIES_PER_SECTOR)) * MINIFAT_ENTRIES_PER_SECTOR
    )
    for ids in mini_chains.values():
        _chain(minifat, ids)
    minifat_sectors = allocate(b"".join(pack("<I", v) for v in minifat)) if minifat_len else []

    # A directory sector holds exactly four 128-byte entries; pad the tail with
    # EMPTY entries rather than zero bytes so readers see a well-formed type.
    padded_entries = entries + [_Entry(name="", kind=TYPE_EMPTY)] * (
        (-len(entries)) % DIR_ENTRIES_PER_SECTOR
    )
    dir_sectors = allocate(b"".join(_encode_entry(e) for e in padded_entries))

    data_sectors = next_sector
    fat_count = 1
    while True:
        total = data_sectors + fat_count
        if -(-total // FAT_ENTRIES_PER_SECTOR) <= fat_count:
            break
        fat_count += 1
    if fat_count > DIFAT_HEADER_SLOTS:
        raise CfbTooLargeError(
            f"Container needs {fat_count} FAT sectors; this writer supports at most "
            f"{DIFAT_HEADER_SLOTS} (~7 MiB). Use a smaller fixture."
        )

    fat_sectors = list(range(data_sectors, data_sectors + fat_count))
    fat = [FREESECT] * (fat_count * FAT_ENTRIES_PER_SECTOR)
    for ids in big_chains.values():
        _chain(fat, ids)
    _chain(fat, mini_container)
    _chain(fat, minifat_sectors)
    _chain(fat, dir_sectors)
    for s in fat_sectors:
        fat[s] = FATSECT

    fat_blob = b"".join(pack("<I", v) for v in fat)
    for c in range(fat_count):
        sector_blobs.append(fat_blob[c * SECTOR_SIZE : (c + 1) * SECTOR_SIZE])

    # ------------------------------------------------------------- header
    header = bytearray()
    header += MAGIC
    header += b"\x00" * 16  # CLSID
    header += pack(
        "<HHHHHHHHIIIIIIIII",
        0x003E,  # minor version
        3,  # major version
        0xFFFE,  # little endian
        9,  # sector shift -> 512
        6,  # mini sector shift -> 64
        0,
        0,
        0,  # reserved
        0,  # number of directory sectors (v3: unused)
        fat_count,
        dir_sectors[0],
        0,  # transaction signature
        MINI_STREAM_CUTOFF,
        minifat_sectors[0] if minifat_sectors else ENDOFCHAIN,
        len(minifat_sectors),
        ENDOFCHAIN,  # first DIFAT sector
        0,  # number of DIFAT sectors
    )
    for i in range(DIFAT_HEADER_SLOTS):
        header += pack("<I", fat_sectors[i] if i < fat_count else FREESECT)
    if len(header) != SECTOR_SIZE:  # pragma: no cover - structural invariant
        raise ValueError(f"CFB header is {len(header)} bytes, expected {SECTOR_SIZE}")

    return bytes(header) + b"".join(sector_blobs)


def _encode_entry(e: _Entry) -> bytes:
    name16 = e.name.encode("utf-16-le")
    name_len = len(name16) + 2 if e.name else 0
    buf = bytearray(name16 + b"\x00\x00")
    buf += b"\x00" * (64 - len(buf))
    out = bytes(buf[:64])
    out += pack("<H", name_len)
    out += pack("<BB", e.kind, COLOR_BLACK)
    out += pack("<III", e.left, e.right, e.child)
    out += b"\x00" * 16  # CLSID
    out += pack("<I", 0)  # state bits
    out += pack("<QQ", 0, 0)  # creation / modification time
    out += pack("<I", e.start if e.kind != TYPE_EMPTY else 0)
    out += pack("<Q", e.size)
    if len(out) != 128:  # pragma: no cover - structural invariant
        raise ValueError(f"CFB directory entry is {len(out)} bytes, expected 128")
    return out
