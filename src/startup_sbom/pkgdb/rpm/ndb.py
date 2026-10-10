"""rpmdb NDB backend (``Packages.db``; openSUSE / SLE 15 SP3+), rpm ``rpmpkg.c``.

Little-endian: a 32-byte ``RpmP`` header, then 16-byte slots (``Slot`` magic,
pkgidx, block offset, block count) and ``BlbS``-prefixed header blobs addressed
in 16-byte blocks.  All offsets and lengths are validated against the file.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Iterator
from typing import BinaryIO

from startup_sbom.errors import ParseError
from startup_sbom.pkgdb.rpm.header import HEADER_MAX_BYTES

NDB_MAGIC = b"RpmP"
_SLOT_MAGIC = b"Slot"
_BLOB_MAGIC = b"BlbS"
_BLK = 16
_SLOT_PAGE = 4096
_MAX_SLOT_PAGES = 2048
_REC = struct.Struct("<4sIII")


def iter_ndb_blobs(
    f: BinaryIO, size: int, warn: Callable[[str], None] | None = None
) -> Iterator[bytes]:
    """Yield every header blob in the NDB file ``f`` of ``size`` bytes."""

    def note(msg: str) -> None:
        if warn:
            warn(msg)

    f.seek(0)
    head = f.read(32)
    if len(head) < 32:
        raise ParseError("NDB file too short")
    magic, version, _gen, slot_npages = _REC.unpack_from(head, 0)
    if magic != NDB_MAGIC or version != 0 or not 0 < slot_npages <= _MAX_SLOT_PAGES:
        raise ParseError("bad NDB header")
    area = min(slot_npages * _SLOT_PAGE, size)
    f.seek(0)
    slots = f.read(area)
    nslots = (len(slots) - 32) // _BLK
    for i in range(nslots):
        smagic, pkgidx, blkoff, _blkcnt = _REC.unpack_from(slots, 32 + i * _BLK)
        if smagic != _SLOT_MAGIC or pkgidx == 0:
            continue  # free or uninitialised slot
        off = blkoff * _BLK
        if off < area or off + _BLK > size:
            note(f"NDB slot {i}: blob offset {off} out of range")
            continue
        f.seek(off)
        bhead = f.read(_BLK)
        bmagic, bidx, _cksum, blen = _REC.unpack_from(bhead, 0)
        if bmagic != _BLOB_MAGIC or bidx != pkgidx:
            note(f"NDB slot {i}: bad blob header for package {pkgidx}")
            continue
        if blen >= HEADER_MAX_BYTES or off + _BLK + blen > size:
            note(f"NDB slot {i}: blob length {blen} out of range")
            continue
        blob = f.read(blen)
        if len(blob) != blen:
            note(f"NDB slot {i}: short read")
            continue
        yield blob
