"""rpmdb Berkeley DB hash backend (``/var/lib/rpm/Packages``), either byte order.

Header blobs are stored off-page in overflow chains.  We linearly scan hash
pages and follow every ``H_OFFPAGE`` data item's chain (go-rpmdb's approach);
bucket hashing is never needed.  Every page number, offset and length is
validated and chains are loop-protected.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Iterator
from typing import BinaryIO

from startup_sbom.errors import ParseError
from startup_sbom.pkgdb.rpm.header import HEADER_MAX_BYTES

BDB_HASH_MAGIC = 0x00061561
_PAGE_HEADER = 26
_P_HASH_UNSORTED, _P_OVERFLOW, _P_HASHMETA, _P_HASH = 2, 7, 8, 13
_H_OFFPAGE = 3
_PAGE_SIZES = frozenset(1 << n for n in range(9, 17))


def is_bdb_hash(head: bytes) -> bool:
    """``True`` if ``head`` (≥ 16 bytes) starts a Berkeley DB hash file."""
    if len(head) < 16:
        return False
    return BDB_HASH_MAGIC in (
        struct.unpack_from("<I", head, 12)[0],
        struct.unpack_from(">I", head, 12)[0],
    )


def iter_bdb_blobs(
    f: BinaryIO, size: int, warn: Callable[[str], None] | None = None
) -> Iterator[bytes]:
    """Yield every header blob stored in the BDB hash file ``f`` of ``size`` bytes."""

    def note(msg: str) -> None:
        if warn:
            warn(msg)

    f.seek(0)
    meta = f.read(512)
    if len(meta) < 64:
        raise ParseError("BDB file too short")
    if struct.unpack_from("<I", meta, 12)[0] == BDB_HASH_MAGIC:
        bo = "<"
    elif struct.unpack_from(">I", meta, 12)[0] == BDB_HASH_MAGIC:
        bo = ">"
    else:
        raise ParseError("not a Berkeley DB hash file")
    (pagesize,) = struct.unpack_from(bo + "I", meta, 20)
    enc_alg, ptype = meta[24], meta[25]
    (last_pgno,) = struct.unpack_from(bo + "I", meta, 32)
    if enc_alg != 0:
        raise ParseError("encrypted Berkeley DB is not supported")
    if ptype != _P_HASHMETA:
        raise ParseError(f"not a hash metadata page (type {ptype})")
    if pagesize not in _PAGE_SIZES:
        raise ParseError(f"bad BDB page size {pagesize}")
    npages = min(last_pgno + 1, size // pagesize)

    def page(n: int) -> bytes:
        f.seek(n * pagesize)
        data = f.read(pagesize)
        if len(data) != pagesize:
            raise ParseError(f"short read of BDB page {n}")
        return data

    for pgno in range(1, npages):
        p = page(pgno)
        if p[25] not in (_P_HASH_UNSORTED, _P_HASH):
            continue
        (n_entries,) = struct.unpack_from(bo + "H", p, 20)
        if n_entries % 2 or _PAGE_HEADER + 2 * n_entries > pagesize:
            note(f"BDB page {pgno}: bad entry count {n_entries}")
            continue
        offs = struct.unpack_from(f"{bo}{n_entries}H", p, _PAGE_HEADER)
        for k in range(1, n_entries, 2):  # odd indexes are data items
            o = offs[k]
            if o + 12 > pagesize or p[o] != _H_OFFPAGE:
                continue  # inline H_KEYDATA records are never headers
            ov_pgno, tlen = struct.unpack_from(bo + "II", p, o + 4)
            if tlen == 0 or tlen >= HEADER_MAX_BYTES:
                note(f"BDB page {pgno}: implausible record length {tlen}")
                continue
            chunks: list[bytes] = []
            total = 0
            seen: set[int] = set()
            ok = True
            while ov_pgno and total < tlen:
                if ov_pgno in seen or ov_pgno >= npages:
                    note(f"BDB page {pgno}: broken overflow chain at {ov_pgno}")
                    ok = False
                    break
                seen.add(ov_pgno)
                op = page(ov_pgno)
                if op[25] != _P_OVERFLOW:
                    note(f"BDB page {ov_pgno}: expected overflow page")
                    ok = False
                    break
                (nxt,) = struct.unpack_from(bo + "I", op, 16)
                (used,) = struct.unpack_from(bo + "H", op, 22)
                body = op[_PAGE_HEADER : _PAGE_HEADER + used] if nxt == 0 else op[_PAGE_HEADER:]
                chunks.append(body)
                total += len(body)
                ov_pgno = nxt
            if not ok:
                continue
            blob = b"".join(chunks)
            if len(blob) < tlen:
                note(f"BDB page {pgno}: truncated record ({len(blob)} < {tlen})")
                continue
            yield blob[:tlen]
