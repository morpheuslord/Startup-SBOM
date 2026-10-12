"""Test helpers that *write* rpmdb structures: header blobs, PGP packets, BDB/NDB/SQLite files."""

from __future__ import annotations

import sqlite3
import struct
from collections.abc import Sequence
from pathlib import Path

from startup_sbom.pkgdb.rpm import header as rpmtag

Value = str | bytes | int | Sequence[str | bytes] | Sequence[int]
Entry = tuple[int, int, Value]

_INT_FMT = {
    rpmtag.CHAR: "B",
    rpmtag.INT8: "B",
    rpmtag.INT16: "H",
    rpmtag.INT32: "I",
    rpmtag.INT64: "Q",
}
_ALIGN = {rpmtag.INT16: 2, rpmtag.INT32: 4, rpmtag.INT64: 8}


def _s(v: str | bytes) -> bytes:
    return v if isinstance(v, bytes) else v.encode()


def encode_header(
    entries: Sequence[Entry], dribble: Sequence[Entry] = (), *, region: bool = True
) -> bytes:
    """Encode an installed header blob (region tag + trailer, then dribble entries)."""
    data = bytearray()
    index: list[tuple[int, int, int, int]] = []

    def add(tag: int, typ: int, value: Value) -> None:
        while len(data) % _ALIGN.get(typ, 1):
            data.append(0)
        off = len(data)
        if typ == rpmtag.STRING:
            assert isinstance(value, str | bytes)
            data.extend(_s(value) + b"\0")
            cnt = 1
        elif typ in (rpmtag.STRING_ARRAY, rpmtag.I18NSTRING):
            assert isinstance(value, list | tuple)
            for item in value:
                assert isinstance(item, str | bytes)
                data.extend(_s(item) + b"\0")
            cnt = len(value)
        elif typ == rpmtag.BIN:
            assert isinstance(value, bytes)
            data.extend(value)
            cnt = len(value)
        else:
            ints = [value] if isinstance(value, int) else list(value)
            data.extend(struct.pack(f">{len(ints)}{_INT_FMT[typ]}", *ints))
            cnt = len(ints)
        index.append((tag, typ, off, cnt))

    for e in entries:
        add(*e)
    if region:
        ril = len(entries) + 1
        trailer_off = len(data)
        data.extend(struct.pack(">iIiI", rpmtag.HEADERIMMUTABLE, rpmtag.BIN, -ril * 16, 16))
        index.insert(0, (rpmtag.HEADERIMMUTABLE, rpmtag.BIN, trailer_off, 16))
    for e in dribble:
        add(*e)
    head = struct.pack(">II", len(index), len(data))
    body = b"".join(struct.pack(">iIiI", *e) for e in index)
    return head + body + bytes(data)


# --------------------------------------------------------------------------- PGP
def _subpacket(stype: int, payload: bytes) -> bytes:
    return bytes([len(payload) + 1, stype]) + payload


def pgp_v4_signature(
    key_id: bytes | None = None,
    fingerprint: bytes | None = None,
    created: int = 1_700_000_000,
    pubalgo: int = 1,
    hashalgo: int = 8,
    *,
    new_format: bool = False,
) -> bytes:
    """A minimal v4 signature packet with issuer / issuer-fingerprint subpackets."""
    hashed = _subpacket(2, struct.pack(">I", created))
    if fingerprint is not None:
        hashed += _subpacket(33, b"\x04" + fingerprint)
    unhashed = _subpacket(16, key_id) if key_id is not None else b""
    body = (
        bytes([4, 0, pubalgo, hashalgo])
        + struct.pack(">H", len(hashed))
        + hashed
        + struct.pack(">H", len(unhashed))
        + unhashed
        + b"\xab\xcd"
        + b"\x00\x08\xff"  # dummy MPI
    )
    if new_format:
        assert len(body) < 192
        return bytes([0xC0 | 2, len(body)]) + body
    return bytes([0x89]) + struct.pack(">H", len(body)) + body


def pgp_v3_signature(key_id: bytes, created: int = 1_200_000_000, pubalgo: int = 17) -> bytes:
    body = (
        bytes([3, 5, 0]) + struct.pack(">I", created) + key_id + bytes([pubalgo, 2]) + b"\x12\x34"
    )
    return bytes([0x89]) + struct.pack(">H", len(body)) + body


# --------------------------------------------------------------------------- packages
def rpm_header(
    name: str,
    version: str,
    release: str,
    *,
    epoch: int | None = None,
    arch: str = "x86_64",
    sourcerpm: str | None = None,
    files: Sequence[tuple[str, int, str, int]] = (),  # (path, mode, digest, flags)
    filestates: Sequence[int] | None = None,
    requires: Sequence[str] = (),
    provides: Sequence[str] = (),
    signature: bytes | None = None,
    installtime: int = 1_760_000_000,
    summary: str | bytes = "summary",
    vendor: str | bytes = "Vendor",
    license_: str = "MIT",
    digest_algo: int | None = 8,
    extra: Sequence[Entry] = (),
) -> bytes:
    entries: list[Entry] = [
        (rpmtag.NAME, rpmtag.STRING, name),
        (rpmtag.VERSION, rpmtag.STRING, version),
        (rpmtag.RELEASE, rpmtag.STRING, release),
    ]
    if epoch is not None:
        entries.append((rpmtag.EPOCH, rpmtag.INT32, [epoch]))
    entries += [
        (rpmtag.SUMMARY, rpmtag.I18NSTRING, [summary]),
        (rpmtag.SIZE, rpmtag.INT32, [12345]),
        (rpmtag.VENDOR, rpmtag.STRING, vendor),
        (rpmtag.LICENSE, rpmtag.STRING, license_),
        (rpmtag.PACKAGER, rpmtag.STRING, "Packager <p@example.org>"),
        (rpmtag.URL, rpmtag.STRING, f"https://example.org/{name}"),
        (rpmtag.ARCH, rpmtag.STRING, arch),
    ]
    if sourcerpm:
        entries.append((rpmtag.SOURCERPM, rpmtag.STRING, sourcerpm))
    if provides:
        entries.append((rpmtag.PROVIDENAME, rpmtag.STRING_ARRAY, list(provides)))
        entries.append((rpmtag.PROVIDEFLAGS, rpmtag.INT32, [0] * len(provides)))
    if requires:
        flags = [rpmtag.RPMSENSE_RPMLIB if r.startswith("rpmlib(") else 0 for r in requires]
        entries.append((rpmtag.REQUIRENAME, rpmtag.STRING_ARRAY, list(requires)))
        entries.append((rpmtag.REQUIREFLAGS, rpmtag.INT32, flags))
    if files:
        dirnames: list[str] = []
        dirindexes: list[int] = []
        basenames: list[str] = []
        for path, _mode, _digest, _flags in files:
            d, _, b = path.rpartition("/")
            d += "/"
            if d not in dirnames:
                dirnames.append(d)
            dirindexes.append(dirnames.index(d))
            basenames.append(b)
        entries += [
            (rpmtag.FILEMODES, rpmtag.INT16, [f[1] for f in files]),
            (rpmtag.FILEDIGESTS, rpmtag.STRING_ARRAY, [f[2] for f in files]),
            (rpmtag.FILEFLAGS, rpmtag.INT32, [f[3] for f in files]),
            (rpmtag.DIRINDEXES, rpmtag.INT32, dirindexes),
            (rpmtag.BASENAMES, rpmtag.STRING_ARRAY, basenames),
            (rpmtag.DIRNAMES, rpmtag.STRING_ARRAY, dirnames),
        ]
        if digest_algo is not None:
            entries.append((rpmtag.FILEDIGESTALGO, rpmtag.INT32, [digest_algo]))
    entries += list(extra)
    dribble: list[Entry] = [(rpmtag.INSTALLTIME, rpmtag.INT32, [installtime])]
    if filestates is not None:
        dribble.append((rpmtag.FILESTATES, rpmtag.CHAR, [s & 0xFF for s in filestates]))
    if signature is not None:
        dribble.append((rpmtag.RSAHEADER, rpmtag.BIN, signature))
    return encode_header(entries, dribble)


def pubkey_header(version: str, summary: str) -> bytes:
    return encode_header(
        [
            (rpmtag.NAME, rpmtag.STRING, "gpg-pubkey"),
            (rpmtag.VERSION, rpmtag.STRING, version),
            (rpmtag.RELEASE, rpmtag.STRING, "5f5f5f5f"),
            (rpmtag.SUMMARY, rpmtag.I18NSTRING, [summary]),
        ]
    )


# --------------------------------------------------------------------------- backends
def build_sqlite(path: Path, blobs: Sequence[bytes]) -> bytes:
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)"
    )
    con.executemany("INSERT INTO Packages (blob) VALUES (?)", [(b,) for b in blobs])
    con.commit()
    con.close()
    return path.read_bytes()


def build_sqlite_with_wal(
    path: Path, base: Sequence[bytes], pending: Sequence[bytes]
) -> tuple[bytes, bytes]:
    """Return (db, wal) bytes where ``pending`` rows exist only in the un-checkpointed WAL."""
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute(
        "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)"
    )
    con.executemany("INSERT INTO Packages (blob) VALUES (?)", [(b,) for b in base])
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.executemany("INSERT INTO Packages (blob) VALUES (?)", [(b,) for b in pending])
    con.commit()
    db, wal = path.read_bytes(), Path(str(path) + "-wal").read_bytes()
    con.close()
    return db, wal


def build_bdb(blobs: Sequence[bytes], *, pagesize: int = 512, big_endian: bool = False) -> bytes:
    """A minimal Berkeley DB hash file: one hash page, values in overflow chains."""
    bo = ">" if big_endian else "<"
    room = pagesize - 26
    pages: list[bytearray] = []
    hash_page = bytearray(pagesize)
    pages.append(bytearray(pagesize))  # page 0: meta (filled later)
    pages.append(hash_page)  # page 1
    items: list[bytes] = []
    for hnum, blob in enumerate(blobs, 1):
        first = len(pages)
        chunks = [blob[i : i + room] for i in range(0, len(blob), room)] or [b""]
        for ci, chunk in enumerate(chunks):
            pg = bytearray(pagesize)
            pgno = first + ci
            nxt = pgno + 1 if ci + 1 < len(chunks) else 0
            struct.pack_into(bo + "I", pg, 8, pgno)
            struct.pack_into(bo + "I", pg, 16, nxt)
            struct.pack_into(bo + "H", pg, 22, len(chunk))
            pg[25] = 7
            pg[26 : 26 + len(chunk)] = chunk
            pages.append(pg)
        items.append(b"\x01" + struct.pack(bo + "I", hnum))  # H_KEYDATA key
        items.append(b"\x03\x00\x00\x00" + struct.pack(bo + "II", first, len(blob)))  # H_OFFPAGE
    # lay items out from the end of the hash page
    end = pagesize
    offsets: list[int] = []
    for item in items:
        end -= len(item)
        hash_page[end : end + len(item)] = item
        offsets.append(end)
    struct.pack_into(bo + "I", hash_page, 8, 1)
    struct.pack_into(bo + "H", hash_page, 20, len(items))
    struct.pack_into(bo + "H", hash_page, 22, end)
    hash_page[25] = 13
    struct.pack_into(f"{bo}{len(offsets)}H", hash_page, 26, *offsets)
    meta = pages[0]
    struct.pack_into(bo + "I", meta, 12, 0x00061561)
    struct.pack_into(bo + "I", meta, 16, 9)
    struct.pack_into(bo + "I", meta, 20, pagesize)
    meta[24] = 0
    meta[25] = 8
    struct.pack_into(bo + "I", meta, 32, len(pages) - 1)
    return b"".join(bytes(p) for p in pages)


def build_ndb(blobs: Sequence[bytes]) -> bytes:
    """A minimal NDB ``Packages.db`` with one slot page."""
    out = bytearray(4096)
    out[0:16] = struct.pack("<4sIII", b"RpmP", 0, 1, 1)
    for i, blob in enumerate(blobs):
        while len(out) % 16:
            out.append(0)
        off = len(out)
        rec = struct.pack("<4sIII", b"BlbS", i + 1, 0, len(blob)) + blob
        rec += b"\0" * (-len(rec) % 16) + b"BlbE" + b"\0" * 12
        out.extend(rec)
        struct.pack_into("<4sIII", out, 32 + i * 16, b"Slot", i + 1, off // 16, len(rec) // 16)
    # remaining slots: free
    for i in range(len(blobs), (4096 - 32) // 16):
        struct.pack_into("<4sIII", out, 32 + i * 16, b"Slot", 0, 0, 0)
    return bytes(out)
