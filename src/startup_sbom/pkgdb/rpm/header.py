"""Bounds-checked parser for installed RPM header blobs (all rpmdb backends).

Layout (big-endian, no lead/magic in rpmdb)::

    uint32 il, uint32 dl, entryInfo[il] (tag, type, offset, count), data[dl]

Entry 0 is normally the region tag ``HEADERIMMUTABLE`` whose trailer gives the
size of the signed region; entries after it are install-time "dribble" entries
that override region entries with the same tag.  Values are decoded lazily and
every offset/count is validated against the data store, so hostile blobs can
only produce :class:`HeaderError` or missing values — never over-reads.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from startup_sbom.errors import ParseError

# --------------------------------------------------------------------------- tags
HEADERIMAGE = 61
HEADERSIGNATURES = 62
HEADERIMMUTABLE = 63
HEADERI18NTABLE = 100

SIGSIZE = 257
SIGPGP = 259
SIGMD5 = 261
SIGGPG = 262
DSAHEADER = 267
RSAHEADER = 268
SHA1HEADER = 269
SHA256HEADER = 273
OPENPGP = 278

NAME = 1000
VERSION = 1001
RELEASE = 1002
EPOCH = 1003
SUMMARY = 1004
DESCRIPTION = 1005
BUILDTIME = 1006
BUILDHOST = 1007
INSTALLTIME = 1008
SIZE = 1009
DISTRIBUTION = 1010
VENDOR = 1011
LICENSE = 1014
PACKAGER = 1015
GROUP = 1016
URL = 1020
OS = 1021
ARCH = 1022
OLDFILENAMES = 1027
FILESIZES = 1028
FILESTATES = 1029
FILEMODES = 1030
FILEMTIMES = 1034
FILEDIGESTS = 1035
FILELINKTOS = 1036
FILEFLAGS = 1037
FILEUSERNAME = 1039
FILEGROUPNAME = 1040
SOURCERPM = 1044
PROVIDENAME = 1047
REQUIREFLAGS = 1048
REQUIRENAME = 1049
REQUIREVERSION = 1050
CONFLICTNAME = 1054
RPMVERSION = 1064
OBSOLETENAME = 1090
PROVIDEFLAGS = 1112
PROVIDEVERSION = 1113
DIRINDEXES = 1116
BASENAMES = 1117
DIRNAMES = 1118
DISTURL = 1123
INSTALLTID = 1128
PLATFORM = 1132
DISTTAG = 1155
LONGFILESIZES = 5008
LONGSIZE = 5009
FILEDIGESTALGO = 5011
BUGURL = 5012
MODULARITYLABEL = 5096
SOURCENEVR = 5120

# --------------------------------------------------------------------------- types
NULL, CHAR, INT8, INT16, INT32, INT64, STRING, BIN, STRING_ARRAY, I18NSTRING = range(10)
_INT_FMT = {CHAR: "B", INT8: "B", INT16: "H", INT32: "I", INT64: "Q"}
_INT_SIZE = {CHAR: 1, INT8: 1, INT16: 2, INT32: 4, INT64: 8}
_STRING_TYPES = (STRING, STRING_ARRAY, I18NSTRING)

ENTRY_SIZE = 16
HEADER_MAX_BYTES = 256 * 1024 * 1024
MAX_INDEX_ENTRIES = 0xFFFF
_ENTRY = struct.Struct(">iIiI")

# FILEFLAGS / FILESTATES / dependency sense bits
RPMFILE_CONFIG = 1
RPMFILE_GHOST = 64
FILESTATE_NORMAL = 0
FILESTATE_NETSHARED = 3
RPMSENSE_RPMLIB = 1 << 24


class HeaderError(ParseError):
    """An RPM header blob is structurally invalid."""


@dataclass(frozen=True, slots=True)
class _Entry:
    type: int
    offset: int
    count: int


def _decode(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")  # legacy headers; never fails


class Header:
    """A parsed RPM header with lazy, validated tag accessors.

    Accessors never raise: a malformed value is reported in :attr:`errors` and
    the accessor returns its default.  Construction raises :class:`HeaderError`
    for an invalid index or region.
    """

    __slots__ = ("_blob", "_data_end", "_data_start", "_index", "errors")

    def __init__(self, blob: bytes) -> None:
        if len(blob) < 8:
            raise HeaderError("header blob too short")
        il, dl = struct.unpack_from(">II", blob, 0)
        if il < 1 or il > MAX_INDEX_ENTRIES:
            raise HeaderError(f"bad index entry count {il}")
        data_start = 8 + il * ENTRY_SIZE
        data_end = data_start + dl
        if data_end > len(blob) or data_end >= HEADER_MAX_BYTES:
            raise HeaderError(f"bad header sizes il={il} dl={dl} len={len(blob)}")
        self._blob = blob
        self._data_start = data_start
        self._data_end = data_end
        self._index: dict[int, _Entry] = {}
        self.errors: list[str] = []

        tag0, type0, off0, cnt0 = _ENTRY.unpack_from(blob, 8)
        start = 0
        if tag0 in (HEADERIMAGE, HEADERSIGNATURES, HEADERIMMUTABLE):
            if type0 != BIN or cnt0 != ENTRY_SIZE:
                raise HeaderError("invalid region tag")
            start = 1
            if off0 != 0:  # offset 0: "upgraded" legacy header, whole index is plain
                if off0 < 0 or off0 + ENTRY_SIZE > dl:
                    raise HeaderError("region trailer out of range")
                _t, _ty, toff, _c = _ENTRY.unpack_from(blob, data_start + off0)
                ril_bytes = -toff
                if ril_bytes <= 0 or ril_bytes % ENTRY_SIZE or ril_bytes // ENTRY_SIZE > il:
                    raise HeaderError("invalid region trailer")
        elif tag0 < HEADERI18NTABLE:
            raise HeaderError(f"unexpected first tag {tag0}")

        for i in range(start, il):
            tag, typ, off, cnt = _ENTRY.unpack_from(blob, 8 + i * ENTRY_SIZE)
            if typ > I18NSTRING:
                raise HeaderError(f"tag {tag}: bad type {typ}")
            if tag < HEADERI18NTABLE:
                continue  # rpm's hdrchkTag: region/internal tags are never data
            self._index[tag] = _Entry(typ, off, cnt)  # later (dribble) entries win

    # -- low level ------------------------------------------------------------
    def tags(self) -> list[int]:
        return sorted(self._index)

    def has(self, tag: int) -> bool:
        return tag in self._index

    def type_of(self, tag: int) -> int | None:
        entry = self._index.get(tag)
        return entry.type if entry else None

    def _fail(self, tag: int, why: str) -> None:
        self.errors.append(f"tag {tag}: {why}")

    def _strings(self, tag: int, entry: _Entry) -> list[str] | None:
        pos = self._data_start + entry.offset
        end = self._data_end
        if entry.offset < 0 or pos > end:
            self._fail(tag, "offset out of range")
            return None
        if entry.count > end - pos:
            self._fail(tag, f"string count {entry.count} exceeds data")
            return None
        blob = self._blob
        out: list[str] = []
        for _ in range(entry.count):
            nul = blob.find(b"\x00", pos, end)
            if nul < 0:
                self._fail(tag, "unterminated string")
                return None
            out.append(_decode(blob[pos:nul]))
            pos = nul + 1
        return out

    def _ints(self, tag: int, entry: _Entry) -> list[int] | None:
        size = _INT_SIZE[entry.type]
        if entry.offset < 0 or entry.offset % size:
            self._fail(tag, "misaligned or negative offset")
            return None
        pos = self._data_start + entry.offset
        if entry.count * size > self._data_end - pos:
            self._fail(tag, "integer array exceeds data")
            return None
        return list(struct.unpack_from(f">{entry.count}{_INT_FMT[entry.type]}", self._blob, pos))

    # -- typed accessors ------------------------------------------------------
    def strings(self, tag: int) -> list[str]:
        """STRING_ARRAY/I18NSTRING/STRING values as a list (``[]`` if absent/bad)."""
        entry = self._index.get(tag)
        if entry is None:
            return []
        if entry.type not in _STRING_TYPES:
            self._fail(tag, f"expected string type, got {entry.type}")
            return []
        values = self._strings(tag, entry)
        if values is None:
            return []
        return values[:1] if entry.type == STRING else values

    def string(self, tag: int) -> str | None:
        """First string value (``C`` locale for i18n); ``None`` if absent or ``(none)``."""
        entry = self._index.get(tag)
        if entry is None:
            return None
        if entry.type not in _STRING_TYPES:
            self._fail(tag, f"expected string type, got {entry.type}")
            return None
        values = self._strings(tag, _Entry(entry.type, entry.offset, min(entry.count, 1)))
        if not values or values[0] == "(none)":
            return None
        return values[0]

    def ints(self, tag: int) -> list[int]:
        """Integer array (CHAR/INT8/16/32/64) as unsigned values (``[]`` if absent/bad)."""
        entry = self._index.get(tag)
        if entry is None:
            return []
        if entry.type not in _INT_FMT:
            self._fail(tag, f"expected integer type, got {entry.type}")
            return []
        return self._ints(tag, entry) or []

    def integer(self, tag: int) -> int | None:
        """First integer value, or ``None``."""
        entry = self._index.get(tag)
        if entry is None or entry.count < 1:
            return None
        if entry.type not in _INT_FMT:
            self._fail(tag, f"expected integer type, got {entry.type}")
            return None
        values = self._ints(tag, _Entry(entry.type, entry.offset, 1))
        return values[0] if values else None

    def binary(self, tag: int) -> bytes | None:
        """BIN value, or ``None``."""
        entry = self._index.get(tag)
        if entry is None:
            return None
        if entry.type != BIN:
            self._fail(tag, f"expected binary type, got {entry.type}")
            return None
        pos = self._data_start + entry.offset
        if entry.offset < 0 or entry.count > self._data_end - pos:
            self._fail(tag, "binary value exceeds data")
            return None
        return bytes(self._blob[pos : pos + entry.count])
