"""Minimal, bounds-checked ELF reader for hostile input (stdlib only).

Only the metadata the loader and supply-chain analysis need is decoded: the
ELF header, program headers (``PT_INTERP``, ``PT_LOAD``, ``PT_DYNAMIC``,
``PT_NOTE``), the dynamic section (``DT_NEEDED``, ``DT_RPATH``, ``DT_RUNPATH``,
``DT_SONAME``, ``DT_FLAGS_1``), FDO ``.note.dlopen`` / ``.note.package`` notes,
the GNU build-id and the section-header names (to locate ``.go.buildinfo`` and
``.dep-v0``).  Program headers are the primary source because stripped binaries
may lack a section table and the loader itself only uses segments.

Reads go through a lazy reader so that a multi-megabyte binary costs a handful
of small, capped reads.  Every offset, size and count is validated against the
file size and fixed caps; malformed input yields ``None`` or partial data, never
an exception.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import BinaryIO

from startup_sbom.errors import RootFSError
from startup_sbom.rootfs import RootFS

ELF_MAGIC = b"\x7fELF"
MAX_FILE_SIZE = 64 * 1024 * 1024  #: never treat more than this as addressable
MAX_PHNUM = 1024
MAX_SHNUM = 16384
MAX_DYN_ENTRIES = 8192
MAX_NEEDED = 1024
MAX_STRTAB = 4 * 1024 * 1024
MAX_NOTE_SEGMENT = 1024 * 1024
MAX_NOTES = 256
MAX_JSON_NOTE = 64 * 1024
MAX_STRING = 4096
MAX_SECTIONS_KEPT = 1024
READ_BUDGET = 16 * 1024 * 1024  #: total bytes one parse may read

ET_EXEC = 2
ET_DYN = 3

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4

SHT_NOTE = 7

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
DT_FLAGS_1 = 0x6FFFFFFB

DF_1_NODEFLIB = 0x800
DF_1_PIE = 0x08000000

NT_GNU_BUILD_ID = 3
NT_GO_BUILD_ID = 4
NT_FDO_PACKAGE = 0xCAFE1A7E
NT_FDO_DLOPEN = 0x407C0C0A

DLOPEN_PRIORITIES = ("required", "recommended", "suggested")

_MACHINES: dict[int, str] = {
    2: "sparc",
    3: "i386",
    4: "m68k",
    8: "mips",
    15: "hppa",
    20: "ppc",
    21: "ppc64",
    22: "s390",
    40: "arm",
    42: "sh",
    43: "sparc64",
    50: "ia64",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
    258: "loongarch",
    0x9026: "alpha",
}


def machine_arch(machine: int, bits: int, little_endian: bool) -> str:
    """Map ``e_machine`` (+ class/endianness) to a conventional arch string."""
    base = _MACHINES.get(machine)
    if base is None:
        return f"em{machine}"
    if base == "x86_64" and bits == 32:
        return "x32"
    if base == "ppc64":
        return "ppc64le" if little_endian else "ppc64"
    if base == "ppc" and little_endian:
        return "ppcle"
    if base == "s390":
        return "s390x" if bits == 64 else "s390"
    if base == "mips":
        suffix = "el" if little_endian else ""
        return f"mips64{suffix}" if bits == 64 else f"mips{suffix}"
    if base in ("riscv", "loongarch"):
        return f"{base}{bits}"
    return base


# --------------------------------------------------------------------------- data
@dataclass(frozen=True, slots=True)
class DlopenEntry:
    """One element of an FDO ``.note.dlopen`` JSON array (UAPI.12)."""

    sonames: tuple[str, ...]
    priority: str = "recommended"
    feature: str | None = None
    description: str | None = None


@dataclass(frozen=True, slots=True)
class ElfLoad:
    """A ``PT_LOAD`` segment: file range ``[offset, offset+filesz)`` mapped at ``vaddr``."""

    vaddr: int
    offset: int
    filesz: int


@dataclass(frozen=True, slots=True)
class ElfSection:
    """A section header entry (only offset/size/type/address are kept)."""

    name: str
    type: int
    offset: int
    size: int
    addr: int


@dataclass(frozen=True, slots=True)
class ElfInfo:
    """Loader- and provenance-relevant metadata of one ELF object."""

    bits: int
    little_endian: bool
    machine: int
    arch: str
    e_type: int
    osabi: int = 0
    interpreter: str | None = None
    needed: tuple[str, ...] = ()
    rpath: str | None = None
    runpath: str | None = None
    soname: str | None = None
    flags_1: int = 0
    has_dynamic: bool = False
    dlopen: tuple[DlopenEntry, ...] = ()
    package_note: Mapping[str, str] | None = None
    build_id: str | None = None
    go_build_id: str | None = None
    loads: tuple[ElfLoad, ...] = ()
    sections: Mapping[str, ElfSection] = field(default_factory=dict)
    size: int = 0

    @property
    def endianness(self) -> str:
        return "little" if self.little_endian else "big"

    @property
    def elf_class(self) -> str:
        return f"ELF{self.bits}"

    @property
    def nodeflib(self) -> bool:
        return bool(self.flags_1 & DF_1_NODEFLIB)

    @property
    def is_static(self) -> bool:
        """``True`` for executables that load no shared objects (incl. static-pie)."""
        if self.interpreter is not None or self.needed:
            return False
        if self.e_type == ET_EXEC:
            return True
        return self.e_type == ET_DYN and bool(self.flags_1 & DF_1_PIE)

    @property
    def is_dynamic(self) -> bool:
        return self.interpreter is not None or bool(self.needed)

    @property
    def has_go_buildinfo(self) -> bool:
        return ".go.buildinfo" in self.sections or self.go_build_id is not None

    def compatible_with(self, other: ElfInfo) -> bool:
        """Same class, byte order and machine (what ld.so requires of a dependency)."""
        return (
            self.bits == other.bits
            and self.little_endian == other.little_endian
            and self.machine == other.machine
        )

    def vaddr_to_offset(self, vaddr: int) -> int | None:
        """Translate a virtual address to a file offset through the ``PT_LOAD`` segments."""
        for seg in self.loads:
            if seg.vaddr <= vaddr < seg.vaddr + seg.filesz:
                return vaddr - seg.vaddr + seg.offset
        return None


# --------------------------------------------------------------------------- reader
class _BudgetError(Exception):
    pass


class _Reader:
    """Bounded random-access reader over bytes or a seekable stream."""

    def __init__(self, read_at: Callable[[int, int], bytes], size: int) -> None:
        self._read_at = read_at
        self.size = min(size, MAX_FILE_SIZE)
        self._budget = READ_BUDGET

    def read(self, offset: int, length: int) -> bytes:
        """Return up to ``length`` bytes at ``offset`` (short or empty when out of range)."""
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        self._budget -= length
        if self._budget < 0:
            raise _BudgetError
        return self._read_at(offset, length)

    def exact(self, offset: int, length: int) -> bytes | None:
        data = self.read(offset, length)
        return data if len(data) == length else None


def _bytes_reader(data: bytes) -> _Reader:
    view = memoryview(data)
    return _Reader(lambda off, n: bytes(view[off : off + n]), len(data))


def _stream_reader(f: BinaryIO, size: int) -> _Reader:
    def read_at(off: int, n: int) -> bytes:
        f.seek(off)
        return f.read(n)

    return _Reader(read_at, size)


# --------------------------------------------------------------------------- parsing
def _cstr(buf: bytes, off: int) -> str | None:
    if off < 0 or off >= len(buf):
        return None
    end = buf.find(b"\x00", off, off + MAX_STRING)
    if end < 0:
        return None
    return buf[off:end].decode("utf-8", "replace")


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


@dataclass(slots=True)
class _Dynamic:
    needed: tuple[str, ...] = ()
    rpath: str | None = None
    runpath: str | None = None
    soname: str | None = None
    flags_1: int = 0


class _Parser:
    def __init__(self, r: _Reader) -> None:
        self.r = r
        self.notes_seen = 0
        self.dlopen: list[DlopenEntry] = []
        self.package_note: dict[str, str] | None = None
        self.build_id: str | None = None
        self.go_build_id: str | None = None

    def parse(self) -> ElfInfo | None:
        r = self.r
        ident = r.exact(0, 16)
        if ident is None or ident[:4] != ELF_MAGIC:
            return None
        ei_class, ei_data = ident[4], ident[5]
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            return None
        self.c64 = ei_class == 2
        self.le = ei_data == 1
        self.e = "<" if self.le else ">"
        e = self.e
        if self.c64:
            hdr = r.exact(16, 48)
            if hdr is None:
                return None
            (e_type, e_machine, _ver, _entry, phoff, shoff, _flags, _ehsize) = struct.unpack_from(
                e + "HHIQQQIH", hdr, 0
            )
            phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(e + "HHHHH", hdr, 38)
        else:
            hdr = r.exact(16, 36)
            if hdr is None:
                return None
            (e_type, e_machine, _ver, _entry, phoff, shoff, _flags, _ehsize) = struct.unpack_from(
                e + "HHIIIIIH", hdr, 0
            )
            phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(e + "HHHHH", hdr, 26)
        bits = 64 if self.c64 else 32
        sections = self._sections(shoff, shentsize, shnum, shstrndx)
        if phnum == 0xFFFF:  # PN_XNUM: real count lives in section 0 sh_info
            phnum = self._section0_field(shoff, shentsize, "info") or 0
        phdrs = self._phdrs(phoff, phentsize, phnum)
        loads = tuple(
            ElfLoad(vaddr, off, filesz) for (pt, off, vaddr, filesz, _a) in phdrs if pt == PT_LOAD
        )
        dyn = _Dynamic()
        interp: str | None = None
        has_dynamic = False
        note_segments = 0
        for pt, off, _vaddr, filesz, palign in phdrs:
            if pt == PT_INTERP and interp is None:
                raw = r.read(off, min(filesz, MAX_STRING))
                interp = raw.split(b"\x00", 1)[0].decode("utf-8", "replace") or None
            elif pt == PT_DYNAMIC and not has_dynamic:
                has_dynamic = True
                dyn = self._dynamic(off, filesz, loads, sections)
            elif pt == PT_NOTE:
                note_segments += 1
                self._notes(off, filesz, 8 if palign == 8 else 4)
        if note_segments == 0:
            for sec in sections.values():
                if sec.type == SHT_NOTE:
                    self._notes(sec.offset, sec.size, 4)
        return ElfInfo(
            bits=bits,
            little_endian=self.le,
            machine=e_machine,
            arch=machine_arch(e_machine, bits, self.le),
            e_type=e_type,
            osabi=ident[7],
            interpreter=interp,
            needed=dyn.needed,
            rpath=dyn.rpath,
            runpath=dyn.runpath,
            soname=dyn.soname,
            flags_1=dyn.flags_1,
            has_dynamic=has_dynamic,
            dlopen=tuple(self.dlopen),
            package_note=self.package_note,
            build_id=self.build_id,
            go_build_id=self.go_build_id,
            loads=loads,
            sections=sections,
            size=r.size,
        )

    # -- program headers ------------------------------------------------------
    def _phdrs(
        self, phoff: int, phentsize: int, phnum: int
    ) -> list[tuple[int, int, int, int, int]]:
        need = 56 if self.c64 else 32
        if phnum <= 0 or phentsize < need or phnum > MAX_PHNUM:
            return []
        table = self.r.read(phoff, phentsize * phnum)
        out: list[tuple[int, int, int, int, int]] = []
        e = self.e
        for i in range(len(table) // phentsize):
            o = i * phentsize
            if self.c64:
                pt, _fl, off, vaddr, _pa, filesz, _memsz, align = struct.unpack_from(
                    e + "IIQQQQQQ", table, o
                )
            else:
                pt, off, vaddr, _pa, filesz, _memsz, _fl, align = struct.unpack_from(
                    e + "IIIIIIII", table, o
                )
            if off >= self.r.size:
                continue
            filesz = min(filesz, self.r.size - off)
            out.append((pt, off, vaddr, filesz, align))
        return out

    # -- sections -------------------------------------------------------------
    def _section0_field(self, shoff: int, shentsize: int, what: str) -> int | None:
        need = 64 if self.c64 else 40
        if shoff == 0 or shentsize < need:
            return None
        raw = self.r.exact(shoff, need)
        if raw is None:
            return None
        if self.c64:
            _n, _t, _f, _a, _o, size, link, info = struct.unpack_from(self.e + "IIQQQQII", raw, 0)
        else:
            _n, _t, _f, _a, _o, size, link, info = struct.unpack_from(self.e + "IIIIIIII", raw, 0)
        values: dict[str, int] = {"size": size, "link": link, "info": info}
        return values[what]

    def _sections(
        self, shoff: int, shentsize: int, shnum: int, shstrndx: int
    ) -> dict[str, ElfSection]:
        need = 64 if self.c64 else 40
        if shoff == 0 or shentsize < need:
            return {}
        if shnum == 0:
            shnum = self._section0_field(shoff, shentsize, "size") or 0
        if shstrndx == 0xFFFF:
            shstrndx = self._section0_field(shoff, shentsize, "link") or 0
        if shnum <= 0 or shnum > MAX_SHNUM or shstrndx >= shnum:
            return {}
        table = self.r.read(shoff, shentsize * shnum)
        count = len(table) // shentsize
        raw: list[tuple[int, int, int, int, int]] = []
        e = self.e
        for i in range(count):
            o = i * shentsize
            if self.c64:
                name, stype, _fl, addr, off, size, _l, _i = struct.unpack_from(
                    e + "IIQQQQII", table, o
                )
            else:
                name, stype, _fl, addr, off, size, _l, _i = struct.unpack_from(
                    e + "IIIIIIII", table, o
                )
            raw.append((name, stype, addr, off, size))
        if shstrndx >= len(raw):
            return {}
        _n, _t, _a, str_off, str_size = raw[shstrndx]
        strtab = self.r.read(str_off, min(str_size, MAX_STRTAB))
        out: dict[str, ElfSection] = {}
        for name_off, stype, addr, off, size in raw:
            if len(out) >= MAX_SECTIONS_KEPT:
                break
            name = _cstr(strtab, name_off)
            if not name or name in out or stype == 8:  # SHT_NOBITS has no file data
                continue
            if off >= self.r.size:
                continue
            out[name] = ElfSection(name, stype, off, min(size, self.r.size - off), addr)
        return out

    # -- dynamic --------------------------------------------------------------
    def _dynamic(
        self,
        off: int,
        size: int,
        loads: tuple[ElfLoad, ...],
        sections: Mapping[str, ElfSection],
    ) -> _Dynamic:
        step = 16 if self.c64 else 8
        fmt = self.e + ("qQ" if self.c64 else "iI")
        raw = self.r.read(off, min(size, step * MAX_DYN_ENTRIES))
        entries: list[tuple[int, int]] = []
        for k in range(0, len(raw) - step + 1, step):
            tag, val = struct.unpack_from(fmt, raw, k)
            if tag == DT_NULL:
                break
            entries.append((tag, val))
        strtab_va = next((v for t, v in entries if t == DT_STRTAB), None)
        strsz = next((v for t, v in entries if t == DT_STRSZ), None)
        strtab_off: int | None = None
        if strtab_va is not None:
            for seg in loads:
                if seg.vaddr <= strtab_va < seg.vaddr + seg.filesz:
                    strtab_off = strtab_va - seg.vaddr + seg.offset
                    if strsz is None:
                        strsz = seg.vaddr + seg.filesz - strtab_va
                    break
        if strtab_off is None and ".dynstr" in sections:
            sec = sections[".dynstr"]
            strtab_off, strsz = sec.offset, sec.size
        strtab = b""
        if strtab_off is not None:
            strtab = self.r.read(strtab_off, min(strsz or 0, MAX_STRTAB))
        needed: list[str] = []
        out = _Dynamic()
        for tag, val in entries:
            if tag == DT_FLAGS_1:
                out.flags_1 = val
                continue
            if tag not in (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH):
                continue
            s = _cstr(strtab, val)
            if s is None:
                continue
            if tag == DT_NEEDED:
                if s and s not in needed and len(needed) < MAX_NEEDED:
                    needed.append(s)
            elif tag == DT_SONAME:
                out.soname = out.soname if out.soname is not None else s
            elif tag == DT_RPATH:
                out.rpath = out.rpath if out.rpath is not None else s
            else:
                out.runpath = out.runpath if out.runpath is not None else s
        out.needed = tuple(needed)
        return out

    # -- notes ----------------------------------------------------------------
    def _notes(self, off: int, size: int, alignment: int) -> None:
        data = self.r.read(off, min(size, MAX_NOTE_SEGMENT))
        e = self.e
        o = 0
        while o + 12 <= len(data) and self.notes_seen < MAX_NOTES:
            namesz, descsz, ntype = struct.unpack_from(e + "III", data, o)
            self.notes_seen += 1
            name_start = o + 12
            desc_start = name_start + _align(namesz, alignment)
            nxt = desc_start + _align(descsz, alignment)
            if desc_start + descsz > len(data) or nxt <= o:
                break
            name = data[name_start : name_start + namesz].rstrip(b"\x00")
            desc = data[desc_start : desc_start + descsz]
            self._note(name, ntype, desc)
            o = nxt

    def _note(self, name: bytes, ntype: int, desc: bytes) -> None:
        if name == b"GNU" and ntype == NT_GNU_BUILD_ID and self.build_id is None:
            if 0 < len(desc) <= 64:
                self.build_id = desc.hex()
        elif name == b"Go" and ntype == NT_GO_BUILD_ID and self.go_build_id is None:
            self.go_build_id = desc[:MAX_STRING].decode("utf-8", "replace").rstrip("\x00")
        elif name == b"FDO" and ntype == NT_FDO_DLOPEN:
            self.dlopen.extend(parse_dlopen_json(desc))
        elif name == b"FDO" and ntype == NT_FDO_PACKAGE and self.package_note is None:
            self.package_note = parse_package_json(desc)


def _json_desc(desc: bytes) -> object:
    if len(desc) > MAX_JSON_NOTE:
        return None
    text = desc.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def parse_dlopen_json(desc: bytes) -> list[DlopenEntry]:
    """Decode one ``.note.dlopen`` descriptor (JSON array of objects)."""
    doc = _json_desc(desc)
    if not isinstance(doc, list):
        return []
    out: list[DlopenEntry] = []
    for item in doc[:256]:
        if not isinstance(item, dict):
            continue
        sonames = item.get("soname")
        if isinstance(sonames, str):
            sonames = [sonames]
        if not isinstance(sonames, list):
            continue
        names = tuple(s for s in sonames[:32] if isinstance(s, str) and 0 < len(s) <= 255)
        if not names:
            continue
        prio = item.get("priority", "recommended")
        if prio not in DLOPEN_PRIORITIES:
            prio = "recommended"
        feature = item.get("feature")
        descr = item.get("description")
        out.append(
            DlopenEntry(
                sonames=names,
                priority=prio,
                feature=feature[:256] if isinstance(feature, str) else None,
                description=descr[:1024] if isinstance(descr, str) else None,
            )
        )
    return out


def parse_package_json(desc: bytes) -> dict[str, str] | None:
    """Decode a ``.note.package`` descriptor (JSON object, UAPI.8); scalar values only."""
    doc = _json_desc(desc)
    if not isinstance(doc, dict):
        return None
    out: dict[str, str] = {}
    for k, v in list(doc.items())[:64]:
        if isinstance(k, str) and isinstance(v, str | int | float) and not isinstance(v, bool):
            out[k[:64]] = str(v)[:1024]
    return out or None


# --------------------------------------------------------------------------- API
def parse_elf(data: bytes) -> ElfInfo | None:
    """Parse ELF metadata from an in-memory buffer; ``None`` if not a usable ELF."""
    return _safe_parse(_bytes_reader(data))


def parse_elf_stream(f: BinaryIO, size: int | None = None) -> ElfInfo | None:
    """Parse ELF metadata from a seekable stream, reading only what is needed."""
    try:
        if size is None:
            size = f.seek(0, 2)
    except OSError:
        return None
    return _safe_parse(_stream_reader(f, size))


def read_elf(fs: RootFS, path: str) -> ElfInfo | None:
    """Parse the ELF at in-image ``path``; ``None`` if missing, irregular or not ELF."""
    try:
        with fs.open(path) as f:
            return parse_elf_stream(f)
    except (RootFSError, OSError, ValueError):
        return None


def read_section(fs: RootFS, path: str, section: ElfSection, limit: int) -> bytes | None:
    """Read the file data of ``section`` (at most ``limit`` bytes) from in-image ``path``."""
    if section.size <= 0 or section.size > limit:
        return None
    try:
        with fs.open(path) as f:
            f.seek(section.offset)
            data = f.read(section.size)
    except (RootFSError, OSError, ValueError):
        return None
    return data if len(data) == section.size else None


def _safe_parse(r: _Reader) -> ElfInfo | None:
    try:
        return _Parser(r).parse()
    except (struct.error, _BudgetError, OSError, ValueError, OverflowError, MemoryError):
        return None
