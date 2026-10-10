"""Tiny synthetic ELF writer for tests (32/64-bit, little/big endian).

Produces files with a single ``PT_LOAD`` covering the whole image, optional
``PT_INTERP``, ``PT_DYNAMIC`` (``DT_NEEDED``/``DT_RPATH``/``DT_RUNPATH``/``DT_SONAME``/
``DT_FLAGS_1``), one ``PT_NOTE`` segment and arbitrary extra named sections
(``.go.buildinfo``, ``.dep-v0`` ...) plus a section header table.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183
EM_PPC64 = 21
EM_S390 = 22

ET_EXEC = 2
ET_DYN = 3

BASE = 0x400000


@dataclass(frozen=True)
class Note:
    name: bytes
    type: int
    desc: bytes


def dlopen_note(entries: Sequence[Mapping[str, object]]) -> Note:
    return Note(b"FDO", 0x407C0C0A, json.dumps(list(entries)).encode() + b"\x00")


def package_note(fields: Mapping[str, str]) -> Note:
    return Note(b"FDO", 0xCAFE1A7E, json.dumps(dict(fields)).encode() + b"\x00")


def build_id_note(raw: bytes) -> Note:
    return Note(b"GNU", 3, raw)


def _pad(buf: bytearray, alignment: int) -> None:
    while len(buf) % alignment:
        buf.append(0)


def _note_bytes(notes: Iterable[Note], e: str) -> bytes:
    out = bytearray()
    for n in notes:
        name = n.name + b"\x00"
        out += struct.pack(e + "III", len(name), len(n.desc), n.type)
        out += name
        _pad(out, 4)
        out += n.desc
        _pad(out, 4)
    return bytes(out)


def build_elf(
    *,
    bits: int = 64,
    little: bool = True,
    machine: int = EM_X86_64,
    e_type: int = ET_DYN,
    interp: str | None = None,
    needed: Sequence[str] = (),
    rpath: str | None = None,
    runpath: str | None = None,
    soname: str | None = None,
    flags_1: int | None = None,
    dynamic: bool | None = None,
    notes: Sequence[Note] = (),
    sections: Mapping[str, bytes] | None = None,
    section_headers: bool = True,
) -> bytes:
    """Return the bytes of a synthetic ELF object."""
    e = "<" if little else ">"
    c64 = bits == 64
    ehsize, phentsize, shentsize = (64, 56, 64) if c64 else (52, 32, 40)
    if dynamic is None:
        dynamic = bool(needed or rpath or runpath or soname or flags_1 is not None or interp)
    sections = dict(sections or {})

    # ---- dynamic string table and entries
    dynstr = bytearray(b"\x00")
    dyn: list[tuple[int, int]] = []

    def add_str(s: str) -> int:
        off = len(dynstr)
        dynstr.extend(s.encode() + b"\x00")
        return off

    dyn.extend((1, add_str(n)) for n in needed)
    if soname is not None:
        dyn.append((14, add_str(soname)))
    if rpath is not None:
        dyn.append((15, add_str(rpath)))
    if runpath is not None:
        dyn.append((29, add_str(runpath)))
    if flags_1 is not None:
        dyn.append((0x6FFFFFFB, flags_1))

    phnum = 1 + (interp is not None) + bool(dynamic) + bool(notes)
    body = bytearray(b"\x00" * (ehsize + phentsize * phnum))
    offs: dict[str, tuple[int, int]] = {}

    def place(name: str, data: bytes, alignment: int) -> None:
        _pad(body, alignment)
        offs[name] = (len(body), len(data))
        body.extend(data)

    if interp is not None:
        place(".interp", interp.encode() + b"\x00", 1)
    if dynamic:
        place(".dynstr", bytes(dynstr), 1)
        strtab_va = BASE + offs[".dynstr"][0]
        entries = [(5, strtab_va), (10, len(dynstr)), *dyn, (0, 0)]
        fmt = e + ("qQ" if c64 else "iI")
        place(".dynamic", b"".join(struct.pack(fmt, t, v) for t, v in entries), 8)
    if notes:
        place(".note", _note_bytes(notes, e), 4)
    for name, data in sections.items():
        place(name, data, 16)
    shnames = bytearray(b"\x00")
    name_offs: dict[str, int] = {}
    for name in [*offs, ".shstrtab"]:
        name_offs[name] = len(shnames)
        shnames.extend(name.encode() + b"\x00")
    place(".shstrtab", bytes(shnames), 1)
    _pad(body, 8)
    shoff = len(body) if section_headers else 0
    shnum = len(offs) + 1 if section_headers else 0
    if section_headers:
        sh_types = {".dynstr": 3, ".dynamic": 6, ".note": 7, ".shstrtab": 3}
        body.extend(b"\x00" * shentsize)
        for name, (off, size) in offs.items():
            stype = sh_types.get(name, 1)
            addr = BASE + off
            if c64:
                body += struct.pack(
                    e + "IIQQQQIIQQ", name_offs[name], stype, 2, addr, off, size, 0, 0, 1, 0
                )
            else:
                body += struct.pack(
                    e + "IIIIIIIIII", name_offs[name], stype, 2, addr, off, size, 0, 0, 1, 0
                )
    total = len(body)

    # ---- program headers
    phdrs: list[tuple[int, int, int, int, int]] = [(1, 0, BASE, total, 0x1000)]
    if interp is not None:
        o, s = offs[".interp"]
        phdrs.append((3, o, BASE + o, s, 1))
    if dynamic:
        o, s = offs[".dynamic"]
        phdrs.append((2, o, BASE + o, s, 8))
    if notes:
        o, s = offs[".note"]
        phdrs.append((4, o, BASE + o, s, 4))
    ph = bytearray()
    for pt, off, va, sz, align in phdrs:
        if c64:
            ph += struct.pack(e + "IIQQQQQQ", pt, 5, off, va, va, sz, sz, align)
        else:
            ph += struct.pack(e + "IIIIIIII", pt, off, va, va, sz, sz, 5, align)
    body[ehsize : ehsize + len(ph)] = ph

    # ---- ELF header
    ident = b"\x7fELF" + bytes([2 if c64 else 1, 1 if little else 2, 1, 0]) + b"\x00" * 8
    shstrndx = shnum - 1 if section_headers else 0
    if c64:
        hdr = struct.pack(
            e + "HHIQQQIHHHHHH", e_type, machine, 1, BASE, ehsize, shoff, 0, ehsize,
            phentsize, phnum, shentsize, shnum, shstrndx,
        )  # fmt: skip
    else:
        hdr = struct.pack(
            e + "HHIIIIIHHHHHH", e_type, machine, 1, BASE, ehsize, shoff, 0, ehsize,
            phentsize, phnum, shentsize, shnum, shstrndx,
        )  # fmt: skip
    body[0 : len(ident) + len(hdr)] = ident + hdr
    return bytes(body)


def exe(
    needed: Sequence[str] = ("libc.so.6",),
    *,
    interp: str = "/lib64/ld-linux-x86-64.so.2",
    **kw: object,
) -> bytes:
    """A dynamically linked x86-64 executable."""
    return build_elf(e_type=ET_DYN, interp=interp, needed=needed, flags_1=0x08000000, **kw)  # type: ignore[arg-type]


def lib(soname: str, needed: Sequence[str] = (), **kw: object) -> bytes:
    """A shared library with ``DT_SONAME``."""
    return build_elf(e_type=ET_DYN, soname=soname, needed=needed, **kw)  # type: ignore[arg-type]


def build_ld_so_cache(
    entries: Sequence[tuple[str, str]], *, flags: int = 0x0303, little: bool = True
) -> bytes:
    """A ``glibc-ld.so.cache1.1`` file mapping sonames to paths."""
    e = "<" if little else ">"
    n = len(entries)
    strings = bytearray()
    header_len = 48 + 24 * n
    packed: list[tuple[int, int]] = []
    for key, value in entries:
        k = header_len + len(strings)
        strings.extend(key.encode() + b"\x00")
        v = header_len + len(strings)
        strings.extend(value.encode() + b"\x00")
        packed.append((k, v))
    out = bytearray(b"glibc-ld.so.cache1.1")
    out += struct.pack(e + "II", n, len(strings))
    out += bytes([2 if little else 3, 0, 0, 0])
    out += struct.pack(e + "I", 0) + b"\x00" * 12
    for k, v in packed:
        out += struct.pack(e + "iIIIQ", flags, k, v, 0, 0)
    out += strings
    return bytes(out)
