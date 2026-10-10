"""ELF reader: all four layouts, notes, and adversarial input."""

from __future__ import annotations

import io
import random
import struct

import pytest
from elfbuilder import (
    EM_386,
    EM_AARCH64,
    EM_PPC64,
    EM_X86_64,
    ET_EXEC,
    Note,
    build_elf,
    build_id_note,
    dlopen_note,
    package_note,
)

from startup_sbom.binaries.elf import (
    parse_dlopen_json,
    parse_elf,
    parse_elf_stream,
    read_elf,
    read_section,
)


def _sample(bits: int, little: bool, machine: int) -> bytes:
    return build_elf(
        bits=bits,
        little=little,
        machine=machine,
        interp="/lib/ld-linux.so.2",
        needed=["libc.so.6", "libz.so.1", "libc.so.6"],
        rpath="/opt/r",
        runpath="$ORIGIN/../lib",
        soname="libsample.so.1",
        flags_1=0x800,
        notes=[
            build_id_note(bytes(range(20))),
            dlopen_note(
                [
                    {"soname": ["liblzma.so.5"], "priority": "suggested", "feature": "lzma"},
                    {"soname": ["libzstd.so.1", "libzstd.so"], "feature": "zstd"},
                ]
            ),
            dlopen_note([{"soname": ["libkmod.so.2"], "priority": "required"}]),
            package_note({"type": "rpm", "name": "systemd", "version": "259.9-1.fc44"}),
        ],
        sections={".go.buildinfo": b"\xff Go buildinf:" + b"\x00" * 18},
    )


@pytest.mark.parametrize(
    ("bits", "little", "machine", "arch"),
    [
        (64, True, EM_X86_64, "x86_64"),
        (64, False, EM_PPC64, "ppc64"),
        (64, True, EM_PPC64, "ppc64le"),
        (32, True, EM_386, "i386"),
        (32, False, EM_386, "i386"),
        (32, True, EM_X86_64, "x32"),
        (64, True, EM_AARCH64, "aarch64"),
    ],
)
def test_parse_all_layouts(bits: int, little: bool, machine: int, arch: str) -> None:
    info = parse_elf(_sample(bits, little, machine))
    assert info is not None
    assert info.bits == bits
    assert info.endianness == ("little" if little else "big")
    assert info.arch == arch
    assert info.interpreter == "/lib/ld-linux.so.2"
    assert info.needed == ("libc.so.6", "libz.so.1")  # duplicates dropped
    assert info.rpath == "/opt/r"
    assert info.runpath == "$ORIGIN/../lib"
    assert info.soname == "libsample.so.1"
    assert info.nodeflib
    assert info.build_id == bytes(range(20)).hex()
    assert [d.sonames for d in info.dlopen] == [
        ("liblzma.so.5",),
        ("libzstd.so.1", "libzstd.so"),
        ("libkmod.so.2",),
    ]
    assert [d.priority for d in info.dlopen] == ["suggested", "recommended", "required"]
    assert info.dlopen[0].feature == "lzma"
    assert info.package_note == {"type": "rpm", "name": "systemd", "version": "259.9-1.fc44"}
    assert info.has_go_buildinfo
    assert info.is_dynamic
    assert not info.is_static


def test_static_binary() -> None:
    info = parse_elf(build_elf(e_type=ET_EXEC, dynamic=False))
    assert info is not None
    assert info.is_static
    assert not info.is_dynamic
    assert info.needed == ()
    static_pie = parse_elf(build_elf(flags_1=0x08000000))
    assert static_pie is not None
    assert static_pie.is_static


def test_no_section_headers_still_parses_segments() -> None:
    info = parse_elf(build_elf(needed=["libc.so.6"], section_headers=False))
    assert info is not None
    assert info.needed == ("libc.so.6",)
    assert info.sections == {}


def test_stream_and_fs_reader(make_fs) -> None:
    data = _sample(64, True, EM_X86_64)
    assert parse_elf_stream(io.BytesIO(data)) == parse_elf(data)
    fs = make_fs({"/usr/bin/x": data, "/etc/notelf": b"hello", "/empty": b""})
    info = read_elf(fs, "/usr/bin/x")
    assert info is not None
    assert info.soname == "libsample.so.1"
    assert read_elf(fs, "/etc/notelf") is None
    assert read_elf(fs, "/empty") is None
    assert read_elf(fs, "/missing") is None
    assert read_elf(fs, "/usr/bin") is None
    sec = info.sections[".go.buildinfo"]
    assert read_section(fs, "/usr/bin/x", sec, 1024) == data[sec.offset : sec.offset + sec.size]
    assert read_section(fs, "/usr/bin/x", sec, 4) is None


def test_not_elf() -> None:
    assert parse_elf(b"") is None
    assert parse_elf(b"\x7fEL") is None
    assert parse_elf(b"#!/bin/sh\n") is None
    assert parse_elf(b"\x7fELF\x03\x01" + b"\x00" * 60) is None  # bad class
    assert parse_elf(b"\x7fELF\x02\x07" + b"\x00" * 60) is None  # bad data encoding


def test_every_truncation_is_safe() -> None:
    data = _sample(64, True, EM_X86_64)
    for n in range(len(data)):
        parse_elf(data[:n])  # must never raise


def test_random_mutations_are_safe() -> None:
    rng = random.Random(1234)  # noqa: S311 - deterministic fuzzing, not crypto
    seeds = [_sample(64, True, EM_X86_64), _sample(32, False, EM_386)]
    for i in range(3000):
        buf = bytearray(seeds[i % 2])
        for _ in range(rng.randint(1, 8)):
            pos = rng.randrange(len(buf))
            buf[pos] = rng.randrange(256)
        parse_elf(bytes(buf))


def _patch(data: bytes, fmt: str, off: int, *values: int) -> bytes:
    buf = bytearray(data)
    struct.pack_into(fmt, buf, off, *values)
    return bytes(buf)


def test_bogus_header_fields() -> None:
    data = build_elf(needed=["libc.so.6"])
    # program header offset far beyond EOF
    info = parse_elf(_patch(data, "<Q", 0x20, 2**63))
    assert info is not None
    assert info.needed == ()
    # huge phnum
    assert parse_elf(_patch(data, "<H", 0x38, 0xFFFE)) is not None
    # PN_XNUM with junk section 0
    assert parse_elf(_patch(data, "<H", 0x38, 0xFFFF)) is not None
    # phentsize too small
    assert parse_elf(_patch(data, "<H", 0x36, 4)).needed == ()  # type: ignore[union-attr]
    # bogus section table
    assert parse_elf(_patch(data, "<Q", 0x28, 2**40)) is not None
    assert parse_elf(_patch(data, "<H", 0x3C, 0xFFFF)) is not None
    assert parse_elf(_patch(data, "<H", 0x3E, 0xFFFF)) is not None


def test_dynamic_without_null_and_bogus_string_offsets() -> None:
    data = build_elf(needed=["libc.so.6"])
    info = parse_elf(data)
    assert info is not None
    dyn = info.sections[".dynamic"]
    buf = bytearray(data)
    # point DT_NEEDED at an offset beyond the string table and drop DT_NULL
    for k in range(dyn.offset, dyn.offset + dyn.size, 16):
        tag, _val = struct.unpack_from("<qQ", buf, k)
        if tag == 1:
            struct.pack_into("<qQ", buf, k, 1, 2**60)
        if tag == 0:
            struct.pack_into("<qQ", buf, k, 0x7FFFFFFF, 0)
    info2 = parse_elf(bytes(buf))
    assert info2 is not None
    assert info2.needed == ()


def test_note_loops_and_huge_sizes() -> None:
    zero = Note(b"", 0, b"")  # zero-sized notes must still advance
    many = [zero] * 1000
    info = parse_elf(build_elf(notes=many))
    assert info is not None
    huge = build_elf(notes=[Note(b"FDO", 0x407C0C0A, b"[]")])
    info = parse_elf(huge)
    assert info is not None
    note = info.sections[".note"]
    bad = _patch(huge, "<I", note.offset + 4, 0xFFFFFFF0)  # descsz past the segment
    assert parse_elf(bad) is not None


def test_dlopen_json_validation() -> None:
    assert parse_dlopen_json(b"not json\x00") == []
    assert parse_dlopen_json(b'{"soname": "x"}') == []
    assert (
        parse_dlopen_json(b'[{"soname": []}, 5, {"soname": [1, "ok.so.1"], "priority": "x"}]')[
            0
        ].priority
        == "recommended"
    )
    deep = b"[" * 100000 + b"]" * 100000
    assert parse_dlopen_json(deep) == []
    big = b'[{"soname":["a"]}' + b" " * 70000 + b"]"
    assert parse_dlopen_json(big) == []


def test_package_note_rejects_non_objects() -> None:
    info = parse_elf(build_elf(notes=[Note(b"FDO", 0xCAFE1A7E, b'["x"]\x00')]))
    assert info is not None
    assert info.package_note is None
