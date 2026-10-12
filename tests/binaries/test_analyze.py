"""Executable reachability: xz-style chains, dlopen notes, preload, scripts, privileges."""

from __future__ import annotations

import os
import struct
import sys

import pytest
from elfbuilder import build_elf, dlopen_note, exe, lib, package_note

from fsbuilder import File, Symlink
from startup_sbom.binaries import (
    analyze_executables,
    find_privileged,
    find_unmanaged_executables,
)
from startup_sbom.binaries.analyze import package_note_purl
from startup_sbom.models import Confidence, Package, PackageType
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks")

T = "x86_64-linux-gnu"
SSHD = "pkg:deb/debian/openssh-server@1:9.2p1-2"
SYSTEMD = "pkg:deb/debian/libsystemd0@252.22-1"
LZMA = "pkg:deb/debian/liblzma5@5.4.1-0.2"
ZSTD = "pkg:deb/debian/libzstd1@1.5.4"
LIBC = "pkg:deb/debian/libc6@2.36-9"


def _base_spec(libsystemd: bytes) -> dict:
    return {
        "/lib": Symlink("usr/lib"),
        "/lib64": Symlink("usr/lib64"),
        "/usr/sbin/sshd": File(exe(["libsystemd.so.0", "libcrypto.so.3", "libc.so.6"]), 0o755),
        f"/usr/lib/{T}/libsystemd.so.0": Symlink("libsystemd.so.0.35.0"),
        f"/usr/lib/{T}/libsystemd.so.0.35.0": libsystemd,
        f"/usr/lib/{T}/liblzma.so.5": Symlink("liblzma.so.5.4.1"),
        f"/usr/lib/{T}/liblzma.so.5.4.1": lib("liblzma.so.5", ["libc.so.6"]),
        f"/usr/lib/{T}/libzstd.so.1": lib("libzstd.so.1", ["libc.so.6"]),
        f"/usr/lib/{T}/libc.so.6": lib("libc.so.6"),
        f"/usr/lib/{T}/ld-linux-x86-64.so.2": lib("ld-linux-x86-64.so.2"),
        "/usr/lib64/ld-linux-x86-64.so.2": Symlink(f"/lib/{T}/ld-linux-x86-64.so.2"),
    }


def _owners(fs) -> FileOwnerIndex:
    idx = FileOwnerIndex(fs)
    idx.add(SSHD, ["/usr/sbin/sshd"])
    idx.add(SYSTEMD, [f"/lib/{T}/libsystemd.so.0", f"/lib/{T}/libsystemd.so.0.35.0"])
    idx.add(LZMA, [f"/lib/{T}/liblzma.so.5", f"/lib/{T}/liblzma.so.5.4.1"])
    idx.add(ZSTD, [f"/lib/{T}/libzstd.so.1"])
    idx.add(
        LIBC,
        [f"/lib/{T}/libc.so.6", "/lib64/ld-linux-x86-64.so.2", f"/lib/{T}/ld-linux-x86-64.so.2"],
    )
    return idx


def _link(binary, soname):
    return next(lk for lk in binary.libraries if lk.soname == soname)


@needs_symlinks
def test_xz_chain_via_needed(make_fs, make_ctx) -> None:
    fs = make_fs(_base_spec(lib("libsystemd.so.0", ["liblzma.so.5", "libc.so.6"])))
    ctx = make_ctx(fs)
    out = analyze_executables(
        ctx, ["/usr/sbin/sshd"], _owners(fs), used_by={"/usr/sbin/sshd": ["systemd:ssh.service"]}
    )
    sshd = out["/usr/sbin/sshd"]
    assert sshd.kind == "elf"
    assert sshd.arch == "x86_64"
    assert sshd.package == SSHD
    assert sshd.used_by == ["systemd:ssh.service"]
    assert sshd.needed == ["libsystemd.so.0", "libcrypto.so.3", "libc.so.6"]
    assert sshd.unresolved == ["libcrypto.so.3"]
    assert sshd.interpreter == f"/usr/lib/{T}/ld-linux-x86-64.so.2"
    loader = _link(sshd, "ld-linux-x86-64.so.2")
    assert (loader.via, loader.package, loader.depth) == ("interpreter", LIBC, 1)
    sd = _link(sshd, "libsystemd.so.0")
    assert (sd.path, sd.package, sd.depth, sd.via) == (
        f"/usr/lib/{T}/libsystemd.so.0.35.0",
        SYSTEMD,
        1,
        "needed",
    )
    lz = _link(sshd, "liblzma.so.5")
    assert lz.path == f"/usr/lib/{T}/liblzma.so.5.4.1"
    assert (lz.package, lz.depth, lz.via, lz.confidence) == (LZMA, 2, "needed", Confidence.HIGH)
    # exact chain: sshd -> libsystemd -> liblzma
    assert lz.parent == f"/usr/lib/{T}/libsystemd.so.0.35.0"
    assert sd.parent == "/usr/sbin/sshd"
    assert loader.parent == "/usr/sbin/sshd"
    libc = _link(sshd, "libc.so.6")
    assert libc.depth == 1
    assert len({lk.path for lk in sshd.libraries}) == len(sshd.libraries)
    assert not ctx.warnings


@needs_symlinks
def test_xz_chain_via_dlopen_note(make_fs, make_ctx) -> None:
    libsystemd = lib(
        "libsystemd.so.0",
        ["libc.so.6"],
        notes=[
            dlopen_note([{"soname": ["liblzma.so.5"], "priority": "suggested", "feature": "lzma"}]),
            dlopen_note([{"soname": ["libzstd.so.1"], "priority": "recommended"}]),
            dlopen_note([{"soname": ["libkmod.so.2"], "priority": "required"}]),
            dlopen_note([{"soname": ["liblz4.so.1"], "priority": "suggested"}]),
        ],
    )
    fs = make_fs(_base_spec(libsystemd))
    out = analyze_executables(make_ctx(fs), ["/usr/sbin/sshd"], _owners(fs))
    sshd = out["/usr/sbin/sshd"]
    lz = _link(sshd, "liblzma.so.5")
    assert (lz.via, lz.confidence, lz.depth, lz.package) == ("dlopen", Confidence.LOW, 2, LZMA)
    assert lz.parent == f"/usr/lib/{T}/libsystemd.so.0.35.0"
    assert _link(sshd, "libsystemd.so.0").parent == "/usr/sbin/sshd"
    zs = _link(sshd, "libzstd.so.1")
    assert (zs.via, zs.confidence, zs.package) == ("dlopen", Confidence.MEDIUM, ZSTD)
    # missing required dlopen deps are reported, missing suggested ones are not
    assert sshd.unresolved == ["libcrypto.so.3", "libkmod.so.2"]


def test_strongest_path_wins(make_fs, make_ctx) -> None:
    fs = make_fs(
        {
            "/usr/bin/app": exe(
                ["liba.so.1"],
                notes=[dlopen_note([{"soname": ["libb.so.1"], "priority": "suggested"}])],
            ),
            "/usr/lib64/liba.so.1": lib("liba.so.1", ["libb.so.1"]),
            "/usr/lib64/libb.so.1": lib("libb.so.1", ["libc.so.6"]),
            "/usr/lib64/libc.so.6": lib("libc.so.6"),
        }
    )
    app = analyze_executables(make_ctx(fs), ["/usr/bin/app"], FileOwnerIndex(fs))["/usr/bin/app"]
    b = _link(app, "libb.so.1")
    assert (b.via, b.confidence, b.depth) == ("needed", Confidence.HIGH, 2)
    c = _link(app, "libc.so.6")
    assert (c.confidence, c.depth) == (Confidence.HIGH, 3)
    assert app.unresolved == ["/lib64/ld-linux-x86-64.so.2"]


def test_dlopen_children_inherit_confidence(make_fs, make_ctx) -> None:
    fs = make_fs(
        {
            "/usr/bin/app": exe(
                [], notes=[dlopen_note([{"soname": ["libplug.so"], "priority": "suggested"}])]
            ),
            "/usr/lib64/libplug.so": lib("libplug.so", ["libdep.so.1"]),
            "/usr/lib64/libdep.so.1": lib("libdep.so.1"),
        }
    )
    app = analyze_executables(make_ctx(fs), ["/usr/bin/app"], FileOwnerIndex(fs))["/usr/bin/app"]
    dep = _link(app, "libdep.so.1")
    assert (dep.via, dep.confidence, dep.depth) == ("dlopen", Confidence.LOW, 2)


def test_preload_applies_to_glibc_only(make_fs, make_ctx) -> None:
    fs = make_fs(
        {
            "/etc/ld.so.preload": "/usr/lib64/libevil.so\nlibmissing.so\n",
            "/usr/lib64/libevil.so": lib("libevil.so", ["libhelper.so.1"]),
            "/usr/lib64/libhelper.so.1": lib("libhelper.so.1"),
            "/usr/bin/app": exe([]),
            "/usr/bin/muslapp": exe([], interp="/lib/ld-musl-x86_64.so.1"),
            "/usr/bin/static": build_elf(e_type=2, dynamic=False),
        }
    )
    out = analyze_executables(
        make_ctx(fs), ["/usr/bin/app", "/usr/bin/muslapp", "/usr/bin/static"], FileOwnerIndex(fs)
    )
    app = out["/usr/bin/app"]
    evil = _link(app, "libevil.so")
    assert (evil.via, evil.depth, evil.path) == ("preload", 1, "/usr/lib64/libevil.so")
    helper = _link(app, "libhelper.so.1")
    assert (helper.via, helper.depth) == ("preload", 2)
    assert evil.parent == "/usr/bin/app"
    assert helper.parent == "/usr/lib64/libevil.so"
    assert "libmissing.so" in app.unresolved
    assert not any(lk.via == "preload" for lk in out["/usr/bin/muslapp"].libraries)
    assert out["/usr/bin/static"].libraries == []


def test_depth_limit(make_fs, make_ctx) -> None:
    spec: dict = {"/usr/bin/app": exe(["l0.so"])}
    for i in range(12):
        spec[f"/usr/lib64/l{i}.so"] = lib(f"l{i}.so", [f"l{i + 1}.so"])
    fs = make_fs(spec)
    app = analyze_executables(make_ctx(fs), ["/usr/bin/app"], FileOwnerIndex(fs), max_depth=3)[
        "/usr/bin/app"
    ]
    assert max(lk.depth for lk in app.libraries) == 3
    deep = analyze_executables(
        make_ctx(fs, max_link_depth=20), ["/usr/bin/app"], FileOwnerIndex(fs)
    )
    assert max(lk.depth for lk in deep["/usr/bin/app"].libraries) == 12


def test_cyclic_needed_terminates(make_fs, make_ctx) -> None:
    fs = make_fs(
        {
            "/usr/bin/app": exe(["liba.so"]),
            "/usr/lib64/liba.so": lib("liba.so", ["libb.so"]),
            "/usr/lib64/libb.so": lib("libb.so", ["liba.so", "libapp.so"]),
            "/usr/lib64/libapp.so": Symlink("/usr/bin/app"),
        }
    )
    app = analyze_executables(make_ctx(fs), ["/usr/bin/app"], FileOwnerIndex(fs))["/usr/bin/app"]
    assert {lk.soname for lk in app.libraries} == {"liba.so", "libb.so"}


@needs_symlinks
def test_script_interpreter_chain(make_fs, make_ctx) -> None:
    fs = make_fs(
        {
            "/usr/local/bin/tool": File("#!/usr/bin/env -S python3 -u\nprint(1)\n", 0o755),
            "/usr/bin/env": File(exe(["libc.so.6"]), 0o755),
            "/usr/bin/python3": Symlink("python3.12"),
            "/usr/bin/python3.12": File(exe(["libpython3.12.so.1.0", "libc.so.6"]), 0o755),
            "/usr/lib64/libpython3.12.so.1.0": lib("libpython3.12.so.1.0", ["libc.so.6"]),
            "/usr/lib64/libc.so.6": lib("libc.so.6"),
            "/usr/lib64/ld-linux-x86-64.so.2": lib("ld-linux-x86-64.so.2"),
            "/etc/init.d/svc": File("#!/bin/sh\n", 0o755),
            "/usr/bin/loop-a": File("#!/usr/bin/loop-b\n", 0o755),
            "/usr/bin/loop-b": File("#!/usr/bin/loop-a\n", 0o755),
            "/usr/bin/bare": File("#!/usr/bin/env nosuchprog\n", 0o755),
        }
    )
    idx = FileOwnerIndex(fs)
    idx.add("pkg:deb/debian/python3.12-minimal@3.12.1", ["/usr/bin/python3.12"])
    out = analyze_executables(
        make_ctx(fs),
        ["/usr/local/bin/tool", "/etc/init.d/svc", "/usr/bin/loop-a", "/usr/bin/bare"],
        idx,
        used_by={"/usr/local/bin/tool": ["systemd:tool.service"]},
    )
    tool = out["/usr/local/bin/tool"]
    assert tool.kind == "script"
    assert tool.interpreter == "/usr/bin/python3.12"
    py = _link(tool, "python3")
    assert (py.via, py.path, py.depth, py.package) == (
        "interpreter",
        "/usr/bin/python3.12",
        1,
        "pkg:deb/debian/python3.12-minimal@3.12.1",
    )
    assert _link(tool, "env").via == "interpreter"
    lp = _link(tool, "libpython3.12.so.1.0")
    assert (lp.via, lp.depth) == ("needed", 2)
    assert py.parent == "/usr/local/bin/tool"
    assert lp.parent == "/usr/bin/python3.12"
    assert out["/usr/bin/python3.12"].used_by == ["systemd:tool.service"]
    assert out["/usr/bin/env"].used_by == ["systemd:tool.service"]
    assert out["/usr/bin/python3.12"].kind == "elf"
    assert out["/etc/init.d/svc"].unresolved == ["/bin/sh"]
    assert "/usr/bin/loop-b" in out
    assert "nosuchprog" in out["/usr/bin/bare"].unresolved


def test_link_analysis_disabled(make_fs, make_ctx) -> None:
    fs = make_fs(
        {"/usr/bin/app": File(exe(["libz.so.1"]), 0o755), "/usr/lib64/libz.so.1": lib("libz.so.1")}
    )
    idx = FileOwnerIndex(fs)
    idx.add("pkg:deb/debian/app@1", ["/usr/bin/app"])
    out = analyze_executables(make_ctx(fs, link_analysis=False), ["/usr/bin/app"], idx)
    app = out["/usr/bin/app"]
    assert (app.kind, app.package, app.libraries, app.needed) == (
        "elf",
        "pkg:deb/debian/app@1",
        [],
        [],
    )


def test_missing_and_garbage_inputs(make_fs, make_ctx) -> None:
    fs = make_fs(
        {
            "/usr/bin/trunc": File(exe(["libz.so.1"])[:40], 0o755),
            "/usr/bin/data": File(b"\x00\x01binary", 0o755),
        }
    )
    ctx = make_ctx(fs)
    out = analyze_executables(
        ctx,
        ["/usr/bin/trunc", "/usr/bin/data", "/nope", "relative", "/usr/bin"],
        FileOwnerIndex(fs),
    )
    assert out["/usr/bin/trunc"].kind == "elf"
    assert out["/usr/bin/trunc"].libraries == []
    assert out["/usr/bin/data"].kind == "unknown"
    assert len(ctx.warnings) == 1
    assert "2 executable path(s)" in ctx.warnings[0]
    assert list(out) == sorted(out)


def test_embedded_package_note(make_fs, make_ctx) -> None:
    note = package_note(
        {
            "type": "rpm",
            "os": "fedora",
            "osVersion": "44",
            "name": "openssh",
            "version": "10.2p1-14.fc44",
            "architecture": "x86_64",
        }
    )
    fs = make_fs({"/usr/local/bin/sshd": File(exe([], notes=[note]), 0o755)})
    b = analyze_executables(make_ctx(fs), ["/usr/local/bin/sshd"], FileOwnerIndex(fs))[
        "/usr/local/bin/sshd"
    ]
    assert b.package is None
    assert (
        b.embedded_package == "pkg:rpm/fedora/openssh@10.2p1-14.fc44?arch=x86_64&distro=fedora-44"
    )
    assert package_note_purl({"name": "x", "version": "1"}) == "x@1"
    assert package_note_purl({"version": "1"}) is None
    assert package_note_purl({"type": "weird type", "name": "x"}) == "x"


# --------------------------------------------------------------------------- privileges
def _caps(*bits: int) -> bytes:
    permitted = 0
    for b in bits:
        permitted |= 1 << b
    return struct.pack("<IIIII", 0x02000001, permitted & 0xFFFFFFFF, 0, permitted >> 32, 0)


def _rec(pid: str, files: list[str]) -> PackageRecord:
    name = pid.rsplit("/", maxsplit=1)[-1].split("@", maxsplit=1)[0]
    return PackageRecord(Package(id=pid, type=PackageType.DEB, name=name, version="1"), files=files)


def test_find_privileged_tar(make_tar_fs, make_ctx) -> None:
    fs = make_tar_fs(
        {
            "/usr/bin/passwd": File(exe([]), 0o4755),
            "/usr/bin/crontab": File(b"#!/bin/sh\n", 0o2755),
            "/usr/bin/ping": File(exe([]), 0o755, xattrs={"security.capability": _caps(13)}),
            "/usr/bin/ls": File(exe([]), 0o755),
            "/usr/lib/openssh/ssh-keysign": File(exe([]), 0o4711),
            "/usr/local/bin/backdoor": File(exe([]), 0o4755, uid=0),
            "/opt/vendor/bin/helper": File(b"#!/bin/sh\n", 0o6755),
            "/var/tmp/hidden": File(exe([]), 0o4755),  # outside the scanned dirs and unowned
        }
    )
    records = [
        _rec("pkg:deb/debian/passwd@1", ["/usr/bin/passwd"]),
        _rec("pkg:deb/debian/cron@1", ["/usr/bin/crontab"]),
        _rec("pkg:deb/debian/iputils-ping@1", ["/usr/bin/ping"]),
        _rec("pkg:deb/debian/coreutils@1", ["/usr/bin/ls", "/missing/file"]),
        _rec("pkg:deb/debian/openssh-client@1", ["/usr/lib/openssh/ssh-keysign"]),
    ]
    idx = FileOwnerIndex(fs)
    idx.add_records(records)
    found = {b.path: b for b in find_privileged(make_ctx(fs), records, idx)}
    assert sorted(found) == [
        "/opt/vendor/bin/helper",
        "/usr/bin/crontab",
        "/usr/bin/passwd",
        "/usr/bin/ping",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/local/bin/backdoor",
    ]
    assert found["/usr/bin/passwd"].setuid
    assert found["/usr/bin/passwd"].package == "pkg:deb/debian/passwd@1"
    assert found["/usr/bin/passwd"].owner_uid == 0
    assert found["/usr/bin/passwd"].arch == "x86_64"
    assert found["/usr/bin/crontab"].setgid
    assert not found["/usr/bin/crontab"].setuid
    assert found["/usr/bin/crontab"].kind == "script"
    assert found["/usr/bin/ping"].capabilities == ["CAP_NET_RAW"]
    assert not found["/usr/bin/ping"].setuid
    assert found["/usr/local/bin/backdoor"].package is None
    assert found["/opt/vendor/bin/helper"].setuid
    assert found["/opt/vendor/bin/helper"].setgid


def test_setuid_in_both_backends(make_fs, make_ctx) -> None:
    fs = make_fs({"/usr/bin/su": File(exe([]), 0o4755), "/usr/bin/id": File(exe([]), 0o755)})
    st = fs.stat("/usr/bin/su")
    if not st.is_setuid:
        pytest.skip("host filesystem dropped the setuid bit")
    found = find_privileged(make_ctx(fs), [], FileOwnerIndex(fs))
    assert [b.path for b in found] == ["/usr/bin/su"]
    out = analyze_executables(make_ctx(fs), ["/usr/bin/su"], FileOwnerIndex(fs))
    assert out["/usr/bin/su"].setuid


@pytest.mark.skipif(not hasattr(os, "getxattr"), reason="xattrs")
def test_caps_tar_survive_analyze(make_tar_fs, make_ctx) -> None:
    fs = make_tar_fs(
        {"/usr/sbin/tool": File(exe([]), 0o755, xattrs={"security.capability": _caps(12, 21)})}
    )
    b = analyze_executables(make_ctx(fs), ["/usr/sbin/tool"], FileOwnerIndex(fs))["/usr/sbin/tool"]
    assert b.capabilities == ["CAP_NET_ADMIN", "CAP_SYS_ADMIN"]


def test_find_unmanaged(make_fs, make_ctx) -> None:
    spec = {
        "/usr/bin/ls": File(exe([]), 0o755),
        "/usr/local/bin/tool": File(exe([]), 0o755),
        "/usr/local/bin/data": File(exe([]), 0o644),
        "/usr/local/bin/notes.txt": File("hello", 0o755),
        "/opt/app/bin/run.sh": File("#!/bin/sh\n", 0o755),
        "/opt/app/lib/deep/deeper/deepest/x/y": File(exe([]), 0o755),
        "/bin": Symlink("usr/bin"),
        "/usr/local/bin/link": Symlink("/usr/bin/ls"),
    }
    fs = make_fs(spec)
    idx = FileOwnerIndex(fs)
    idx.add("pkg:deb/debian/coreutils@1", ["/bin/ls"])
    assert find_unmanaged_executables(make_ctx(fs), idx) == [
        "/opt/app/bin/run.sh",
        "/usr/local/bin/tool",
    ]
    assert find_unmanaged_executables(make_ctx(fs), idx, ["/opt"], max_depth=10) == [
        "/opt/app/bin/run.sh",
        "/opt/app/lib/deep/deeper/deepest/x/y",
    ]


def test_already_loaded_soname_is_reused(make_fs, make_ctx) -> None:
    # libcore has no RUNPATH, so on its own it could not find libshared; ld.so reuses the
    # copy the executable already mapped through its RUNPATH (systemd's private libs).
    fs = make_fs(
        {
            "/usr/lib/systemd/systemd": exe(
                ["libshared.so", "libcore.so"], runpath="/usr/lib64/systemd"
            ),
            "/usr/lib64/systemd/libshared.so": lib("libshared.so"),
            "/usr/lib64/systemd/libcore.so": lib("libcore.so", ["libshared.so"]),
        }
    )
    b = analyze_executables(make_ctx(fs), ["/usr/lib/systemd/systemd"], FileOwnerIndex(fs))[
        "/usr/lib/systemd/systemd"
    ]
    assert "libshared.so" not in b.unresolved
    assert _link(b, "libshared.so").depth == 1
