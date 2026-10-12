"""Root-confined ld.so emulation."""

from __future__ import annotations

import sys

import pytest
from elfbuilder import EM_386, EM_AARCH64, build_elf, build_ld_so_cache, exe, lib

from fsbuilder import File, Symlink
from startup_sbom.binaries.elf import parse_elf
from startup_sbom.binaries.linker import (
    LibraryResolver,
    expand_tokens,
    parse_ld_so_cache,
    split_search_path,
)

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks")

T = "x86_64-linux-gnu"
MUSL_INTERP = "/lib/ld-musl-x86_64.so.1"


def _resolve(fs, exe_path: str, soname: str, **kw) -> str | None:
    r = LibraryResolver(fs)
    info = r.elf(exe_path)
    assert info is not None
    return r.resolve(soname, info, exe_path, **kw)


def test_multiarch_default_dirs(make_fs) -> None:
    fs = make_fs(
        {
            "/usr/bin/app": File(exe(["libz.so.1"]), 0o755),
            f"/usr/lib/{T}/libz.so.1": lib("libz.so.1"),
        }
    )
    assert _resolve(fs, "/usr/bin/app", "libz.so.1") == f"/usr/lib/{T}/libz.so.1"
    assert _resolve(fs, "/usr/bin/app", "libnope.so.1") is None


def test_runpath_beats_rpath_and_rpath_ignored(make_fs) -> None:
    spec = {
        "/opt/a/libfoo.so.1": lib("libfoo.so.1"),
        "/opt/b/libfoo.so.1": lib("libfoo.so.1"),
        "/usr/lib64/libfoo.so.1": lib("libfoo.so.1"),
        "/usr/bin/both": exe(["libfoo.so.1"], rpath="/opt/a", runpath="/opt/b"),
        "/usr/bin/rp": exe(["libfoo.so.1"], rpath="/opt/a"),
        "/usr/bin/plain": exe(["libfoo.so.1"]),
    }
    fs = make_fs(spec)
    assert _resolve(fs, "/usr/bin/both", "libfoo.so.1") == "/opt/b/libfoo.so.1"
    assert _resolve(fs, "/usr/bin/rp", "libfoo.so.1") == "/opt/a/libfoo.so.1"
    assert _resolve(fs, "/usr/bin/plain", "libfoo.so.1") == "/usr/lib64/libfoo.so.1"


def test_rpath_inherited_runpath_not(make_fs) -> None:
    fs = make_fs(
        {
            "/usr/bin/app": exe(["libmid.so.1"], rpath="/opt/x"),
            "/usr/bin/app2": exe(["libmid.so.1"], runpath="/opt/x"),
            "/opt/x/libmid.so.1": lib("libmid.so.1", ["libleaf.so.1"]),
            "/opt/x/libleaf.so.1": lib("libleaf.so.1"),
        }
    )
    r = LibraryResolver(fs)
    app, mid = r.elf("/usr/bin/app"), r.elf("/opt/x/libmid.so.1")
    app2 = r.elf("/usr/bin/app2")
    assert app
    assert mid
    assert app2
    assert r.resolve("libmid.so.1", app, "/usr/bin/app") == "/opt/x/libmid.so.1"
    assert (
        r.resolve("libleaf.so.1", mid, "/opt/x/libmid.so.1", chain=[(app, "/usr/bin/app")])
        == "/opt/x/libleaf.so.1"
    )
    assert (
        r.resolve("libleaf.so.1", mid, "/opt/x/libmid.so.1", chain=[(app2, "/usr/bin/app2")])
        is None
    )


def test_origin_expansion(make_fs) -> None:
    fs = make_fs(
        {
            "/opt/app/bin/app": exe(
                ["libfoo.so.1", "libbar.so.1"], runpath="$ORIGIN/../lib:${ORIGIN}/../lib2"
            ),
            "/opt/app/lib/libfoo.so.1": lib("libfoo.so.1"),
            "/opt/app/lib2/libbar.so.1": lib("libbar.so.1"),
        }
    )
    assert _resolve(fs, "/opt/app/bin/app", "libfoo.so.1") == "/opt/app/lib/libfoo.so.1"
    assert _resolve(fs, "/opt/app/bin/app", "libbar.so.1") == "/opt/app/lib2/libbar.so.1"


def test_token_helpers() -> None:
    info = parse_elf(exe())
    assert info is not None
    assert expand_tokens("$ORIGIN/x", info, ["/a", "/b"]) == ["/a/x", "/b/x"]
    assert "/usr/lib64/x" in expand_tokens("/usr/$LIB/x", info, [])
    assert f"/usr/lib/{T}/x" in expand_tokens("/usr/${LIB}/x", info, [])
    assert "/p/x86_64" in expand_tokens("/p/$PLATFORM", info, [])
    assert expand_tokens("$ORIGINAL/x", info, ["/a"]) == []  # not a token; left unexpandable
    assert split_search_path("/a::rel:$ORIGIN/x:") == ["/a", "$ORIGIN/x"]


def test_ld_so_conf_includes_and_cycles(make_fs) -> None:
    fs = make_fs(
        {
            "/etc/ld.so.conf": "include /etc/ld.so.conf.d/*.conf\n# comment\n/opt/top\n",
            "/etc/ld.so.conf.d/a.conf": "/opt/custom/lib  # trailing\ninclude ../ld.so.conf\n",
            "/etc/ld.so.conf.d/b.conf": "include b.conf\n/opt/other,/opt/third\nhwcap 0 nosegneg\n",
            "/etc/ld.so.conf.d/ignored.txt": "/opt/never\n",
            "/opt/custom/lib/libc1.so.1": lib("libc1.so.1"),
            "/usr/bin/app": exe(["libc1.so.1"]),
        }
    )
    r = LibraryResolver(fs)
    assert r.ld_conf_dirs == ["/opt/custom/lib", "/opt/other", "/opt/third", "/opt/top"]
    assert _resolve(fs, "/usr/bin/app", "libc1.so.1") == "/opt/custom/lib/libc1.so.1"


def test_ld_so_cache(make_fs) -> None:
    cache = build_ld_so_cache(
        [
            ("libweird.so.1", "/srv/weird/libweird.so.1"),
            ("libgone.so.1", "/srv/gone/libgone.so.1"),
            ("libgone.so.1", "/srv/gone/libgone.so.1"),
        ]
    )
    assert parse_ld_so_cache(cache) == {
        "libweird.so.1": ["/srv/weird/libweird.so.1"],
        "libgone.so.1": ["/srv/gone/libgone.so.1"],
    }
    assert parse_ld_so_cache(b"ld.so-1.7.0" + b"\x00" * 20 + cache)["libweird.so.1"]
    assert parse_ld_so_cache(
        build_ld_so_cache([("libbe.so.1", "/x/libbe.so.1")], little=False)
    ) == {"libbe.so.1": ["/x/libbe.so.1"]}
    fs = make_fs(
        {
            "/etc/ld.so.cache": cache,
            "/srv/weird/libweird.so.1": lib("libweird.so.1"),
            "/usr/lib64/libgone.so.1": lib("libgone.so.1"),
            "/usr/bin/app": exe(["libweird.so.1", "libgone.so.1"]),
        }
    )
    assert _resolve(fs, "/usr/bin/app", "libweird.so.1") == "/srv/weird/libweird.so.1"
    # stale cache entry: falls back to default dirs
    assert _resolve(fs, "/usr/bin/app", "libgone.so.1") == "/usr/lib64/libgone.so.1"


def test_ld_so_cache_garbage() -> None:
    good = build_ld_so_cache([("liba.so.1", "/a/liba.so.1")])
    assert parse_ld_so_cache(b"") == {}
    assert parse_ld_so_cache(b"glibc-ld.so.cache1.1") == {}
    assert parse_ld_so_cache(good[:60]) == {}
    huge = bytearray(good)
    huge[20:24] = (0xFFFFFFFF).to_bytes(4, "little")
    assert parse_ld_so_cache(bytes(huge)) == {}
    bad_off = bytearray(good)
    bad_off[52:56] = (0x7FFFFFFF).to_bytes(4, "little")
    assert parse_ld_so_cache(bytes(bad_off)) == {}
    rel = build_ld_so_cache([("liba.so.1", "relative/liba.so.1"), ("x/y", "/abs")])
    assert parse_ld_so_cache(rel) == {}


def test_nodeflib_skips_defaults(make_fs) -> None:
    fs = make_fs(
        {
            "/usr/bin/app": build_elf(
                interp="/lib64/ld-linux-x86-64.so.2", needed=["libz.so.1"], flags_1=0x800
            ),
            "/usr/lib64/libz.so.1": lib("libz.so.1"),
        }
    )
    assert _resolve(fs, "/usr/bin/app", "libz.so.1") is None


def test_wrong_arch_is_skipped(make_fs) -> None:
    fs = make_fs(
        {
            "/opt/mixed/libz.so.1": lib("libz.so.1", bits=32, machine=EM_386),
            "/opt/mixed/libq.so.1": lib("libq.so.1", machine=EM_AARCH64),
            "/opt/mixed/libt.so.1": "INPUT(-lt)\n",  # linker script, not ELF
            "/usr/lib64/libz.so.1": lib("libz.so.1"),
            "/usr/lib/libz.so.1": lib("libz.so.1", bits=32, machine=EM_386),
            "/usr/bin/app64": exe(["libz.so.1"], runpath="/opt/mixed"),
            "/usr/bin/app32": build_elf(
                bits=32, machine=EM_386, interp="/lib/ld-linux.so.2", needed=["libz.so.1"]
            ),
        }
    )
    assert _resolve(fs, "/usr/bin/app64", "libz.so.1") == "/usr/lib64/libz.so.1"
    assert _resolve(fs, "/usr/bin/app64", "libq.so.1") is None
    assert _resolve(fs, "/usr/bin/app64", "libt.so.1") is None
    assert _resolve(fs, "/usr/bin/app32", "libz.so.1") == "/usr/lib/libz.so.1"


@needs_symlinks
def test_usr_merge_symlinks(make_fs) -> None:
    fs = make_fs(
        {
            "/lib": Symlink("usr/lib"),
            "/lib64": Symlink("usr/lib64"),
            "/bin": Symlink("usr/bin"),
            f"/usr/lib/{T}/libc.so.6": lib("libc.so.6"),
            f"/usr/lib/{T}/libz.so.1.2.13": lib("libz.so.1"),
            f"/usr/lib/{T}/libz.so.1": Symlink("libz.so.1.2.13"),
            "/usr/lib64/ld-linux-x86-64.so.2": Symlink(f"/lib/{T}/ld-linux-x86-64.so.2"),
            f"/usr/lib/{T}/ld-linux-x86-64.so.2": lib("ld-linux-x86-64.so.2"),
            "/usr/bin/app": exe(["libz.so.1"]),
        }
    )
    assert _resolve(fs, "/bin/app", "libz.so.1") == f"/usr/lib/{T}/libz.so.1.2.13"
    r = LibraryResolver(fs)
    info = r.elf("/bin/app")
    assert info is not None
    full = r.resolve_full("libz.so.1", info, "/bin/app")
    assert full is not None
    assert full.lookup == f"/lib/{T}/libz.so.1"


@needs_symlinks
def test_symlink_loops_do_not_hang(make_fs) -> None:
    fs = make_fs(
        {
            "/usr/lib64/libloop.so.1": Symlink("libloop.so.1"),
            "/usr/lib/libping.so.1": Symlink("/usr/lib/libpong.so.1"),
            "/usr/lib/libpong.so.1": Symlink("/usr/lib/libping.so.1"),
            "/opt/self": Symlink("/opt/self"),
            "/usr/bin/app": exe(["libloop.so.1", "libping.so.1"], runpath="/opt/self/lib"),
        }
    )
    assert _resolve(fs, "/usr/bin/app", "libloop.so.1") is None
    assert _resolve(fs, "/usr/bin/app", "libping.so.1") is None


def test_preload_parsing(make_fs) -> None:
    fs = make_fs({"/etc/ld.so.preload": "/usr/lib/evil.so  libhook.so.1:/x.so\n# /commented.so\n"})
    assert LibraryResolver(fs).preload() == ["/usr/lib/evil.so", "libhook.so.1", "/x.so"]
    assert LibraryResolver(make_fs({"/etc/hostname": "x"})).preload() == []


def test_musl_path_file(make_fs) -> None:
    fs = make_fs(
        {
            "/etc/ld-musl-x86_64.path": "/opt/musl/lib\n/usr/lib:/lib\n",
            "/opt/musl/lib/libfoo.so.1": lib("libfoo.so.1"),
            f"/usr/lib/{T}/libbar.so.1": lib("libbar.so.1"),
            "/usr/lib/libbaz.so.1": lib("libbaz.so.1"),
            "/usr/bin/app": exe(["libfoo.so.1"], interp=MUSL_INTERP),
        }
    )
    assert _resolve(fs, "/usr/bin/app", "libfoo.so.1") == "/opt/musl/lib/libfoo.so.1"
    assert _resolve(fs, "/usr/bin/app", "libbar.so.1") is None  # glibc multiarch dir not searched
    assert _resolve(fs, "/usr/bin/app", "libbaz.so.1") == "/usr/lib/libbaz.so.1"


def test_musl_defaults_and_transitive_runpath(make_fs) -> None:
    fs = make_fs(
        {
            "/usr/local/lib/libloc.so.1": lib("libloc.so.1"),
            "/opt/m/libmid.so.1": lib("libmid.so.1"),
            "/opt/m/libleaf.so.1": lib("libleaf.so.1"),
            "/usr/bin/app": exe(["libmid.so.1"], interp=MUSL_INTERP, runpath="/opt/m"),
        }
    )
    r = LibraryResolver(fs)
    app, mid = r.elf("/usr/bin/app"), r.elf("/opt/m/libmid.so.1")
    assert app
    assert mid
    assert r.resolve("libloc.so.1", app, "/usr/bin/app") == "/usr/local/lib/libloc.so.1"
    # musl searches the executable's RUNPATH for libraries' deps too
    assert (
        r.resolve("libleaf.so.1", mid, "/opt/m/libmid.so.1", chain=[(app, "/usr/bin/app")])
        == "/opt/m/libleaf.so.1"
    )


def test_slash_in_soname(make_fs) -> None:
    fs = make_fs(
        {"/opt/x/libdirect.so": lib("libdirect.so"), "/usr/bin/app": exe(["/opt/x/libdirect.so"])}
    )
    assert _resolve(fs, "/usr/bin/app", "/opt/x/libdirect.so") == "/opt/x/libdirect.so"
    assert _resolve(fs, "/usr/bin/app", "../../opt/x/libdirect.so") == "/opt/x/libdirect.so"


def test_results_are_cached(make_fs) -> None:
    fs = make_fs({"/usr/lib64/libz.so.1": lib("libz.so.1"), "/usr/bin/app": exe(["libz.so.1"])})
    r = LibraryResolver(fs)
    info = r.elf("/usr/bin/app")
    assert info is not None
    first = r.resolve("libz.so.1", info, "/usr/bin/app")
    assert first == "/usr/lib64/libz.so.1"
    assert len(r._results) == 1
    assert r.resolve("libz.so.1", info, "/usr/bin/other") == first
    assert len(r._results) == 1
