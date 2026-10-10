"""dpkg status / status.d / info parsing."""

from __future__ import annotations

import sys

import pytest

from fsbuilder import Dir, Symlink
from startup_sbom.models import OSInfo
from startup_sbom.pkgdb.dpkg import (
    DpkgDatabase,
    dependency_groups,
    is_installed,
    parse_deb822,
    parse_source,
)
from startup_sbom.pkgdb.ownership import FileOwnerIndex

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
DEBIAN = OSInfo(id="debian", version_id="12", version_codename="bookworm")

STATUS = """\
Package: libc6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 12000
Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
Architecture: amd64
Multi-Arch: same
Source: glibc
Version: 2.36-9+deb12u7
Depends: libgcc-s1
Description: GNU C Library: Shared libraries
 Contains the standard libraries that are used by nearly all programs on
 the system.
 .
 This package includes shared versions.
Homepage: https://www.gnu.org/software/libc/libc.html

Package: libc6
Status: install ok installed
Architecture: i386
Multi-Arch: same
Source: glibc
Version: 2.36-9+deb12u7
Depends: libgcc-s1

Package: libgcc-s1
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Source: gcc-12 (12.2.0-14)
Version: 12.2.0-14
Provides: libgcc1 (= 1:12.2.0-14)
Depends: gcc-12-base (= 12.2.0-14), libc6 (>= 2.35)

Package: openssh-server
Status: install ok installed
Architecture: amd64
Source: openssh
Version: 1:9.2p1-2+deb12u3
Pre-Depends: init-system-helpers (>= 1.54~)
Depends: libc6 (>= 2.36), libgcc1 | libgcc-s1, debconf (>= 0.5) | debconf-2.0, procps
Conffiles:
 /etc/ssh/moduli 8d9be1c5c1e5d4ae4cc8f7b2d6b46f6b
 /etc/default/ssh 500e3cf069fe9a7b9936108eb9d9c035
 /etc/old.conf 00000000000000000000000000000000 obsolete
Description: secure shell (SSH) server
Built-Using:

Package: zlib1g
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Source: zlib (1:1.2.13.dfsg-1)
Version: 1:1.2.13.dfsg-1+b1

Package: removed-pkg
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1

Package: held
Status: hold ok installed
Architecture: all
Version: 2.0

Package: going-away
Status: deinstall ok installed
Architecture: all
Version: 3.0

Package: half
Status: install reinstreq half-installed
Architecture: all
Version: 4.0

Package: unpacked-only
Status: install ok unpacked
Architecture: all
Version: 5.0

Package: no-status
Architecture: all
Version: 6.0

Package: no-version
Status: install ok installed
Architecture: all
"""


def _spec() -> dict:
    return {
        "/var/lib/dpkg/status": STATUS,
        "/var/lib/dpkg/info/libc6:amd64.list": "/.\n/usr\n/usr/lib\n/usr/lib/x86_64-linux-gnu\n"
        "/usr/lib/x86_64-linux-gnu/libc.so.6\n/lib64/ld-linux-x86-64.so.2\n/usr/share/empty\n",
        "/var/lib/dpkg/info/libc6:amd64.md5sums": "0123456789abcdef0123456789abcdef  "
        "usr/lib/x86_64-linux-gnu/libc.so.6\nnot-an-md5  junk\n",
        "/var/lib/dpkg/info/libc6:i386.list": "/usr/lib/i386-linux-gnu/libc.so.6\n",
        "/var/lib/dpkg/info/openssh-server.list": "/etc/ssh/moduli\n/usr/sbin/sshd\n/bin/fake\n",
        "/var/lib/dpkg/info/openssh-server.md5sums": "a" * 32 + "  usr/sbin/sshd\n",
        "/var/lib/dpkg/info/zlib1g:amd64.list": "/usr/lib/x86_64-linux-gnu/libz.so.1\n",
        "/usr/share/doc/openssh-server/copyright": "Format: https://www.debian.org/doc/"
        "packaging-manuals/copyright-format/1.0/\n\nFiles: *\nLicense: BSD-2-clause\n\n"
        "Files: x\nLicense: ISC\n Long text\n",
        "/usr/share/doc/libc6/copyright": "not machine readable\nLicense: GPL\n",
        "/usr/share/empty": Dir(),
        "/usr/lib/x86_64-linux-gnu/libc.so.6": b"\x7fELF",
        "/usr/sbin/sshd": b"\x7fELF",
    }


def test_status_parsing(make_fs, make_ctx):
    ctx = make_ctx(make_fs(_spec()))
    ctx.os = DEBIAN
    records = DpkgDatabase().read(ctx)
    keys = [(r.package.name, r.package.arch) for r in records]
    assert keys == [
        ("going-away", "all"),
        ("held", "all"),
        ("libc6", "amd64"),
        ("libc6", "i386"),
        ("libgcc-s1", "amd64"),
        ("openssh-server", "amd64"),
        ("zlib1g", "amd64"),
    ]
    by = {(r.package.name, r.package.arch): r for r in records}
    libc = by[("libc6", "amd64")]
    assert libc.package.source_name == "glibc"
    assert libc.package.source_version == "2.36-9+deb12u7"
    assert libc.package.installed_size == 12000 * 1024
    assert libc.package.summary == "GNU C Library: Shared libraries"
    assert libc.package.depends == ["libgcc-s1"]
    assert libc.package.license is None  # non-DEP-5 copyright ignored
    assert libc.files == [
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/ld-linux-x86-64.so.2",
    ]
    assert "/usr/share/empty" in libc.directories  # empty directory detected via the image
    assert "/usr/lib" in libc.directories
    assert libc.digests == {
        "/usr/lib/x86_64-linux-gnu/libc.so.6": "md5:0123456789abcdef0123456789abcdef"
    }
    assert by[("libc6", "i386")].files == ["/usr/lib/i386-linux-gnu/libc.so.6"]
    assert libc.package.id != by[("libc6", "i386")].package.id

    ssh = by[("openssh-server", "amd64")].package
    assert ssh.version == "1:9.2p1-2+deb12u3"
    assert ssh.epoch == 1
    assert ssh.source_version == "1:9.2p1-2+deb12u3"
    # libgcc1 is provided by libgcc-s1; debconf / init-system-helpers unresolved → raw
    assert ssh.depends == ["debconf", "init-system-helpers", "libc6", "libgcc-s1", "procps"]
    assert ssh.license == "BSD-2-clause AND ISC"
    assert ssh.purl == (
        "pkg:deb/debian/openssh-server@1:9.2p1-2%2Bdeb12u3?arch=amd64&distro=debian-12"
        "&upstream=openssh"
    )
    ssh_rec = by[("openssh-server", "amd64")]
    assert ssh_rec.conffiles == ["/etc/default/ssh", "/etc/ssh/moduli"]
    assert ssh_rec.digests["/etc/ssh/moduli"] == "md5:8d9be1c5c1e5d4ae4cc8f7b2d6b46f6b"
    assert "/etc/default/ssh" in ssh_rec.files

    zlib = by[("zlib1g", "amd64")].package
    assert zlib.version == "1:1.2.13.dfsg-1+b1"
    assert zlib.source_version == "1:1.2.13.dfsg-1"
    assert "upstream=zlib%401:1.2.13.dfsg-1" in (zlib.purl or "")
    gcc = by[("libgcc-s1", "amd64")].package
    assert gcc.provides == ["libgcc1"]
    assert any("no-version" in w for w in ctx.warnings)


@needs_symlinks
def test_usr_merge_paths_resolve_through_ownership(make_fs, make_ctx):
    spec = _spec()
    spec["/bin"] = Symlink("usr/bin")
    spec["/usr/bin/fake"] = b"x"
    fs = make_fs(spec)
    ctx = make_ctx(fs)
    records = DpkgDatabase().read(ctx)
    index = FileOwnerIndex(fs)
    index.add_records(records)
    owner = index.owner("/usr/bin/fake")
    assert owner is not None
    assert "openssh-server" in owner


def test_distroless_status_d(make_fs, make_ctx):
    fs = make_fs(
        {
            "/var/lib/dpkg/status.d/base-files": "Package: base-files\nVersion: 12.4+deb12u5\n"
            "Architecture: amd64\nMaintainer: Santiago Vila <sanvila@debian.org>\n",
            "/var/lib/dpkg/status.d/base-files.md5sums": "11111111111111111111111111111111  "
            "etc/debian_version\n22222222222222222222222222222222  usr/lib/os-release\n",
            "/var/lib/dpkg/status.d/zlib1g": "Package: zlib1g\nSource: zlib (1:1.3.dfsg-3)\n"
            "Version: 1:1.3.dfsg+really1.3.1-1+b1\nArchitecture: amd64\n",
            "/var/lib/dpkg/status.d/broken": b"\xff\xfe\x00garbage without colon\n\n",
        }
    )
    ctx = make_ctx(fs)
    db = DpkgDatabase()
    assert db.detect(ctx)
    records = db.read(ctx)
    assert [r.package.name for r in records] == ["base-files", "zlib1g"]
    base = records[0]
    assert base.files == ["/etc/debian_version", "/usr/lib/os-release"]
    assert base.digests["/etc/debian_version"] == "md5:" + "1" * 32
    assert base.package.location == "/var/lib/dpkg/status.d/base-files"
    z = records[1].package
    assert (z.source_name, z.source_version) == ("zlib", "1:1.3.dfsg-3")


def test_missing_db_and_unreadable_entries(make_fs, make_ctx):
    ctx = make_ctx(make_fs({"/var/lib/dpkg/info/x.list": "/x\n"}))
    assert not DpkgDatabase().detect(ctx)
    assert DpkgDatabase().read(ctx) == []


def test_status_directory_instead_of_file(make_dir_fs, make_ctx):
    ctx = make_ctx(make_dir_fs({"/var/lib/dpkg/status": Dir()}))
    assert not DpkgDatabase().detect(ctx)
    assert DpkgDatabase().read(ctx) == []
    assert ctx.warnings  # recorded, not raised


def test_helpers():
    paras = list(parse_deb822("A: 1\nB:\n x\n y\n\n\n# c\nC: 3\nnocolon\n z\n"))
    assert paras == [{"a": "1", "b": "\nx\ny"}, {"c": "3"}]
    assert is_installed("install ok installed")
    assert is_installed("deinstall ok installed")
    assert is_installed("hold ok triggers-pending")
    assert not is_installed("install ok half-configured")
    assert not is_installed("purge ok not-installed")
    assert not is_installed("garbage")
    assert not is_installed(None)
    assert parse_source("glibc (2.36-9)", "libc6", "x") == ("glibc", "2.36-9")
    assert parse_source(None, "a", "1") == ("a", "1")
    assert parse_source("bad (", "a", "1") == ("a", "1")
    assert dependency_groups("a (>= 1) | b:any, c [amd64] <!nocheck>, ${misc:Depends}") == [
        ["a", "b"],
        ["c"],
    ]
