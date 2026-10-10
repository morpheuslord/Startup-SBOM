"""pacman local database parsing."""

from __future__ import annotations

import gzip

from fsbuilder import Dir
from startup_sbom.models import OSInfo
from startup_sbom.pkgdb.alpm import AlpmDatabase, parse_desc, parse_mtree

ARCH = OSInfo(id="arch", build_id="rolling")

DESC = """\
%NAME%
openssh

%VERSION%
1:9.8p1-1

%BASE%
openssh

%DESC%
SSH protocol implementation for remote login

%URL%
https://www.openssh.com/portable.html

%ARCH%
x86_64

%BUILDDATE%
1720000000

%INSTALLDATE%
1721000000

%PACKAGER%
Giancarlo Razzolini <grazzolini@archlinux.org>

%SIZE%
5000000

%REASON%
1

%LICENSE%
BSD-2-Clause
ISC

%VALIDATION%
pgp

%DEPENDS%
glibc
openssl>=3.0
sh
krb5

%PROVIDES%
ssh=9.8

%XDATA%
pkgtype=pkg

"""

FILES = """\
%FILES%
etc/
etc/ssh/
etc/ssh/sshd_config
usr/bin/ssh
usr/bin/sshd

%BACKUP%
etc/ssh/sshd_config\t0123456789abcdef0123456789abcdef

"""

MTREE = (
    "#mtree\n/set type=file uid=0 gid=0 mode=644\n"
    "./.BUILDINFO time=1 size=1 md5digest=00000000000000000000000000000000\n"
    "./usr time=1 type=dir\n"
    f"./usr/bin/ssh time=1 mode=755 size=10 md5digest={'1' * 32} sha256digest={'2' * 64}\n"
    f"./usr/bin/ssh\\040x time=1 sha256digest={'3' * 64}\n"
    "./usr/bin/sshd \\\n"
)


def _spec() -> dict:
    base = "/var/lib/pacman/local/openssh-9.8p1-1"  # real dirs contain ":"; Windows-safe here
    return {
        f"{base}/desc": DESC,
        f"{base}/files": FILES,
        f"{base}/mtree": gzip.compress(MTREE.encode()),
        "/var/lib/pacman/local/bash-5.2-1/desc": "%NAME%\nbash\n\n%VERSION%\n5.2-1\n\n"
        "%PROVIDES%\nsh\n\n%VALIDATION%\nsha256\n\n%PACKAGER%\nUnknown Packager\n",
        "/var/lib/pacman/local/glibc-2.40-1/desc": "%NAME%\nglibc\n\n%VERSION%\n2.40-1\n",
        "/var/lib/pacman/local/glibc-2.40-1/mtree": b"not gzip at all",
        "/var/lib/pacman/local/broken/desc": "%NAME%\n\n",
        "/var/lib/pacman/local/nodesc": Dir(),
        "/var/lib/pacman/local/ALPM_DB_VERSION": "9\n",
    }


def test_local_db(make_fs, make_ctx):
    ctx = make_ctx(make_fs(_spec()))
    ctx.os = ARCH
    db = AlpmDatabase()
    assert db.detect(ctx)
    records = db.read(ctx)
    by = {r.package.name: r for r in records}
    assert sorted(by) == ["bash", "glibc", "openssh"]
    rec = by["openssh"]
    p = rec.package
    assert (p.version, p.epoch, p.arch) == ("1:9.8p1-1", 1, "x86_64")
    assert (p.source_name, p.source_version) == ("openssh", "1:9.8p1-1")
    assert p.packager == "Giancarlo Razzolini <grazzolini@archlinux.org>"
    assert p.license == "BSD-2-Clause AND ISC"
    assert p.signed is True
    assert p.signing_key is None
    assert p.properties["alpm:validation"] == "pgp"
    assert p.properties["alpm:pkgtype"] == "pkg"
    assert p.install_time == "2024-07-14T23:33:20Z"
    assert p.depends == ["bash", "glibc", "krb5", "openssl"]  # sh → bash via provides
    assert p.provides == ["ssh"]
    assert p.purl == "pkg:alpm/arch/openssh@1:9.8p1-1?arch=x86_64&distro=arch"
    assert rec.files == ["/etc/ssh/sshd_config", "/usr/bin/ssh", "/usr/bin/sshd"]
    assert rec.directories == ["/etc", "/etc/ssh"]
    assert rec.conffiles == ["/etc/ssh/sshd_config"]
    assert rec.digests == {
        "/etc/ssh/sshd_config": "md5:0123456789abcdef0123456789abcdef",
        "/usr/bin/ssh": "sha256:" + "2" * 64,
    }
    assert by["bash"].package.signed is False
    assert any("mtree unreadable" in w for w in ctx.warnings)
    assert any("missing %NAME%" in w for w in ctx.warnings)


def test_dbpath_from_pacman_conf(make_fs, make_ctx):
    spec = {
        "/etc/pacman.conf": "[options]\nDBPath = /srv/pacman/\n",
        "/srv/pacman/local/zsh-5.9-5/desc": "%NAME%\nzsh\n\n%VERSION%\n5.9-5\n",
    }
    ctx = make_ctx(make_fs(spec))
    assert [r.package.name for r in AlpmDatabase().read(ctx)] == ["zsh"]


def test_absent(make_dir_fs, make_ctx):
    ctx = make_ctx(make_dir_fs({"/var/lib/pacman/local": Dir()}))
    assert not AlpmDatabase().detect(ctx)
    assert AlpmDatabase().read(ctx) == []


def test_parsers():
    assert parse_desc("%A%\n1\n2\n\n%B%\n\nstray\n%C%\nx") == {"A": ["1", "2"], "B": [], "C": ["x"]}
    digests = parse_mtree(MTREE)
    assert digests == {"/usr/bin/ssh": "sha256:" + "2" * 64, "/usr/bin/ssh x": "sha256:" + "3" * 64}
