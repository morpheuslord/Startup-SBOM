"""apk installed database parsing."""

from __future__ import annotations

import base64
import hashlib
import sys

import pytest

from fsbuilder import Dir, Symlink
from startup_sbom.models import OSInfo
from startup_sbom.pkgdb.apk import ApkDatabase, decode_apk_digest

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
ALPINE = OSInfo(id="alpine", version_id="3.20.3")
SHA1 = hashlib.sha1(b"content").digest()  # noqa: S324 - matches apk's own digest
Q1 = "Q1" + base64.b64encode(SHA1).decode()

INSTALLED = f"""\
C:Q1aaaaaaaaaaaaaaaaaaaaaaaaaaa=
P:musl
V:1.2.5-r0
A:x86_64
S:400000
I:800000
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Natanael Copa <ncopa@alpinelinux.org>
t:1717000000
c:abcdef0123456789
p:so:libc.musl-x86_64.so.1=1
F:lib
R:ld-musl-x86_64.so.1
a:0:0:755
Z:{Q1}
R:libc.musl-x86_64.so.1
Z:not-a-digest

C:Q1bbbbbbbbbbbbbbbbbbbbbbbbbbb=
P:libcrypto3
V:3.3.2-r0
A:x86_64
o:openssl
L:Apache-2.0
D:so:libc.musl-x86_64.so.1 !libcrypto1.1 /bin/sh
p:so:libcrypto.so.3=3
F:usr/lib
M:0:0:755
R:libcrypto.so.3
Z:{Q1}
R:../../etc/passwd
F:../../tmp/./x
R:y

P:apk3-pkg
V:1.0-r0
A:x86_64
f:S
R:rootfile
Z:{Q1}

P:busybox-binsh
V:1.36.1-r29
A:x86_64
o:busybox
F:bin
R:sh

garbage line without colon
X
P:no-version-pkg

"""


def test_installed_parsing(make_fs, make_ctx):
    fs = make_fs({"/lib/apk/db/installed": INSTALLED})
    ctx = make_ctx(fs)
    ctx.os = ALPINE
    db = ApkDatabase()
    assert db.detect(ctx)
    records = db.read(ctx)
    by = {r.package.name: r for r in records}
    assert sorted(by) == ["apk3-pkg", "busybox-binsh", "libcrypto3", "musl"]
    musl = by["musl"]
    p = musl.package
    assert (p.version, p.arch, p.source_name, p.source_version) == (
        "1.2.5-r0",
        "x86_64",
        "musl",
        "1.2.5-r0",
    )
    assert p.installed_size == 800000
    assert p.maintainer == "Natanael Copa <ncopa@alpinelinux.org>"
    assert p.license == "MIT"
    assert p.properties["apk:commit"] == "abcdef0123456789"
    assert p.properties["apk:build_time"] == "2024-05-29T16:26:40Z"
    assert p.provides == ["so:libc.musl-x86_64.so.1"]
    assert musl.files == ["/lib/ld-musl-x86_64.so.1", "/lib/libc.musl-x86_64.so.1"]
    assert musl.directories == ["/lib"]
    assert musl.digests == {"/lib/ld-musl-x86_64.so.1": "sha1:" + SHA1.hex()}
    assert p.purl == "pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20.3"

    crypto = by["libcrypto3"]
    assert crypto.package.source_name == "openssl"
    assert "upstream=openssl" in (crypto.package.purl or "")
    assert crypto.package.depends == ["busybox-binsh", "musl"]  # so: + file dep, conflict dropped
    # path traversal in R:/F: never escapes: "../../etc/passwd" refused, F: dots stripped
    assert crypto.files == ["/usr/lib/libcrypto.so.3", "/tmp/x/y"]
    assert by["apk3-pkg"].digests == {"/rootfile": "sha256-160:" + SHA1.hex()}
    assert any("without P:/V:" in w for w in ctx.warnings)


@needs_symlinks
def test_usr_merged_db_read_once(make_fs, make_ctx):
    fs = make_fs({"/lib": Symlink("usr/lib"), "/usr/lib/apk/db/installed": INSTALLED})
    ctx = make_ctx(fs)
    db = ApkDatabase()
    assert db.database_paths(ctx) == ["/usr/lib/apk/db/installed"]
    records = db.read(ctx)
    assert len(records) == 4
    assert len({r.package.id for r in records}) == 4
    assert not any("duplicate" in w for w in ctx.warnings)


def test_missing_and_non_regular(make_dir_fs, make_ctx):
    assert not ApkDatabase().detect(make_ctx(make_dir_fs({"/etc/alpine-release": "3.20.0\n"})))
    assert not ApkDatabase().detect(make_ctx(make_dir_fs({"/lib/apk/db/installed": Dir()})))


def test_binary_garbage_db(make_dir_fs, make_ctx):
    ctx = make_ctx(make_dir_fs({"/lib/apk/db/installed": bytes(range(256)) * 50}))
    assert ApkDatabase().read(ctx) == []


def test_decode_digest():
    assert decode_apk_digest(Q1) == ("sha1", SHA1.hex())
    assert decode_apk_digest("X2" + "ab" * 32) == ("sha256", "ab" * 32)
    assert decode_apk_digest("Q1!!!") is None
    assert decode_apk_digest("Q9abcd") is None
    assert decode_apk_digest("Z1abcd") is None
    assert decode_apk_digest("Q") is None
