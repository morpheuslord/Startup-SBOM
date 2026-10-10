"""RPM header parsing, backends (SQLite/BDB/NDB), signatures and the rpm reader."""

from __future__ import annotations

import base64
import random
import struct
import sys

import pytest

from fsbuilder import Dir, Symlink
from pkgdb.rpm_encode import (
    build_bdb,
    build_ndb,
    build_sqlite,
    build_sqlite_with_wal,
    encode_header,
    pgp_v3_signature,
    pgp_v4_signature,
    pubkey_header,
    rpm_header,
)
from startup_sbom.models import OSInfo
from startup_sbom.pkgdb import read_all
from startup_sbom.pkgdb.rpm import Header, HeaderError, RpmDatabase, find_rpmdb, parse_signature
from startup_sbom.pkgdb.rpm import header as rpmtag
from startup_sbom.pkgdb.rpm.reader import header_to_info, parse_source_rpm, signer_for

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")

FEDORA = OSInfo(id="fedora", version_id="44", id_like=[])
RHEL = OSInfo(id="rhel", version_id="9.4", id_like=["fedora"])
KEY_FPR = bytes.fromhex("36f612dcf27f7d1a48a835e4dbfcf71c6d9f90a6")
KEY_ID = KEY_FPR[-8:]
DIR_MODE = 0o040755
REG_MODE = 0o100644
SHA = "ab" * 32


def _openssl_libs() -> bytes:
    return rpm_header(
        "openssl-libs",
        "3.0.7",
        "27.el9",
        epoch=1,
        sourcerpm="openssl-3.0.7-27.el9.src.rpm",
        files=[
            ("/etc/pki/tls", DIR_MODE, "", 0),
            ("/etc/pki/tls/openssl.cnf", REG_MODE, SHA, rpmtag.RPMFILE_CONFIG),
            ("/usr/lib64/libssl.so.3", REG_MODE, "cd" * 32, 0),
            ("/usr/share/doc/openssl-libs/README", REG_MODE, "ef" * 32, 2),
        ],
        filestates=[0, 0, 0, 2],  # README not installed (tsflags=nodocs)
        provides=["libssl.so.3()(64bit)", "openssl-libs", "openssl-libs(x86-64)"],
        requires=["rpmlib(CompressedFileNames)", "libc.so.6()(64bit)", "/bin/sh", "(foo if bar)"],
        signature=pgp_v4_signature(key_id=KEY_ID, fingerprint=KEY_FPR),
    )


def _glibc() -> bytes:
    return rpm_header(
        "glibc",
        "2.34",
        "100.el9",
        sourcerpm="glibc-2.34-100.el9.src.rpm",
        files=[("/usr/lib64/libc.so.6", REG_MODE, "11" * 32, 0)],
        provides=["libc.so.6()(64bit)", "glibc"],
    )


def _bash() -> bytes:
    return rpm_header(
        "bash",
        "5.1.8",
        "9.el9",
        sourcerpm="bash-5.1.8-9.el9.src.rpm",
        files=[("/usr/bin/bash", 0o100755, "22" * 32, 0), ("/usr/bin/sh", 0o120777, "", 0)],
        provides=["bash"],
        requires=["glibc"],
    )


def _blobs() -> list[bytes]:
    return [
        _openssl_libs(),
        _glibc(),
        _bash(),
        pubkey_header(
            KEY_FPR.hex(), "Red Hat, Inc. (release key 2) <security@redhat.com> public key"
        ),
    ]


def _check_openssl(records: list) -> None:
    by_name = {r.package.name: r for r in records}
    assert set(by_name) == {"openssl-libs", "glibc", "bash"}  # gpg-pubkey skipped
    rec = by_name["openssl-libs"]
    p = rec.package
    assert p.version == "1:3.0.7-27.el9"
    assert p.epoch == 1
    assert p.source_name == "openssl"
    assert p.source_version == "1:3.0.7-27.el9"
    assert p.signing_key == KEY_ID.hex()
    assert p.signed is True
    assert p.properties["rpm:signer"].startswith("Red Hat, Inc.")
    assert p.properties["rpm:files_not_installed"] == "1"
    assert p.depends == ["bash", "glibc"]  # libc capability + /bin/sh file dep; rich dep dropped
    assert p.install_time == "2025-10-09T08:53:20Z"
    assert p.purl is not None
    assert p.purl.startswith("pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?")
    assert "epoch=1" in p.purl
    assert "upstream=openssl-3.0.7-27.el9.src.rpm" in p.purl
    assert p.id == p.purl
    assert rec.files == ["/etc/pki/tls/openssl.cnf", "/usr/lib64/libssl.so.3"]
    assert rec.directories == ["/etc/pki/tls"]
    assert rec.conffiles == ["/etc/pki/tls/openssl.cnf"]
    assert rec.digests["/usr/lib64/libssl.so.3"] == "sha256:" + "cd" * 32
    assert p.file_count == 2
    assert by_name["bash"].files == ["/usr/bin/bash", "/usr/bin/sh"]
    assert "/usr/bin/sh" not in by_name["bash"].digests


# --------------------------------------------------------------------------- header
def test_header_accessors_and_dribble_override():
    blob = encode_header(
        [(rpmtag.NAME, rpmtag.STRING, "x"), (rpmtag.INSTALLTIME, rpmtag.INT32, [1])],
        dribble=[(rpmtag.INSTALLTIME, rpmtag.INT32, [2]), (rpmtag.SIGMD5, rpmtag.BIN, b"\x01\x02")],
    )
    h = Header(blob)
    assert h.string(rpmtag.NAME) == "x"
    assert h.integer(rpmtag.INSTALLTIME) == 2
    assert h.binary(rpmtag.SIGMD5) == b"\x01\x02"
    assert h.string(rpmtag.VERSION) is None
    assert h.errors == []


def test_header_legacy_without_region():
    h = Header(
        encode_header(
            [(rpmtag.NAME, rpmtag.STRING, "old"), (rpmtag.VERSION, rpmtag.STRING, "1")],
            region=False,
        )
    )
    assert h.string(rpmtag.NAME) == "old"


@pytest.mark.parametrize("cut", [0, 4, 7, 8, 20, 40, -1, -5])
def test_truncated_header_rejected(cut):
    blob = _openssl_libs()
    with pytest.raises(HeaderError):
        Header(blob[:cut])


def test_huge_counts_and_offsets_are_contained():
    blob = bytearray(
        encode_header(
            [(rpmtag.NAME, rpmtag.STRING, "n"), (rpmtag.BASENAMES, rpmtag.STRING_ARRAY, ["a"])]
        )
    )
    # entry 2 (BASENAMES): set count to 2**32-1
    struct.pack_into(">I", blob, 8 + 2 * 16 + 12, 0xFFFFFFFF)
    h = Header(bytes(blob))
    assert h.strings(rpmtag.BASENAMES) == []
    assert h.errors
    blob2 = bytearray(
        encode_header([(rpmtag.NAME, rpmtag.STRING, "n"), (rpmtag.FILESIZES, rpmtag.INT32, [1])])
    )
    struct.pack_into(">i", blob2, 8 + 2 * 16 + 8, 0x7FFFFFF0)  # offset far outside data
    h2 = Header(bytes(blob2))
    assert h2.ints(rpmtag.FILESIZES) == []
    assert h2.integer(rpmtag.FILESIZES) is None


def test_bad_index_count_and_region():
    with pytest.raises(HeaderError):
        Header(struct.pack(">II", 0x10000000, 0) + b"\0" * 64)
    blob = bytearray(encode_header([(rpmtag.NAME, rpmtag.STRING, "n")]))
    struct.pack_into(">I", blob, 8 + 4, rpmtag.STRING)  # region tag with wrong type
    with pytest.raises(HeaderError):
        Header(bytes(blob))


def test_non_utf8_strings_decode():
    blob = rpm_header("pkg", "1", "1", vendor=b"Soci\xe9t\xe9", summary=b"\xff\xfe bad")
    h = Header(blob)
    assert h.string(rpmtag.VENDOR) == "Société"
    assert h.string(rpmtag.SUMMARY) == "ÿþ bad"


def test_random_mutations_never_crash():
    rng = random.Random(1234)  # noqa: S311 - deterministic fuzzing, not crypto
    base = _openssl_libs()
    for _ in range(600):
        blob = bytearray(base)
        for _ in range(rng.randint(1, 8)):
            blob[rng.randrange(len(blob))] = rng.randrange(256)
        if rng.random() < 0.3:
            blob = blob[: rng.randrange(len(blob))]
        try:
            h = Header(bytes(blob))
        except HeaderError:
            continue
        header_to_info(h, os_info=FEDORA, location="/x", backend="test", warn=lambda _m: None)


def test_dirindex_out_of_range_is_skipped():
    blob = encode_header(
        [
            (rpmtag.NAME, rpmtag.STRING, "p"),
            (rpmtag.VERSION, rpmtag.STRING, "1"),
            (rpmtag.RELEASE, rpmtag.STRING, "1"),
            (rpmtag.DIRINDEXES, rpmtag.INT32, [0, 9]),
            (rpmtag.BASENAMES, rpmtag.STRING_ARRAY, ["a", "b"]),
            (rpmtag.DIRNAMES, rpmtag.STRING_ARRAY, ["/usr/"]),
        ]
    )
    msgs: list[str] = []
    info = header_to_info(Header(blob), os_info=None, location="/x", backend="t", warn=msgs.append)
    assert info is not None
    assert info.record.files == ["/usr/a"]
    assert any("invalid directory index" in m for m in msgs)


def test_parse_source_rpm():
    assert parse_source_rpm("bash-5.2.26-3.fc40.src.rpm") == ("bash", "5.2.26-3.fc40")
    assert parse_source_rpm("foo-bar-1.0-1.nosrc.rpm") == ("foo-bar", "1.0-1")
    assert parse_source_rpm("garbage") is None
    assert parse_source_rpm("x.src.rpm") is None


def test_sourcenevr_preferred():
    blob = rpm_header(
        "openssl-libs",
        "3.2.2",
        "3.fc41",
        epoch=1,
        sourcerpm="openssl-3.2.2-3.fc41.src.rpm",
        extra=[(rpmtag.SOURCENEVR, rpmtag.STRING, "openssl-1:3.2.2-3.fc41")],
    )
    info = header_to_info(Header(blob), os_info=FEDORA, location="/x", backend="t", warn=print)
    assert info is not None
    assert info.record.package.source_name == "openssl"
    assert info.record.package.source_version == "1:3.2.2-3.fc41"


# --------------------------------------------------------------------------- PGP
def test_pgp_v4_issuer_and_fingerprint():
    sig = parse_signature(pgp_v4_signature(key_id=KEY_ID, fingerprint=KEY_FPR))
    assert sig is not None
    assert sig.key_id == KEY_ID.hex()
    assert sig.fingerprint == KEY_FPR.hex()
    assert sig.pubkey_algo == "RSA"
    assert sig.hash_algo == "sha256"
    assert "Key ID dbfcf71c6d9f90a6" in sig.summary()


def test_pgp_v4_fingerprint_only_and_new_format():
    sig = parse_signature(pgp_v4_signature(fingerprint=KEY_FPR, pubalgo=22, new_format=True))
    assert sig is not None
    assert sig.key_id == KEY_ID.hex()
    assert sig.pubkey_algo == "EdDSA"


def test_pgp_v3_dsa():
    sig = parse_signature(pgp_v3_signature(bytes.fromhex("a8a447dce8562897")))
    assert sig is not None
    assert sig.key_id == "a8a447dce8562897"
    assert sig.pubkey_algo == "DSA"


@pytest.mark.parametrize(
    "raw",
    [b"", b"\x00", b"\x89", b"\x89\xff\xff\x04", b"\xc2\xff\xff\xff\xff\xff", b"\x99\x00\x01\x04"],
)
def test_pgp_malformed_returns_none(raw):
    assert parse_signature(raw) is None


def test_pgp_truncations_never_raise():
    full = pgp_v4_signature(key_id=KEY_ID, fingerprint=KEY_FPR)
    for n in range(len(full)):
        parse_signature(full[:n])


def test_openpgp_tag_base64_and_signer_matching():
    sig_b64 = base64.b64encode(pgp_v4_signature(fingerprint=KEY_FPR)).decode()
    blob = rpm_header(
        "p", "1", "1", extra=[(rpmtag.OPENPGP, rpmtag.STRING_ARRAY, [sig_b64, "!!notb64"])]
    )
    info = header_to_info(Header(blob), os_info=None, location="/x", backend="t", warn=print)
    assert info is not None
    assert info.record.package.signing_key == KEY_ID.hex()
    assert signer_for(KEY_ID.hex(), None, {KEY_ID.hex()[-8:]: "short"}) == "short"
    assert signer_for(None, KEY_FPR.hex(), {KEY_FPR.hex(): "full"}) == "full"
    assert signer_for("0000000000000000", None, {KEY_FPR.hex(): "full"}) is None


def test_unsigned_package():
    info = header_to_info(
        Header(rpm_header("p", "1", "1")), os_info=None, location="/x", backend="t", warn=print
    )
    assert info is not None
    assert info.record.package.signed is False
    assert info.record.package.signing_key is None


# --------------------------------------------------------------------------- backends
@needs_symlinks
def test_sqlite_fedora_layout(make_fs, make_ctx, tmp_path):
    db = build_sqlite(tmp_path / "rpmdb.sqlite", _blobs())
    fs = make_fs(
        {
            "/usr/lib/sysimage/rpm/rpmdb.sqlite": db,
            "/var/lib/rpm": Symlink("../../usr/lib/sysimage/rpm"),
        }
    )
    ctx = make_ctx(fs)
    ctx.os = RHEL
    found = find_rpmdb(fs)
    assert found is not None
    assert found.path == "/usr/lib/sysimage/rpm/rpmdb.sqlite"
    assert found.backend == "sqlite"
    reader = RpmDatabase()
    assert reader.detect(ctx)
    records = reader.read(ctx)
    _check_openssl(records)
    assert reader.installed_keys == {
        KEY_FPR.hex(): "Red Hat, Inc. (release key 2) <security@redhat.com> public key"
    }
    assert ctx.warnings == []


def test_sqlite_uncheckpointed_wal_is_read(make_dir_fs, make_ctx, tmp_path):
    db, wal = build_sqlite_with_wal(tmp_path / "rpmdb.sqlite", [_glibc()], [_bash()])
    assert wal
    fs = make_dir_fs({"/var/lib/rpm/rpmdb.sqlite": db, "/var/lib/rpm/rpmdb.sqlite-wal": wal})
    ctx = make_ctx(fs)
    names = sorted(r.package.name for r in RpmDatabase().read(ctx))
    assert names == ["bash", "glibc"]
    # the target was not modified
    assert (
        fs.read_bytes("/var/lib/rpm/rpmdb.sqlite"),
        fs.read_bytes("/var/lib/rpm/rpmdb.sqlite-wal"),
    ) == (db, wal)


@pytest.mark.parametrize("big_endian", [False, True])
def test_bdb_backend(make_fs, make_ctx, big_endian):
    fs = make_fs({"/var/lib/rpm/Packages": build_bdb(_blobs(), big_endian=big_endian)})
    ctx = make_ctx(fs)
    ctx.os = RHEL
    found = find_rpmdb(fs)
    assert found is not None
    assert found.backend == "bdb"
    _check_openssl(RpmDatabase().read(ctx))
    assert ctx.warnings == []


def test_ndb_backend(make_fs, make_ctx):
    fs = make_fs({"/usr/lib/sysimage/rpm/Packages.db": build_ndb(_blobs())})
    ctx = make_ctx(fs)
    ctx.os = RHEL
    found = find_rpmdb(fs)
    assert found is not None
    assert found.backend == "ndb"
    _check_openssl(RpmDatabase().read(ctx))


def test_bdb_broken_chain_and_garbage_header(make_dir_fs, make_ctx):
    data = bytearray(build_bdb([_glibc(), b"\x00\x00\x00\x01garbage-not-a-header", _bash()]))
    fs = make_dir_fs({"/var/lib/rpm/Packages": bytes(data)})
    ctx = make_ctx(fs)
    names = [r.package.name for r in RpmDatabase().read(ctx)]
    assert names == ["bash", "glibc"]
    assert any("rejected" in w for w in ctx.warnings)
    # overflow chain pointing past the end of the file: skipped, not fatal
    bad = bytearray(build_bdb([_glibc()]))
    pagesize = 512
    off = pagesize + (pagesize - 5 - 12) + 4  # H_OFFPAGE pgno (item follows the 5-byte key)
    struct.pack_into("<I", bad, off, 9999)
    ctx2 = make_ctx(make_dir_fs({"/var/lib/rpm/Packages": bytes(bad)}))
    assert RpmDatabase().read(ctx2) == []
    assert any("overflow chain" in w for w in ctx2.warnings)


def test_ndb_bad_slots(make_dir_fs, make_ctx):
    data = bytearray(build_ndb([_glibc(), _bash()]))
    struct.pack_into("<I", data, 32 + 16 + 8, 0xFFFFFFF)  # second slot: offset beyond EOF
    ctx = make_ctx(make_dir_fs({"/var/lib/rpm/Packages.db": bytes(data)}))
    assert [r.package.name for r in RpmDatabase().read(ctx)] == ["glibc"]
    assert any("out of range" in w for w in ctx.warnings)


def test_dbpath_macro_override(make_dir_fs, make_ctx, tmp_path):
    db = build_sqlite(tmp_path / "x.sqlite", [_glibc()])
    fs = make_dir_fs(
        {
            "/usr/lib/rpm/macros.d/macros.rpm-ostree": "%_dbpath /usr/share/rpm\n",
            "/usr/share/rpm/rpmdb.sqlite": db,
            "/var/lib/rpm/Packages": build_bdb([_bash()]),  # stale, lower priority
        }
    )
    found = find_rpmdb(fs)
    assert found is not None
    assert found.path == "/usr/share/rpm/rpmdb.sqlite"
    assert [r.package.name for r in RpmDatabase().read(make_ctx(fs))] == ["glibc"]


def test_garbage_db_files_not_detected(make_dir_fs, make_ctx):
    fs = make_dir_fs(
        {
            "/var/lib/rpm/rpmdb.sqlite": b"not sqlite at all",
            "/var/lib/rpm/Packages": b"",
            "/usr/lib/sysimage/rpm/Packages.db": Dir(),
        }
    )
    assert find_rpmdb(fs) is None
    assert not RpmDatabase().detect(make_ctx(fs))


def test_hostile_sqlite_view_is_refused(make_dir_fs, make_ctx, tmp_path):
    import sqlite3

    path = tmp_path / "evil.sqlite"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (blob BLOB)")
    con.execute("CREATE VIEW Packages AS SELECT 1 AS hnum, blob FROM t")
    con.commit()
    con.close()
    ctx = make_ctx(make_dir_fs({"/var/lib/rpm/rpmdb.sqlite": path.read_bytes()}))
    records, names = read_all(ctx)
    assert records == []
    assert names == ["rpm"]
    assert any("no Packages table" in w for w in ctx.warnings)
    assert ctx.limitations


def test_truncated_sqlite_reports_limitation(make_dir_fs, make_ctx, tmp_path):
    db = build_sqlite(tmp_path / "t.sqlite", _blobs())
    ctx = make_ctx(make_dir_fs({"/var/lib/rpm/rpmdb.sqlite": db[: len(db) // 2]}))
    read_all(ctx)  # must not raise
    assert ctx.warnings


def test_mariner_container_manifest(make_dir_fs, make_ctx):
    line = "\t".join(
        [
            "openssl",
            "3.3.3-1.azl3",
            "1700000000",
            "1690000000",
            "Microsoft Corporation",
            "(none)",
            "4567",
            "x86_64",
            "0",
            "openssl-3.3.3-1.azl3.src.rpm",
        ]
    )
    fs = make_dir_fs({"/var/lib/rpmmanifest/container-manifest-2": line + "\nbroken\tline\n"})
    ctx = make_ctx(fs)
    ctx.os = OSInfo(id="azurelinux", version_id="3.0")
    records = RpmDatabase().read(ctx)
    assert len(records) == 1
    p = records[0].package
    assert (p.name, p.version, p.source_name, p.source_version) == (
        "openssl",
        "3.3.3-1.azl3",
        "openssl",
        "3.3.3-1.azl3",
    )
    assert p.purl == (
        "pkg:rpm/azurelinux/openssl@3.3.3-1.azl3?arch=x86_64&distro=azurelinux-3.0"
        "&upstream=openssl-3.3.3-1.azl3.src.rpm"
    )
    assert any("malformed manifest line" in w for w in ctx.warnings)
