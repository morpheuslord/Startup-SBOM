"""read_all: multiple databases in one image, unique ids, failure isolation."""

from __future__ import annotations

from pkgdb.rpm_encode import build_ndb, rpm_header
from startup_sbom.models import OSInfo, Package, PackageType
from startup_sbom.pkgdb import ALL_DATABASES, ensure_unique_ids, read_all
from startup_sbom.pkgdb.base import PackageRecord

DPKG_STATUS = (
    "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nMulti-Arch: same\n"
    "Source: glibc\nVersion: 2.36-9\n\n"
    "Package: libc6\nStatus: install ok installed\nArchitecture: i386\nMulti-Arch: same\n"
    "Source: glibc\nVersion: 2.36-9\n"
)
APK = "P:busybox\nV:1.36.1-r29\nA:x86_64\n\n"
PACMAN = "%NAME%\nfilesystem\n\n%VERSION%\n2024.04.07-1\n"


def test_database_registry():
    assert [c.name for c in ALL_DATABASES] == ["dpkg", "rpm", "apk", "alpm"]


def test_mixed_image(make_fs, make_ctx):
    fs = make_fs(
        {
            "/var/lib/dpkg/status": DPKG_STATUS,
            "/var/lib/rpm/Packages.db": build_ndb([rpm_header("alien", "1.0", "1")]),
            "/lib/apk/db/installed": APK,
            "/var/lib/pacman/local/filesystem-2024.04.07-1/desc": PACMAN,
        }
    )
    ctx = make_ctx(fs)
    ctx.os = OSInfo(id="debian", version_id="12")
    records, names = read_all(ctx)
    assert names == ["dpkg", "rpm", "apk", "alpm"]
    types = [r.package.type for r in records]
    assert types == sorted(types, key=lambda t: t.value)
    assert {r.package.type for r in records} == {
        PackageType.DEB,
        PackageType.RPM,
        PackageType.APK,
        PackageType.ALPM,
    }
    ids = [r.package.id for r in records]
    assert len(ids) == len(set(ids)) == 5
    assert all(r.package.id == r.package.purl for r in records)


def test_unique_ids_for_true_duplicates():
    def rec(location: str) -> PackageRecord:
        pid = "pkg:rpm/fedora/dup@1-1?arch=x86_64"
        return PackageRecord(
            package=Package(
                id=pid, purl=pid, type=PackageType.RPM, name="dup", version="1-1", location=location
            )
        )

    records = [rec("/b"), rec("/a"), rec("/c")]
    ensure_unique_ids(records)
    by_loc = {r.package.location: r.package.id for r in records}
    assert by_loc["/a"] == "pkg:rpm/fedora/dup@1-1?arch=x86_64"
    assert by_loc["/b"] == "pkg:rpm/fedora/dup@1-1?arch=x86_64&instance=2"
    assert by_loc["/c"] == "pkg:rpm/fedora/dup@1-1?arch=x86_64&instance=3"


def test_empty_image(make_fs, make_ctx):
    ctx = make_ctx(make_fs({"/etc/hostname": "x\n"}))
    assert read_all(ctx) == ([], [])
    assert ctx.warnings == []


def test_reader_crash_is_isolated(make_dir_fs, make_ctx, monkeypatch):
    from startup_sbom.pkgdb.apk import ApkDatabase

    def boom(self, ctx):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(ApkDatabase, "read", boom)
    ctx = make_ctx(make_dir_fs({"/lib/apk/db/installed": APK, "/var/lib/dpkg/status": DPKG_STATUS}))
    records, names = read_all(ctx)
    assert names == ["dpkg", "apk"]
    assert len(records) == 2
    assert any("kaboom" in w for w in ctx.warnings)
    assert any("apk" in lim for lim in ctx.limitations)
