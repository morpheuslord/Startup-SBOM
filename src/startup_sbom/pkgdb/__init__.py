"""OS package database readers (dpkg, rpm, apk, alpm) and the file-ownership index.

:func:`read_all` probes every supported database — an image can carry more than
one — and returns their records with globally unique ``Package.id`` values.
Readers use ``ctx.os`` (set by :func:`startup_sbom.distro.identify`) for purl
namespaces and ``distro=`` qualifiers.
"""

from __future__ import annotations

from collections import defaultdict

from startup_sbom.context import ScanContext
from startup_sbom.errors import StartupSBOMError
from startup_sbom.log import ops
from startup_sbom.pkgdb.alpm import AlpmDatabase
from startup_sbom.pkgdb.apk import ApkDatabase
from startup_sbom.pkgdb.base import PackageDatabase, PackageRecord
from startup_sbom.pkgdb.dpkg import DpkgDatabase
from startup_sbom.pkgdb.rpm import RpmDatabase, installed_rpm_keys
from startup_sbom.purls import with_qualifiers

ALL_DATABASES: tuple[type[PackageDatabase], ...] = (
    DpkgDatabase,
    RpmDatabase,
    ApkDatabase,
    AlpmDatabase,
)


def _sort_key(rec: PackageRecord) -> tuple[str, str, str, str, str]:
    p = rec.package
    return (p.type.value, p.name, p.version, p.arch or "", p.id)


def ensure_unique_ids(records: list[PackageRecord]) -> None:
    """Disambiguate colliding ``Package.id``/purl values with an ``instance`` qualifier.

    Records are processed in canonical order; the first of each colliding group
    keeps its id, later ones get ``instance=2``, ``instance=3`` ...
    """
    groups: dict[str, list[PackageRecord]] = defaultdict(list)
    for rec in sorted(records, key=lambda r: (_sort_key(r), r.package.location or "")):
        groups[rec.package.id].append(rec)
    taken = {r.package.id for r in records}
    for pid, members in groups.items():
        n = 1
        for rec in members[1:]:
            new_id = pid
            while new_id in taken:
                n += 1
                new_id = with_qualifiers(pid, instance=str(n))
            taken.add(new_id)
            rec.package.id = new_id
            rec.package.purl = new_id


def read_all(ctx: ScanContext) -> tuple[list[PackageRecord], list[str]]:
    """Read every detected package database in ``ctx.fs``.

    Returns ``(records, database_names)``.  A database that fails to read is
    recorded as a warning and a coverage limitation; it never aborts the scan.
    """
    records: list[PackageRecord] = []
    names: list[str] = []
    for db_cls in ALL_DATABASES:
        db = db_cls()
        try:
            if not db.detect(ctx):
                continue
        except (StartupSBOMError, OSError) as exc:
            ctx.warn(f"{db.name}: detection failed: {exc}")
            continue
        names.append(db.name)
        try:
            found = db.read(ctx)
        except Exception as exc:  # noqa: BLE001 - one broken database must not abort the scan
            ctx.warn(f"{db.name}: database could not be read: {exc}")
            ctx.limit(f"{db.name} package database present but unreadable")
            continue
        if not found:
            ctx.limit(f"{db.name} package database present but contained no installed packages")
        ops.info("%s: %s installed package(s) read", db.name, f"{len(found):,}")
        records.extend(found)
    ensure_unique_ids(records)
    records.sort(key=_sort_key)
    return records, names


__all__ = [
    "ALL_DATABASES",
    "AlpmDatabase",
    "ApkDatabase",
    "DpkgDatabase",
    "PackageDatabase",
    "PackageRecord",
    "RpmDatabase",
    "ensure_unique_ids",
    "installed_rpm_keys",
    "read_all",
]
