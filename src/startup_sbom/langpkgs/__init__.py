"""Embedded language-ecosystem packages: Python, npm, Go, Java (Maven) and Rust (cargo).

:func:`scan` runs every ecosystem scanner, isolating failures per ecosystem,
and returns :class:`~startup_sbom.pkgdb.base.PackageRecord` objects whose
``Package.id`` is the purl.  When the same purl is found at several locations
(e.g. one Go module embedded in two binaries) each of those ids gets a
``file_path`` qualifier so ids stay unique; ``Package.purl`` stays unqualified.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable

from packageurl import PackageURL

from startup_sbom.binaries.elf import read_elf
from startup_sbom.binaries.privileged import iter_files
from startup_sbom.context import ScanContext
from startup_sbom.langpkgs import golang, java, npm, python, rust
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex

#: Directories whose executables are checked for Go buildinfo / cargo-auditable data.
BINARY_DIRS: tuple[tuple[str, int], ...] = (
    ("/usr/local/bin", 0),
    ("/usr/local/sbin", 0),
    ("/usr/bin", 0),
    ("/usr/sbin", 0),
    ("/bin", 0),
    ("/sbin", 0),
    ("/app", 3),
    ("/opt", 4),
)
MAX_BINARIES = 6_000

__all__ = ["assign_ids", "golang", "java", "npm", "python", "rust", "scan"]


def _binary_candidates(ctx: ScanContext, executables: Iterable[str]) -> dict[str, bool]:
    """Canonical path -> explicitly requested, for executables to inspect."""
    fs = ctx.fs
    out: dict[str, bool] = {}
    for p in executables:
        c = fs.try_resolve(p) if isinstance(p, str) and p.startswith("/") else None
        if c is not None:
            out[c] = True
    seen_dirs: set[str] = set()
    for d, depth in BINARY_DIRS:
        cdir = fs.try_resolve(d)
        if cdir is None or cdir in seen_dirs:
            continue
        seen_dirs.add(cdir)
        for st in iter_files(fs, cdir, max_depth=depth, max_entries=20_000):
            if len(out) >= MAX_BINARIES:
                ctx.limit(f"embedded-package binary scan stopped after {MAX_BINARIES} files")
                return out
            if st.mode & 0o111 and st.size >= 64:
                out.setdefault(st.path, False)
    return out


def scan_binaries(
    ctx: ScanContext, owners: FileOwnerIndex, executables: Iterable[str] = ()
) -> list[PackageRecord]:
    """Go and Rust packages embedded in executables."""
    out: list[PackageRecord] = []
    for path, explicit in sorted(_binary_candidates(ctx, executables).items()):
        info = read_elf(ctx.fs, path)
        if info is None:
            continue
        stripped = not info.sections
        out += golang.extract(ctx.fs, path, info, owners, scan=explicit and stripped)
        out += rust.extract(ctx.fs, path, info, owners)
    return out


def assign_ids(records: list[PackageRecord]) -> list[PackageRecord]:
    """Drop same-location duplicates, make ids unique and sort deterministically."""
    unique: list[PackageRecord] = []
    seen: set[tuple[str, str]] = set()
    for rec in records:
        purl = rec.package.purl or rec.package.id
        key = (purl, rec.package.location or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(rec)
    groups: dict[str, list[PackageRecord]] = defaultdict(list)
    for rec in unique:
        groups[rec.package.purl or rec.package.id].append(rec)
    for purl, recs in groups.items():
        if len(recs) == 1:
            recs[0].package.id = purl
            continue
        for rec in recs:
            try:
                p = PackageURL.from_string(purl)
                quals = dict(p.qualifiers) if isinstance(p.qualifiers, dict) else {}
                quals["file_path"] = rec.package.location or ""
                rec.package.id = PackageURL(
                    type=p.type,
                    namespace=p.namespace,
                    name=p.name,
                    version=p.version,
                    qualifiers=quals,
                    subpath=p.subpath,
                ).to_string()
            except ValueError:
                rec.package.id = f"{purl}#{rec.package.location}"
    unique.sort(
        key=lambda r: (r.package.type, r.package.name, r.package.version, r.package.location or "")
    )
    return unique


def scan(
    ctx: ScanContext, owners: FileOwnerIndex, executables: Iterable[str] = ()
) -> list[PackageRecord]:
    """Every embedded language package in the root (empty if disabled by options)."""
    if not ctx.options.language_packages:
        return []
    records: list[PackageRecord] = []
    scanners: tuple[tuple[str, Callable[[], list[PackageRecord]]], ...] = (
        ("python", lambda: python.scan(ctx, owners)),
        ("npm", lambda: npm.scan(ctx, owners)),
        ("java", lambda: java.scan(ctx, owners)),
        ("go/rust", lambda: scan_binaries(ctx, owners, executables)),
    )
    for name, run in scanners:
        try:
            records += run()
        except Exception as exc:  # noqa: BLE001 - one ecosystem must never abort the scan
            ctx.warn(f"{name} package scan failed: {type(exc).__name__}: {exc}")
    return assign_ids(records)
