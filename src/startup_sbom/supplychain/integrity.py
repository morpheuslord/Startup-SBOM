"""File integrity: recorded package digests versus the bytes actually on disk.

Only runs when ``ScanOptions.integrity_check`` is set.  Hashing every file is I/O
heavy, so candidates are ordered by how much they matter and the work is bounded:

1. executables of services that start automatically,
2. libraries/interpreters those services load,
3. executables and libraries of the remaining services,
4. any other binary known to the report.

Conffiles are skipped (local changes are expected), as are files without a
recorded digest, non-regular files and files over :data:`MAX_FILE_BYTES`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from startup_sbom.context import ScanContext
from startup_sbom.errors import RootFSError
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.supplychain.graph import RunningSet

MAX_FILES = 4_000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_CHUNK = 1 << 20

_ALGOS = {
    "md5": "md5",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
}
_HEX = re.compile(r"[0-9a-fA-F]+")


@dataclass(frozen=True, slots=True)
class ModifiedFile:
    """A packaged file whose content no longer matches the package database."""

    path: str
    package: str
    algorithm: str
    expected: str
    actual: str
    code: bool  # executable or shared library


@dataclass(slots=True)
class IntegrityResult:
    """Outcome of :func:`verify_integrity`."""

    checked: int = 0
    unverifiable: int = 0  # owned but no usable recorded digest
    skipped: int = 0  # budget/size/read limits
    modified: list[ModifiedFile] = field(default_factory=list)


def parse_digest(value: str) -> tuple[str, str] | None:
    """``"sha256:<hex|base64>"`` → ``("sha256", "<hex>")``; ``None`` if unusable."""
    algo, sep, digest = value.partition(":")
    if not sep:
        return None
    name = _ALGOS.get(algo.strip().lower())
    digest = digest.strip()
    if name is None or not digest:
        return None
    size = hashlib.new(name, usedforsecurity=False).digest_size
    if _HEX.fullmatch(digest) and len(digest) == size * 2:
        return name, digest.lower()
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(digest + "=" * (-len(digest) % 4))
        except (binascii.Error, ValueError):
            continue
        if len(raw) == size:
            return name, raw.hex()
    return None


def _hash_file(ctx: ScanContext, path: str, algo: str, limit: int) -> str | None:
    h = hashlib.new(algo, usedforsecurity=False)
    read = 0
    try:
        with ctx.fs.open(path) as f:
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                read += len(chunk)
                if read > limit:
                    return None
                h.update(chunk)
    except (RootFSError, OSError):
        return None
    return h.hexdigest()


def _is_code(path: str, mode: int) -> bool:
    base = posixpath.basename(path)
    return bool(mode & 0o111) or ".so" in base


def candidate_paths(running: RunningSet, extra: Iterable[str] = ()) -> list[str]:
    """Paths to verify, most important first, de-duplicated."""
    auto = running.automatic
    tiers: list[list[str]] = [[], [], [], []]
    for path, sids in running.executables.items():
        tiers[0 if sids & auto else 2].append(path)
    for path, sids in running.libraries.items():
        tiers[1 if sids & auto else 2].append(path)
    tiers[3].extend(running.canon(p) for p in extra)
    tiers[3].extend(running.binaries)
    seen: set[str] = set()
    out: list[str] = []
    for tier in tiers:
        for p in sorted(tier):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def verify_integrity(
    ctx: ScanContext,
    records: Iterable[PackageRecord],
    running: RunningSet,
    owners: FileOwnerIndex,
    *,
    extra_paths: Iterable[str] = (),
    max_files: int = MAX_FILES,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> IntegrityResult:
    """Compare recorded digests with actual file hashes for the most relevant files."""
    by_id = {r.package.id: r for r in records}
    canon_maps: dict[str, dict[str, tuple[str, str]]] = {}
    result = IntegrityResult()
    total = 0

    def digest_map(rec: PackageRecord) -> dict[str, tuple[str, str]]:
        cached = canon_maps.get(rec.package.id)
        if cached is None:
            conf = set(rec.conffiles)
            cached = {}
            for recorded, digest in rec.digests.items():
                if recorded in conf:
                    continue
                try:
                    parent, base = posixpath.split(recorded)
                    key = posixpath.join(ctx.fs.resolve(parent or "/", strict=False), base)
                except (RootFSError, OSError):
                    continue
                cached.setdefault(key, (recorded, digest))
            canon_maps[rec.package.id] = cached
        return cached

    for path in candidate_paths(running, extra_paths):
        if result.checked >= max_files or total >= max_total_bytes:
            result.skipped += 1
            continue
        owner = running.file_owner.get(path) or owners.owner(path)
        rec = by_id.get(owner) if owner else None
        if rec is None or not rec.digests:
            continue
        entry = digest_map(rec).get(path)
        if entry is None:
            try:
                parent, base = posixpath.split(path)
                alt = posixpath.join(ctx.fs.resolve(parent or "/", strict=False), base)
            except (RootFSError, OSError):
                alt = path
            entry = digest_map(rec).get(alt)
        if entry is None:
            result.unverifiable += 1
            continue
        _recorded, raw_digest = entry
        parsed = parse_digest(raw_digest)
        if parsed is None:
            result.unverifiable += 1
            continue
        st = ctx.fs.try_stat(path)
        if st is None or not st.is_file:
            continue
        if st.size > max_file_bytes:
            result.skipped += 1
            continue
        algo, expected = parsed
        actual = _hash_file(ctx, path, algo, max_file_bytes)
        if actual is None:
            result.skipped += 1
            continue
        total += st.size
        result.checked += 1
        if actual != expected:
            result.modified.append(
                ModifiedFile(
                    path=path,
                    package=rec.package.id,
                    algorithm=algo,
                    expected=expected,
                    actual=actual,
                    code=_is_code(path, st.mode)
                    or path in running.executables
                    or path in running.libraries,
                )
            )
    if result.skipped:
        ctx.limit(f"integrity check budget reached: {result.skipped} candidate files not verified")
    result.modified.sort(key=lambda m: (m.package, m.path))
    return result
