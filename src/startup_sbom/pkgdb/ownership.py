"""Path → owning package index, canonicalised through the target's symlinks.

Package databases record paths as installed (``/bin/ip``) while the file may
really live elsewhere after usr-merge (``/usr/bin/ip``).  Every recorded path is
indexed under its canonical *parent directory* + basename, resolved inside the
analysed root, so lookups by either spelling succeed.  Matching is exact — never
substring based.
"""

from __future__ import annotations

import posixpath
from collections import defaultdict
from collections.abc import Iterable

from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.rootfs import RootFS, normalize


class FileOwnerIndex:
    """Exact, symlink-aware mapping from in-image paths to owning package ids."""

    def __init__(self, fs: RootFS) -> None:
        self._fs = fs
        self._dir_cache: dict[str, str] = {}
        self._owners: dict[str, set[str]] = defaultdict(set)

    def _canon_dir(self, directory: str) -> str:
        cached = self._dir_cache.get(directory)
        if cached is None:
            try:
                cached = self._fs.resolve(directory, strict=False)
            except OSError:
                cached = normalize(directory)
            self._dir_cache[directory] = cached
        return cached

    def _key(self, path: str) -> str:
        norm = normalize(path)
        if norm == "/":
            return "/"
        parent, base = posixpath.split(norm)
        return posixpath.join(self._canon_dir(parent), base)

    def add(self, package_id: str, paths: Iterable[str]) -> None:
        for p in paths:
            if p:
                self._owners[self._key(p)].add(package_id)

    def add_records(self, records: Iterable[PackageRecord]) -> None:
        for rec in records:
            self.add(rec.package.id, rec.files)

    def owners(self, path: str) -> list[str]:
        """Owners of ``path``: of the fully resolved target first, then of the link itself."""
        found: list[str] = []
        try:
            resolved = self._fs.resolve(path)
        except OSError:
            resolved = None
        for candidate in (resolved, self._key(path)):
            if candidate is None:
                continue
            for owner in sorted(self._owners.get(candidate, ())):
                if owner not in found:
                    found.append(owner)
        return found

    def owner(self, path: str) -> str | None:
        owners = self.owners(path)
        return owners[0] if owners else None

    def __contains__(self, path: object) -> bool:
        return isinstance(path, str) and bool(self.owners(path))

    def __len__(self) -> int:
        return len(self._owners)
