"""Privileged (setuid/setgid/file-capability) and unmanaged executables.

Packaged files are checked exhaustively; a bounded walk of the usual binary
directories additionally catches privileged or executable files that no
package owns (dropped-in binaries, backdoors, ``make install`` leftovers).
"""

from __future__ import annotations

import posixpath
from collections.abc import Callable, Iterable, Iterator, Sequence

from startup_sbom.binaries.analyze import BinaryAnalyzer, is_privileged
from startup_sbom.binaries.elf import ELF_MAGIC
from startup_sbom.context import ScanContext
from startup_sbom.errors import RootFSError
from startup_sbom.models import Binary
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.rootfs import FileStat, RootFS, split_posix

MAX_PACKAGED_FILES = 1_000_000
MAX_WALK_ENTRIES = 50_000

#: Directories whose direct entries are checked for privileged files.
BIN_DIRS: tuple[str, ...] = (
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
)

#: Default directories searched for unmanaged executables.
UNMANAGED_DIRS: tuple[str, ...] = (
    *BIN_DIRS,
    "/usr/libexec",
    "/usr/local/libexec",
    "/opt",
)


def walk_tree(
    fs: RootFS,
    top: str,
    *,
    max_depth: int = 8,
    max_entries: int = MAX_WALK_ENTRIES,
    prune: Callable[[str, str], bool] | None = None,
) -> Iterator[tuple[str, list[str], list[str]]]:
    """Bounded :meth:`RootFS.walk`: ``(canonical dir, subdir names, other names)``.

    ``top`` is resolved; symlinked directories are never followed (they are
    listed among the non-directories).  Directories deeper than ``max_depth``
    below ``top`` are not entered, nor are those for which ``prune(parent, name)``
    is true (applied after the consumer has seen the entry).  At most
    ``max_entries`` entries are visited.
    """
    ctop = fs.try_resolve(top)
    if ctop is None or not fs.is_dir(ctop):
        return
    base = len(split_posix(ctop))
    for d, dirs, files in fs.walk(ctop, max_entries=max_entries):
        yield d, dirs, files
        if len(split_posix(d)) - base >= max_depth:
            dirs.clear()
        elif prune is not None:
            dirs[:] = [n for n in dirs if not prune(d, n)]


def iter_files(
    fs: RootFS,
    top: str,
    *,
    max_depth: int = 8,
    max_entries: int = MAX_WALK_ENTRIES,
    prune: Callable[[str, str], bool] | None = None,
) -> Iterator[FileStat]:
    """``lstat`` results of the regular files found by :func:`walk_tree`."""
    for d, _dirs, files in walk_tree(
        fs, top, max_depth=max_depth, max_entries=max_entries, prune=prune
    ):
        for name in files:
            st = fs.try_lstat(posixpath.join(d, name))
            if st is not None and st.is_file:
                yield st


def _privileged_walk(fs: RootFS) -> Iterator[FileStat]:
    for d in BIN_DIRS:
        yield from iter_files(fs, d, max_depth=0)
    yield from iter_files(fs, "/usr/libexec", max_depth=4)
    for libdir in ("/usr/lib", "/usr/lib64"):
        yield from iter_files(fs, libdir, max_depth=1)
    yield from iter_files(fs, "/opt", max_depth=6, max_entries=20_000)


def find_privileged(
    ctx: ScanContext, records: Iterable[PackageRecord], owners: FileOwnerIndex
) -> list[Binary]:
    """Every setuid/setgid/file-capability regular file, packaged or not, sorted by path."""
    fs = ctx.fs
    analyzer = BinaryAnalyzer(ctx, owners)
    found: dict[str, Binary] = {}
    checked: set[str] = set()

    def consider(st: FileStat) -> None:
        if st.path in checked:
            return
        checked.add(st.path)
        if not is_privileged(st):
            return
        b = analyzer.base_binary(st.path)
        if b.kind == "elf":
            info = analyzer.resolver.elf(st.path)
            if info is not None:
                b.arch = info.arch
                b.interpreter = info.interpreter
                b.needed = list(info.needed)
        found[st.path] = b

    budget = MAX_PACKAGED_FILES
    for rec in records:
        for f in rec.files:
            budget -= 1
            if budget < 0:
                break
            st = fs.try_lstat(f)
            if st is not None and st.is_file:
                consider(st)
    if budget < 0:
        ctx.limit(f"privileged-file check stopped after {MAX_PACKAGED_FILES} packaged files")
    for st in _privileged_walk(fs):
        consider(st)
    return [found[k] for k in sorted(found)]


def _looks_executable(fs: RootFS, path: str) -> bool:
    try:
        head = fs.read_head(path, 4)
    except (RootFSError, OSError):
        return False
    return head == ELF_MAGIC or head.startswith(b"#!")


def find_unmanaged_executables(
    ctx: ScanContext,
    owners: FileOwnerIndex,
    dirs: Sequence[str] = UNMANAGED_DIRS,
    *,
    max_depth: int = 4,
    max_entries: int = MAX_WALK_ENTRIES,
) -> list[str]:
    """Canonical paths of ELF/script executables in ``dirs`` owned by no package."""
    fs = ctx.fs
    out: set[str] = set()
    seen_dirs: set[str] = set()
    for d in dirs:
        cdir = fs.try_resolve(d)
        if cdir is None or cdir in seen_dirs:
            continue
        seen_dirs.add(cdir)
        for st in iter_files(fs, cdir, max_depth=max_depth, max_entries=max_entries):
            if not st.mode & 0o111 or st.path in out:
                continue
            if owners.owner(st.path) is None and _looks_executable(fs, st.path):
                out.add(st.path)
    return sorted(out)
