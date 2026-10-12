"""Read-only, root-confined filesystem abstraction.

Every analyzer reads the target exclusively through :class:`RootFS`.  In-image
paths are always absolute POSIX strings (``"/etc/os-release"``) manipulated with
:mod:`posixpath` only, so behaviour is identical on Linux, macOS and Windows hosts.

Symlinks are resolved by our own resolver against the *image* root (semantics of
``openat2(RESOLVE_IN_ROOT)`` / Go's ``filepath-securejoin``): absolute targets
re-root at the image root, ``..`` can never climb above it, and loops are bounded.
Nothing is ever executed, mounted, extracted or written.
"""

from __future__ import annotations

import posixpath
import stat as st_mod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

from startup_sbom.errors import (
    NotADirError,
    PathNotFoundError,
    ReadLimitError,
    RootFSError,
    SymlinkLoopError,
)
from startup_sbom.rootfs.caps import FileCaps, decode_vfs_cap

MAX_SYMLINKS = 40  # Linux MAXSYMLINKS
DEFAULT_READ_LIMIT = 32 * 1024 * 1024
TEXT_READ_LIMIT = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class FileStat:
    """``lstat``-like metadata of an entry in the analysed root filesystem."""

    path: str
    mode: int
    uid: int | None
    gid: int | None
    size: int
    mtime: float
    linkname: str | None = None
    xattrs: dict[str, bytes] = field(default_factory=dict)
    hardlink_of: str | None = None
    layer: int | None = None

    @property
    def is_dir(self) -> bool:
        return st_mod.S_ISDIR(self.mode)

    @property
    def is_file(self) -> bool:
        return st_mod.S_ISREG(self.mode)

    @property
    def is_symlink(self) -> bool:
        return st_mod.S_ISLNK(self.mode)

    @property
    def is_setuid(self) -> bool:
        return bool(self.mode & st_mod.S_ISUID)

    @property
    def is_setgid(self) -> bool:
        return bool(self.mode & st_mod.S_ISGID)

    @property
    def is_executable(self) -> bool:
        return self.is_file and bool(self.mode & 0o111)

    @property
    def perms(self) -> int:
        return st_mod.S_IMODE(self.mode)

    @property
    def world_writable(self) -> bool:
        return bool(self.mode & 0o002)

    @property
    def capabilities(self) -> FileCaps | None:
        raw = self.xattrs.get("security.capability")
        return decode_vfs_cap(raw) if raw else None


def split_posix(path: str) -> list[str]:
    """Split an in-image path into components (keeps ``..``, drops ``""`` and ``"."``)."""
    if "\x00" in path:
        raise RootFSError("NUL byte in path")
    return [c for c in path.split("/") if c not in ("", ".")]


def lexical_join(parts: list[str]) -> str:
    """Join components lexically, clamping ``..`` at the root."""
    out: list[str] = []
    for c in parts:
        if c == "..":
            if out:
                out.pop()
        else:
            out.append(c)
    return "/" + "/".join(out)


def normalize(path: str) -> str:
    """Return a lexically normalised absolute in-image path."""
    return lexical_join(split_posix(path))


class RootFS:
    """Base class implementing root-confined resolution and helpers.

    Backends implement three primitives that take a *canonical* (symlink-free)
    path and never follow symlinks: :meth:`_lstat_raw`, :meth:`_listdir_raw`
    and :meth:`_open_raw`.
    """

    name: str = "rootfs"
    case_sensitive: bool = True
    has_ownership: bool = True

    def __init__(self) -> None:
        self.warnings: list[str] = []

    # -- primitives -----------------------------------------------------------
    def _lstat_raw(self, cpath: str) -> FileStat | None:
        raise NotImplementedError

    def _listdir_raw(self, cpath: str) -> list[str]:
        raise NotImplementedError

    def _open_raw(self, cpath: str) -> BinaryIO:
        raise NotImplementedError

    # -- resolution -----------------------------------------------------------
    def resolve(self, path: str, *, follow_final: bool = True, strict: bool = True) -> str:
        """Resolve ``path`` to a canonical in-image path without ever leaving the root."""
        pending = list(reversed(split_posix(path)))
        stack: list[str] = []
        links = 0
        while pending:
            comp = pending.pop()
            if comp == "..":
                if stack:
                    stack.pop()
                continue
            cand = [*stack, comp]
            cpath = "/" + "/".join(cand)
            st = self._lstat_raw(cpath)
            if st is None:
                if strict:
                    raise PathNotFoundError(path)
                return lexical_join(cand + list(reversed(pending)))
            if st.is_symlink and (pending or follow_final):
                links += 1
                if links > MAX_SYMLINKS:
                    raise SymlinkLoopError(path)
                target = st.linkname or ""
                if not target:
                    raise PathNotFoundError(path)
                if target.startswith("/"):
                    stack = []
                pending.extend(reversed(split_posix(target)))
                continue
            if pending and not st.is_dir:
                if strict:
                    raise NotADirError(path)
                return lexical_join(cand + list(reversed(pending)))
            stack = cand
        return "/" + "/".join(stack)

    def try_resolve(self, path: str) -> str | None:
        """Resolve ``path`` following symlinks; return ``None`` if it does not exist."""
        try:
            return self.resolve(path)
        except (RootFSError, OSError):
            return None

    # -- metadata -------------------------------------------------------------
    def lstat(self, path: str) -> FileStat:
        cpath = self.resolve(path, follow_final=False)
        st = self._lstat_raw(cpath)
        if st is None:
            raise PathNotFoundError(path)
        return st

    def stat(self, path: str) -> FileStat:
        cpath = self.resolve(path)
        st = self._lstat_raw(cpath)
        if st is None:
            raise PathNotFoundError(path)
        return st

    def readlink(self, path: str) -> str:
        st = self.lstat(path)
        if not st.is_symlink:
            raise RootFSError(f"not a symlink: {path}")
        return st.linkname or ""

    def listdir(self, path: str) -> list[str]:
        cpath = self.resolve(path)
        st = self._lstat_raw(cpath)
        if st is None or not st.is_dir:
            raise NotADirError(path)
        return sorted(self._listdir_raw(cpath))

    def safe_listdir(self, path: str) -> list[str]:
        """Like :meth:`listdir` but returns ``[]`` instead of raising."""
        try:
            return self.listdir(path)
        except (RootFSError, OSError):
            return []

    # -- content --------------------------------------------------------------
    def open(self, path: str) -> BinaryIO:
        cpath = self.resolve(path)
        st = self._lstat_raw(cpath)
        if st is None:
            raise PathNotFoundError(path)
        if not st.is_file:
            raise RootFSError(f"not a regular file: {path} (mode {oct(st.mode)})")
        return self._open_raw(cpath)

    def read_bytes(self, path: str, limit: int = DEFAULT_READ_LIMIT) -> bytes:
        with self.open(path) as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise ReadLimitError(f"{path} exceeds read limit of {limit} bytes")
        return data

    def read_head(self, path: str, size: int) -> bytes:
        """Read at most ``size`` bytes from the start of a regular file."""
        with self.open(path) as f:
            return f.read(size)

    def read_text(self, path: str, limit: int = TEXT_READ_LIMIT) -> str:
        return self.read_bytes(path, limit).decode("utf-8", "replace")

    def try_read_text(self, path: str, limit: int = TEXT_READ_LIMIT) -> str | None:
        """Return file text or ``None`` if missing, not regular, or too large."""
        try:
            return self.read_text(path, limit)
        except (RootFSError, OSError) as exc:
            if not isinstance(exc, PathNotFoundError | FileNotFoundError):
                self.warnings.append(f"could not read {path}: {exc}")
            return None

    # -- predicates -----------------------------------------------------------
    def _probe(self, path: str, *, follow: bool) -> FileStat | None:
        try:
            return self.stat(path) if follow else self.lstat(path)
        except (RootFSError, OSError):
            return None

    def exists(self, path: str) -> bool:
        return self._probe(path, follow=True) is not None

    def lexists(self, path: str) -> bool:
        return self._probe(path, follow=False) is not None

    def is_file(self, path: str) -> bool:
        st = self._probe(path, follow=True)
        return bool(st and st.is_file)

    def is_dir(self, path: str) -> bool:
        st = self._probe(path, follow=True)
        return bool(st and st.is_dir)

    def is_symlink(self, path: str) -> bool:
        st = self._probe(path, follow=False)
        return bool(st and st.is_symlink)

    def try_stat(self, path: str) -> FileStat | None:
        return self._probe(path, follow=True)

    def try_lstat(self, path: str) -> FileStat | None:
        return self._probe(path, follow=False)

    # -- traversal ------------------------------------------------------------
    def walk(
        self, top: str = "/", *, max_entries: int = 2_000_000
    ) -> Iterator[tuple[str, list[str], list[str]]]:
        """``os.walk`` equivalent that never follows symlinked directories."""
        try:
            ctop = self.resolve(top)
        except (RootFSError, OSError):
            return
        seen = 0
        stack = [ctop]
        while stack:
            d = stack.pop()
            dirs: list[str] = []
            files: list[str] = []
            for name in sorted(self._listdir_raw(d)):
                seen += 1
                if seen > max_entries:
                    self.warnings.append(f"walk of {top} truncated after {max_entries} entries")
                    return
                child = posixpath.join(d, name)
                st = self._lstat_raw(child)
                if st is not None and st.is_dir:
                    dirs.append(name)
                else:
                    files.append(name)
            yield d, dirs, files
            stack.extend(posixpath.join(d, n) for n in reversed(dirs))

    def glob_dir(self, directory: str, suffix: str = "") -> list[str]:
        """Absolute paths of entries in ``directory`` whose name ends with ``suffix``."""
        return [
            posixpath.join(normalize(directory), n)
            for n in self.safe_listdir(directory)
            if n.endswith(suffix)
        ]

    def close(self) -> None:
        """Release backend resources."""

    def __enter__(self) -> RootFS:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
