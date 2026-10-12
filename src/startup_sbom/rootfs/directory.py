"""Root filesystem backed by a host directory (mounted disk, extracted rootfs, ``/``)."""

from __future__ import annotations

import contextlib
import os
import stat as st_mod
import sys
from typing import BinaryIO

from startup_sbom.errors import RootFSError
from startup_sbom.rootfs.base import FileStat, RootFS, split_posix


class DirectoryRootFS(RootFS):
    """A host directory analysed as a root filesystem.

    Every component is ``lstat()``-ed individually and symlinks are resolved by
    the base-class resolver against the *image* root, so an absolute link such as
    ``/etc/alternatives/x -> /usr/bin/x`` never touches the host's ``/usr/bin``.
    Files are opened with ``O_NOFOLLOW | O_NONBLOCK`` and re-checked with
    ``fstat`` so a FIFO, device or swapped-in symlink can neither hang nor
    redirect a read.
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        super().__init__()
        real = os.path.realpath(os.fspath(root))
        if not os.path.isdir(real):
            raise RootFSError(f"not a directory: {root}")
        self.root = real
        self.name = f"dir:{real}"
        self.has_ownership = os.name == "posix"
        self.case_sensitive = self._probe_case_sensitive()
        self._bad_chars = {c for c in (os.sep, os.altsep) if c and c != "/"}
        if os.name == "nt":
            self._bad_chars |= set(':*?"<>|')
            self.warnings.append(
                "dir: target on a Windows host: NTFS does not store POSIX permission bits,"
                " so executable, setuid and capability findings are incomplete; scan a tar"
                " or OCI archive of the root filesystem for full fidelity"
            )

    def _probe_case_sensitive(self) -> bool:
        try:
            for name in os.listdir(self.root):
                swapped = name.swapcase()
                if swapped != name:
                    a = os.lstat(os.path.join(self.root, name))
                    try:
                        b = os.lstat(os.path.join(self.root, swapped))
                    except OSError:
                        return True
                    return not os.path.samestat(a, b)
        except OSError:
            pass
        return os.name == "posix" and sys.platform != "darwin"

    def _host(self, cpath: str) -> str | None:
        parts = split_posix(cpath)
        for p in parts:
            if p == ".." or any(c in p for c in self._bad_chars):
                return None
        return os.path.join(self.root, *parts) if parts else self.root

    def _lstat_raw(self, cpath: str) -> FileStat | None:
        host = self._host(cpath)
        if host is None:
            return None
        try:
            st = os.lstat(host)
        except OSError:
            return None
        link: str | None = None
        if st_mod.S_ISLNK(st.st_mode):
            try:
                link = os.readlink(host)
            except OSError:
                link = ""
            if os.name == "nt":
                link = link.replace("\\", "/")
        xattrs: dict[str, bytes] = {}
        getxattr = getattr(os, "getxattr", None)
        if getxattr is not None and st_mod.S_ISREG(st.st_mode) and st.st_mode & 0o111:
            with contextlib.suppress(OSError):
                xattrs["security.capability"] = getxattr(
                    host, "security.capability", follow_symlinks=False
                )
        return FileStat(
            path=cpath,
            mode=st.st_mode,
            uid=st.st_uid if self.has_ownership else None,
            gid=st.st_gid if self.has_ownership else None,
            size=st.st_size,
            mtime=st.st_mtime,
            linkname=link,
            xattrs=xattrs,
        )

    def _listdir_raw(self, cpath: str) -> list[str]:
        host = self._host(cpath)
        if host is None:
            return []
        try:
            return os.listdir(host)
        except OSError:
            return []

    def _open_raw(self, cpath: str) -> BinaryIO:
        host = self._host(cpath)
        if host is None:
            raise RootFSError(f"unrepresentable path on this host: {cpath}")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(host, flags)
        try:
            if not st_mod.S_ISREG(os.fstat(fd).st_mode):
                raise RootFSError(f"not a regular file: {cpath}")
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise

    def host_path(self, path: str) -> str | None:
        """Real host path of an in-image path (only meaningful for this backend)."""
        return self._host(self.resolve(path))
