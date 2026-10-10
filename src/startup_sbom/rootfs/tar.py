"""Root filesystem backed by one or more (layered) tar archives.

Only tar *headers* are indexed in memory; file contents stay in the layer blobs
and are read on demand by seeking.  Layers are flattened following the OCI
image-spec whiteout rules.  Nothing is ever extracted to disk, so setuid bits,
ownership and file capabilities survive and no hostile member can escape.
"""

from __future__ import annotations

import base64
import contextlib
import io
import os
import posixpath
import stat as st_mod
import tarfile
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import BinaryIO

from startup_sbom.errors import RootFSError
from startup_sbom.rootfs.base import FileStat, RootFS, split_posix

WH_PREFIX = ".wh."
WH_OPAQUE = ".wh..wh..opq"

_TYPE_BITS = {
    tarfile.REGTYPE: st_mod.S_IFREG,
    tarfile.AREGTYPE: st_mod.S_IFREG,
    tarfile.CONTTYPE: st_mod.S_IFREG,
    tarfile.DIRTYPE: st_mod.S_IFDIR,
    tarfile.SYMTYPE: st_mod.S_IFLNK,
    tarfile.CHRTYPE: st_mod.S_IFCHR,
    tarfile.BLKTYPE: st_mod.S_IFBLK,
    tarfile.FIFOTYPE: st_mod.S_IFIFO,
}


class FileWindow(io.RawIOBase):
    """Seekable read-only view of ``[offset, offset + size)`` of a host file."""

    def __init__(self, path: str, offset: int = 0, size: int | None = None) -> None:
        super().__init__()
        self.path = path
        self.base = offset
        self.size = os.path.getsize(path) - offset if size is None else size
        self._f = open(path, "rb")  # noqa: SIM115 - closed in close()
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, off: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = off
        elif whence == io.SEEK_CUR:
            self._pos += off
        else:
            self._pos = self.size + off
        self._pos = max(0, self._pos)
        return self._pos

    def readinto(self, b: bytearray | memoryview) -> int:  # type: ignore[override]
        n = min(len(b), self.size - self._pos)
        if n <= 0:
            return 0
        self._f.seek(self.base + self._pos)
        data = self._f.read(n)
        b[: len(data)] = data
        self._pos += len(data)
        return len(data)

    def close(self) -> None:
        try:
            self._f.close()
        finally:
            super().close()


@dataclass(frozen=True, slots=True)
class LayerBlob:
    """An *uncompressed, seekable* tar stream: a window into a host file."""

    path: str
    offset: int = 0
    size: int | None = None
    label: str = ""

    def open(self) -> FileWindow:
        return FileWindow(self.path, self.offset, self.size)


class _Entry:
    __slots__ = (
        "blob", "gid", "hardlink_of", "layer", "linkname", "mode", "mtime", "offset",
        "size", "uid", "xattrs",
    )  # fmt: skip

    def __init__(
        self,
        mode: int,
        uid: int = 0,
        gid: int = 0,
        size: int = 0,
        mtime: float = 0.0,
        linkname: str | None = None,
        layer: int | None = None,
        blob: LayerBlob | None = None,
        offset: int = 0,
        xattrs: dict[str, bytes] | None = None,
        hardlink_of: str | None = None,
    ) -> None:
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.size = size
        self.mtime = mtime
        self.linkname = linkname
        self.layer = layer
        self.blob = blob
        self.offset = offset
        self.xattrs = xattrs
        self.hardlink_of = hardlink_of


def member_xattrs(m: tarfile.TarInfo) -> dict[str, bytes] | None:
    """Extract extended attributes from PAX headers (GNU tar and libarchive styles)."""
    out: dict[str, bytes] = {}
    for k, v in m.pax_headers.items():
        if k.startswith("SCHILY.xattr."):
            out[k[len("SCHILY.xattr.") :]] = v.encode("utf-8", "surrogateescape")
        elif k.startswith("LIBARCHIVE.xattr."):
            name = urllib.parse.unquote(k[len("LIBARCHIVE.xattr.") :])
            with contextlib.suppress(ValueError):
                out[name] = base64.b64decode(v)
    return out or None


class LayeredTarRootFS(RootFS):
    """Flattens N uncompressed tar layers into an in-memory header index."""

    def __init__(
        self,
        layers: list[LayerBlob],
        *,
        whiteouts: bool = True,
        name: str = "image",
        max_entries: int = 5_000_000,
        cleanup: Callable[[], None] | None = None,
    ) -> None:
        super().__init__()
        self.name = name
        self.layers = layers
        self.whiteouts = whiteouts
        self.max_entries = max_entries
        self._cleanup = cleanup
        self._entries: dict[str, _Entry] = {"/": _Entry(st_mod.S_IFDIR | 0o755)}
        self._children: dict[str, set[str]] = {"/": set()}
        for idx, blob in enumerate(layers):
            self._apply_layer(idx, blob)

    # -- index maintenance ----------------------------------------------------
    def _delete_subtree(self, p: str) -> None:
        e = self._entries.pop(p, None)
        if e is None:
            return
        if st_mod.S_ISDIR(e.mode):
            for child in list(self._children.pop(p, ())):
                self._delete_subtree(posixpath.join(p, child))
        parent = posixpath.dirname(p)
        self._children.get(parent, set()).discard(posixpath.basename(p))

    def _ensure_dir(self, p: str, layer: int) -> None:
        if p in self._entries:
            return
        parent = posixpath.dirname(p)
        self._ensure_dir(parent, layer)
        self._entries[p] = _Entry(st_mod.S_IFDIR | 0o755, layer=layer)
        self._children[p] = set()
        self._children[parent].add(posixpath.basename(p))

    def _canon_dir(self, parts: list[str]) -> str:
        lex = "/" + "/".join(parts)
        e = self._entries.get(lex)
        if e is not None and st_mod.S_ISDIR(e.mode):
            return lex
        return self.resolve(lex, follow_final=True, strict=False)

    def _place(self, raw_name: str, layer: int) -> str | None:
        parts = split_posix(raw_name)
        if not parts:
            return "/"
        if ".." in parts:
            self.warnings.append(f"layer {layer}: rejected member with '..': {raw_name!r}")
            return None
        parent = self._canon_dir(parts[:-1])
        pst = self._lstat_raw(parent)
        if pst is not None and not pst.is_dir:
            self.warnings.append(f"layer {layer}: parent of {raw_name!r} is not a directory")
            self._delete_subtree(parent)
        self._ensure_dir(parent, layer)
        return posixpath.join(parent, parts[-1])

    def _apply_layer(self, idx: int, blob: LayerBlob) -> None:
        members: list[tarfile.TarInfo] = []
        try:
            with blob.open() as fobj, tarfile.open(fileobj=fobj, mode="r:") as tf:
                while (m := tf.next()) is not None:
                    cached = getattr(tf, "members", None)  # tarfile caches every header
                    if isinstance(cached, list):
                        cached.clear()  # keep memory bounded by our own cap
                    if len(members) + len(self._entries) >= self.max_entries:
                        raise RootFSError("entry limit exceeded (possible tar bomb)")
                    if m.issparse():
                        self.warnings.append(f"layer {idx}: skipped sparse member {m.name!r}")
                        continue
                    members.append(m)
        except tarfile.TarError as exc:
            raise RootFSError(f"layer {idx} ({blob.label or blob.path}): {exc}") from exc

        regular: list[tarfile.TarInfo] = []
        for m in members:
            base = posixpath.basename(m.name.rstrip("/"))
            if self.whiteouts and base.startswith(WH_PREFIX):
                pparts = split_posix(m.name)[:-1]
                if ".." in pparts:
                    self.warnings.append(f"layer {idx}: rejected whiteout {m.name!r}")
                    continue
                parent = self._canon_dir(pparts)
                if base == WH_OPAQUE:
                    for child in list(self._children.get(parent, ())):
                        self._delete_subtree(posixpath.join(parent, child))
                elif not base.startswith(WH_PREFIX + WH_PREFIX):
                    self._delete_subtree(posixpath.join(parent, base[len(WH_PREFIX) :]))
                continue
            regular.append(m)

        for m in regular:
            key = self._place(m.name, idx)
            if key is None:
                continue
            if len(self._entries) >= self.max_entries:
                raise RootFSError("entry limit exceeded (possible tar bomb)")
            if m.islnk():
                self._add_hardlink(key, m, idx)
                continue
            ftype = _TYPE_BITS.get(m.type)
            if ftype is None:
                continue
            self._insert(
                key,
                _Entry(
                    mode=ftype | (m.mode & 0o7777),
                    uid=m.uid,
                    gid=m.gid,
                    size=m.size if ftype == st_mod.S_IFREG else 0,
                    mtime=float(m.mtime),
                    linkname=m.linkname if ftype == st_mod.S_IFLNK else None,
                    layer=idx,
                    blob=blob if ftype == st_mod.S_IFREG else None,
                    offset=m.offset_data,
                    xattrs=member_xattrs(m),
                ),
            )

    def _insert(self, key: str, entry: _Entry) -> None:
        if key == "/":
            if st_mod.S_ISDIR(entry.mode):
                self._entries["/"] = entry
            return
        old = self._entries.get(key)
        if old is not None:
            if st_mod.S_ISDIR(old.mode) and st_mod.S_ISDIR(entry.mode):
                self._entries[key] = entry
                return
            self._delete_subtree(key)
        parent = posixpath.dirname(key)
        self._entries[key] = entry
        self._children[parent].add(posixpath.basename(key))
        if st_mod.S_ISDIR(entry.mode):
            self._children[key] = set()

    def _add_hardlink(self, key: str, m: tarfile.TarInfo, idx: int) -> None:
        tparts = split_posix(m.linkname)
        if ".." in tparts or not tparts:
            self.warnings.append(f"layer {idx}: rejected hardlink target {m.linkname!r}")
            return
        tkey = posixpath.join(self._canon_dir(tparts[:-1]), tparts[-1])
        target = self._entries.get(tkey)
        if target is None or not st_mod.S_ISREG(target.mode):
            return
        self._insert(
            key,
            _Entry(
                mode=target.mode,
                uid=target.uid,
                gid=target.gid,
                size=target.size,
                mtime=target.mtime,
                layer=idx,
                blob=target.blob,
                offset=target.offset,
                xattrs=target.xattrs,
                hardlink_of=tkey,
            ),
        )

    # -- primitives -----------------------------------------------------------
    def _lstat_raw(self, cpath: str) -> FileStat | None:
        e = self._entries.get(cpath)
        if e is None:
            return None
        return FileStat(
            path=cpath,
            mode=e.mode,
            uid=e.uid,
            gid=e.gid,
            size=e.size,
            mtime=e.mtime,
            linkname=e.linkname,
            xattrs=e.xattrs or {},
            hardlink_of=e.hardlink_of,
            layer=e.layer,
        )

    def _listdir_raw(self, cpath: str) -> list[str]:
        return list(self._children.get(cpath, ()))

    def _open_raw(self, cpath: str) -> BinaryIO:
        e = self._entries[cpath]
        if e.blob is None:
            raise RootFSError(f"no data for {cpath}")
        return io.BufferedReader(FileWindow(e.blob.path, e.blob.offset + e.offset, e.size))

    def iter_entries(self) -> Iterator[FileStat]:
        for p in sorted(self._entries):
            st = self._lstat_raw(p)
            if st is not None:
                yield st

    def __len__(self) -> int:
        return len(self._entries)

    def close(self) -> None:
        if self._cleanup is not None:
            cleanup, self._cleanup = self._cleanup, None
            cleanup()
