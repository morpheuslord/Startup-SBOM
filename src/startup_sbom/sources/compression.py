"""Compression sniffing and the per-scan temporary workspace.

``tarfile`` cannot seek inside gzip/xz/bzip2/zstd streams, so a compressed layer
or tarball is decompressed exactly once into a private ``tempfile.mkdtemp()``
directory and then addressed as an uncompressed :class:`LayerBlob`.  Nothing is
ever extracted.  Every byte written is charged against a byte budget so a
decompression bomb fails fast instead of filling the disk.
"""

from __future__ import annotations

import bz2
import contextlib
import gzip
import hashlib
import io
import logging
import lzma
import os
import shutil
import stat as st_mod
import sys
import tempfile
import time
import zlib
from typing import Any

from startup_sbom.errors import TargetError
from startup_sbom.rootfs import LayerBlob

log = logging.getLogger(__name__)

CHUNK = 1 << 20
DEFAULT_MAX_BYTES = 64 * 1024**3

GZIP = "gzip"
ZSTD = "zstd"
XZ = "xz"
BZIP2 = "bzip2"


def sniff_bytes(head: bytes) -> str | None:
    """Return the compression of a stream from its magic bytes (``None`` = uncompressed)."""
    if head[:2] == b"\x1f\x8b":
        return GZIP
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return ZSTD
    if head[:6] == b"\xfd7zXZ\x00":
        return XZ
    if head[:3] == b"BZh":
        return BZIP2
    return None


def sniff_blob(blob: LayerBlob) -> str | None:
    """Sniff the compression of a blob window."""
    try:
        with blob.open() as f:
            return sniff_bytes(f.read(8))
    except OSError as exc:
        raise TargetError(f"cannot read {blob.label or 'blob'}: {exc}") from exc


def _zstd_module() -> Any:
    try:
        if sys.version_info >= (3, 14):
            from compression import zstd
        else:
            from backports import zstd
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise TargetError("zstd support unavailable: needs Python 3.14+ or backports.zstd") from exc
    return zstd


def open_decompressor(fobj: Any, kind: str) -> io.BufferedIOBase:
    """Wrap ``fobj`` in a streaming decompressor for ``kind``."""
    if kind == GZIP:
        return gzip.GzipFile(fileobj=fobj, mode="rb")
    if kind == XZ:
        return lzma.LZMAFile(fobj, mode="rb")
    if kind == BZIP2:
        return bz2.BZ2File(fobj, mode="rb")
    if kind == ZSTD:
        reader: io.BufferedIOBase = _zstd_module().ZstdFile(fobj, mode="rb")
        return reader
    raise TargetError(f"unsupported compression {kind!r}")


def _decompression_errors() -> tuple[type[BaseException], ...]:
    errors: list[type[BaseException]] = [OSError, EOFError, lzma.LZMAError, zlib.error]
    with contextlib.suppress(TargetError):
        errors.append(_zstd_module().ZstdError)
    return tuple(errors)


def _make_writable(path: str) -> None:
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            with contextlib.suppress(OSError):
                os.chmod(full, st_mod.S_IWRITE | st_mod.S_IREAD | st_mod.S_IEXEC)


def remove_tree(path: str, *, attempts: int = 5, delay: float = 0.2) -> bool:
    """Delete a temp tree we created, retrying for Windows file locks; never raises."""
    for attempt in range(attempts):
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.lexists(path):
            return True
        _make_writable(path)
        time.sleep(delay * (attempt + 1))
    log.warning("could not fully remove temporary directory %s", path)
    return False


class Workspace:
    """A private temp directory plus a byte budget for everything written into it."""

    def __init__(self, *, max_bytes: int = DEFAULT_MAX_BYTES, base: str | None = None) -> None:
        self.path = tempfile.mkdtemp(prefix="startup-sbom-", dir=base)
        self.max_bytes = max_bytes
        self.used = 0
        self._cache: dict[str, LayerBlob] = {}
        self._closed = False

    def charge(self, nbytes: int, what: str = "data") -> None:
        """Account ``nbytes`` against the budget; raise :class:`TargetError` when exceeded."""
        self.used += nbytes
        if self.used > self.max_bytes:
            raise TargetError(
                f"{what} exceeds the size limit of {self.max_bytes} bytes "
                "(possible decompression bomb; raise max_bytes if legitimate)"
            )

    def new_file(self, suffix: str = ".tar") -> str:
        """Create an empty private file inside the workspace and return its host path."""
        if self._closed:
            raise TargetError("workspace already closed")
        fd, path = tempfile.mkstemp(suffix=suffix, dir=self.path)
        os.close(fd)
        return path

    def materialize(self, src: LayerBlob, key: str | None = None) -> LayerBlob:
        """Return an uncompressed, seekable view of ``src`` (decompressing once if needed)."""
        kind = sniff_blob(src)
        if kind is None:
            return src
        cache_key = key or f"{src.path}:{src.offset}:{src.size}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        label = src.label or os.path.basename(src.path)
        out = os.path.join(self.path, hashlib.sha256(cache_key.encode()).hexdigest()[:32] + ".tar")
        total = 0
        try:
            with src.open() as raw, open_decompressor(raw, kind) as rd, open(out, "wb") as w:
                while chunk := rd.read(CHUNK):
                    total += len(chunk)
                    self.charge(len(chunk), f"decompressed {label}")
                    w.write(chunk)
        except TargetError:
            raise
        except _decompression_errors() as exc:
            raise TargetError(f"cannot decompress {label} ({kind}): {exc}") from exc
        blob = LayerBlob(out, 0, total, label=label)
        self._cache[cache_key] = blob
        return blob

    def close(self) -> None:
        """Remove the workspace (idempotent; robust to Windows file locks)."""
        if self._closed:
            return
        self._closed = True
        self._cache.clear()
        remove_tree(self.path)

    def __enter__(self) -> Workspace:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
