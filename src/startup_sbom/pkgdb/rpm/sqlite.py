"""rpmdb SQLite backend (``rpmdb.sqlite``, rpm ≥ 4.16).

SQLite needs a real file, so the database (and a non-empty ``-wal``) is streamed
through :meth:`RootFS.open` into a private temporary directory and opened
read-only there.  The target is never written to.  ``-shm`` is deliberately not
copied: it is a cache SQLite rebuilds from the WAL, and copying a hostile one
would only add attack surface.
"""

from __future__ import annotations

import sqlite3
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path

from startup_sbom.errors import ParseError
from startup_sbom.pkgdb.rpm.header import HEADER_MAX_BYTES
from startup_sbom.rootfs import RootFS

SQLITE_MAGIC = b"SQLite format 3\x00"
MAX_COPY_BYTES = 2 * 1024 * 1024 * 1024
QUERY_TIME_BUDGET = 300.0
_CHUNK = 1024 * 1024


def _copy(fs: RootFS, src: str, dst: Path, budget: int) -> int:
    """Stream ``src`` (in-image) to host ``dst``; return bytes copied."""
    copied = 0
    with fs.open(src) as fin, dst.open("wb") as fout:
        while True:
            chunk = fin.read(_CHUNK)
            if not chunk:
                break
            copied += len(chunk)
            if copied > budget:
                raise ParseError(f"{src}: rpmdb exceeds the {MAX_COPY_BYTES} byte copy limit")
            fout.write(chunk)
    return copied


def iter_sqlite_blobs(
    fs: RootFS, path: str, warn: Callable[[str], None] | None = None
) -> Iterator[bytes]:
    """Yield every ``Packages.blob`` of the rpmdb at in-image ``path``."""
    with tempfile.TemporaryDirectory(prefix="startup-sbom-rpmdb-") as tmp:
        dst = Path(tmp) / "rpmdb.sqlite"
        used = _copy(fs, path, dst, MAX_COPY_BYTES)
        wal = path + "-wal"
        wst = fs.try_stat(wal)
        if wst is not None and wst.is_file and wst.size > 0:
            _copy(fs, wal, Path(str(dst) + "-wal"), MAX_COPY_BYTES - used)
        deadline = time.monotonic() + QUERY_TIME_BUDGET
        try:
            con = sqlite3.connect(dst.as_uri() + "?mode=ro", uri=True)
        except sqlite3.Error as exc:
            raise ParseError(f"{path}: cannot open rpmdb: {exc}") from exc
        try:
            con.set_progress_handler(lambda: int(time.monotonic() > deadline), 10_000)
            try:
                con.execute("PRAGMA trusted_schema=OFF")
                con.execute("PRAGMA query_only=ON")
                row = con.execute("SELECT type FROM sqlite_master WHERE name='Packages'").fetchone()
                if row is None or row[0] != "table":
                    raise ParseError(f"{path}: no Packages table")
                cur = con.execute("SELECT hnum, blob FROM Packages ORDER BY hnum")
                for hnum, blob in cur:
                    if not isinstance(blob, bytes | memoryview):
                        if warn:
                            warn(f"{path}: package {hnum} has a non-blob header")
                        continue
                    if len(blob) >= HEADER_MAX_BYTES:
                        if warn:
                            warn(f"{path}: package {hnum} header too large")
                        continue
                    yield bytes(blob)
            except sqlite3.Error as exc:
                raise ParseError(f"{path}: rpmdb query failed: {exc}") from exc
        finally:
            con.close()
