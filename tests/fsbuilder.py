"""Helpers to build synthetic root filesystems (as directories or tar layers) for tests.

A *spec* maps absolute in-image paths to entries::

    {
        "/etc/os-release": 'ID=debian\\nVERSION_ID="12"\\n',
        "/usr/bin/sshd": File(b"\\x7fELF...", mode=0o755),
        "/bin": Symlink("usr/bin"),
        "/var/empty": Dir(),
        "/usr/bin/passwd": File(b"", mode=0o4755),
    }

``str``/``bytes`` values are shorthand for regular files with mode 0o644.
"""

from __future__ import annotations

import io
import os
import posixpath
import tarfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class File:
    content: bytes | str = b""
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    xattrs: dict[str, bytes] = field(default_factory=dict)

    @property
    def data(self) -> bytes:
        return self.content.encode() if isinstance(self.content, str) else self.content


@dataclass(frozen=True)
class Symlink:
    target: str


@dataclass(frozen=True)
class Dir:
    mode: int = 0o755


@dataclass(frozen=True)
class Whiteout:
    """Marks deletion of a lower-layer path (tar layers only)."""


Entry = File | Symlink | Dir | Whiteout | str | bytes
Spec = dict[str, Entry]


def _norm(entry: Entry) -> File | Symlink | Dir | Whiteout:
    if isinstance(entry, str | bytes):
        return File(entry)
    return entry


def build_dir(root: Path, spec: Spec) -> Path:
    """Materialise ``spec`` under ``root`` (setuid bits applied where the host allows)."""
    root.mkdir(parents=True, exist_ok=True)
    for path, raw in sorted(spec.items()):
        entry = _norm(raw)
        host = root.joinpath(*[p for p in path.split("/") if p])
        if isinstance(entry, Dir):
            host.mkdir(parents=True, exist_ok=True)
            continue
        host.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(entry, Symlink):
            os.symlink(entry.target, host)
        elif isinstance(entry, File):
            host.write_bytes(entry.data)
            os.chmod(host, entry.mode)
    return root


def build_tar(path: Path, spec: Spec) -> Path:
    """Write ``spec`` as an uncompressed tar layer (whiteouts become ``.wh.`` entries)."""
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        dirs: set[str] = set()
        for p, raw in sorted(spec.items()):
            entry = _norm(raw)
            name = p.lstrip("/")
            parent = posixpath.dirname(name)
            while parent and parent not in dirs:
                dirs.add(parent)
                parent = posixpath.dirname(parent)
            if isinstance(entry, Whiteout):
                wh = posixpath.join(posixpath.dirname(name), ".wh." + posixpath.basename(name))
                tf.addfile(tarfile.TarInfo(wh), io.BytesIO(b""))
                continue
            info = tarfile.TarInfo(name)
            if isinstance(entry, Dir):
                info.type = tarfile.DIRTYPE
                info.mode = entry.mode
                tf.addfile(info)
            elif isinstance(entry, Symlink):
                info.type = tarfile.SYMTYPE
                info.linkname = entry.target
                tf.addfile(info)
            else:
                data = entry.data
                info.size = len(data)
                info.mode = entry.mode
                info.uid, info.gid = entry.uid, entry.gid
                if entry.xattrs:
                    info.pax_headers = {
                        "SCHILY.xattr." + k: v.decode("utf-8", "surrogateescape")
                        for k, v in entry.xattrs.items()
                    }
                tf.addfile(info, io.BytesIO(data))
    return path
