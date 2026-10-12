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
import sys
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest


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


def _unrepresentable_on_windows(path: str, entry: File | Symlink | Dir | Whiteout) -> str | None:
    if ":" in path:
        return "NTFS treats ':' in a file name as an alternate data stream"
    if isinstance(entry, Symlink):
        return "POSIX symlink semantics need a POSIX host filesystem"
    if isinstance(entry, File) and entry.mode & 0o7111:
        return "NTFS cannot store POSIX execute/setuid/setgid bits"
    return None


def build_dir(root: Path, spec: Spec) -> Path:
    """Materialise ``spec`` under ``root`` (setuid bits applied where the host allows).

    On Windows a spec the host filesystem cannot represent skips the test; the
    tar backend runs the same spec there with full fidelity.
    """
    if sys.platform == "win32":
        for path, raw in spec.items():
            reason = _unrepresentable_on_windows(path, _norm(raw))
            if reason is not None:
                pytest.skip(f"dir backend on Windows: {reason} (covered by the tar backend)")
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
