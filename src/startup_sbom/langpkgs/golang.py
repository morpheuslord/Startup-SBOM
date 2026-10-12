"""Go module inventory from the ``.go.buildinfo`` blob of Go executables.

Layout (``debug/buildinfo``): a 32-byte header ``"\\xff Go buildinf:"`` + pointer
size (1 byte) + flags (1 byte: bit 0 big-endian, bit 1 inline strings) + padding,
16-byte aligned.  Go >= 1.18 stores two uvarint-length-prefixed strings inline
(Go version, modinfo); older toolchains store two pointers to Go string headers,
which are followed through the ``PT_LOAD`` mapping.  Modinfo is framed by
16-byte sentinels and holds TAB-separated ``path``/``mod``/``dep``/``=>``/``build``
lines.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass, field

from packageurl import PackageURL

from startup_sbom.binaries.elf import MAX_FILE_SIZE, ElfInfo
from startup_sbom.errors import RootFSError
from startup_sbom.models import Package, PackageType
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.rootfs import RootFS

GO_MAGIC = b"\xff Go buildinf:"
MAX_BLOB = 4 * 1024 * 1024
MAX_STRING = 4 * 1024 * 1024
MAX_DEPS = 10_000
SCAN_CHUNK = 1024 * 1024
KEPT_SETTINGS = (
    "-buildmode",
    "-compiler",
    "CGO_ENABLED",
    "GOARCH",
    "GOOS",
    "vcs",
    "vcs.revision",
    "vcs.time",
    "vcs.modified",
)

#: ``read_at(vaddr, size)`` returns the bytes mapped at a virtual address.
VaddrReader = Callable[[int, int], bytes | None]


@dataclass(slots=True)
class GoModule:
    path: str
    version: str = ""
    sum: str = ""
    replace: GoModule | None = None


@dataclass(slots=True)
class GoBuildInfo:
    go_version: str
    path: str | None = None
    main: GoModule | None = None
    deps: list[GoModule] = field(default_factory=list)
    settings: dict[str, str] = field(default_factory=dict)


def _uvarint(buf: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    for _ in range(10):
        if pos >= len(buf):
            raise ValueError("truncated uvarint")
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if b < 0x80:
            return value, pos
        shift += 7
    raise ValueError("uvarint too long")


def _inline_str(buf: bytes, pos: int) -> tuple[bytes, int]:
    n, pos = _uvarint(buf, pos)
    if n > MAX_STRING or pos + n > len(buf):
        raise ValueError("bad inline string")
    return buf[pos : pos + n], pos + n


def find_magic(buf: bytes, start: int = 0) -> int:
    """Offset of the first 16-byte aligned buildinfo header in ``buf`` (or -1)."""
    i = buf.find(GO_MAGIC, start)
    while i != -1 and i % 16:
        i = buf.find(GO_MAGIC, i + 1)
    return i


def _ptr_str(read_at: VaddrReader, ptr: int, ptrsize: int, e: str) -> bytes | None:
    fmt = e + ("Q" if ptrsize == 8 else "I")
    hdr = read_at(ptr, 2 * ptrsize)
    if hdr is None or len(hdr) != 2 * ptrsize:
        return None
    data_ptr = struct.unpack_from(fmt, hdr, 0)[0]
    length = struct.unpack_from(fmt, hdr, ptrsize)[0]
    if length > MAX_STRING:
        return None
    if length == 0:
        return b""
    data = read_at(data_ptr, length)
    return data if data is not None and len(data) == length else None


def parse_buildinfo(blob: bytes, read_at: VaddrReader | None = None) -> GoBuildInfo | None:
    """Decode the buildinfo header found in ``blob`` (``None`` if absent/malformed)."""
    i = find_magic(blob)
    if i < 0 or i + 32 > len(blob):
        return None
    ptrsize, flags = blob[i + 14], blob[i + 15]
    try:
        if flags & 2:
            ver, pos = _inline_str(blob, i + 32)
            mod, _ = _inline_str(blob, pos)
        else:
            if read_at is None or ptrsize not in (4, 8):
                return None
            e = ">" if flags & 1 else "<"
            fmt = e + ("Q" if ptrsize == 8 else "I")
            vptr = struct.unpack_from(fmt, blob, i + 16)[0]
            mptr = struct.unpack_from(fmt, blob, i + 16 + ptrsize)[0]
            v = _ptr_str(read_at, vptr, ptrsize, e)
            m = _ptr_str(read_at, mptr, ptrsize, e)
            if v is None or m is None:
                return None
            ver, mod = v, m
    except (ValueError, struct.error):
        return None
    version = ver.decode("utf-8", "replace")
    if not version.startswith("go") and not version.startswith("devel"):
        return None
    if len(mod) >= 33 and mod[-17] == 0x0A:
        mod = mod[16:-16]
    info = GoBuildInfo(go_version=version[:128])
    parse_modinfo(mod.decode("utf-8", "replace"), info)
    return info


def parse_modinfo(text: str, info: GoBuildInfo) -> None:
    """Fill ``info`` from ``runtime/debug.BuildInfo`` text."""
    last: GoModule | None = None
    for line in text.splitlines():
        f = line.split("\t")
        tag = f[0]
        if tag == "path" and len(f) > 1:
            info.path = f[1][:512]
        elif tag in ("mod", "dep") and len(f) > 1:
            last = GoModule(
                f[1][:512], f[2][:256] if len(f) > 2 else "", f[3] if len(f) > 3 else ""
            )
            if tag == "mod":
                info.main = last
            elif len(info.deps) < MAX_DEPS:
                info.deps.append(last)
        elif tag == "=>" and last is not None and len(f) > 1:
            last.replace = GoModule(
                f[1][:512], f[2][:256] if len(f) > 2 else "", f[3] if len(f) > 3 else ""
            )
        elif tag == "build" and len(f) > 1:
            key, _, value = f[1].partition("=")
            if key in KEPT_SETTINGS:
                info.settings[key] = value[:256]


def golang_purl(module: str, version: str | None) -> str:
    """purl of a Go module (``pkg:golang/<namespace>/<name>@<version>``)."""
    namespace, _, name = module.rpartition("/")
    ver = version if version and version != "(devel)" else None
    return PackageURL(
        type="golang", namespace=namespace or None, name=name, version=ver
    ).to_string()


def stdlib_version(go_version: str) -> str | None:
    """``go1.26.6 X:nocoverageredesign`` -> ``1.26.6`` (``None`` for devel toolchains)."""
    words = go_version.split(maxsplit=1)
    v = words[0] if words else ""
    if not v.startswith("go") or not v[2:3].isdigit():
        return None
    return v[2:]


def read_buildinfo(
    fs: RootFS, path: str, info: ElfInfo, *, scan: bool = False
) -> GoBuildInfo | None:
    """Read and decode the Go buildinfo of the ELF at ``path``.

    Uses the ``.go.buildinfo`` section when present; otherwise, if ``scan`` is
    true (or the binary carries a Go build-id note), searches the file for an
    aligned header in bounded chunks.
    """
    sec = info.sections.get(".go.buildinfo")
    try:
        with fs.open(path) as f:

            def read_at(vaddr: int, size: int) -> bytes | None:
                off = info.vaddr_to_offset(vaddr)
                if off is None or size > MAX_STRING:
                    return None
                f.seek(off)
                return f.read(size)

            if sec is not None:
                f.seek(sec.offset)
                blob = f.read(min(max(sec.size, 64 * 1024), MAX_BLOB))
                return parse_buildinfo(blob, read_at)
            if not (scan or info.go_build_id):
                return None
            pos = 0
            limit = min(info.size, MAX_FILE_SIZE)
            while pos < limit:
                f.seek(pos)
                chunk = f.read(min(SCAN_CHUNK + 64 * 1024, limit - pos))
                if not chunk:
                    break
                i = find_magic(chunk)
                if i >= 0:
                    f.seek(pos + i)
                    return parse_buildinfo(f.read(MAX_BLOB), read_at)
                pos += SCAN_CHUNK
    except (RootFSError, OSError, ValueError):
        return None
    return None


def records_for(path: str, bi: GoBuildInfo, owners: FileOwnerIndex) -> list[PackageRecord]:
    """Package records (main module, dependencies, stdlib) for one Go binary."""
    base: dict[str, str] = {"binary": path, "go_version": bi.go_version}
    owner = owners.owner(path)
    if owner:
        base["managed_by"] = owner
    for k, v in bi.settings.items():
        base[f"go.{k}"] = v
    out: list[PackageRecord] = []

    def add(mod: GoModule, *, main: bool) -> None:
        eff = mod
        props = dict(base)
        if mod.replace is not None:
            props["replaces"] = f"{mod.path}@{mod.version}" if mod.version else mod.path
            if mod.replace.version:
                eff = mod.replace
            else:
                props["replaced_by_path"] = mod.replace.path
        if eff.sum:
            props["sum"] = eff.sum[:128]
        if main:
            props["main_module"] = "true"
            if bi.path:
                props["main_package"] = bi.path
        version = eff.version or "(devel)"
        purl = golang_purl(eff.path, version)
        pkg = Package(
            id=purl,
            type=PackageType.GOLANG,
            name=eff.path,
            version=version,
            purl=purl,
            depends=[d.path for d in bi.deps] if main else [],
            file_count=1 if main else 0,
            location=path,
            properties=props,
        )
        out.append(PackageRecord(package=pkg, files=[path] if main else []))

    if bi.main is not None and bi.main.path:
        add(bi.main, main=True)
    for dep in bi.deps:
        if dep.path:
            add(dep, main=False)
    std = stdlib_version(bi.go_version)
    if std:
        purl = PackageURL(type="golang", name="stdlib", version=std).to_string()
        out.append(
            PackageRecord(
                package=Package(
                    id=purl,
                    type=PackageType.GOLANG,
                    name="stdlib",
                    version=std,
                    purl=purl,
                    location=path,
                    properties=dict(base),
                )
            )
        )
    return out


def extract(
    fs: RootFS, path: str, info: ElfInfo, owners: FileOwnerIndex, *, scan: bool = False
) -> list[PackageRecord]:
    """Go packages embedded in the ELF at ``path`` (empty if not a Go binary)."""
    if not (info.has_go_buildinfo or scan):
        return []
    bi = read_buildinfo(fs, path, info, scan=scan)
    if bi is None:
        return []
    return records_for(path, bi, owners)
