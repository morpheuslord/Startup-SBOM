"""Root-confined emulation of the dynamic loader's library search (glibc and musl).

:class:`LibraryResolver` answers "which file would ``ld.so`` map for soname *N*
requested by object *O*?" by reading only the analysed root:

* glibc: ``DT_RPATH`` of the requester and its loader chain (ignored when the
  requester has ``DT_RUNPATH``; an object's own RPATH is ignored when it has a
  RUNPATH), then ``DT_RUNPATH``, then ``/etc/ld.so.cache`` (``glibc-ld.so.cache1.1``,
  every entry re-validated inside the root), then the directories of
  ``/etc/ld.so.conf`` (+ ``include`` globs, as if ``ldconfig`` had been re-run),
  then the default/multiarch directories.  ``DF_1_NODEFLIB`` skips the last three.
* musl: RUNPATH-or-RPATH of the requester and its whole loader chain, then
  ``/etc/ld-musl-<arch>.path`` or ``/lib:/usr/local/lib:/usr/lib``.

``$ORIGIN``, ``$LIB`` and ``$PLATFORM`` are expanded to every plausible value.
Candidates must be regular ELF files of the requester's class, byte order and
machine (ld.so skips "wrong ELF class" objects).  Results are canonical in-image
paths and are cached.  ``LD_LIBRARY_PATH``/``LD_PRELOAD`` from the environment
and ``glibc-hwcaps`` subdirectories are not modelled.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import struct
from collections.abc import Sequence
from dataclasses import dataclass

from startup_sbom.binaries.elf import ElfInfo, read_elf
from startup_sbom.errors import RootFSError
from startup_sbom.rootfs import RootFS, normalize, split_posix

LD_CACHE_PATH = "/etc/ld.so.cache"
LD_CONF_PATH = "/etc/ld.so.conf"
LD_PRELOAD_PATH = "/etc/ld.so.preload"
LD_CACHE_MAGIC = b"glibc-ld.so.cache1.1"

MAX_CACHE_SIZE = 16 * 1024 * 1024
MAX_CACHE_ENTRIES = 200_000
MAX_CONF_FILES = 256
MAX_CONF_DEPTH = 8
MAX_CONF_DIRS = 512
MAX_GLOB_RESULTS = 256
MAX_PRELOAD = 64
MAX_EXPANSIONS = 16
MAX_SEARCH_DIRS = 256

MUSL_DEFAULT_DIRS = ("/lib", "/usr/local/lib", "/usr/lib")

#: Debian/Ubuntu multiarch triplets per arch (see ``dpkg-architecture -L``).
TRIPLETS: dict[str, tuple[str, ...]] = {
    "x86_64": ("x86_64-linux-gnu",),
    "i386": ("i386-linux-gnu", "i686-linux-gnu"),
    "x32": ("x86_64-linux-gnux32",),
    "aarch64": ("aarch64-linux-gnu",),
    "arm": ("arm-linux-gnueabihf", "arm-linux-gnueabi"),
    "ppc64le": ("powerpc64le-linux-gnu",),
    "ppc64": ("powerpc64-linux-gnu",),
    "ppc": ("powerpc-linux-gnu",),
    "s390x": ("s390x-linux-gnu",),
    "riscv64": ("riscv64-linux-gnu",),
    "mips64el": ("mips64el-linux-gnuabi64",),
    "mips64": ("mips64-linux-gnuabi64",),
    "mipsel": ("mipsel-linux-gnu",),
    "mips": ("mips-linux-gnu",),
    "loongarch64": ("loongarch64-linux-gnu",),
    "sparc64": ("sparc64-linux-gnu",),
    "m68k": ("m68k-linux-gnu",),
    "alpha": ("alpha-linux-gnu",),
    "hppa": ("hppa-linux-gnu",),
    "sh": ("sh4-linux-gnu",),
    "ia64": ("ia64-linux-gnu",),
}

#: Candidate ``AT_PLATFORM`` strings per arch, for ``$PLATFORM`` expansion.
PLATFORMS: dict[str, tuple[str, ...]] = {
    "x86_64": ("x86_64", "haswell", "xeon_phi"),
    "i386": ("i686", "i586", "i486", "i386"),
    "aarch64": ("aarch64",),
    "arm": ("v7l", "v6l", "v5l"),
    "ppc64le": ("power8", "power9", "power10", "ppc64le"),
    "ppc64": ("power8", "power7", "ppc64"),
    "s390x": ("z13", "z14", "z15", "s390x"),
}

#: musl ``$ARCH`` names used in ``ld-musl-$ARCH.so.1`` / ``ld-musl-$ARCH.path``.
MUSL_ARCH: dict[str, tuple[str, ...]] = {
    "x86_64": ("x86_64",),
    "i386": ("i386", "x86"),
    "x32": ("x32",),
    "aarch64": ("aarch64",),
    "arm": ("armhf", "arm"),
    "ppc64le": ("powerpc64le",),
    "ppc64": ("powerpc64",),
    "ppc": ("powerpc",),
    "s390x": ("s390x",),
    "riscv64": ("riscv64",),
    "mips64el": ("mips64el",),
    "mips64": ("mips64",),
    "mipsel": ("mipsel",),
    "mips": ("mips",),
    "loongarch64": ("loongarch64",),
}

_TOKEN_RE = re.compile(r"\$(?:\{(ORIGIN|LIB|PLATFORM)\}|(ORIGIN|LIB|PLATFORM)(?![A-Za-z0-9_]))")
_MUSL_INTERP_RE = re.compile(r"ld-musl-([A-Za-z0-9_]+)\.so")


@dataclass(frozen=True, slots=True)
class Resolution:
    """A resolved library: ``lookup`` is the search-path spelling, ``path`` the canonical file."""

    lookup: str
    path: str


#: A loader-chain element: ``(elf info, lookup path)`` from the executable downwards.
ChainLink = tuple[ElfInfo, str]


def default_dirs(info: ElfInfo) -> list[str]:
    """Compiled-in glibc search directories for ``info``'s arch (multiarch union)."""
    dirs: list[str] = []
    for t in TRIPLETS.get(info.arch, ()):
        dirs += [f"/lib/{t}", f"/usr/lib/{t}"]
    if info.arch == "x32":
        dirs += ["/libx32", "/usr/libx32"]
    elif info.bits == 64:
        dirs += ["/lib64", "/usr/lib64"]
    else:
        dirs += ["/lib32", "/usr/lib32"]
    dirs += ["/lib", "/usr/lib"]
    return dirs


def lib_values(info: ElfInfo) -> list[str]:
    """Candidate values of ``$LIB`` for ``info``."""
    vals = ["lib64", "lib"] if info.bits == 64 else ["lib", "lib32"]
    if info.arch == "x32":
        vals = ["libx32", "lib"]
    vals += [f"lib/{t}" for t in TRIPLETS.get(info.arch, ())]
    return vals


def expand_tokens(path: str, info: ElfInfo, origins: Sequence[str]) -> list[str]:
    """Expand ``$ORIGIN``/``$LIB``/``$PLATFORM`` in one search-path element."""
    results = [path]
    for _ in range(4):  # a path rarely carries more than a couple of tokens
        nxt: list[str] = []
        changed = False
        for p in results:
            m = _TOKEN_RE.search(p)
            if m is None:
                nxt.append(p)
                continue
            changed = True
            kind = m.group(1) or m.group(2)
            if kind == "ORIGIN":
                values: Sequence[str] = origins
            elif kind == "LIB":
                values = lib_values(info)
            else:
                values = PLATFORMS.get(info.arch, (info.arch,))
            nxt.extend(p[: m.start()] + v + p[m.end() :] for v in values)
        results = list(dict.fromkeys(nxt))[:MAX_EXPANSIONS]
        if not changed:
            break
    return [r for r in results if "$" not in r]


def split_search_path(value: str | None) -> list[str]:
    """Split a ``DT_RPATH``/``DT_RUNPATH`` value; relative and empty entries are dropped."""
    if not value:
        return []
    return [p for p in value.split(":") if p.startswith(("/", "$"))]


def parse_ld_so_cache(data: bytes) -> dict[str, list[str]]:
    """Parse a ``glibc-ld.so.cache1.1`` image into ``soname -> [paths]`` (cache order).

    Handles both the new-only layout and the legacy combined layout (new
    section after an ``ld.so-1.7.0`` block); string offsets are relative to the
    start of the new header.  Malformed input yields an empty or partial map.
    """
    i = data.find(LD_CACHE_MAGIC)
    if i < 0 or len(data) - i < 48:
        return {}
    endian_flag = data[i + 28]
    order = [">"] if endian_flag == 3 else ["<"] if endian_flag == 2 else ["<", ">"]
    avail = (len(data) - i - 48) // 24
    for e in order:
        (nlibs,) = struct.unpack_from(e + "I", data, i + 20)
        if nlibs <= min(avail, MAX_CACHE_ENTRIES):
            break
    else:
        return {}
    out: dict[str, list[str]] = {}

    def cstr(off: int) -> str | None:
        start = i + off
        if off <= 0 or start >= len(data):
            return None
        end = data.find(b"\x00", start, start + 4096)
        if end < 0:
            return None
        return data[start:end].decode("utf-8", "replace")

    for k in range(nlibs):
        _flags, key, value, _osv, _hw = struct.unpack_from(e + "iIIIQ", data, i + 48 + k * 24)
        name, path = cstr(key), cstr(value)
        if not name or not path or not path.startswith("/") or "/" in name:
            continue
        paths = out.setdefault(name, [])
        if path not in paths:
            paths.append(path)
    return out


class LibraryResolver:
    """Emulates ``ld.so`` library lookup inside one analysed root."""

    def __init__(self, fs: RootFS) -> None:
        self.fs = fs
        self._elf: dict[str, ElfInfo | None] = {}
        self._canon: dict[str, str | None] = {}
        self._results: dict[tuple[object, ...], Resolution | None] = {}
        self._cache: dict[str, list[str]] | None = None
        self._conf_dirs: list[str] | None = None
        self._musl_dirs: dict[str, list[str]] = {}
        self._preload: list[str] | None = None

    # -- memoised filesystem helpers -------------------------------------------
    def canonical(self, path: str) -> str | None:
        """Canonical in-image path of ``path`` or ``None`` if it does not exist."""
        if path in self._canon:
            return self._canon[path]
        result = self.fs.try_resolve(path)
        self._canon[path] = result
        return result

    def elf(self, path: str) -> ElfInfo | None:
        """Parsed ELF metadata of ``path`` (memoised by canonical path)."""
        cpath = self.canonical(path)
        if cpath is None:
            return None
        if cpath not in self._elf:
            self._elf[cpath] = read_elf(self.fs, cpath)
        return self._elf[cpath]

    # -- configuration ---------------------------------------------------------
    @property
    def ld_cache(self) -> dict[str, list[str]]:
        """``/etc/ld.so.cache`` as ``soname -> [paths]`` (empty if absent/invalid)."""
        if self._cache is None:
            self._cache = {}
            try:
                data = self.fs.read_bytes(LD_CACHE_PATH, MAX_CACHE_SIZE)
            except (RootFSError, OSError):
                data = b""
            if data:
                self._cache = parse_ld_so_cache(data)
        return self._cache

    @property
    def ld_conf_dirs(self) -> list[str]:
        """Directories listed by ``/etc/ld.so.conf`` and its includes, in order."""
        if self._conf_dirs is None:
            dirs: list[str] = []
            self._read_conf(LD_CONF_PATH, dirs, set(), 0)
            self._conf_dirs = dirs
        return self._conf_dirs

    def _read_conf(self, path: str, dirs: list[str], seen: set[str], depth: int) -> None:
        cpath = self.canonical(path)
        if cpath is None or cpath in seen or depth > MAX_CONF_DEPTH or len(seen) >= MAX_CONF_FILES:
            return
        seen.add(cpath)
        text = self.fs.try_read_text(cpath, 1024 * 1024)
        if text is None:
            return
        base = posixpath.dirname(normalize(path))
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            words = line.split()
            if words[0] == "include":
                for pattern in words[1:]:
                    full = pattern if pattern.startswith("/") else posixpath.join(base, pattern)
                    for match in self.glob(full):
                        self._read_conf(match, dirs, seen, depth + 1)
                continue
            if words[0] == "hwcap":
                continue
            for item in re.split(r"[\s,:]+", line):
                d = item.split("=", 1)[0]
                if d.startswith("/") and len(dirs) < MAX_CONF_DIRS:
                    nd = normalize(d)
                    if nd not in dirs:
                        dirs.append(nd)

    def glob(self, pattern: str) -> list[str]:
        """Expand a shell glob inside the root (sorted, bounded, no ``**``)."""
        parts = split_posix(pattern)
        current = ["/"]
        for comp in parts:
            nxt: list[str] = []
            for d in current:
                if any(c in comp for c in "*?["):
                    nxt.extend(
                        posixpath.join(d, n)
                        for n in self.fs.safe_listdir(d)
                        if fnmatch.fnmatchcase(n, comp) and not n.startswith(".")
                    )
                else:
                    nxt.append(posixpath.join(d, comp))
                if len(nxt) > MAX_GLOB_RESULTS:
                    break
            current = nxt[:MAX_GLOB_RESULTS]
        return sorted(p for p in current if self.fs.lexists(p))

    def musl_dirs(self, info: ElfInfo, interpreter: str | None = None) -> list[str]:
        """System search path of musl for ``info``'s arch."""
        names: list[str] = []
        if interpreter:
            m = _MUSL_INTERP_RE.search(interpreter)
            if m:
                names.append(m.group(1))
        names += MUSL_ARCH.get(info.arch, (info.arch,))
        key = "|".join(names)
        if key in self._musl_dirs:
            return self._musl_dirs[key]
        dirs = list(MUSL_DEFAULT_DIRS)
        for name in dict.fromkeys(names):
            text = self.fs.try_read_text(f"/etc/ld-musl-{name}.path", 64 * 1024)
            if text is not None:
                entries = (d.strip() for d in re.split(r"[\n:]+", text))
                dirs = [normalize(d) for d in entries if d.startswith("/")][:MAX_CONF_DIRS]
                break
        self._musl_dirs[key] = dirs
        return dirs

    def preload(self) -> list[str]:
        """Raw entries of ``/etc/ld.so.preload`` (paths or sonames), in order."""
        if self._preload is None:
            entries: list[str] = []
            text = self.fs.try_read_text(LD_PRELOAD_PATH, 256 * 1024)
            if text:
                for raw in text.splitlines():
                    line = raw.split("#", 1)[0]
                    for tok in re.split(r"[\s:]+", line):
                        if tok and tok not in entries and len(entries) < MAX_PRELOAD:
                            entries.append(tok)
            self._preload = entries
        return self._preload

    @staticmethod
    def is_musl(info: ElfInfo | None) -> bool:
        """``True`` if ``info``'s ``PT_INTERP`` names the musl loader."""
        return bool(info and info.interpreter and "ld-musl" in info.interpreter)

    # -- resolution ------------------------------------------------------------
    def _origins(self, lookup: str) -> list[str]:
        out = [posixpath.dirname(normalize(lookup))]
        canon = self.canonical(lookup)
        if canon is not None:
            out.append(posixpath.dirname(canon))
        return list(dict.fromkeys(out))

    def _expand(self, value: str | None, info: ElfInfo, lookup: str) -> list[str]:
        dirs: list[str] = []
        for element in split_search_path(value):
            origins = self._origins(lookup) if "ORIGIN" in element else []
            dirs.extend(normalize(p) for p in expand_tokens(element, info, origins))
        return dirs

    def resolve(
        self,
        soname: str,
        requester: ElfInfo,
        requester_path: str,
        *,
        chain: Sequence[ChainLink] = (),
        musl: bool | None = None,
    ) -> str | None:
        """Canonical in-image path ld.so would load for ``soname``, or ``None``.

        ``chain`` lists the loaders from the executable down to (excluding) the
        requester; it supplies inherited ``DT_RPATH`` entries.  ``musl`` defaults to
        whether the requester (or the chain's executable) uses the musl loader.
        """
        res = self.resolve_full(soname, requester, requester_path, chain=chain, musl=musl)
        return res.path if res is not None else None

    def resolve_full(
        self,
        soname: str,
        requester: ElfInfo,
        requester_path: str,
        *,
        chain: Sequence[ChainLink] = (),
        musl: bool | None = None,
    ) -> Resolution | None:
        """Like :meth:`resolve` but also return the search-path spelling."""
        if not soname or "\x00" in soname:
            return None
        if musl is None:
            root_info = chain[0][0] if chain else requester
            musl = self.is_musl(root_info) or self.is_musl(requester)
        if "/" in soname:
            origins = self._origins(requester_path)
            for cand in expand_tokens(soname, requester, origins):
                hit = self._check(cand if cand.startswith("/") else "/" + cand, requester)
                if hit is not None:
                    return hit
            return None

        prefix: list[str] = []
        loaders: list[ChainLink] = [(requester, requester_path), *reversed(chain)]
        if musl:
            for info, path in loaders:
                prefix += self._expand(info.runpath or info.rpath, info, path)
        else:
            if not requester.runpath:
                for info, path in loaders:
                    if not info.runpath:
                        prefix += self._expand(info.rpath, info, path)
            prefix += self._expand(requester.runpath, requester, requester_path)
        prefix = list(dict.fromkeys(prefix))[:MAX_SEARCH_DIRS]
        nodeflib = requester.nodeflib and not musl
        interp = (chain[0][0] if chain else requester).interpreter
        key = (
            soname,
            tuple(prefix),
            requester.bits,
            requester.machine,
            requester.little_endian,
            musl,
            nodeflib,
            interp if musl else None,
        )
        if key in self._results:
            return self._results[key]
        result = self._search(
            soname, requester, prefix, musl=musl, nodeflib=nodeflib, interp=interp
        )
        self._results[key] = result
        return result

    def _search(
        self,
        soname: str,
        requester: ElfInfo,
        prefix: list[str],
        *,
        musl: bool,
        nodeflib: bool,
        interp: str | None,
    ) -> Resolution | None:
        for d in prefix:
            hit = self._check(posixpath.join(d, soname), requester)
            if hit is not None:
                return hit
        if nodeflib:
            return None
        if musl:
            system = self.musl_dirs(requester, interp)
        else:
            for path in self.ld_cache.get(soname, ()):
                hit = self._check(path, requester)
                if hit is not None:
                    return hit
            system = [*self.ld_conf_dirs, *default_dirs(requester)]
        for d in dict.fromkeys(system):
            if d in prefix:
                continue
            hit = self._check(posixpath.join(d, soname), requester)
            if hit is not None:
                return hit
        return None

    def _check(self, candidate: str, requester: ElfInfo) -> Resolution | None:
        lookup = normalize(candidate)
        canon = self.canonical(lookup)
        if canon is None:
            return None
        info = self.elf(canon)
        if info is None or not info.compatible_with(requester):
            return None
        return Resolution(lookup, canon)
