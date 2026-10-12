"""Repository provenance: which configured repository each installed package came from.

Package databases rarely record where a package was downloaded from, so origin is
inferred the way the package managers themselves would (``apt-cache policy``,
``pacman -Qm``, apk index lookups, rpm signature checks), using only files inside
the analysed root:

* **apt** — ``sources.list`` / deb822 ``*.sources`` plus the cached
  ``/var/lib/apt/lists/*_Packages`` indexes (plain, gzip, xz, bzip2, zstd; lz4 is
  reported as a limitation).  Exact ``name+version+arch`` → repository; same name
  with another version → ``repo_version_mismatch`` (superseded, *not* an orphan);
  no match while lists exist → ``not_in_repository``.
* **rpm** — signing key id → installed ``gpg-pubkey`` / ``/etc/pki/rpm-gpg`` keys
  → vendor and the ``*.repo`` files that reference the key; ``unsigned`` packages;
  enabled third-party and ``gpgcheck=0`` repositories.
* **apk** — ``/etc/apk/repositories`` hosts, non-distro keys and the installed
  ``C:`` identity checksum versus cached ``APKINDEX`` files.
* **pacman** — ``/etc/pacman.conf`` repositories, ``Unknown Packager`` local builds
  and membership in the ``/var/lib/pacman/sync/*.db`` databases.

Everything is read through :class:`~startup_sbom.rootfs.RootFS` with bounded,
streaming reads; malformed input is skipped, never fatal.
"""

from __future__ import annotations

import base64
import bz2
import configparser
import contextlib
import gzip
import hashlib
import importlib
import io
import lzma
import posixpath
import re
import struct
import tarfile
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import BinaryIO, cast
from urllib.parse import unquote, urlsplit

from startup_sbom.context import ScanContext
from startup_sbom.errors import RootFSError
from startup_sbom.models import OSInfo, Package, PackageType
from startup_sbom.pkgdb.base import PackageRecord

# --------------------------------------------------------------------------- flags
THIRD_PARTY = "third_party_repo"
INSECURE_REPO = "insecure_repository"
UNSIGNED = "unsigned"
LOCAL_BUILD = "local_build"
NOT_IN_REPO = "not_in_repository"
VERSION_MISMATCH = "repo_version_mismatch"
CHECKSUM_MISMATCH = "repo_checksum_mismatch"
UNKNOWN_KEY = "unknown_signing_key"

#: Compressed index files larger than this are skipped.
MAX_INDEX_BYTES = 256 * 1024 * 1024
#: Decompressed bytes read from any one index before giving up (bomb guard).
MAX_DECOMPRESSED_BYTES = 768 * 1024 * 1024
#: Maximum number of index/list files considered per package manager.
MAX_INDEX_FILES = 256
#: Maximum tar members inspected in one pacman sync db / APKINDEX archive.
MAX_TAR_MEMBERS = 400_000
CONFIG_READ_LIMIT = 2 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_APKINDEX_BYTES = 64 * 1024 * 1024


# --------------------------------------------------------------------------- distro trust
@dataclass(frozen=True, slots=True)
class DistroTrust:
    """What counts as *official* for a distribution."""

    name: str  # vendor display name, e.g. "Debian"
    hosts: tuple[str, ...] = ()  # official repository host suffixes
    origins: tuple[str, ...] = ()  # apt Release ``Origin`` prefixes (lower case)
    domains: tuple[str, ...] = ()  # e-mail domains of official keys / maintainers
    vendors: tuple[str, ...] = ()  # rpm VENDOR prefixes (lower case)
    repos: tuple[str, ...] = ()  # official pacman repository names
    apk_keys: tuple[str, ...] = ()  # official apk key file name prefixes


_DEBIAN = DistroTrust(
    "Debian",
    hosts=("debian.org",),
    origins=("debian",),
    domains=("debian.org", "alioth.debian.org", "lists.debian.org", "tracker.debian.org"),
)
_UBUNTU = DistroTrust(
    "Ubuntu",
    hosts=("ubuntu.com", "canonical.com"),
    origins=("ubuntu", "canonical"),
    domains=("ubuntu.com", "canonical.com", "lists.ubuntu.com", "lists.canonical.com"),
)
_ARCH_REPOS = (
    "core",
    "extra",
    "multilib",
    "community",
    "testing",
    "community-testing",
    "core-testing",
    "extra-testing",
    "multilib-testing",
    "staging",
    "core-staging",
    "extra-staging",
    "multilib-staging",
    "gnome-unstable",
    "kde-unstable",
)
_RHEL_DOMAINS = ("redhat.com", "fedoraproject.org", "centos.org")

DISTRO_TRUST: dict[str, DistroTrust] = {
    "debian": _DEBIAN,
    "ubuntu": _UBUNTU,
    "kali": DistroTrust(
        "Kali", hosts=("kali.org", "kali.download"), origins=("kali",), domains=("kali.org",)
    ),
    "raspbian": DistroTrust(
        "Raspberry Pi",
        hosts=("raspbian.org", "raspberrypi.org", "raspberrypi.com", "debian.org"),
        origins=("raspbian", "raspberry pi", "debian"),
        domains=("raspbian.org", "raspberrypi.org", "raspberrypi.com", "debian.org"),
    ),
    "devuan": DistroTrust(
        "Devuan", hosts=("devuan.org", "devuan.dev"), origins=("devuan",), domains=("devuan.org",)
    ),
    "linuxmint": DistroTrust(
        "Linux Mint",
        hosts=("linuxmint.com", "ubuntu.com", "canonical.com"),
        origins=("linuxmint", "ubuntu", "canonical"),
        domains=("linuxmint.com", *_UBUNTU.domains),
    ),
    "fedora": DistroTrust(
        "Fedora Project",
        hosts=("fedoraproject.org",),
        domains=("fedoraproject.org",),
        vendors=("fedora project",),
    ),
    "rhel": DistroTrust(
        "Red Hat",
        hosts=("redhat.com", "redhat.io"),
        domains=_RHEL_DOMAINS,
        vendors=("red hat",),
    ),
    "centos": DistroTrust(
        "CentOS",
        hosts=("centos.org",),
        domains=_RHEL_DOMAINS,
        vendors=("centos", "red hat"),
    ),
    "rocky": DistroTrust(
        "Rocky Linux",
        hosts=("rockylinux.org",),
        domains=("rockylinux.org", "redhat.com"),
        vendors=("rocky", "red hat"),
    ),
    "almalinux": DistroTrust(
        "AlmaLinux",
        hosts=("almalinux.org",),
        domains=("almalinux.org", "redhat.com"),
        vendors=("almalinux", "red hat"),
    ),
    "ol": DistroTrust(
        "Oracle",
        hosts=("oracle.com",),
        domains=("oracle.com",),
        vendors=("oracle",),
    ),
    "amzn": DistroTrust(
        "Amazon Linux",
        hosts=("amazonlinux.com", "amazonaws.com", "amazon.com"),
        domains=("amazon.com", "amazonaws.com"),
        vendors=("amazon",),
    ),
    "opensuse-leap": DistroTrust(
        "openSUSE",
        hosts=("opensuse.org", "suse.com"),
        domains=("opensuse.org", "suse.com", "suse.de"),
        vendors=("opensuse", "suse"),
    ),
    "opensuse-tumbleweed": DistroTrust(
        "openSUSE",
        hosts=("opensuse.org",),
        domains=("opensuse.org", "suse.com", "suse.de"),
        vendors=("opensuse", "suse"),
    ),
    "sles": DistroTrust(
        "SUSE",
        hosts=("suse.com", "suse.de"),
        domains=("suse.com", "suse.de"),
        vendors=("suse",),
    ),
    "alpine": DistroTrust(
        "Alpine Linux",
        hosts=("alpinelinux.org",),
        domains=("alpinelinux.org",),
        apk_keys=("alpine-devel@lists.alpinelinux.org",),
    ),
    "wolfi": DistroTrust(
        "Wolfi",
        hosts=("wolfi.dev", "cgr.dev"),
        domains=("wolfi.dev", "chainguard.dev"),
        apk_keys=("wolfi-signing", "chainguard"),
    ),
    "chainguard": DistroTrust(
        "Chainguard",
        hosts=("cgr.dev", "wolfi.dev"),
        domains=("chainguard.dev", "wolfi.dev"),
        apk_keys=("chainguard", "wolfi-signing"),
    ),
    "arch": DistroTrust(
        "Arch Linux", domains=("archlinux.org",), hosts=("archlinux.org",), repos=_ARCH_REPOS
    ),
    "manjaro": DistroTrust(
        "Manjaro", domains=("manjaro.org",), hosts=("manjaro.org",), repos=_ARCH_REPOS
    ),
    "endeavouros": DistroTrust(
        "EndeavourOS",
        domains=("archlinux.org", "endeavouros.com"),
        hosts=("archlinux.org", "endeavouros.com"),
        repos=(*_ARCH_REPOS, "endeavouros"),
    ),
}
DISTRO_TRUST["centos-stream"] = DISTRO_TRUST["centos"]
DISTRO_TRUST["sles_sap"] = DISTRO_TRUST["sles"]
DISTRO_TRUST["opensuse"] = DISTRO_TRUST["opensuse-leap"]

_FAMILY_FALLBACK = {
    "debian": "debian",
    "rhel": "rhel",
    "fedora": "fedora",
    "suse": "opensuse-leap",
    "alpine": "alpine",
    "arch": "arch",
}


def distro_trust(os_info: OSInfo) -> DistroTrust | None:
    """Return the trust profile for ``os_info`` (``ID`` first, then ``ID_LIKE``/family)."""
    for ident in (os_info.id, *os_info.id_like):
        trust = DISTRO_TRUST.get((ident or "").strip().lower())
        if trust is not None:
            return trust
    fam = _FAMILY_FALLBACK.get((os_info.family or "").lower())
    return DISTRO_TRUST.get(fam) if fam else None


def host_matches(host: str | None, suffixes: Iterable[str]) -> bool:
    """``True`` if ``host`` equals or is a sub-domain of one of ``suffixes``."""
    if not host:
        return False
    h = host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in suffixes)


def email_domain(text: str | None) -> str | None:
    """Domain of the first e-mail address in ``text`` (``"A <a@b.org>"`` → ``"b.org"``)."""
    if not text:
        return None
    m = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", text)
    return m.group(1).lower() if m else None


# --------------------------------------------------------------------------- results
@dataclass(slots=True)
class Repository:
    """A configured (or index-derived) package repository."""

    id: str  # stable label, e.g. "deb.debian.org/debian bookworm/main"
    manager: str  # apt | rpm | apk | pacman
    url: str | None = None
    host: str | None = None
    enabled: bool = True
    signed: bool | None = None  # False: signature verification disabled
    official: bool | None = None  # None: cannot be determined
    origin: str | None = None  # apt Release Origin, repo display name, ...
    source_file: str | None = None
    evidence: list[str] = field(default_factory=list)

    @property
    def third_party(self) -> bool:
        return self.official is False


@dataclass(slots=True)
class SigningKey:
    """An OpenPGP key trusted by the package manager."""

    key_id: str  # lower-case hex (16 digits when known, 8 for legacy short ids)
    fingerprint: str | None = None
    uid: str | None = None
    source: str = ""
    official: bool | None = None


@dataclass(slots=True)
class PackageProvenance:
    """Repository match and provenance flags of one installed package."""

    repository: str | None = None
    flags: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)
    third_party: set[str] = field(default_factory=set)  # labels of third-party origins


@dataclass(slots=True)
class RepoAnalysis:
    """Outcome of :func:`analyze_repositories`."""

    trust: DistroTrust | None = None
    repositories: dict[str, Repository] = field(default_factory=dict)
    packages: dict[str, PackageProvenance] = field(default_factory=dict)
    keys: dict[str, SigningKey] = field(default_factory=dict)
    third_party_keys: list[SigningKey] = field(default_factory=list)

    def prov(self, package_id: str) -> PackageProvenance:
        p = self.packages.get(package_id)
        if p is None:
            p = self.packages[package_id] = PackageProvenance()
        return p

    def add_repo(self, repo: Repository) -> Repository:
        existing = self.repositories.get(repo.id)
        if existing is None:
            self.repositories[repo.id] = repo
            return repo
        if existing.official is None or (
            existing.official is False and repo.official is True and repo.origin
        ):
            existing.official = repo.official
        existing.evidence.extend(e for e in repo.evidence if e not in existing.evidence)
        if existing.signed is None:
            existing.signed = repo.signed
        existing.origin = existing.origin or repo.origin
        existing.url = existing.url or repo.url
        existing.host = existing.host or repo.host
        existing.source_file = existing.source_file or repo.source_file
        return existing

    def apply(self, packages: Iterable[Package]) -> None:
        """Write results into ``packages`` in place.

        ``repository`` is only set when the package reader left it empty;
        ``provenance_flags`` is merged and kept sorted.
        """
        for pkg in packages:
            prov = self.packages.get(pkg.id)
            if prov is None:
                continue
            if prov.repository and not pkg.repository:
                pkg.repository = prov.repository
            if prov.flags:
                pkg.provenance_flags = sorted(set(pkg.provenance_flags) | prov.flags)


def analyze_repositories(
    ctx: ScanContext,
    packages: Iterable[Package],
    records: Iterable[PackageRecord] = (),
) -> RepoAnalysis:
    """Infer repository provenance for every OS package in ``packages``."""
    del records  # reserved: per-file data is not needed for repository matching
    pkgs = list(packages)
    out = RepoAnalysis(trust=distro_trust(ctx.os))
    if out.trust is None and any(
        p.type in (PackageType.DEB, PackageType.RPM, PackageType.APK, PackageType.ALPM)
        for p in pkgs
    ):
        ctx.limit(
            f"distribution {ctx.os.id!r} not recognised; third-party repository detection "
            "is disabled"
        )
    by_type: dict[PackageType, list[Package]] = defaultdict(list)
    for p in pkgs:
        by_type[p.type].append(p)
    handlers = (
        (PackageType.DEB, _apt),
        (PackageType.RPM, _rpm),
        (PackageType.APK, _apk),
        (PackageType.ALPM, _pacman),
    )
    for ptype, handler in handlers:
        if by_type.get(ptype):
            try:
                handler(ctx, by_type[ptype], out, pkgs)
            except (RootFSError, OSError, ValueError, EOFError, struct.error) as exc:
                ctx.warn(f"supply chain: {ptype.value} repository analysis failed: {exc}")
    return out


# --------------------------------------------------------------------------- streaming io
class _LimitExceededError(Exception):
    pass


class _CappedReader(io.RawIOBase):
    """Read-through wrapper that raises once ``limit`` bytes were consumed."""

    def __init__(self, inner: BinaryIO, limit: int, closers: tuple[BinaryIO, ...] = ()) -> None:
        super().__init__()
        self._inner = inner
        self._left = limit
        self._closers = closers or (inner,)

    def close(self) -> None:
        if not self.closed:
            for c in self._closers:
                with contextlib.suppress(OSError):
                    c.close()
        super().close()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: memoryview | bytearray) -> int:  # type: ignore[override]
        want = len(buffer)
        data = self._inner.read(want)
        self._left -= len(data)
        if self._left < 0:
            raise _LimitExceededError
        buffer[: len(data)] = data
        return len(data)


_MAGICS = (
    (b"\x1f\x8b", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x04\x22\x4d\x18", "lz4"),
)


def _sniff(head: bytes) -> str:
    for magic, name in _MAGICS:
        if head.startswith(magic):
            return name
    return "plain"


def _zstd_reader(raw: BinaryIO) -> BinaryIO | None:
    for modname in ("compression.zstd", "backports.zstd"):
        try:
            mod = importlib.import_module(modname)
        except ImportError:
            continue
        return cast("BinaryIO", mod.ZstdFile(raw))
    return None


def _open_decompressed(ctx: ScanContext, path: str) -> tuple[BinaryIO | None, str]:
    """Open ``path`` and return a capped, decompressing binary stream and its format.

    ``None`` is returned for unsupported formats (lz4, zstd without a module) and
    for files that are missing, non-regular or larger than :data:`MAX_INDEX_BYTES`.
    """
    st = ctx.fs.try_stat(path)
    if st is None or not st.is_file or st.size > MAX_INDEX_BYTES:
        return None, "skipped"
    try:
        kind = _sniff(ctx.fs.read_head(path, 8))
        if kind == "lz4":
            from startup_sbom.lz4frame import LZ4Error, decompress

            try:
                data = decompress(ctx.fs.read_bytes(path, MAX_INDEX_BYTES), MAX_DECOMPRESSED_BYTES)
            except LZ4Error:
                return None, kind
            return cast("BinaryIO", io.BytesIO(data)), kind
        raw = ctx.fs.open(path)
    except (RootFSError, OSError):
        return None, "unreadable"
    stream: BinaryIO | None
    if kind == "gzip":
        stream = cast("BinaryIO", gzip.GzipFile(fileobj=raw))
    elif kind == "xz":
        stream = cast("BinaryIO", lzma.LZMAFile(raw))  # noqa: SIM115 - closed via _CappedReader
    elif kind == "bzip2":
        stream = cast("BinaryIO", bz2.BZ2File(raw))
    elif kind == "zstd":
        stream = _zstd_reader(raw)
        if stream is None:
            raw.close()
            return None, kind
    else:
        stream = raw
    closers = (stream, raw) if stream is not raw else (raw,)
    capped = io.BufferedReader(_CappedReader(stream, MAX_DECOMPRESSED_BYTES, closers), 1 << 16)
    return cast("BinaryIO", capped), kind


def _lines(stream: BinaryIO) -> Iterator[str]:
    """Decoded lines, each read with a length cap (over-long lines are split)."""
    while True:
        raw = stream.readline(MAX_LINE_BYTES)
        if not raw:
            return
        yield raw.decode("utf-8", "replace").rstrip("\r\n")


def _iter_stanzas(stream: BinaryIO, keys: frozenset[str]) -> Iterator[dict[str, str]]:
    """Yield RFC-822 stanzas (only ``keys`` fields, first line of each) from a stream."""
    cur: dict[str, str] = {}
    for line in _lines(stream):
        if not line.strip():
            if cur:
                yield cur
                cur = {}
            continue
        if line[0] in " \t":
            continue
        key, sep, value = line.partition(":")
        if sep and key in keys:
            cur[key] = value.strip()
    if cur:
        yield cur


def _read_config(ctx: ScanContext, path: str) -> str | None:
    return ctx.fs.try_read_text(path, CONFIG_READ_LIMIT)


def _strip_scheme(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    if parts.scheme in ("file", "copy", "cdrom") or not host:
        return url.split("://", 1)[-1].rstrip("/")
    return f"{host}{port}{parts.path}".rstrip("/")


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return None
    if not host or "$" in host:
        return None
    return host.lower()


def _official_host(host: str | None, trust: DistroTrust | None) -> bool | None:
    if trust is None or not host:
        return None
    return host_matches(host, trust.hosts)


# --------------------------------------------------------------------------- apt
_APT_LISTS = "/var/lib/apt/lists"
_APT_QUOTE = set('\\|{}[]<>"^~_=!@#$%^&*')
_PKG_KEYS = frozenset({"Package", "Version", "Architecture"})
_RELEASE_KEYS = ("Origin", "Label", "Suite", "Codename")


@dataclass(slots=True)
class _AptSource:
    uri: str
    suites: list[str]
    components: list[str]
    archs: list[str]
    trusted: bool
    signed_by: str | None
    enabled: bool
    file: str


def apt_uri_to_filename(uri: str) -> str:
    """Mangle a URI the way apt names files in ``/var/lib/apt/lists``."""
    body = uri.split("://", 1)[-1]
    if "@" in body.split("/", 1)[0]:
        body = body.split("@", 1)[1]
    quoted = "".join(
        f"%{ord(c):02x}" if c in _APT_QUOTE or ord(c) <= 0x20 or ord(c) >= 0x7F else c for c in body
    )
    return quoted.replace("/", "_")


def _apt_repo_id(uri: str, suite: str, component: str | None) -> str:
    base = _strip_scheme(uri)
    if suite.endswith("/") or not component:
        return f"{base} {suite.rstrip('/') or '.'}"
    return f"{base} {suite}/{component}"


def _parse_one_line_sources(text: str, path: str) -> list[_AptSource]:
    out: list[_AptSource] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line.startswith("deb ") and not line.startswith("deb\t"):
            continue
        rest = line[3:].strip()
        opts: dict[str, str] = {}
        if rest.startswith("["):
            end = rest.find("]")
            if end < 0:
                continue
            for tok in rest[1:end].split():
                k, _, v = tok.partition("=")
                opts[k.strip().lower()] = v.strip()
            rest = rest[end + 1 :].strip()
        parts = rest.split()
        if len(parts) < 2:
            continue
        out.append(
            _AptSource(
                uri=parts[0],
                suites=[parts[1]],
                components=parts[2:],
                archs=[a for a in opts.get("arch", "").split(",") if a],
                trusted=opts.get("trusted", "").lower() == "yes"
                or opts.get("allow-insecure", "").lower() == "yes",
                signed_by=opts.get("signed-by") or None,
                enabled=True,
                file=path,
            )
        )
    return out


def _parse_deb822_sources(text: str, path: str) -> list[_AptSource]:
    out: list[_AptSource] = []
    for block in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        key = ""
        for raw in block.splitlines():
            if raw.startswith("#"):
                continue
            if raw[:1] in (" ", "\t") and key:
                fields[key] += "\n" + raw.strip()
                continue
            k, sep, v = raw.partition(":")
            if not sep:
                continue
            key = k.strip().lower()
            fields[key] = v.strip()
        if "deb" not in fields.get("types", "").split():
            continue
        signed_by = fields.get("signed-by", "").strip()
        if "BEGIN PGP" in signed_by:
            signed_by = "inline key"
        out.extend(
            _AptSource(
                uri=uri,
                suites=fields.get("suites", "").split(),
                components=fields.get("components", "").split(),
                archs=fields.get("architectures", "").split(),
                trusted=fields.get("trusted", "").lower() == "yes"
                or fields.get("allow-insecure", "").lower() == "yes",
                signed_by=signed_by.splitlines()[0] if signed_by else None,
                enabled=fields.get("enabled", "yes").lower() not in ("no", "false", "0"),
                file=path,
            )
            for uri in fields.get("uris", "").split()
        )
    return out


def _apt_sources(ctx: ScanContext) -> list[_AptSource]:
    files = ["/etc/apt/sources.list"]
    files += ctx.fs.glob_dir("/etc/apt/sources.list.d", ".list")
    files += ctx.fs.glob_dir("/etc/apt/sources.list.d", ".sources")
    out: list[_AptSource] = []
    for path in files[:MAX_INDEX_FILES]:
        text = _read_config(ctx, path)
        if text is None:
            continue
        if path.endswith(".sources"):
            out.extend(_parse_deb822_sources(text, path))
        else:
            out.extend(_parse_one_line_sources(text, path))
    return out


def _parse_release(ctx: ScanContext, path: str) -> dict[str, str]:
    try:
        head = ctx.fs.read_head(path, 64 * 1024).decode("utf-8", "replace")
    except (RootFSError, OSError):
        return {}
    out: dict[str, str] = {}
    for line in head.splitlines():
        if line.startswith((" ", "MD5Sum", "SHA1", "SHA256", "SHA512")):
            if out:
                break
            continue
        k, sep, v = line.partition(":")
        if sep and k in _RELEASE_KEYS and k not in out:
            out[k] = v.strip()
    return out


_LIST_RE = re.compile(r"^(?P<prefix>.+?)_dists_(?P<rest>.+)_binary-(?P<arch>[^_]+)_Packages$")
_COMPRESSION_EXTS = (".gz", ".xz", ".bz2", ".lzma", ".zst", ".lz4")


def _apt_list_base(name: str) -> str | None:
    for ext in _COMPRESSION_EXTS:
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    return name if name.endswith("Packages") else None


def _apt_list_repo(
    ctx: ScanContext,
    base: str,
    sources: list[_AptSource],
    out: RepoAnalysis,
) -> tuple[Repository, str | None]:
    """Map a list file base name to a :class:`Repository` and its architecture."""
    trust = out.trust
    m = _LIST_RE.match(base)
    if m is None:  # flat repository: "<mangled uri+dir>_Packages"
        prefix = base[: -len("_Packages")] if base.endswith("_Packages") else base
        src = next(
            (s for s in sources if prefix.startswith(apt_uri_to_filename(s.uri.rstrip("/")))),
            None,
        )
        if src is not None:
            repo_id = _apt_repo_id(src.uri, src.suites[0] if src.suites else "./", None)
            url: str | None = src.uri
        else:
            repo_id = unquote(prefix.replace("_", "/"))
            url = None
        arch = None
        release: dict[str, str] = {}
        rel_prefix = prefix
    else:
        prefix, rest, arch = m.group("prefix"), m.group("rest"), m.group("arch")
        src = None
        repo_id = ""
        url = None
        suite_m = rest
        for s in sources:
            if apt_uri_to_filename(s.uri.rstrip("/")) != prefix:
                continue
            for suite in s.suites:
                sm = apt_uri_to_filename(suite)
                if rest.startswith(sm + "_"):
                    comp = unquote(rest[len(sm) + 1 :].replace("_", "/"))
                    src, repo_id, url, suite_m = s, _apt_repo_id(s.uri, suite, comp), s.uri, sm
                    break
            if src is not None:
                break
        if src is None:
            suite, _, comp = rest.partition("_")
            uri_guess = unquote(prefix.replace("_", "/"))
            repo_id = f"{uri_guess} {unquote(suite)}/{unquote(comp.replace('_', '/'))}"
            suite_m = suite
        release = {}
        rel_prefix = f"{prefix}_dists_{suite_m}"
    for rel_name in ("_InRelease", "_Release"):
        rel_path = posixpath.join(_APT_LISTS, rel_prefix + rel_name)
        if ctx.fs.is_file(rel_path):
            release = _parse_release(ctx, rel_path)
            break
    host_token = prefix.split("_", 1)[0]
    host = _host("http://" + unquote(host_token)) if host_token else None
    official = _official_host(host, trust)
    origin = release.get("Origin")
    evidence = [f"index {base}"]
    if official is False and origin and trust and origin.lower().startswith(trust.origins):
        official = True  # a mirror of the distribution archive
        evidence.append(f"non-distro host {host} serves Release Origin {origin!r} (mirror)")
    repo = Repository(
        id=repo_id,
        manager="apt",
        url=url,
        host=host,
        enabled=src.enabled if src is not None else True,
        signed=(not src.trusted) if src is not None else None,
        official=official,
        origin=origin,
        source_file=src.file if src is not None else None,
        evidence=evidence,
    )
    if src is None:
        repo.evidence.append("no matching entry in sources.list (stale list?)")
    return out.add_repo(repo), arch


def _read_packages_index(
    ctx: ScanContext, path: str, wanted: set[str]
) -> tuple[dict[str, set[tuple[str, str]]] | None, str]:
    stream, kind = _open_decompressed(ctx, path)
    if stream is None:
        return None, kind
    found: dict[str, set[tuple[str, str]]] = defaultdict(set)
    try:
        with stream:
            for st in _iter_stanzas(stream, _PKG_KEYS):
                name = st.get("Package")
                if name in wanted:
                    found[name].add((st.get("Version", ""), st.get("Architecture", "")))
    except _LimitExceededError:
        ctx.limit(f"apt list {path} exceeds {MAX_DECOMPRESSED_BYTES} bytes; truncated")
    except (OSError, EOFError, lzma.LZMAError, ValueError) as exc:
        ctx.warn(f"could not read apt list {path}: {exc}")
    return found, kind


def _arch_ok(pkg_arch: str | None, other: str | None) -> bool:
    if not pkg_arch or not other:
        return True
    return pkg_arch == other or "all" in (pkg_arch, other)


def _apt(ctx: ScanContext, pkgs: list[Package], out: RepoAnalysis, _all: list[Package]) -> None:
    sources = _apt_sources(ctx)
    trust = out.trust
    for s in sources:
        comps: list[str | None] = list(s.components) or [None]
        for suite in s.suites or ["./"]:
            for comp in comps:
                out.add_repo(
                    Repository(
                        id=_apt_repo_id(s.uri, suite, comp),
                        manager="apt",
                        url=s.uri,
                        host=_host(s.uri),
                        enabled=s.enabled,
                        signed=not s.trusted,
                        official=_official_host(_host(s.uri), trust),
                        source_file=s.file,
                        evidence=[f"configured in {s.file}"]
                        + ([f"signed-by {s.signed_by}"] if s.signed_by else []),
                    )
                )
    names = [n for n in ctx.fs.safe_listdir(_APT_LISTS) if _apt_list_base(n)]
    if len(names) > MAX_INDEX_FILES:
        ctx.limit(f"only the first {MAX_INDEX_FILES} apt lists were analysed")
        names = names[:MAX_INDEX_FILES]
    if not names:
        ctx.limit(
            f"apt package lists absent ({_APT_LISTS}); repository provenance of "
            f"{len(pkgs)} dpkg packages is unknown"
        )
        return
    wanted = {p.name for p in pkgs}
    indexes: list[tuple[Repository, str | None, dict[str, set[tuple[str, str]]]]] = []
    skipped: list[str] = []
    for name in names:
        base = _apt_list_base(name) or name
        found, kind = _read_packages_index(ctx, posixpath.join(_APT_LISTS, name), wanted)
        if found is None:
            skipped.append(f"{name} ({kind})")
            continue
        repo, arch = _apt_list_repo(ctx, base, sources, out)
        indexes.append((repo, arch, found))
    if skipped:
        ctx.limit(
            "apt lists not readable with the standard library were skipped "
            f"(e.g. lz4): {', '.join(skipped[:5])}" + (" ..." if len(skipped) > 5 else "")
        )
    if not indexes:
        return
    list_archs = {a for _, a, _ in indexes if a}
    for pkg in pkgs:
        prov = out.prov(pkg.id)
        exact: list[Repository] = []
        other_versions: list[tuple[Repository, str]] = []
        for repo, arch, found in indexes:
            if not _arch_ok(pkg.arch, arch):
                continue
            for ver, parch in sorted(found.get(pkg.name, ())):
                if not _arch_ok(pkg.arch, parch):
                    continue
                if ver == pkg.version:
                    exact.append(repo)
                else:
                    other_versions.append((repo, ver))
        exact = sorted({r.id: r for r in exact}.values(), key=lambda r: (r.third_party, r.id))
        if exact:
            prov.repository = exact[0].id
            prov.evidence.append(
                f"{pkg.name} {pkg.version} listed in " + ", ".join(r.id for r in exact[:5])
            )
            if all(r.third_party for r in exact):
                prov.flags.add(THIRD_PARTY)
                prov.third_party.update(r.id for r in exact)
        elif other_versions:
            prov.flags.add(VERSION_MISMATCH)
            prov.evidence.extend(
                f"repository {r.id} has version {v}" for r, v in other_versions[:5]
            )
            repos = {r.id: r for r, _ in other_versions}
            if all(r.third_party for r in repos.values()):
                prov.flags.add(THIRD_PARTY)
                prov.third_party.update(repos)
        elif pkg.arch in (None, "all") or pkg.arch in list_archs:
            prov.flags.add(NOT_IN_REPO)
            prov.evidence.append(f"{pkg.name} not found in any of {len(indexes)} apt lists")


# --------------------------------------------------------------------------- OpenPGP keys
def _armored_to_binary(text: str) -> bytes:
    out: list[str] = []
    inside = False
    in_headers = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("-----BEGIN PGP PUBLIC KEY BLOCK"):
            inside, in_headers, out = True, True, []
            continue
        if not inside:
            continue
        if s.startswith("-----END"):
            break
        if in_headers:
            if not s:
                in_headers = False
            elif ":" not in s:
                in_headers = False
                out.append(s)
            continue
        if s.startswith("="):
            continue
        out.append(s)
    try:
        return base64.b64decode("".join(out), validate=False)
    except ValueError:
        return b""


def _pgp_packets(data: bytes) -> Iterator[tuple[int, bytes]]:
    i = 0
    n = len(data)
    count = 0
    while i < n and count < 10_000:
        count += 1
        t = data[i]
        if not t & 0x80:
            return
        if t & 0x40:
            tag = t & 0x3F
            if i + 1 >= n:
                return
            first = data[i + 1]
            if first < 192:
                length, hl = first, 2
            elif first < 224:
                if i + 2 >= n:
                    return
                length, hl = ((first - 192) << 8) + data[i + 2] + 192, 3
            elif first == 255:
                if i + 6 > n:
                    return
                length, hl = struct.unpack(">I", data[i + 2 : i + 6])[0], 6
            else:  # partial body lengths never occur in key material
                return
        else:
            tag = (t >> 2) & 0xF
            lt = t & 3
            if lt == 3:
                return
            size = {0: 1, 1: 2, 2: 4}[lt]
            length, hl = int.from_bytes(data[i + 1 : i + 1 + size], "big"), 1 + size
        body = data[i + hl : i + hl + length]
        if len(body) < length:
            return
        yield tag, body
        i += hl + length


def parse_pgp_keys(data: bytes, source: str) -> list[SigningKey]:
    """Extract primary/sub keys with user ids from armored or binary OpenPGP data."""
    if b"-----BEGIN PGP" in data[:4096] or data[:1] == b"-":
        data = _armored_to_binary(data.decode("ascii", "replace"))
    keys: list[SigningKey] = []
    current: list[SigningKey] = []
    for tag, body in _pgp_packets(data):
        if tag == 6:  # primary public key
            current = []
        if tag in (6, 14) and body:
            version = body[0]
            if version == 4:
                # SHA-1 is mandated by the OpenPGP v4 fingerprint format (RFC 4880 12.2).
                fp = hashlib.sha1(  # nosemgrep
                    b"\x99" + struct.pack(">H", len(body)) + body, usedforsecurity=False
                ).hexdigest()
                key = SigningKey(key_id=fp[-16:], fingerprint=fp, source=source)
            elif version in (5, 6):
                fp = hashlib.sha256(
                    (b"\x9a" if version == 5 else b"\x9b") + struct.pack(">I", len(body)) + body
                ).hexdigest()
                key = SigningKey(key_id=fp[:16], fingerprint=fp, source=source)
            elif version in (2, 3) and len(body) > 10:
                # v3 RSA: key id = low 64 bits of the modulus
                mlen_bits = int.from_bytes(body[8:10], "big")
                modulus = body[10 : 10 + (mlen_bits + 7) // 8]
                key = SigningKey(key_id=modulus[-8:].hex(), source=source)
            else:
                continue
            if tag == 14 and current:
                key.uid = current[0].uid
            keys.append(key)
            current.append(key)
        elif tag == 13 and current:
            uid = body.decode("utf-8", "replace").strip()
            for k in current:
                if k.uid is None:
                    k.uid = uid
    return keys


def normalize_key_id(value: str | None) -> str | None:
    """Lower-case hex key id/fingerprint without ``0x`` or spaces, or ``None``."""
    if not value:
        return None
    v = re.sub(r"[\s:]", "", value).lower()
    v = v.removeprefix("0x")
    return v if re.fullmatch(r"[0-9a-f]{8,64}", v) else None


def find_key(keys: dict[str, SigningKey], key_id: str) -> SigningKey | None:
    """Look up ``key_id`` (short id, long id or fingerprint) in ``keys``."""
    hit = keys.get(key_id)
    if hit is not None:
        return hit
    for k in sorted(keys):
        info = keys[k]
        fp = info.fingerprint or info.key_id
        for cand in (fp, info.key_id):
            if len(key_id) >= 8 and (cand.endswith(key_id) or key_id.endswith(cand)):
                return info
    return None


def _key_official(key: SigningKey, trust: DistroTrust | None) -> bool | None:
    if trust is None:
        return None
    dom = email_domain(key.uid)
    if dom is None:
        return None
    return host_matches(dom, trust.domains)


# --------------------------------------------------------------------------- rpm
_RPM_KEY_DIRS = ("/etc/pki/rpm-gpg", "/usr/share/distribution-gpg-keys")


def _rpm_keys(ctx: ScanContext, all_pkgs: list[Package], out: RepoAnalysis) -> dict[str, str]:
    """Collect trusted rpm keys; return ``key file path → key id`` for repo mapping."""
    file_keys: dict[str, str] = {}
    for p in all_pkgs:
        if p.type is not PackageType.RPM or p.name != "gpg-pubkey":
            continue
        kid = normalize_key_id(p.version.split("-", 1)[0])
        if kid is None:
            continue
        uid = (p.summary or "").strip()
        uid = re.sub(r"^gpg\((.*)\)$", r"\1", uid).removesuffix(" public key").strip()
        out.keys[kid] = SigningKey(
            key_id=kid[-16:] if len(kid) > 16 else kid,
            fingerprint=kid if len(kid) >= 32 else None,
            uid=uid or None,
            source=f"rpmdb gpg-pubkey-{p.version}",
        )
    for d in _RPM_KEY_DIRS:
        for path in ctx.fs.glob_dir(d)[:MAX_INDEX_FILES]:
            st = ctx.fs.try_stat(path)
            if st is None or not st.is_file or st.size > CONFIG_READ_LIMIT:
                continue
            try:
                data = ctx.fs.read_bytes(path, CONFIG_READ_LIMIT)
            except (RootFSError, OSError):
                continue
            for parsed in parse_pgp_keys(data, path):
                key = find_key(out.keys, parsed.key_id)
                if key is not None:
                    key.uid = key.uid or parsed.uid
                    key.fingerprint = key.fingerprint or parsed.fingerprint
                    if len(parsed.key_id) > len(key.key_id):
                        key.key_id = parsed.key_id
                else:
                    key = out.keys[parsed.key_id] = parsed
                file_keys.setdefault(path, key.key_id)
                file_keys[f"{path}#{key.key_id}"] = key.key_id
    for key in out.keys.values():
        key.official = _key_official(key, out.trust)
    return file_keys


def _expand_repo_vars(value: str, ctx: ScanContext, archs: Iterable[str]) -> list[str]:
    """Expand ``$releasever``/``$basearch``/``$arch`` in a repo file value (all candidates)."""
    release = (ctx.os.version_id or "").strip()
    out = value.replace("$releasever_major", release.split(".", 1)[0])
    out = out.replace("$releasever", release)
    if "$basearch" not in out and "$arch" not in out:
        return [out]
    return sorted({out.replace("$basearch", a).replace("$arch", a) for a in archs})


def _rpm_repos(
    ctx: ScanContext, out: RepoAnalysis, file_keys: dict[str, str], archs: Iterable[str]
) -> dict[str, set[str]]:
    """Parse yum/dnf/zypper repo files; return ``key id → repo ids`` referencing it."""
    archs = sorted({a for a in archs if a and a != "noarch"} | {"x86_64", "aarch64"})
    key_repos: dict[str, set[str]] = defaultdict(set)
    files = ctx.fs.glob_dir("/etc/yum.repos.d", ".repo") + ctx.fs.glob_dir(
        "/etc/zypp/repos.d", ".repo"
    )
    for path in files[:MAX_INDEX_FILES]:
        text = _read_config(ctx, path)
        if text is None:
            continue
        cp = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            cp.read_string(text, source=path)
        except configparser.Error as exc:
            ctx.warn(f"could not parse {path}: {exc}")
            continue
        for section in cp.sections():
            sec = cp[section]
            urls = (sec.get("baseurl") or "").split()
            url = urls[0] if urls else (sec.get("metalink") or sec.get("mirrorlist") or None)
            host = _host(url)
            enabled = (sec.get("enabled") or "1").strip().lower() in ("1", "yes", "true")
            gpg = sec.get("gpgcheck")
            signed = None if gpg is None else gpg.strip().lower() in ("1", "yes", "true")
            official = _official_host(host, out.trust)
            repo = out.add_repo(
                Repository(
                    id=section.strip(),
                    manager="rpm",
                    url=url,
                    host=host,
                    enabled=enabled,
                    signed=signed,
                    official=official,
                    origin=(sec.get("name") or "").strip() or None,
                    source_file=path,
                    evidence=[f"configured in {path}"],
                )
            )
            for keyref in (sec.get("gpgkey") or "").split():
                if not keyref.startswith("file://"):
                    continue
                for kpath in _expand_repo_vars(posixpath.normpath(keyref[7:]), ctx, archs):
                    for fk, kid in file_keys.items():
                        if fk == kpath or fk.startswith(kpath + "#"):
                            key_repos[kid].add(repo.id)
    return key_repos


def _rpm_vendor_official(vendor: str | None, trust: DistroTrust | None) -> bool | None:
    if not vendor or trust is None or not trust.vendors:
        return None
    return vendor.strip().lower().startswith(trust.vendors)


def _rpm(ctx: ScanContext, pkgs: list[Package], out: RepoAnalysis, all_pkgs: list[Package]) -> None:
    file_keys = _rpm_keys(ctx, all_pkgs, out)
    key_repos = _rpm_repos(ctx, out, file_keys, (p.arch or "" for p in pkgs))
    for key in sorted(out.keys.values(), key=lambda k: k.key_id):
        if key.official is False and key not in out.third_party_keys:
            out.third_party_keys.append(key)
    for pkg in pkgs:
        if pkg.name == "gpg-pubkey":
            continue
        prov = out.prov(pkg.id)
        if pkg.signed is False:
            prov.flags.add(UNSIGNED)
            prov.evidence.append("package header carries no signature")
            if not pkg.vendor and not pkg.source_name:
                prov.flags.add(LOCAL_BUILD)
                prov.evidence.append("unsigned, no VENDOR and no SOURCERPM")
        kid = normalize_key_id(pkg.signing_key)
        if kid:
            info = find_key(out.keys, kid)
            if info is None:
                if out.keys:
                    prov.flags.add(UNKNOWN_KEY)
                    prov.evidence.append(f"signed by key {kid} which is not installed")
            else:
                prov.evidence.append(f"signed by {info.key_id} ({info.uid or 'unknown uid'})")
                repos = sorted(
                    r
                    for r in key_repos.get(info.key_id, ())
                    if out.repositories.get(r) is None or out.repositories[r].enabled
                ) or sorted(key_repos.get(info.key_id, ()))
                if repos:
                    prov.repository = ",".join(repos[:4])
                if info.official is False:
                    prov.flags.add(THIRD_PARTY)
                    prov.third_party.update(repos or [f"signing key {info.uid or info.key_id}"])
        if _rpm_vendor_official(pkg.vendor, out.trust) is False:
            prov.flags.add(THIRD_PARTY)
            prov.third_party.add(f"vendor {pkg.vendor}")
            prov.evidence.append(f"VENDOR {pkg.vendor!r} is not the distribution vendor")


# --------------------------------------------------------------------------- apk
_APK_INSTALLED = "/lib/apk/db/installed"
_APK_CACHE_DIRS = ("/var/cache/apk", "/etc/apk/cache")


def _apk_installed_checksums(ctx: ScanContext) -> dict[tuple[str, str], str]:
    text = ctx.fs.try_read_text(_APK_INSTALLED, 64 * 1024 * 1024)
    out: dict[tuple[str, str], str] = {}
    if not text:
        return out
    cur: dict[str, str] = {}
    for line in [*text.splitlines(), ""]:
        if not line.strip():
            if "P" in cur and "V" in cur and "C" in cur:
                out[(cur["P"], cur["V"])] = cur["C"]
            cur = {}
            continue
        if len(line) > 2 and line[1] == ":" and line[0] in "PVC":
            cur[line[0]] = line[2:].strip()
    return out


def _apk_checksum(pkg: Package, installed: dict[tuple[str, str], str]) -> str | None:
    for key in ("apk:checksum", "checksum", "apk:C", "C"):
        if pkg.properties.get(key):
            return pkg.properties[key]
    return installed.get((pkg.name, pkg.version))


def _parse_apkindex(stream: BinaryIO) -> dict[str, list[tuple[str, str]]]:
    """Return ``name → [(version, checksum)]`` from an APKINDEX stream."""
    out: dict[str, list[tuple[str, str]]] = defaultdict(list)
    cur: dict[str, str] = {}
    for line in [*_lines(stream), ""]:
        if not line.strip():
            if "P" in cur:
                out[cur["P"]].append((cur.get("V", ""), cur.get("C", "")))
            cur = {}
            continue
        if len(line) > 2 and line[1] == ":" and line[0] in "PVC":
            cur[line[0]] = line[2:].strip()
    return out


def _read_apkindex(ctx: ScanContext, path: str) -> dict[str, list[tuple[str, str]]] | None:
    stream, _kind = _open_decompressed(ctx, path)
    if stream is None:
        return None
    try:
        with stream, tarfile.open(fileobj=stream, mode="r|", ignore_zeros=True) as tf:
            for count, member in enumerate(tf):
                if count > MAX_TAR_MEMBERS:
                    break
                if member.isfile() and member.name.lstrip("./") == "APKINDEX":
                    fobj = tf.extractfile(member)
                    if fobj is None:
                        return None
                    return _parse_apkindex(
                        cast("BinaryIO", io.BytesIO(fobj.read(MAX_APKINDEX_BYTES)))
                    )
    except (_LimitExceededError, tarfile.TarError, OSError, EOFError, ValueError) as exc:
        ctx.warn(f"could not read {path}: {exc}")
    return None


def _apk(ctx: ScanContext, pkgs: list[Package], out: RepoAnalysis, _all: list[Package]) -> None:
    trust = out.trust
    repo_urls: list[str] = []
    text = _read_config(ctx, "/etc/apk/repositories") or ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        tag = None
        if line.startswith("@"):
            tag, _, line = line.partition(" ")
            line = line.strip()
        if not line:
            continue
        repo_urls.append(line)
        host = _host(line)
        out.add_repo(
            Repository(
                id=_strip_scheme(line) + (f" ({tag})" if tag else ""),
                manager="apk",
                url=line,
                host=host,
                official=_official_host(host, trust),
                source_file="/etc/apk/repositories",
                evidence=["configured in /etc/apk/repositories"],
            )
        )
    for path in ctx.fs.glob_dir("/etc/apk/keys"):
        name = posixpath.basename(path)
        if trust is not None and trust.apk_keys and not name.startswith(trust.apk_keys):
            out.third_party_keys.append(
                SigningKey(key_id=name, uid=name, source=path, official=False)
            )
    archs = sorted({p.arch for p in pkgs if p.arch}) or ["x86_64"]
    hash_to_repo: dict[str, str] = {}
    for url in repo_urls:
        for arch in archs:
            idx = f"{url.rstrip('/')}/{arch}/APKINDEX.tar.gz".encode()
            for h in (
                # apk names its index cache after the SHA-1 of the URL; not a security use.
                hashlib.sha1(idx, usedforsecurity=False).hexdigest(),  # nosemgrep
                hashlib.sha256(idx).hexdigest(),
            ):
                hash_to_repo[h[:8]] = _strip_scheme(url)
    indexes: list[tuple[str, dict[str, list[tuple[str, str]]]]] = []
    for d in _APK_CACHE_DIRS:
        for path in ctx.fs.glob_dir(d, ".tar.gz")[:MAX_INDEX_FILES]:
            name = posixpath.basename(path)
            if not name.startswith("APKINDEX."):
                continue
            parsed = _read_apkindex(ctx, path)
            if parsed is None:
                continue
            h = name[len("APKINDEX.") : -len(".tar.gz")]
            repo_id = hash_to_repo.get(h[:8], f"apk cache {name}")
            repo = out.repositories.get(repo_id)
            if repo is None:
                repo = out.add_repo(
                    Repository(id=repo_id, manager="apk", evidence=[f"cached index {path}"])
                )
            indexes.append((repo.id, parsed))
    if not indexes:
        ctx.limit(
            "no cached APKINDEX found; apk package checksums could not be matched to a repository"
        )
        return
    installed = _apk_installed_checksums(ctx)
    for pkg in pkgs:
        prov = out.prov(pkg.id)
        csum = _apk_checksum(pkg, installed)
        exact: list[str] = []
        same_version_other_bytes: list[str] = []
        other_versions: list[tuple[str, str]] = []
        for repo_id, parsed in indexes:
            for ver, c in parsed.get(pkg.name, ()):
                if ver == pkg.version:
                    if csum and c and c != csum:
                        same_version_other_bytes.append(repo_id)
                    else:
                        exact.append(repo_id)
                else:
                    other_versions.append((repo_id, ver))
        if exact:
            prov.repository = sorted(set(exact))[0]
            prov.evidence.append("identity checksum matches " + ", ".join(sorted(set(exact))))
            repo = out.repositories.get(prov.repository)
            if repo is not None and repo.third_party:
                prov.flags.add(THIRD_PARTY)
                prov.third_party.add(repo.id)
        elif same_version_other_bytes:
            prov.flags.add(CHECKSUM_MISMATCH)
            prov.evidence.append(
                f"{pkg.name} {pkg.version} in {', '.join(sorted(set(same_version_other_bytes)))}"
                f" has a different identity checksum than the installed one ({csum})"
            )
        elif other_versions:
            prov.flags.add(VERSION_MISMATCH)
            prov.evidence.extend(f"repository {r} has version {v}" for r, v in other_versions[:5])
        else:
            prov.flags.add(NOT_IN_REPO)
            prov.evidence.append(f"{pkg.name} not found in {len(indexes)} cached APKINDEX files")


# --------------------------------------------------------------------------- pacman
_PACMAN_SYNC = "/var/lib/pacman/sync"


def _parse_pacman_conf(ctx: ScanContext, text: str) -> list[tuple[str, list[str], str | None, str]]:
    """Return ``[(repo, servers, siglevel, source)]`` from pacman.conf text."""
    repos: list[tuple[str, list[str], str | None, str]] = []
    global_sig: str | None = None
    section: str | None = None
    servers: list[str] = []
    sig: str | None = None

    def flush() -> None:
        if section and section != "options":
            repos.append((section, list(servers), sig or global_sig, "/etc/pacman.conf"))

    includes_read = 0
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            flush()
            section, servers, sig = line[1:-1].strip(), [], None
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key == "SigLevel":
            if section == "options":
                global_sig = value
            else:
                sig = value
        elif key == "Server":
            servers.append(value)
        elif key == "Include" and section and section != "options" and includes_read < 32:
            includes_read += 1
            inc = _read_config(ctx, value) or ""
            for inc_line in inc.splitlines():
                k2, _, v2 = inc_line.split("#", 1)[0].partition("=")
                if k2.strip() == "Server" and v2.strip():
                    servers.append(v2.strip())
    flush()
    return repos


def _read_sync_db(ctx: ScanContext, path: str) -> dict[str, set[str]] | None:
    stream, kind = _open_decompressed(ctx, path)
    if stream is None:
        if kind in ("lz4", "zstd"):
            ctx.limit(f"pacman sync db {path} is {kind}-compressed and could not be read")
        return None
    out: dict[str, set[str]] = defaultdict(set)
    try:
        with stream, tarfile.open(fileobj=stream, mode="r|", ignore_zeros=True) as tf:
            for count, member in enumerate(tf):
                if count > MAX_TAR_MEMBERS:
                    ctx.limit(f"pacman sync db {path} truncated after {MAX_TAR_MEMBERS} entries")
                    break
                top = member.name.lstrip("./").split("/", 1)[0]
                parts = top.rsplit("-", 2)
                if len(parts) == 3 and parts[0]:
                    out[parts[0]].add(f"{parts[1]}-{parts[2]}")
    except (_LimitExceededError, tarfile.TarError, OSError, EOFError, ValueError) as exc:
        ctx.warn(f"could not read pacman sync db {path}: {exc}")
    return out


def _pacman(ctx: ScanContext, pkgs: list[Package], out: RepoAnalysis, _all: list[Package]) -> None:
    trust = out.trust
    text = _read_config(ctx, "/etc/pacman.conf") or ""
    configured = _parse_pacman_conf(ctx, text)
    for name, servers, sig, source in configured:
        official: bool | None = None
        if trust is not None and trust.repos:
            official = name in trust.repos
        sig_tokens = (sig or "").split()
        signed: bool | None = None
        if sig_tokens:
            signed = not any(t in ("Never", "PackageNever") for t in sig_tokens)
        out.add_repo(
            Repository(
                id=name,
                manager="pacman",
                url=servers[0] if servers else None,
                host=_host(servers[0]) if servers else None,
                signed=signed,
                official=official,
                origin=name,
                source_file=source,
                evidence=[f"[{name}] in {source}"] + ([f"SigLevel = {sig}"] if sig else []),
            )
        )
    db_paths = ctx.fs.glob_dir(_PACMAN_SYNC, ".db")[:MAX_INDEX_FILES]
    indexes: list[tuple[str, dict[str, set[str]]]] = []
    for path in db_paths:
        repo_name = posixpath.basename(path)[: -len(".db")]
        parsed = _read_sync_db(ctx, path)
        if parsed is None:
            continue
        if repo_name not in out.repositories:
            out.add_repo(
                Repository(
                    id=repo_name,
                    manager="pacman",
                    official=(repo_name in trust.repos) if trust and trust.repos else None,
                    origin=repo_name,
                    evidence=[f"sync database {path} (not in pacman.conf)"],
                )
            )
        indexes.append((repo_name, parsed))
    if not indexes:
        ctx.limit("no readable pacman sync databases; repository membership is unknown")
    for pkg in pkgs:
        prov = out.prov(pkg.id)
        if (pkg.packager or "").strip().lower() == "unknown packager":
            prov.flags.add(LOCAL_BUILD)
            prov.evidence.append("%PACKAGER% is 'Unknown Packager' (makepkg default)")
        if not indexes:
            continue
        exact = sorted(r for r, idx in indexes if pkg.version in idx.get(pkg.name, ()))
        others = [(r, v) for r, idx in indexes for v in sorted(idx.get(pkg.name, ()))]
        if exact:
            prov.repository = exact[0]
            repo = out.repositories.get(exact[0])
            if repo is not None and repo.third_party:
                prov.flags.add(THIRD_PARTY)
                prov.third_party.add(repo.id)
        elif others:
            prov.flags.add(VERSION_MISMATCH)
            prov.evidence.extend(f"repository {r} has version {v}" for r, v in others[:5])
            third = [r for r, _ in others if (rr := out.repositories.get(r)) and rr.third_party]
            if third and len(third) == len(others):
                prov.flags.add(THIRD_PARTY)
                prov.third_party.update(third)
        else:
            prov.flags.add(NOT_IN_REPO)
            prov.evidence.append(f"{pkg.name} is not in any sync database (foreign package)")
