"""RPM database discovery and conversion of headers into package records.

The database is located inside the image (``%_dbpath`` macro overrides first,
then the well-known locations), its backend chosen by magic bytes — SQLite,
Berkeley DB hash or NDB — and every header converted into a
:class:`~startup_sbom.pkgdb.base.PackageRecord`.  CBL-Mariner / Azure Linux
distroless images without an rpmdb are read from their container manifest.

``gpg-pubkey`` pseudo-packages are not reported as packages; they map
signature key ids to signer names (``Package.properties["rpm:signer"]``) and
are available through :func:`installed_rpm_keys`.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
import stat as st_mod
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

from startup_sbom.context import ScanContext
from startup_sbom.errors import ParseError, RootFSError
from startup_sbom.models import OSInfo, Package, PackageType
from startup_sbom.pkgdb.base import PackageDatabase, PackageRecord
from startup_sbom.pkgdb.rpm import header as rpmtag
from startup_sbom.pkgdb.rpm.bdb import is_bdb_hash, iter_bdb_blobs
from startup_sbom.pkgdb.rpm.header import Header, HeaderError
from startup_sbom.pkgdb.rpm.ndb import NDB_MAGIC, iter_ndb_blobs
from startup_sbom.pkgdb.rpm.pgp import HASH_ALGOS, PgpSignature, parse_signature
from startup_sbom.pkgdb.rpm.sqlite import SQLITE_MAGIC, iter_sqlite_blobs
from startup_sbom.purls import package_purl
from startup_sbom.rootfs import RootFS

DB_FILES = ("rpmdb.sqlite", "Packages.db", "Packages")
DB_DIRS = ("/usr/lib/sysimage/rpm", "/var/lib/rpm", "/usr/share/rpm")
MANIFEST_PATHS = (
    "/var/lib/rpmmanifest/container-manifest-2",
    "/var/lib/rpmmanifest/container-manifest-1",
)
_MACRO_LIMIT = 1024 * 1024
_MANIFEST_LIMIT = 16 * 1024 * 1024
_DBPATH_RE = re.compile(r"^\s*%_dbpath\s+(\S+)", re.MULTILINE)
_MACRO_EXPAND = {
    "%{_usr}": "/usr",
    "%{_prefix}": "/usr",
    "%{_var}": "/var",
    "%{_localstatedir}": "/var",
    "%{_sharedstatedir}": "/var/lib",
}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_SIG_TAGS = (rpmtag.RSAHEADER, rpmtag.DSAHEADER, rpmtag.SIGPGP, rpmtag.SIGGPG)
_MAX_WARNINGS = 50


@dataclass(frozen=True, slots=True)
class RpmDB:
    """A located rpmdb: in-image canonical path and backend name."""

    path: str
    backend: str  # sqlite | bdb | ndb | manifest


def iso_utc(ts: int | None) -> str | None:
    """Format a unix timestamp as ISO 8601 UTC, ``None`` if absent or invalid."""
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


# --------------------------------------------------------------------------- discovery
def detect_backend(head: bytes) -> str | None:
    """Return ``sqlite``/``ndb``/``bdb`` from a file's first bytes, else ``None``."""
    if head.startswith(SQLITE_MAGIC):
        return "sqlite"
    if head[:4] == NDB_MAGIC:
        return "ndb"
    if is_bdb_hash(head):
        return "bdb"
    return None


def _macro_files(fs: RootFS) -> list[str]:
    """rpm macro files in rpm's load order (later files win)."""

    def prefixed(directory: str, prefix: str) -> list[str]:
        return [p for p in fs.glob_dir(directory) if posixpath.basename(p).startswith(prefix)]

    return [
        "/usr/lib/rpm/macros",
        *prefixed("/usr/lib/rpm/macros.d", "macros."),
        *(
            posixpath.join("/usr/lib/rpm/platform", d, "macros")
            for d in fs.safe_listdir("/usr/lib/rpm/platform")
        ),
        *prefixed("/etc/rpm", "macros."),
        "/etc/rpm/macros",
        *fs.glob_dir("/etc/rpm/macros.d"),
    ]


def dbpath_from_macros(fs: RootFS) -> list[str]:
    """``%_dbpath`` values from the image's rpm macro files, highest priority first."""
    files = _macro_files(fs)
    found: list[str] = []
    for path in files:
        text = fs.try_read_text(path, _MACRO_LIMIT)
        if not text:
            continue
        for m in _DBPATH_RE.finditer(text):
            value = m.group(1)
            for macro, repl in _MACRO_EXPAND.items():
                value = value.replace(macro, repl)
            if "%" not in value and value.startswith("/"):
                found.append(value.rstrip("/") or "/")
    return list(reversed(found))


def find_rpmdb(fs: RootFS) -> RpmDB | None:
    """Locate the image's rpmdb (or Mariner container manifest)."""
    seen: set[str] = set()
    dirs = [*dbpath_from_macros(fs), *DB_DIRS]
    for directory in dirs:
        for fname in DB_FILES:
            canon = fs.try_resolve(posixpath.join(directory, fname))
            if canon is None or canon in seen:
                continue
            seen.add(canon)
            st = fs.try_lstat(canon)
            if st is None or not st.is_file or st.size == 0:
                continue
            try:
                head = fs.read_head(canon, 32)
            except (RootFSError, OSError):
                continue
            backend = detect_backend(head)
            if backend is not None:
                return RpmDB(canon, backend)
    for path in MANIFEST_PATHS:
        canon = fs.try_resolve(path)
        if canon is not None and fs.is_file(canon):
            return RpmDB(canon, "manifest")
    return None


def iter_blobs(fs: RootFS, db: RpmDB, warn: Callable[[str], None]) -> Iterator[bytes]:
    """Yield raw header blobs of ``db`` (not for ``manifest``)."""
    if db.backend == "sqlite":
        yield from iter_sqlite_blobs(fs, db.path, warn)
        return
    size = fs.stat(db.path).size
    with fs.open(db.path) as f:
        if db.backend == "bdb":
            yield from iter_bdb_blobs(f, size, warn)
        elif db.backend == "ndb":
            yield from iter_ndb_blobs(f, size, warn)
        else:
            raise ParseError(f"unsupported rpmdb backend {db.backend}")


# --------------------------------------------------------------------------- headers
@dataclass(slots=True)
class RpmHeaderInfo:
    """Intermediate result for one header (before dependency resolution)."""

    record: PackageRecord
    requires: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)


def evr(epoch: int | None, version: str, release: str | None) -> str:
    """``[epoch:]version[-release]``; epoch 0 is omitted (rpmvercmp-equivalent)."""
    vr = f"{version}-{release}" if release else version
    return f"{epoch}:{vr}" if epoch else vr


def parse_source_rpm(srpm: str) -> tuple[str, str] | None:
    """``"bash-5.2.26-3.fc40.src.rpm"`` → ``("bash", "5.2.26-3.fc40")``."""
    base = srpm
    for suffix in (".src.rpm", ".nosrc.rpm"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    else:
        return None
    parts = base.rsplit("-", 2)
    if len(parts) != 3 or not all(parts):
        return None
    return parts[0], f"{parts[1]}-{parts[2]}"


def _source(h: Header, name: str, version: str, epoch: int | None) -> tuple[str, str]:
    nevr = h.string(rpmtag.SOURCENEVR)
    if nevr:
        parts = nevr.rsplit("-", 2)
        if len(parts) == 3 and all(parts):
            return parts[0], f"{parts[1]}-{parts[2]}"
    srpm = h.string(rpmtag.SOURCERPM)
    if srpm:
        parsed = parse_source_rpm(srpm)
        if parsed:
            sname, svr = parsed
            return sname, f"{epoch}:{svr}" if epoch else svr
    return name, version


def signatures(h: Header) -> tuple[list[PgpSignature], bool]:
    """Decoded signatures and whether any signature tag was present at all."""
    sigs: list[PgpSignature] = []
    present = False
    for tag in _SIG_TAGS:
        raw = h.binary(tag) if h.type_of(tag) == rpmtag.BIN else None
        if raw:
            present = True
            sig = parse_signature(raw)
            if sig is not None:
                sigs.append(sig)
    for text in h.strings(rpmtag.OPENPGP):
        present = True
        try:
            sig = parse_signature(base64.b64decode(text, validate=False))
        except (binascii.Error, ValueError):
            sig = None
        if sig is not None:
            sigs.append(sig)
    return sigs, present


def _files(
    h: Header, warn: Callable[[str], None], label: str
) -> tuple[list[str], list[str], dict[str, str], list[str], int]:
    """Return (files, directories, digests, conffiles, not_installed_count)."""
    basenames = h.strings(rpmtag.BASENAMES)
    paths: list[str | None]
    if basenames:
        dirnames = h.strings(rpmtag.DIRNAMES)
        dirindexes = h.ints(rpmtag.DIRINDEXES)
        if len(dirindexes) != len(basenames):
            warn(f"{label}: DIRINDEXES/BASENAMES length mismatch; file list dropped")
            return [], [], {}, [], 0
        paths = []
        bad = 0
        for di, bn in zip(dirindexes, basenames, strict=True):
            if di < len(dirnames):
                paths.append(dirnames[di] + bn)
            else:
                paths.append(None)
                bad += 1
        if bad:
            warn(f"{label}: {bad} file(s) with an invalid directory index")
    else:
        paths = list(h.strings(rpmtag.OLDFILENAMES))
    n = len(paths)
    modes = h.ints(rpmtag.FILEMODES)
    states = h.ints(rpmtag.FILESTATES)
    flags = h.ints(rpmtag.FILEFLAGS)
    digests_raw = h.strings(rpmtag.FILEDIGESTS)
    algo_id = h.integer(rpmtag.FILEDIGESTALGO)
    algo = HASH_ALGOS.get(algo_id if algo_id is not None else 1, f"pgphash{algo_id}")
    files: list[str] = []
    dirs: list[str] = []
    digests: dict[str, str] = {}
    conffiles: list[str] = []
    skipped = 0
    for i in range(n):
        path = paths[i]
        if not path or not path.startswith("/"):
            continue
        if i < len(states):
            state = states[i] - 256 if states[i] > 127 else states[i]
            if state not in (rpmtag.FILESTATE_NORMAL, rpmtag.FILESTATE_NETSHARED):
                skipped += 1
                continue
        if i < len(modes) and st_mod.S_ISDIR(modes[i]):
            dirs.append(path)
            continue
        files.append(path)
        if i < len(digests_raw) and digests_raw[i] and _HEX_RE.match(digests_raw[i]):
            digests[path] = f"{algo}:{digests_raw[i].lower()}"
        if i < len(flags) and flags[i] & rpmtag.RPMFILE_CONFIG:
            conffiles.append(path)
    return files, dirs, digests, conffiles, skipped


def _dep_names(h: Header, names_tag: int, flags_tag: int) -> list[str]:
    names = h.strings(names_tag)
    flags = h.ints(flags_tag)
    out: list[str] = []
    for i, name in enumerate(names):
        if i < len(flags) and flags[i] & rpmtag.RPMSENSE_RPMLIB:
            continue
        if not name or name.startswith(("rpmlib(", "(")):
            continue  # rpmlib features and rich/boolean dependencies
        out.append(name)
    return out


def header_to_info(
    h: Header,
    *,
    os_info: OSInfo | None,
    location: str,
    backend: str,
    warn: Callable[[str], None],
) -> RpmHeaderInfo | None:
    """Convert one parsed header into a record; ``None`` for nameless/versionless ones."""
    name = h.string(rpmtag.NAME)
    version = h.string(rpmtag.VERSION)
    if not name or not version:
        return None
    release = h.string(rpmtag.RELEASE)
    epoch = h.integer(rpmtag.EPOCH)
    arch = h.string(rpmtag.ARCH)
    full = evr(epoch, version, release)
    label = f"{location}: {name}-{full}"
    source_name, source_version = _source(h, name, full, epoch)
    sigs, signed = signatures(h)
    sig = sigs[0] if sigs else None
    files, dirs, digests, conffiles, skipped = _files(h, warn, label)
    props: dict[str, str] = {"rpm:db_backend": backend}
    nevra = f"{name}-{full}" + (f".{arch}" if arch else "")
    props["rpm:nevra"] = nevra
    optional = {
        "rpm:sourcerpm": h.string(rpmtag.SOURCERPM),
        "rpm:buildhost": h.string(rpmtag.BUILDHOST),
        "rpm:build_time": iso_utc(h.integer(rpmtag.BUILDTIME)),
        "rpm:distribution": h.string(rpmtag.DISTRIBUTION),
        "rpm:modularitylabel": h.string(rpmtag.MODULARITYLABEL),
        "rpm:disturl": h.string(rpmtag.DISTURL),
    }
    props.update({k: v for k, v in optional.items() if v})
    sigmd5 = h.binary(rpmtag.SIGMD5) if h.type_of(rpmtag.SIGMD5) == rpmtag.BIN else None
    if sigmd5:
        props["rpm:sigmd5"] = sigmd5.hex()
    if sig is not None:
        props["rpm:signature"] = sig.summary()
        if sig.fingerprint:
            props["rpm:signature_fingerprint"] = sig.fingerprint
    if skipped:
        props["rpm:files_not_installed"] = str(skipped)
    size = h.integer(rpmtag.LONGSIZE)
    if size is None:
        size = h.integer(rpmtag.SIZE)
    provides = sorted(set(_dep_names(h, rpmtag.PROVIDENAME, rpmtag.PROVIDEFLAGS)))
    pkg = Package(
        id="",
        type=PackageType.RPM,
        name=name,
        version=full,
        epoch=epoch,
        arch=arch,
        source_name=source_name,
        source_version=source_version,
        summary=h.string(rpmtag.SUMMARY),
        vendor=h.string(rpmtag.VENDOR),
        packager=h.string(rpmtag.PACKAGER),
        license=h.string(rpmtag.LICENSE),
        homepage=h.string(rpmtag.URL),
        installed_size=size,
        provides=provides,
        file_count=len(files),
        signing_key=sig.key_id if sig else None,
        signed=signed,
        install_time=iso_utc(h.integer(rpmtag.INSTALLTIME)),
        location=location,
        properties=props,
    )
    pkg.purl = package_purl(
        PackageType.RPM,
        name,
        full,
        os_info=os_info,
        arch=arch,
        epoch=epoch,
        source_name=source_name if h.has(rpmtag.SOURCERPM) or h.has(rpmtag.SOURCENEVR) else None,
        source_version=source_version,
    )
    pkg.id = pkg.purl
    if h.errors:
        warn(f"{label}: {len(h.errors)} malformed tag(s), first: {h.errors[0]}")
    record = PackageRecord(
        package=pkg, files=files, directories=dirs, digests=digests, conffiles=conffiles
    )
    return RpmHeaderInfo(
        record=record,
        requires=_dep_names(h, rpmtag.REQUIRENAME, rpmtag.REQUIREFLAGS),
        provides=provides,
    )


_MERGED_DIRS = ("/bin/", "/sbin/", "/lib/", "/lib64/")


def _path_variants(path: str) -> tuple[str, ...]:
    """A file dependency plus its usr-merge spelling (``/bin/sh`` ↔ ``/usr/bin/sh``)."""
    for prefix in _MERGED_DIRS:
        if path.startswith(prefix):
            return path, "/usr" + path
        if path.startswith("/usr" + prefix):
            return path, path[4:]
    return (path,)


def resolve_requires(infos: Iterable[RpmHeaderInfo]) -> None:
    """Fill ``Package.depends`` with names of installed packages satisfying requires."""
    items = list(infos)
    providers: dict[str, set[str]] = {}
    wanted_files: set[str] = set()
    for info in items:
        pkg = info.record.package
        providers.setdefault(pkg.name, set()).add(pkg.name)
        for cap in info.provides:
            providers.setdefault(cap, set()).add(pkg.name)
        for req in info.requires:
            if req.startswith("/"):
                wanted_files.update(_path_variants(req))
    if wanted_files:
        for info in items:
            for path in info.record.files:
                if path in wanted_files:
                    providers.setdefault(path, set()).add(info.record.package.name)
    for info in items:
        pkg = info.record.package
        deps: set[str] = set()
        for req in info.requires:
            found: set[str] = set()
            for variant in _path_variants(req) if req.startswith("/") else (req,):
                found.update(providers.get(variant, ()))
            if found:
                deps.update(found)
            else:
                deps.add(req)
        deps.discard(pkg.name)
        pkg.depends = sorted(deps)


# --------------------------------------------------------------------------- manifest
def read_manifest(
    fs: RootFS, path: str, os_info: OSInfo | None, warn: Callable[[str], None]
) -> list[PackageRecord]:
    """Parse a CBL-Mariner/Azure Linux ``container-manifest-2`` (tab separated)."""
    text = fs.try_read_text(path, _MANIFEST_LIMIT) or ""
    records: list[PackageRecord] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        cols = line.split("\t")
        if len(cols) < 10:
            if line.strip():
                warn(f"{path}:{lineno}: malformed manifest line")
            continue
        name, vr, itime, btime, vendor, _epoch_s, size, arch, epochnum, srpm = cols[:10]
        if not name or not vr:
            continue
        epoch = int(epochnum) if epochnum.isdigit() else None
        full = f"{epoch}:{vr}" if epoch else vr
        parsed = parse_source_rpm(srpm)
        sname, svr = (
            (parsed[0], f"{epoch}:{parsed[1]}" if epoch else parsed[1])
            if parsed
            else (
                name,
                full,
            )
        )
        pkg = Package(
            id="",
            type=PackageType.RPM,
            name=name,
            version=full,
            epoch=epoch,
            arch=arch or None,
            source_name=sname,
            source_version=svr,
            vendor=vendor or None,
            installed_size=int(size) if size.isdigit() else None,
            install_time=iso_utc(int(itime)) if itime.isdigit() else None,
            location=path,
            properties={
                k: v
                for k, v in {
                    "rpm:db_backend": "manifest",
                    "rpm:sourcerpm": srpm,
                    "rpm:build_time": iso_utc(int(btime)) if btime.isdigit() else None,
                }.items()
                if v
            },
        )
        pkg.purl = package_purl(
            PackageType.RPM,
            name,
            full,
            os_info=os_info,
            arch=pkg.arch,
            epoch=epoch,
            source_name=sname if parsed else None,
            source_version=svr,
        )
        pkg.id = pkg.purl
        records.append(PackageRecord(package=pkg))
    return records


# --------------------------------------------------------------------------- database
class RpmDatabase(PackageDatabase):
    """Pure-Python rpmdb reader (SQLite, Berkeley DB hash, NDB, Mariner manifest).

    After :meth:`read`, :attr:`installed_keys` maps imported ``gpg-pubkey``
    versions (8-hex short key id, or 40-hex fingerprint on rpm ≥ 6) to their
    summaries.
    """

    name = "rpm"
    package_type = PackageType.RPM

    def __init__(self) -> None:
        self.installed_keys: dict[str, str] = {}
        self.db: RpmDB | None = None

    def detect(self, ctx: ScanContext) -> bool:
        self.db = find_rpmdb(ctx.fs)
        return self.db is not None

    def read(self, ctx: ScanContext) -> list[PackageRecord]:
        db = self.db or find_rpmdb(ctx.fs)
        if db is None:
            return []
        self.db = db
        warned = 0

        def warn(msg: str) -> None:
            nonlocal warned
            warned += 1
            if warned <= _MAX_WARNINGS:
                ctx.warn(f"rpm: {msg}")
            elif warned == _MAX_WARNINGS + 1:
                ctx.warn(f"rpm: further warnings for {db.path} suppressed")

        if db.backend == "manifest":
            return sorted(read_manifest(ctx.fs, db.path, ctx.os, warn), key=lambda r: r.package.id)

        infos: list[RpmHeaderInfo] = []
        keys: dict[str, str] = {}
        index = 0
        for blob in iter_blobs(ctx.fs, db, warn):
            index += 1
            try:
                h = Header(blob)
            except HeaderError as exc:
                warn(f"{db.path}: header #{index} rejected: {exc}")
                continue
            try:
                name = h.string(rpmtag.NAME)
                if name == "gpg-pubkey":
                    version = (h.string(rpmtag.VERSION) or "").lower()
                    if version:
                        keys[version] = h.string(rpmtag.SUMMARY) or ""
                    continue
                info = header_to_info(
                    h, os_info=ctx.os, location=db.path, backend=db.backend, warn=warn
                )
            except Exception as exc:  # noqa: BLE001 - isolate one hostile header
                warn(f"{db.path}: header #{index} could not be converted: {exc}")
                continue
            if info is None:
                warn(f"{db.path}: header #{index} has no name or version")
                continue
            infos.append(info)
        self.installed_keys = keys
        resolve_requires(infos)
        for info in infos:
            pkg = info.record.package
            signer = signer_for(
                pkg.signing_key, pkg.properties.get("rpm:signature_fingerprint"), keys
            )
            if signer:
                pkg.properties["rpm:signer"] = signer
        records = [i.record for i in infos]
        records.sort(key=lambda r: (r.package.name, r.package.version, r.package.arch or ""))
        return records


def signer_for(key_id: str | None, fingerprint: str | None, keys: dict[str, str]) -> str | None:
    """Return the ``gpg-pubkey`` summary matching a signature key id / fingerprint."""
    if not key_id and not fingerprint:
        return None
    kid = (key_id or "").lower()
    fpr = (fingerprint or "").lower()
    for version, summary in sorted(keys.items()):
        if fpr and version == fpr:
            return summary
        if kid and len(version) == 8 and kid.endswith(version):
            return summary
        if kid and len(version) >= 16 and version.endswith(kid):
            return summary
    return None


def installed_rpm_keys(ctx: ScanContext) -> dict[str, str]:
    """Imported rpm signing keys (``gpg-pubkey`` version → summary) of the image."""
    db = RpmDatabase()
    if not db.detect(ctx):
        return {}
    try:
        db.read(ctx)
    except (ParseError, RootFSError, OSError) as exc:
        ctx.warn(f"rpm: cannot read signing keys: {exc}")
        return {}
    return db.installed_keys
