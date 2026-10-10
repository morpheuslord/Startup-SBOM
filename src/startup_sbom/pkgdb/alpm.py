"""pacman/libalpm local database reader (Arch Linux and derivatives).

``<DBPath>/local/<name>-<version>/`` (default DBPath ``/var/lib/pacman/``,
overridable in ``/etc/pacman.conf``) holds ``desc`` (``%KEY%`` sections, one
value per line), ``files`` (``%FILES%`` root-relative paths, directories end
in ``/``; ``%BACKUP%`` ``path<TAB>md5``) and an optional gzip ``mtree`` with
per-file SHA-256 digests.  Directory names are never parsed: ``%NAME%`` and
``%VERSION%`` come from ``desc``.

``%VALIDATION%`` lists how the package was verified (``pgp``, ``sha256``,
``md5``, ``none``); it is not a key id, so ``Package.signed`` reflects ``pgp``
and the raw value is kept in ``properties["alpm:validation"]``.
"""

from __future__ import annotations

import gzip
import posixpath
import re
import zlib
from collections.abc import Callable
from datetime import UTC, datetime

from startup_sbom.context import ScanContext
from startup_sbom.errors import RootFSError
from startup_sbom.models import Package, PackageType
from startup_sbom.pkgdb.base import PackageDatabase, PackageRecord
from startup_sbom.purls import package_purl, split_epoch
from startup_sbom.rootfs import RootFS

DEFAULT_DBPATH = "/var/lib/pacman/"
PACMAN_CONF = "/etc/pacman.conf"
_DESC_LIMIT = 4 * 1024 * 1024
_FILES_LIMIT = 64 * 1024 * 1024
_MTREE_GZ_LIMIT = 16 * 1024 * 1024
_MTREE_LIMIT = 64 * 1024 * 1024
_MTREE_MAX_LINES = 300_000
_MAX_WARNINGS = 50
_DEP_SPLIT = re.compile(r"[<>=:]")
_DBPATH_RE = re.compile(r"^\s*DBPath\s*=\s*(\S+)", re.MULTILINE)
_OCTAL_ESC = re.compile(r"\\([0-7]{3})")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")


def iso_utc(ts: int | None) -> str | None:
    """Format a unix timestamp as ISO 8601 UTC, ``None`` if absent or invalid."""
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def parse_desc(text: str) -> dict[str, list[str]]:
    """Parse ``%KEY%`` sections into ``{KEY: [values]}``."""
    out: dict[str, list[str]] = {}
    key: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if len(line) > 2 and line.startswith("%") and line.endswith("%"):
            key = line[1:-1]
            out.setdefault(key, [])
        elif not line.strip():
            key = None
        elif key is not None:
            out[key].append(line)
    return out


def _first(desc: dict[str, list[str]], key: str) -> str | None:
    values = desc.get(key)
    return values[0].strip() or None if values else None


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    value = value.strip()
    return int(value) if value.isdigit() and len(value) < 20 else None


def _dep_name(token: str) -> str | None:
    name = _DEP_SPLIT.split(token.strip(), 1)[0].strip()
    return name or None


def _unescape_mtree(path: str) -> str:
    return _OCTAL_ESC.sub(lambda m: chr(int(m.group(1), 8)), path)


def parse_mtree(text: str) -> dict[str, str]:
    """``{"/abs/path": "sha256:<hex>" | "md5:<hex>"}`` from an mtree(5) spec."""
    digests: dict[str, str] = {}
    for count, raw in enumerate(text.splitlines()):
        if count >= _MTREE_MAX_LINES:
            break
        line = raw.strip()
        if not line or line.startswith(("#", "/")) or line.endswith("\\"):
            continue
        parts = line.split()
        path = _unescape_mtree(parts[0])
        if not path.startswith("./"):
            continue
        path = "/" + path[2:].lstrip("/")
        if posixpath.basename(path).startswith(".") and posixpath.dirname(path) == "/":
            continue  # .BUILDINFO, .PKGINFO, .MTREE, .INSTALL
        kv = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
        if kv.get("type", "file") != "file":
            continue
        sha = kv.get("sha256digest", "").lower()
        md5 = kv.get("md5digest", "").lower()
        if _HEX64.match(sha):
            digests[path] = f"sha256:{sha}"
        elif _HEX32.match(md5):
            digests[path] = f"md5:{md5}"
    return digests


def _read_mtree(fs: RootFS, path: str) -> dict[str, str] | None:
    st = fs.try_stat(path)
    if st is None or not st.is_file or st.size > _MTREE_GZ_LIMIT:
        return None
    with fs.open(path) as raw, gzip.GzipFile(fileobj=raw) as gz:
        data = gz.read(_MTREE_LIMIT + 1)
    if len(data) > _MTREE_LIMIT:
        return None
    return parse_mtree(data.decode("utf-8", "replace"))


def dbpath(fs: RootFS) -> str:
    """The pacman ``DBPath`` configured in the image (default ``/var/lib/pacman/``)."""
    conf = fs.try_read_text(PACMAN_CONF, 1024 * 1024) or ""
    for m in _DBPATH_RE.finditer(conf):
        value = m.group(1)
        if value.startswith("/"):
            return value
    return DEFAULT_DBPATH


class AlpmDatabase(PackageDatabase):
    """Reader for the pacman local database."""

    name = "alpm"
    package_type = PackageType.ALPM

    @staticmethod
    def local_dir(ctx: ScanContext) -> str | None:
        """Canonical ``<DBPath>/local`` directory, if present."""
        candidates = dict.fromkeys(
            [posixpath.join(dbpath(ctx.fs), "local"), posixpath.join(DEFAULT_DBPATH, "local")]
        )
        for cand in candidates:
            canon = ctx.fs.try_resolve(cand)
            if canon and ctx.fs.is_dir(canon):
                return canon
        return None

    def detect(self, ctx: ScanContext) -> bool:
        local = self.local_dir(ctx)
        return local is not None and any(
            ctx.fs.is_file(posixpath.join(local, d, "desc")) for d in ctx.fs.safe_listdir(local)
        )

    def read(self, ctx: ScanContext) -> list[PackageRecord]:
        local = self.local_dir(ctx)
        if local is None:
            return []
        warned = 0

        def warn(msg: str) -> None:
            nonlocal warned
            warned += 1
            if warned <= _MAX_WARNINGS:
                ctx.warn(f"alpm: {msg}")
            elif warned == _MAX_WARNINGS + 1:
                ctx.warn("alpm: further warnings suppressed")

        built: list[tuple[PackageRecord, list[str]]] = []
        seen: set[str] = set()
        for entry in ctx.fs.safe_listdir(local):
            directory = posixpath.join(local, entry)
            desc_path = posixpath.join(directory, "desc")
            if not ctx.fs.is_file(desc_path):
                continue
            try:
                result = self._build(ctx, directory, desc_path, warn)
            except Exception as exc:  # noqa: BLE001 - isolate one hostile entry
                warn(f"{directory}: skipped malformed entry: {exc}")
                continue
            if result is None:
                continue
            if result[0].package.name in seen:
                warn(f"{directory}: duplicate package {result[0].package.name} ignored")
                continue
            seen.add(result[0].package.name)
            built.append(result)

        providers: dict[str, set[str]] = {}
        for rec, _ in built:
            providers.setdefault(rec.package.name, set()).add(rec.package.name)
            for cap in rec.package.provides:
                providers.setdefault(cap, set()).add(rec.package.name)
        for rec, tokens in built:
            deps: set[str] = set()
            for token in tokens:
                name = _dep_name(token)
                if name:
                    deps.update(providers.get(name) or {name})
            deps.discard(rec.package.name)
            rec.package.depends = sorted(deps)
        records = [r for r, _ in built]
        records.sort(key=lambda r: (r.package.name, r.package.version))
        return records

    @staticmethod
    def _build(
        ctx: ScanContext, directory: str, desc_path: str, warn: Callable[[str], None]
    ) -> tuple[PackageRecord, list[str]] | None:
        fs = ctx.fs
        desc = parse_desc(fs.read_text(desc_path, _DESC_LIMIT))
        name = _first(desc, "NAME")
        version = _first(desc, "VERSION")
        if not name or not version:
            warn(f"{desc_path}: missing %NAME% or %VERSION%")
            return None
        arch = _first(desc, "ARCH")
        base = _first(desc, "BASE") or name
        epoch, _ = split_epoch(version)
        validation = [v.strip() for v in desc.get("VALIDATION", []) if v.strip()]
        licenses = [v.strip() for v in desc.get("LICENSE", []) if v.strip()]
        provides = sorted({n for n in (_dep_name(t) for t in desc.get("PROVIDES", [])) if n})

        files: list[str] = []
        dirs: list[str] = []
        conffiles: list[str] = []
        digests: dict[str, str] = {}
        files_path = posixpath.join(directory, "files")
        text: str | None = None
        try:
            text = fs.read_text(files_path, _FILES_LIMIT)
        except FileNotFoundError:
            text = None
        except (RootFSError, OSError) as exc:
            warn(f"cannot read {files_path}: {exc}")
        section = None
        for raw in (text or "").splitlines():
            line = raw.rstrip("\r")
            if line.startswith("%") and line.endswith("%"):
                section = line
                continue
            if not line.strip():
                continue
            if section == "%FILES%":
                path = "/" + line.lstrip("/")
                if path.endswith("/"):
                    if path != "/":
                        dirs.append(path.rstrip("/"))
                else:
                    files.append(path)
            elif section == "%BACKUP%":
                rel, _, md5 = line.partition("\t")
                path = "/" + rel.lstrip("/")
                conffiles.append(path)
                if _HEX32.match(md5.strip().lower()):
                    digests[path] = "md5:" + md5.strip().lower()
        try:
            mtree = _read_mtree(fs, posixpath.join(directory, "mtree"))
        except (RootFSError, OSError, EOFError, zlib.error, gzip.BadGzipFile) as exc:
            warn(f"{directory}/mtree unreadable: {exc}")
            mtree = None
        if mtree:
            file_set = set(files)
            digests.update({p: d for p, d in mtree.items() if p in file_set})

        props: dict[str, str] = {"alpm:base": base}
        if validation:
            props["alpm:validation"] = " ".join(validation)
        for key, prop in (("REASON", "alpm:reason"), ("GROUPS", "alpm:groups")):
            if desc.get(key):
                props[prop] = " ".join(v.strip() for v in desc[key])[:200]
        if build := iso_utc(_int(_first(desc, "BUILDDATE"))):
            props["alpm:build_time"] = build
        for xdata in desc.get("XDATA", []):
            if xdata.startswith("pkgtype="):
                props["alpm:pkgtype"] = xdata.split("=", 1)[1][:50]
        pkg = Package(
            id="",
            type=PackageType.ALPM,
            name=name,
            version=version,
            epoch=epoch,
            arch=arch,
            source_name=base,
            source_version=version,
            summary=_first(desc, "DESC"),
            packager=_first(desc, "PACKAGER"),
            license=" AND ".join(licenses) if licenses else None,
            homepage=_first(desc, "URL"),
            installed_size=_int(_first(desc, "SIZE")),
            provides=provides,
            file_count=len(files),
            signed="pgp" in validation if validation else None,
            install_time=iso_utc(_int(_first(desc, "INSTALLDATE"))),
            location=desc_path,
            properties=props,
        )
        pkg.purl = package_purl(
            PackageType.ALPM,
            name,
            version,
            os_info=ctx.os,
            arch=arch,
            source_name=base,
            source_version=version,
        )
        pkg.id = pkg.purl
        record = PackageRecord(
            package=pkg,
            files=files,
            directories=dirs,
            digests=digests,
            conffiles=sorted(set(conffiles)),
        )
        return record, list(desc.get("DEPENDS", []))
