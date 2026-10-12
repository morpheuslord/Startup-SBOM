"""apk installed-database reader (Alpine, Wolfi/Chainguard, postmarketOS, ...).

``/lib/apk/db/installed`` (or ``/usr/lib/apk/db/installed``) holds blank-line
separated records of ``X:value`` lines; apk-tools 2 and 3 share the format.
Files are ``F:`` directories followed by ``R:`` names; ``Z:`` digests are
``Q1``+base64 SHA-1 (``Q2``/``X2`` SHA-256).  With the apk3 ``f:S`` flag the
``Q1`` slot holds SHA-256 truncated to 160 bits, reported as ``sha256-160``.
For symlinks the digest covers the link target string, not file content.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from startup_sbom.context import ScanContext
from startup_sbom.errors import RootFSError
from startup_sbom.models import Package, PackageType
from startup_sbom.pkgdb.base import PackageDatabase, PackageRecord
from startup_sbom.purls import package_purl

APK_DB_PATHS = ("/lib/apk/db/installed", "/usr/lib/apk/db/installed")
_DB_LIMIT = 512 * 1024 * 1024
_MAX_WARNINGS = 50
_DEP_SPLIT = re.compile(r"[<>=~]")


def iso_utc(ts: int | None) -> str | None:
    """Format a unix timestamp as ISO 8601 UTC, ``None`` if absent or invalid."""
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def decode_apk_digest(value: str) -> tuple[str, str] | None:
    """``Q1<b64>``/``Q2<b64>``/``X1<hex>``/``X2<hex>`` → ``(algo, hex)``."""
    if len(value) < 3:
        return None
    algo = {"1": "sha1", "2": "sha256"}.get(value[1])
    if algo is None:
        return None
    try:
        if value[0] == "Q":
            raw = base64.b64decode(value[2:], validate=True)
        elif value[0] == "X":
            raw = bytes.fromhex(value[2:])
        else:
            return None
    except (binascii.Error, ValueError):
        return None
    return (algo, raw.hex()) if raw else None


def _int(value: str) -> int | None:
    value = value.strip()
    return int(value) if value.isdigit() and len(value) < 20 else None


def _dep_name(token: str) -> str | None:
    if not token or token.startswith("!"):
        return None  # conflicts
    name = _DEP_SPLIT.split(token, 1)[0]
    return name or None


@dataclass(slots=True)
class _ApkEntry:
    fields: dict[str, str] = field(default_factory=dict)
    depends: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    dirs: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    digests: dict[str, str] = field(default_factory=dict)
    line: int = 1


def parse_installed(text: str) -> list[_ApkEntry]:
    """Parse the ``installed`` database into raw entries (no validation)."""
    entries: list[_ApkEntry] = []
    cur = _ApkEntry()
    cur_dir = ""
    cur_file: str | None = None
    for lineno, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if len(line) < 2:
            if cur.fields or cur.files:
                entries.append(cur)
            cur, cur_dir, cur_file = _ApkEntry(line=lineno + 1), "", None
            continue
        if line[1] != ":":
            continue
        key, value = line[0], line[2:]
        if key == "F":
            cur_dir = "/".join(c for c in value.split("/") if c not in ("", ".", ".."))
            cur_file = None
            cur.dirs.append("/" + cur_dir if cur_dir else "/")
        elif key == "R":
            if not value or "/" in value or value in (".", ".."):
                cur_file = None
                continue
            cur_file = f"/{cur_dir}/{value}" if cur_dir else f"/{value}"
            cur.files.append(cur_file)
        elif key == "Z":
            if cur_file is not None:
                decoded = decode_apk_digest(value)
                if decoded:
                    cur.digests[cur_file] = f"{decoded[0]}:{decoded[1]}"
        elif key == "D":
            cur.depends.extend(value.split())
        elif key == "p":
            cur.provides.extend(value.split())
        elif key in ("M", "a"):
            continue  # ACLs
        elif key not in cur.fields:
            cur.fields[key] = value
    if cur.fields or cur.files:
        entries.append(cur)
    return entries


class ApkDatabase(PackageDatabase):
    """Reader for the apk ``installed`` database."""

    name = "apk"
    package_type = PackageType.APK

    @staticmethod
    def database_paths(ctx: ScanContext) -> list[str]:
        """Distinct canonical database files present in the image."""
        out: list[str] = []
        for path in APK_DB_PATHS:
            canon = ctx.fs.try_resolve(path)
            if canon and canon not in out and ctx.fs.is_file(canon):
                out.append(canon)
        return out

    def detect(self, ctx: ScanContext) -> bool:
        return bool(self.database_paths(ctx))

    def read(self, ctx: ScanContext) -> list[PackageRecord]:
        warned = 0

        def warn(msg: str) -> None:
            nonlocal warned
            warned += 1
            if warned <= _MAX_WARNINGS:
                ctx.warn(f"apk: {msg}")
            elif warned == _MAX_WARNINGS + 1:
                ctx.warn("apk: further warnings suppressed")

        built: list[tuple[PackageRecord, list[str]]] = []
        seen: set[tuple[str, str]] = set()
        for path in self.database_paths(ctx):
            try:
                text = ctx.fs.read_text(path, _DB_LIMIT)
            except (RootFSError, OSError) as exc:
                warn(f"cannot read {path}: {exc}")
                continue
            for entry in parse_installed(text):
                try:
                    rec = self._build(ctx, entry, path, warn)
                except Exception as exc:  # noqa: BLE001 - isolate one hostile record
                    warn(f"{path}:{entry.line}: skipped malformed record: {exc}")
                    continue
                if rec is None:
                    continue
                key = (rec.package.name, rec.package.arch or "")
                if key in seen:
                    warn(f"{path}: duplicate record for {key[0]} ignored")
                    continue
                seen.add(key)
                built.append((rec, entry.depends))
        self._resolve(built)
        records = [r for r, _ in built]
        records.sort(key=lambda r: (r.package.name, r.package.arch or "", r.package.version))
        return records

    @staticmethod
    def _resolve(built: list[tuple[PackageRecord, list[str]]]) -> None:
        providers: dict[str, set[str]] = {}
        for rec, _ in built:
            pkg = rec.package
            providers.setdefault(pkg.name, set()).add(pkg.name)
            for cap in pkg.provides:
                providers.setdefault(cap, set()).add(pkg.name)
            for path in rec.files:
                providers.setdefault(path, set()).add(pkg.name)
        for rec, tokens in built:
            deps: set[str] = set()
            for token in tokens:
                name = _dep_name(token)
                if name:
                    deps.update(providers.get(name) or {name})
            deps.discard(rec.package.name)
            rec.package.depends = sorted(deps)

    @staticmethod
    def _build(
        ctx: ScanContext, entry: _ApkEntry, location: str, warn: Callable[[str], None]
    ) -> PackageRecord | None:
        f = entry.fields
        name = f.get("P", "").strip()
        version = f.get("V", "").strip()
        if not name or not version:
            warn(f"{location}:{entry.line}: record without P:/V: skipped")
            return None
        arch = f.get("A", "").strip() or None
        origin = f.get("o", "").strip() or name
        digests = entry.digests
        if "S" in f.get("f", ""):
            digests = {
                p: d.replace("sha1:", "sha256-160:", 1) if d.startswith("sha1:") else d
                for p, d in digests.items()
            }
        props: dict[str, str] = {}
        for key, prop in (("C", "apk:checksum"), ("c", "apk:commit"), ("f", "apk:flags")):
            if f.get(key):
                props[prop] = f[key][:200]
        if origin != name or f.get("o"):
            props["apk:origin"] = origin
        if build := iso_utc(_int(f.get("t", ""))):
            props["apk:build_time"] = build
        if (size := _int(f.get("S", ""))) is not None:
            props["apk:package_size"] = str(size)
        provides = sorted({n for n in (_dep_name(t) for t in entry.provides) if n})
        files = list(dict.fromkeys(entry.files))
        pkg = Package(
            id="",
            type=PackageType.APK,
            name=name,
            version=version,
            arch=arch,
            source_name=origin,
            source_version=version,
            summary=f.get("T") or None,
            maintainer=f.get("m") or None,
            license=f.get("L") or None,
            homepage=f.get("U") or None,
            installed_size=_int(f.get("I", "")),
            provides=provides,
            file_count=len(files),
            repository=f.get("s") or None,
            location=location,
            properties=props,
        )
        pkg.purl = package_purl(
            PackageType.APK,
            name,
            version,
            os_info=ctx.os,
            arch=arch,
            source_name=origin,
            source_version=version,
        )
        pkg.id = pkg.purl
        dirs = sorted({d for d in entry.dirs if d != "/"})
        return PackageRecord(package=pkg, files=files, directories=dirs, digests=digests)
