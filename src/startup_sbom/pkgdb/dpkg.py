"""dpkg database reader (Debian, Ubuntu and derivatives, incl. distroless).

Sources:

* ``/var/lib/dpkg/status`` — deb822 paragraphs; only packages whose ``Status``
  state word is ``installed`` or ``triggers-awaited``/``triggers-pending`` are
  reported (so ``deinstall ok installed`` and ``hold ok installed`` count;
  ``config-files``, ``not-installed``, ``unpacked`` and ``half-*`` do not).
* ``/var/lib/dpkg/status.d/<pkg>`` — distroless: one paragraph per file and no
  ``Status`` field (installed); the file list comes from ``<pkg>.md5sums``.
* ``/var/lib/dpkg/info/<pkg>[:<arch>].list`` / ``.md5sums`` — file lists and
  digests (``Multi-Arch: same`` packages use the ``pkg:arch`` stem).

Licenses come from machine-readable (DEP-5) ``/usr/share/doc/<pkg>/copyright``
files; ``install_time`` approximates the install date by the ``.list`` mtime.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime

from startup_sbom.context import ScanContext
from startup_sbom.errors import RootFSError
from startup_sbom.models import Package, PackageType
from startup_sbom.pkgdb.base import PackageDatabase, PackageRecord
from startup_sbom.purls import package_purl, split_epoch
from startup_sbom.rootfs import RootFS

DPKG_DIR = "/var/lib/dpkg"
STATUS = "/var/lib/dpkg/status"
STATUS_D = "/var/lib/dpkg/status.d"
INFO_DIR = "/var/lib/dpkg/info"
INSTALLED_STATES = frozenset({"installed", "triggers-awaited", "triggers-pending"})
_STATUS_LIMIT = 256 * 1024 * 1024
_LIST_LIMIT = 64 * 1024 * 1024
_COPYRIGHT_LIMIT = 1024 * 1024
_MAX_WARNINGS = 50
_SOURCE_RE = re.compile(r"^(\S+)(?:\s+\(([^)\s]+)\))?\s*$")
_DEP_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9.+\-]*)")
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def iso_utc(ts: float | None) -> str | None:
    """Format a unix timestamp as ISO 8601 UTC, ``None`` if absent or invalid."""
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def parse_deb822(text: str) -> Iterator[dict[str, str]]:
    """Yield RFC822-style paragraphs with lower-cased field names.

    Continuation lines (leading space/tab) are appended with ``\\n``; a field
    without a value is kept as ``""``.
    """
    para: dict[str, str] = {}
    last: str | None = None
    for raw in text.splitlines():
        if not raw.strip():
            if para:
                yield para
            para, last = {}, None
            continue
        if raw[0] in " \t":
            if last is not None:
                para[last] += "\n" + raw[1:]
            continue
        if raw.startswith("#"):
            continue
        key, sep, value = raw.partition(":")
        if not sep or not key.strip():
            last = None
            continue
        last = key.strip().lower()
        para[last] = value.strip()
    if para:
        yield para


def is_installed(status: str | None) -> bool:
    """``True`` if a ``Status: want flag state`` value means files are installed."""
    if status is None:
        return False
    parts = status.split()
    return len(parts) == 3 and parts[2] in INSTALLED_STATES


def parse_source(field: str | None, name: str, version: str) -> tuple[str, str]:
    """``Source: name [(version)]`` → (source name, source version) with defaults."""
    if field:
        m = _SOURCE_RE.match(field.strip())
        if m:
            return m.group(1), m.group(2) or version
    return name, version


def dependency_groups(value: str) -> list[list[str]]:
    """Split a Depends-style field into alternative groups of bare package names."""
    groups: list[list[str]] = []
    for part in value.replace("\n", " ").split(","):
        alts: list[str] = []
        for alt in part.split("|"):
            m = _DEP_NAME_RE.match(alt.strip())
            if m:
                alts.append(m.group(1).lower())
        if alts:
            groups.append(alts)
    return groups


def resolve_groups(
    groups: list[list[str]], installed: set[str], providers: dict[str, set[str]]
) -> set[str]:
    """Resolve alternative groups to installed package names (raw name if unresolved)."""
    out: set[str] = set()
    for alts in groups:
        hit: set[str] = set()
        for name in alts:
            if name in installed:
                hit.add(name)
            hit.update(providers.get(name, ()))
        out.update(hit or {alts[0]})
    return out


def _license_from_copyright(text: str) -> str | None:
    if not text.lstrip().lower().startswith("format:"):
        return None  # only machine-readable DEP-5 files are trusted
    found: set[str] = set()
    for para in parse_deb822(text):
        value = para.get("license", "")
        first = value.split("\n", 1)[0].strip()
        if first and len(first) <= 200:
            found.add(first)
    return " AND ".join(sorted(found)) if found else None


def _paths_from_md5sums(text: str) -> dict[str, str]:
    digests: dict[str, str] = {}
    for line in text.splitlines():
        bits = line.split(None, 1)
        if len(bits) != 2 or not _MD5_RE.match(bits[0]):
            continue
        path = "/" + bits[1].strip().lstrip("/")
        if path != "/":
            digests[path] = "md5:" + bits[0].lower()
    return digests


def _split_list(paths: list[str]) -> tuple[list[str], list[str]]:
    """Split a ``.list`` (files *and* directories) into (files, directories)."""
    prefixes: set[str] = set()
    for p in paths:
        parent = posixpath.dirname(p)
        while parent not in prefixes and parent not in ("", "/"):
            prefixes.add(parent)
            parent = posixpath.dirname(parent)
    files = [p for p in paths if p not in prefixes]
    dirs = sorted(p for p in set(paths) if p in prefixes)
    return files, dirs


class DpkgDatabase(PackageDatabase):
    """Reader for ``/var/lib/dpkg`` (status file, distroless ``status.d``, info files)."""

    name = "dpkg"
    package_type = PackageType.DEB

    def detect(self, ctx: ScanContext) -> bool:
        if ctx.fs.is_file(STATUS):
            return True
        return any(not n.endswith(".md5sums") for n in ctx.fs.safe_listdir(STATUS_D))

    def read(self, ctx: ScanContext) -> list[PackageRecord]:
        fs = ctx.fs
        warned = 0

        def warn(msg: str) -> None:
            nonlocal warned
            warned += 1
            if warned <= _MAX_WARNINGS:
                ctx.warn(f"dpkg: {msg}")
            elif warned == _MAX_WARNINGS + 1:
                ctx.warn("dpkg: further warnings suppressed")

        info_names = set(fs.safe_listdir(INFO_DIR))
        # (paragraph, location, sidecar md5sums candidates, default-installed)
        entries: list[tuple[dict[str, str], str, list[str], bool]] = []
        status_text = self._read_text(fs, STATUS, _STATUS_LIMIT, warn)
        if status_text:
            entries.extend((p, STATUS, [], False) for p in parse_deb822(status_text))
        for fname in fs.safe_listdir(STATUS_D):
            if fname.endswith(".md5sums"):
                continue
            path = posixpath.join(STATUS_D, fname)
            text = self._read_text(fs, path, _STATUS_LIMIT, warn)
            if not text:
                continue
            sidecars = [path + ".md5sums"]
            entries.extend((p, path, sidecars, True) for p in parse_deb822(text))

        records: list[PackageRecord] = []
        seen: set[tuple[str, str]] = set()
        pending: list[tuple[PackageRecord, list[list[str]]]] = []
        for para, location, sidecars, default_installed in entries:
            try:
                built = self._build(
                    ctx,
                    para,
                    location=location,
                    sidecars=sidecars,
                    default_installed=default_installed,
                    info_names=info_names,
                    warn=warn,
                )
            except Exception as exc:  # noqa: BLE001 - isolate one hostile paragraph
                warn(f"{location}: skipped malformed entry {para.get('package', '?')!r}: {exc}")
                continue
            if built is None:
                continue
            record, groups = built
            key = (record.package.name, record.package.arch or "")
            if key in seen:
                warn(f"{location}: duplicate entry for {key[0]}:{key[1]} ignored")
                continue
            seen.add(key)
            pending.append((record, groups))
            records.append(record)

        installed = {r.package.name for r in records}
        providers: dict[str, set[str]] = {}
        for r in records:
            for cap in r.package.provides:
                providers.setdefault(cap, set()).add(r.package.name)
        for record, groups in pending:
            deps = resolve_groups(groups, installed, providers)
            deps.discard(record.package.name)
            record.package.depends = sorted(deps)
        records.sort(key=lambda r: (r.package.name, r.package.arch or "", r.package.version))
        return records

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def _read_text(fs: RootFS, path: str, limit: int, warn: Callable[[str], None]) -> str | None:
        try:
            return fs.read_text(path, limit)
        except FileNotFoundError:
            return None
        except (RootFSError, OSError) as exc:
            warn(f"cannot read {path}: {exc}")
            return None

    def _build(
        self,
        ctx: ScanContext,
        para: dict[str, str],
        *,
        location: str,
        sidecars: list[str],
        default_installed: bool,
        info_names: set[str],
        warn: Callable[[str], None],
    ) -> tuple[PackageRecord, list[list[str]]] | None:
        fs = ctx.fs
        name = para.get("package", "").strip()
        version = para.get("version", "").strip()
        if not name:
            return None
        status = para.get("status")
        if status is None and not default_installed:
            return None
        if status is not None and not is_installed(status):
            return None
        if not version:
            warn(f"{location}: package {name!r} has no Version; skipped")
            return None
        arch = para.get("architecture", "").strip() or None
        multi_arch = para.get("multi-arch", "").strip().lower()
        source_name, source_version = parse_source(para.get("source"), name, version)
        epoch, _ = split_epoch(version)

        # file list, digests ------------------------------------------------
        stems = [name, f"{name}:{arch}"] if arch else [name]
        if multi_arch == "same":
            stems.reverse()
        files: list[str] = []
        dirs: list[str] = []
        digests: dict[str, str] = {}
        install_time: str | None = None
        list_found = False
        for stem in stems:
            if f"{stem}.list" not in info_names:
                continue
            list_path = posixpath.join(INFO_DIR, f"{stem}.list")
            text = self._read_text(fs, list_path, _LIST_LIMIT, warn)
            if text is None:
                continue
            list_found = True
            raw = [ln.strip() for ln in text.splitlines()]
            files, dirs = _split_list([p for p in dict.fromkeys(raw) if p.startswith("/")])
            files = [p for p in files if p != "/."]
            dirs = [p for p in dirs if p != "/."]
            st = fs.try_lstat(list_path)
            install_time = iso_utc(st.mtime) if st else None
            if f"{stem}.md5sums" in info_names:
                md5 = self._read_text(
                    fs, posixpath.join(INFO_DIR, f"{stem}.md5sums"), _LIST_LIMIT, warn
                )
                digests = _paths_from_md5sums(md5 or "")
            break
        if not list_found and sidecars:
            for sidecar in dict.fromkeys([*sidecars, posixpath.join(STATUS_D, f"{name}.md5sums")]):
                if not fs.is_file(sidecar):
                    continue
                md5 = self._read_text(fs, sidecar, _LIST_LIMIT, warn)
                if md5 is not None:
                    digests = _paths_from_md5sums(md5)
                    files = sorted(digests)
                    break

        conffiles: list[str] = []
        for line in para.get("conffiles", "").splitlines():
            bits = line.split()
            if not bits or not bits[0].startswith("/"):
                continue
            if len(bits) >= 3 and bits[2] in ("obsolete", "remove-on-upgrade"):
                continue
            conffiles.append(bits[0])
            if len(bits) >= 2 and _MD5_RE.match(bits[1]) and bits[0] not in digests:
                digests[bits[0]] = "md5:" + bits[1].lower()
        for path in conffiles:
            if path not in files and path not in dirs:
                files.append(path)
        if list_found:
            # Leaves without a digest may be empty directories; ask the image.
            conf = set(conffiles)
            empty_dirs = {
                p
                for p in files
                if p not in digests and p not in conf and (st := fs.try_lstat(p)) and st.is_dir
            }
            if empty_dirs:
                files = [p for p in files if p not in empty_dirs]
                dirs = sorted({*dirs, *empty_dirs})

        # metadata ------------------------------------------------------------
        try:
            installed_size: int | None = int(para.get("installed-size", "").strip()) * 1024
        except ValueError:
            installed_size = None
        provides = sorted({n for g in dependency_groups(para.get("provides", "")) for n in g})
        groups = dependency_groups(para.get("pre-depends", "")) + dependency_groups(
            para.get("depends", "")
        )
        description = para.get("description", "")
        props: dict[str, str] = {}
        for fld in ("multi-arch", "priority", "section", "essential", "origin"):
            if para.get(fld):
                props[f"dpkg:{fld.replace('-', '_')}"] = para[fld].split("\n", 1)[0][:200]
        if status:
            props["dpkg:status"] = status
        if para.get("original-maintainer"):
            props["dpkg:original_maintainer"] = para["original-maintainer"][:200]
        license_ = None
        copyright_text = fs.try_read_text(
            posixpath.join("/usr/share/doc", name, "copyright"), _COPYRIGHT_LIMIT
        )
        if copyright_text:
            license_ = _license_from_copyright(copyright_text)

        pkg = Package(
            id="",
            type=PackageType.DEB,
            name=name,
            version=version,
            epoch=epoch,
            arch=arch,
            source_name=source_name,
            source_version=source_version,
            summary=description.split("\n", 1)[0].strip() or None,
            maintainer=para.get("maintainer") or None,
            vendor=para.get("origin") or None,
            license=license_,
            homepage=para.get("homepage") or None,
            installed_size=installed_size,
            provides=provides,
            file_count=len(files),
            install_time=install_time,
            location=location,
            properties=props,
        )
        pkg.purl = package_purl(
            PackageType.DEB,
            name,
            version,
            os_info=ctx.os,
            arch=arch,
            source_name=source_name,
            source_version=source_version,
        )
        pkg.id = pkg.purl
        record = PackageRecord(
            package=pkg,
            files=files,
            directories=dirs,
            digests=digests,
            conffiles=sorted(set(conffiles)),
        )
        return record, groups
