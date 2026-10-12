"""Java archives: ``META-INF/maven/<g>/<a>/pom.properties`` inside ``*.jar|*.war|*.ear``.

Archives are read into memory through the RootFS with a size cap and opened
with :mod:`zipfile` (never extracted).  Nested archives (``BOOT-INF/lib``,
``WEB-INF/lib`` ...) are inspected one level deep within a per-archive budget
of uncompressed bytes, so zip bombs and lying headers are bounded.  Archives
without ``pom.properties`` fall back to ``META-INF/MANIFEST.MF``.
"""

from __future__ import annotations

import io
import posixpath
import re
import zipfile
import zlib

from packageurl import PackageURL

from startup_sbom.binaries.privileged import walk_tree
from startup_sbom.context import ScanContext
from startup_sbom.errors import ReadLimitError, RootFSError
from startup_sbom.models import Package, PackageType
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex

WALK_ROOTS = ("/opt", "/app", "/usr/share/java", "/srv", "/usr/local/lib", "/usr/src")
PRUNE_NAMES = frozenset({"node_modules", "proc", "sys", "dev", "site-packages", "dist-packages"})
ARCHIVE_EXT = (".jar", ".war", ".ear")

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_NESTED = 32 * 1024 * 1024
MAX_ARCHIVE_BUDGET = 256 * 1024 * 1024
MAX_MEMBER_TEXT = 64 * 1024
MAX_ARCHIVES = 2_000
MAX_MEMBERS = 100_000
MAX_NESTING = 2

_POM_RE = re.compile(r"^META-INF/maven/[^/]+/[^/]+/pom\.properties$")
_ZIP_ERRORS = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    zlib.error,
    NotImplementedError,
    RuntimeError,
    EOFError,
    OSError,
    ValueError,
    KeyError,
)


def parse_properties(text: str) -> dict[str, str]:
    """Minimal Java ``.properties`` parser (``key=value``/``key: value``, ``#``/``!`` comments)."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!":
            continue
        m = re.match(r"^([^=:\s]+)\s*[=:\s]\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def parse_manifest(text: str) -> dict[str, str]:
    """Main section of a JAR ``MANIFEST.MF`` (continuation lines start with a space)."""
    out: dict[str, str] = {}
    last: str | None = None
    for line in text.splitlines():
        if not line.strip():
            break
        if line.startswith(" ") and last is not None:
            out[last] += line[1:]
            continue
        key, sep, value = line.partition(":")
        if sep:
            last = key.strip()
            out[last] = value.strip()
    return out


class _Budget:
    def __init__(self) -> None:
        self.left = MAX_ARCHIVE_BUDGET

    def read(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes | None:
        if info.file_size > limit or info.file_size > self.left:
            return None
        with zf.open(info) as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            return None
        self.left -= len(data)
        return data


def _maven_record(
    props: dict[str, str], location: str, archive: str, managed_by: str | None, evidence: str
) -> PackageRecord | None:
    group, artifact, version = props.get("groupId"), props.get("artifactId"), props.get("version")
    if not artifact or not version or len(artifact) > 256 or len(version) > 128:
        return None
    if group is not None and len(group) > 256:
        return None
    purl = PackageURL(type="maven", namespace=group or None, name=artifact, version=version)
    sp: dict[str, str] = {"archive": archive, "evidence": evidence}
    if managed_by:
        sp["managed_by"] = managed_by
    pkg = Package(
        id=purl.to_string(),
        type=PackageType.MAVEN,
        name=f"{group}:{artifact}" if group else artifact,
        version=version,
        purl=purl.to_string(),
        location=location,
        properties=sp,
    )
    return PackageRecord(package=pkg)


def scan_archive(
    data: bytes,
    display: str,
    managed_by: str | None,
    *,
    budget: _Budget | None = None,
    nesting: int = 0,
) -> list[PackageRecord]:
    """Maven coordinates found in one archive's bytes (nested archives included)."""
    budget = budget or _Budget()
    out: list[PackageRecord] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except _ZIP_ERRORS:
        return out
    with zf:
        infos = zf.infolist()[:MAX_MEMBERS]
        for info in infos:
            if not _POM_RE.match(info.filename):
                continue
            try:
                raw = budget.read(zf, info, MAX_MEMBER_TEXT)
            except _ZIP_ERRORS:
                continue
            if raw is None:
                continue
            props = parse_properties(raw.decode("utf-8", "replace"))
            rec = _maven_record(
                props, f"{display}!/{info.filename}", display, managed_by, "pom.properties"
            )
            if rec is not None:
                out.append(rec)
        if not out:
            rec = _manifest_record(zf, display, managed_by, budget)
            if rec is not None:
                out.append(rec)
        if nesting >= MAX_NESTING - 1:
            return out
        for info in infos:
            if info.is_dir() or not info.filename.lower().endswith(ARCHIVE_EXT):
                continue
            try:
                nested = budget.read(zf, info, MAX_NESTED)
            except _ZIP_ERRORS:
                continue
            if nested is not None:
                out += scan_archive(
                    nested,
                    f"{display}!/{info.filename}",
                    managed_by,
                    budget=budget,
                    nesting=nesting + 1,
                )
    return out


def _manifest_record(
    zf: zipfile.ZipFile, display: str, managed_by: str | None, budget: _Budget
) -> PackageRecord | None:
    try:
        info = zf.getinfo("META-INF/MANIFEST.MF")
        raw = budget.read(zf, info, MAX_MEMBER_TEXT)
    except _ZIP_ERRORS:
        return None
    if raw is None:
        return None
    mf = parse_manifest(raw.decode("utf-8", "replace"))
    version = mf.get("Implementation-Version") or mf.get("Bundle-Version")
    name = (
        mf.get("Bundle-SymbolicName", "").split(";")[0].strip()
        or mf.get("Implementation-Title")
        or posixpath.splitext(posixpath.basename(display.rsplit("!/", 1)[-1]))[0]
    )
    group = mf.get("Implementation-Vendor-Id") or None
    if not version or not name or not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
        return None
    props = {"artifactId": name, "version": version}
    if group:
        props["groupId"] = group
    return _maven_record(
        props, f"{display}!/META-INF/MANIFEST.MF", display, managed_by, "MANIFEST.MF"
    )


def find_archives(ctx: ScanContext) -> list[str]:
    """Canonical paths of Java archives in the usual application trees (bounded)."""
    found: set[str] = set()
    for root in WALK_ROOTS:
        for d, _dirs, files in walk_tree(
            ctx.fs,
            root,
            max_depth=8,
            max_entries=100_000,
            prune=lambda _p, n: n.startswith(".") or n in PRUNE_NAMES,
        ):
            for name in files:
                if name.lower().endswith(ARCHIVE_EXT):
                    found.add(posixpath.join(d, name))
            if len(found) >= MAX_ARCHIVES:
                ctx.limit(f"Java archive scan stopped after {MAX_ARCHIVES} archives")
                return sorted(found)[:MAX_ARCHIVES]
    return sorted(found)


def scan(ctx: ScanContext, owners: FileOwnerIndex) -> list[PackageRecord]:
    """Maven packages from every Java archive found in the root."""
    out: list[PackageRecord] = []
    too_big = 0
    for path in find_archives(ctx):
        try:
            data = ctx.fs.read_bytes(path, MAX_ARCHIVE)
        except ReadLimitError:
            too_big += 1
            continue
        except (RootFSError, OSError):
            continue
        out += scan_archive(data, path, owners.owner(path))
    if too_big:
        ctx.limit(f"{too_big} Java archive(s) larger than {MAX_ARCHIVE // 2**20} MiB not inspected")
    return out
