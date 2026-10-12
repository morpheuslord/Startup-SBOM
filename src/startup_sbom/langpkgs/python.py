"""Python distributions: ``*.dist-info/METADATA`` (+ ``RECORD``) and ``*.egg-info``.

Site directories (``site-packages``/``dist-packages``) are located under the
interpreter library roots and by bounded walks of application trees (venvs in
``/opt``, ``/app``, ``/srv``, user ``~/.local``).  Distributions whose metadata
file is owned by an OS package are still reported, with
``properties["managed_by"]`` naming that package.
"""

from __future__ import annotations

import csv
import json
import posixpath
import re
from collections.abc import Iterator
from urllib.parse import urlsplit, urlunsplit

from packageurl import PackageURL

from startup_sbom.binaries.privileged import walk_tree
from startup_sbom.context import ScanContext
from startup_sbom.errors import RootFSError
from startup_sbom.models import Package, PackageType
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.rootfs import RootFS, normalize

SITE_DIR_NAMES = frozenset({"site-packages", "dist-packages"})
LIB_ROOTS = ("/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64")
WALK_ROOTS = ("/opt", "/app", "/srv", "/usr/src")
PRUNE_NAMES = frozenset({"node_modules", "__pycache__", "proc", "sys", "dev"})
VENV_DOT_DIRS = frozenset({".venv", ".virtualenvs", ".local"})

MAX_METADATA = 1024 * 1024
MAX_RECORD = 8 * 1024 * 1024
MAX_RECORD_ROWS = 100_000
MAX_DISTS = 20_000
MAX_SITE_DIRS = 512
MAX_FIELD = 1024

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize_name(name: str) -> str:
    """PEP 503 normalised project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_metadata(text: str) -> dict[str, list[str]]:
    """Parse RFC 822-style core metadata headers (lower-cased keys, repeated values kept)."""
    out: dict[str, list[str]] = {}
    last: str | None = None
    for line in text.splitlines():
        if not line.strip():
            break
        if line[0] in " \t" and last is not None:
            out[last][-1] += "\n" + line.strip()
            continue
        key, sep, value = line.partition(":")
        if not sep or not key or " " in key.strip():
            last = None
            continue
        last = key.strip().lower()
        out.setdefault(last, []).append(value.strip())
    return out


def _first(meta: dict[str, list[str]], *keys: str) -> str | None:
    for k in keys:
        for raw in meta.get(k, ()):
            v = raw.strip()
            if v and v.upper() != "UNKNOWN":
                return v[:MAX_FIELD]
    return None


def _homepage(meta: dict[str, list[str]]) -> str | None:
    home = _first(meta, "home-page")
    if home:
        return home
    for entry in meta.get("project-url", ()):
        label, _, url = entry.partition(",")
        if label.strip().lower() in ("homepage", "home", "source", "repository") and url.strip():
            return url.strip()[:MAX_FIELD]
    return None


def _requirements(meta: dict[str, list[str]]) -> list[str]:
    names: list[str] = []
    for req in meta.get("requires-dist", ())[:1000]:
        if "extra ==" in req.replace("extra==", "extra =="):
            continue
        m = _REQ_NAME.match(req)
        if m:
            n = normalize_name(m.group(1))
            if n not in names:
                names.append(n)
    return names


def sanitize_url(url: str) -> str:
    """Drop credentials from a URL (``https://user:token@host`` -> ``https://host``)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    netloc = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))[:MAX_FIELD]


def _lib_sites(fs: RootFS, base: str, found: set[str]) -> None:
    for name in fs.safe_listdir(base):
        if not name.startswith("python"):
            continue
        for site in SITE_DIR_NAMES:
            cand = fs.try_resolve(posixpath.join(base, name, site))
            if cand is not None and fs.is_dir(cand):
                found.add(cand)


def _prune(_parent: str, name: str) -> bool:
    if name.startswith(".") and name not in VENV_DOT_DIRS:
        return True
    return name in PRUNE_NAMES or name in SITE_DIR_NAMES


def find_site_dirs(fs: RootFS) -> list[str]:
    """Canonical site directories found in the root (sorted, bounded).

    Interpreter library roots and ``~/.local/lib`` of every user are checked
    directly; application trees are walked (bounded) for venvs.
    """
    found: set[str] = set()
    for base in LIB_ROOTS:
        _lib_sites(fs, base, found)
    homes = [posixpath.join("/home", u) for u in fs.safe_listdir("/home")[:1000]]
    for home in [*homes, "/root"]:
        _lib_sites(fs, posixpath.join(home, ".local", "lib"), found)
    for root in WALK_ROOTS:
        for d, dirs, _files in walk_tree(fs, root, max_depth=8, max_entries=100_000, prune=_prune):
            found.update(posixpath.join(d, n) for n in dirs if n in SITE_DIR_NAMES)
            if len(found) >= MAX_SITE_DIRS:
                break
    return sorted(found)[:MAX_SITE_DIRS]


def _record_files(fs: RootFS, dist_dir: str, site: str) -> list[str]:
    try:
        text = fs.read_text(posixpath.join(dist_dir, "RECORD"), MAX_RECORD)
    except (RootFSError, OSError):
        return []
    files: list[str] = []
    try:
        for row in csv.reader(text.splitlines()):
            if len(files) >= MAX_RECORD_ROWS:
                break
            if not row or not row[0] or "\x00" in row[0]:
                continue
            rel = row[0]
            files.append(normalize(rel if rel.startswith("/") else posixpath.join(site, rel)))
    except csv.Error:
        pass
    return files


def _read_small(fs: RootFS, path: str, limit: int = 64 * 1024) -> str | None:
    try:
        return fs.read_text(path, limit)
    except (RootFSError, OSError):
        return None


def _dist_record(fs: RootFS, owners: FileOwnerIndex, site: str, entry: str) -> PackageRecord | None:
    path = posixpath.join(site, entry)
    if entry.endswith(".dist-info"):
        meta_path = posixpath.join(path, "METADATA")
        kind = "dist-info"
    elif fs.is_dir(path):
        meta_path = posixpath.join(path, "PKG-INFO")
        kind = "egg-info"
    else:
        meta_path = path
        kind = "egg-info"
    try:
        text = fs.read_text(meta_path, MAX_METADATA)
    except (RootFSError, OSError):
        return None
    meta = parse_metadata(text)
    name, version = _first(meta, "name"), _first(meta, "version")
    if not name or not version or len(name) > 256 or len(version) > 256:
        return None
    purl = PackageURL(type="pypi", name=normalize_name(name), version=version).to_string()
    props: dict[str, str] = {"metadata_format": kind, "site_packages": site}
    flags: list[str] = []
    files: list[str] = []
    if kind == "dist-info":
        files = _record_files(fs, path, site)
        installer = _read_small(fs, posixpath.join(path, "INSTALLER"), 4096)
        if installer and installer.strip():
            props["installer"] = installer.strip().splitlines()[0][:64]
        direct = _read_small(fs, posixpath.join(path, "direct_url.json"))
        if direct:
            try:
                doc = json.loads(direct)
            except ValueError:
                doc = None
            if isinstance(doc, dict) and isinstance(doc.get("url"), str):
                props["direct_url"] = sanitize_url(doc["url"])
                flags.append("direct_url_install")
                if isinstance(doc.get("vcs_info"), dict):
                    flags.append("vcs_install")
    owner = owners.owner(meta_path)
    if owner:
        props["managed_by"] = owner
    pkg = Package(
        id=purl,
        type=PackageType.PYPI,
        name=name,
        version=version,
        purl=purl,
        summary=_first(meta, "summary"),
        license=_first(meta, "license-expression", "license"),
        homepage=_homepage(meta),
        maintainer=_first(meta, "maintainer-email", "maintainer", "author-email", "author"),
        depends=_requirements(meta),
        file_count=len(files),
        location=meta_path,
        provenance_flags=flags,
        properties=props,
    )
    return PackageRecord(package=pkg, files=files)


def _dist_entries(fs: RootFS, site: str) -> Iterator[str]:
    for entry in fs.safe_listdir(site):
        if entry.endswith((".dist-info", ".egg-info")):
            yield entry


def scan(ctx: ScanContext, owners: FileOwnerIndex) -> list[PackageRecord]:
    """Every Python distribution installed in the root."""
    fs = ctx.fs
    out: list[PackageRecord] = []
    bad = 0
    for site in find_site_dirs(fs):
        for entry in _dist_entries(fs, site):
            if len(out) >= MAX_DISTS:
                ctx.limit(f"Python package scan stopped after {MAX_DISTS} distributions")
                return out
            try:
                rec = _dist_record(fs, owners, site, entry)
            except (RootFSError, OSError, ValueError, UnicodeError) as exc:
                fs.warnings.append(f"python metadata {site}/{entry}: {exc}")
                rec = None
            if rec is None:
                bad += 1
            else:
                out.append(rec)
    if bad:
        ctx.fs.warnings.append(f"{bad} Python metadata entries were unreadable or incomplete")
    return out
