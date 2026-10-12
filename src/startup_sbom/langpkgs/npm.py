"""npm packages: ``node_modules/[@scope/]<name>/package.json`` (nested installs included).

``node_modules`` directories are discovered by bounded walks of the global
module roots and application trees; walks never enter test/fixture/example
directories, and only package directories directly inside a ``node_modules``
(or Debian's ``/usr/share/nodejs``) count, so stray ``package.json`` fixtures
inside packages are ignored.
"""

from __future__ import annotations

import json
import posixpath

from packageurl import PackageURL

from startup_sbom.binaries.privileged import walk_tree
from startup_sbom.context import ScanContext
from startup_sbom.errors import RootFSError
from startup_sbom.models import Package, PackageType
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.rootfs import RootFS

#: Directories that are themselves module directories.
MODULE_ROOTS = ("/usr/lib/node_modules", "/usr/local/lib/node_modules", "/usr/share/nodejs")
#: Trees searched for ``node_modules`` directories: ``(root, max depth, max entries)``.
WALK_ROOTS: tuple[tuple[str, int, int], ...] = (
    ("/opt", 6, 100_000),
    ("/app", 6, 100_000),
    ("/srv", 6, 100_000),
    ("/usr/src", 6, 100_000),
    ("/var/www", 6, 100_000),
    ("/usr/local/share", 4, 20_000),
    ("/home", 4, 20_000),
    ("/root", 4, 20_000),
)
PRUNE_NAMES = frozenset(
    {
        "node_modules", "test", "tests", "__tests__", "fixtures", "__fixtures__",
        "example", "examples", "proc", "sys", "dev", "site-packages", "dist-packages",
    }
)  # fmt: skip

MAX_PACKAGE_JSON = 1024 * 1024
MAX_PACKAGES = 50_000
MAX_NESTING = 8
MAX_MODULE_DIRS = 2_000
MAX_FIELD = 1024


def _str(doc: dict[str, object], key: str) -> str | None:
    v = doc.get(key)
    return v.strip()[:MAX_FIELD] if isinstance(v, str) and v.strip() else None


def _license(doc: dict[str, object]) -> str | None:
    lic = doc.get("license")
    if isinstance(lic, str):
        return lic[:MAX_FIELD] or None
    if isinstance(lic, dict) and isinstance(lic.get("type"), str):
        return str(lic["type"])[:MAX_FIELD]
    return None


def _repository(doc: dict[str, object]) -> str | None:
    repo = doc.get("repository")
    if isinstance(repo, str):
        return repo[:MAX_FIELD]
    if isinstance(repo, dict) and isinstance(repo.get("url"), str):
        return str(repo["url"])[:MAX_FIELD]
    return None


def npm_purl(name: str, version: str) -> str:
    """purl of an npm package (``@scope/name`` -> namespace ``@scope``)."""
    namespace: str | None = None
    if name.startswith("@") and "/" in name:
        namespace, name = name.split("/", 1)
    return PackageURL(type="npm", namespace=namespace, name=name, version=version).to_string()


def parse_package_json(
    fs: RootFS, owners: FileOwnerIndex, manifest: str, nesting: int
) -> PackageRecord | None:
    """One installed package from its ``package.json``; ``None`` if invalid."""
    try:
        doc = json.loads(fs.read_bytes(manifest, MAX_PACKAGE_JSON))
    except (RootFSError, OSError, ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    name, version = doc.get("name"), doc.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    if not 0 < len(name) <= 214 or not 0 < len(version) <= 256:
        return None
    purl = npm_purl(name, version)
    props: dict[str, str] = {}
    for key in ("_resolved", "_integrity", "_from"):
        v = _str(doc, key)
        if v:
            props[key.lstrip("_")] = v
    if nesting:
        props["nesting"] = str(nesting)
    owner = owners.owner(manifest)
    if owner:
        props["managed_by"] = owner
    deps = doc.get("dependencies")
    depends = sorted(k for k in deps if isinstance(k, str))[:1000] if isinstance(deps, dict) else []
    homepage = _str(doc, "homepage") or _repository(doc)
    pkg = Package(
        id=purl,
        type=PackageType.NPM,
        name=name,
        version=version,
        purl=purl,
        summary=_str(doc, "description"),
        license=_license(doc),
        homepage=homepage,
        depends=depends,
        location=manifest,
        properties=props,
    )
    return PackageRecord(package=pkg)


def _find_module_dirs(fs: RootFS) -> list[str]:
    found: set[str] = set()
    for root in MODULE_ROOTS:
        c = fs.try_resolve(root)
        if c is not None and fs.is_dir(c):
            found.add(c)
    for root, depth, budget in WALK_ROOTS:
        for d, dirs, _files in walk_tree(
            fs,
            root,
            max_depth=depth,
            max_entries=budget,
            prune=lambda _p, n: n.startswith(".") or n in PRUNE_NAMES,
        ):
            if "node_modules" in dirs:
                found.add(posixpath.join(d, "node_modules"))
                if len(found) >= MAX_MODULE_DIRS:
                    return sorted(found)
    return sorted(found)


def scan(ctx: ScanContext, owners: FileOwnerIndex) -> list[PackageRecord]:
    """Every npm package installed in the root (pnpm ``.pnpm`` stores included)."""
    fs = ctx.fs
    out: list[PackageRecord] = []
    visited: set[str] = set()
    seen_pkgs: set[str] = set()
    stack: list[tuple[str, int]] = [(d, 0) for d in reversed(_find_module_dirs(fs))]
    while stack:
        mdir, nesting = stack.pop()
        if mdir in visited or len(visited) >= MAX_MODULE_DIRS * 4:
            continue
        visited.add(mdir)
        pkg_dirs: list[str] = []
        nested: list[tuple[str, int]] = []
        for name in fs.safe_listdir(mdir):
            child = posixpath.join(mdir, name)
            if name == ".pnpm" and nesting < MAX_NESTING:
                for store in fs.safe_listdir(child):
                    sub = fs.try_resolve(posixpath.join(child, store, "node_modules"))
                    if sub is not None and fs.is_dir(sub):
                        nested.append((sub, nesting + 1))
            elif name.startswith("."):
                continue
            elif name.startswith("@"):
                pkg_dirs += [posixpath.join(child, n) for n in fs.safe_listdir(child)]
            else:
                pkg_dirs.append(child)
        for pdir in pkg_dirs:
            if len(out) >= MAX_PACKAGES:
                ctx.limit(f"npm package scan stopped after {MAX_PACKAGES} packages")
                return out
            cdir = fs.try_resolve(pdir)
            if cdir is None or cdir in seen_pkgs or not fs.is_dir(cdir):
                continue
            seen_pkgs.add(cdir)
            rec = parse_package_json(fs, owners, posixpath.join(cdir, "package.json"), nesting)
            if rec is not None:
                out.append(rec)
            sub = fs.try_resolve(posixpath.join(cdir, "node_modules"))
            if nesting < MAX_NESTING and sub is not None and fs.is_dir(sub):
                nested.append((sub, nesting + 1))
        stack.extend(reversed(nested))
    return out
