"""Vendor-chain graph: vendor → source → binary package → file → service.

Only what matters for "does this reach something that runs" is materialised:

* every non-masked service, a ``boot`` node with ``starts_at_boot`` edges to the
  services that start automatically;
* the files those services execute and every library/interpreter they load
  (``links``/``dlopens``/``interprets``/``preload``/``loads_config`` edges with the
  confidence recorded by link analysis);
* the packages shipping those files, plus any package that is vulnerable or
  carries a provenance flag, with their source package, vendor, repository and
  signing key;
* weak (low-confidence) ``depends`` edges between included packages.

Node ids: files are in-image paths, services are ``Service.id``, packages are
``Package.id``; other kinds are prefixed (``vendor:``, ``repo:``, ``key:``) and
source packages use a purl with ``arch=source`` (``arch=src`` for rpm).
"""

from __future__ import annotations

import posixpath
import re
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from packageurl import PackageURL

from startup_sbom.errors import RootFSError
from startup_sbom.models import (
    Activation,
    Binary,
    Confidence,
    GraphEdge,
    GraphNode,
    LibraryLink,
    Package,
    PackageType,
    Report,
    Service,
)
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.rootfs import RootFS, normalize

#: Hard caps keeping the exported graph bounded on very large systems.
MAX_NODES = 30_000
MAX_EDGES = 150_000
#: Maximum loader hops followed from one executable through library Binary records.
MAX_LOAD_DEPTH = 16

BOOT_NODE = "boot"

CONFIDENCE_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
CONFIDENCE_WEIGHT = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.6, Confidence.LOW: 0.25}

#: ``LibraryLink.via`` → edge kind.
VIA_KIND = {
    "needed": "links",
    "dlopen": "dlopens",
    "preload": "preload",
    "interpreter": "interprets",
    "config": "loads_config",
}
#: Edge kinds through which code of the target ends up running in the source.
CODE_EDGE_KINDS = frozenset({"links", "dlopens", "preload", "interprets", "loads_config"})

_LANG_TYPES = frozenset(
    {PackageType.PYPI, PackageType.NPM, PackageType.GOLANG, PackageType.MAVEN, PackageType.CARGO}
)
_KIND_ORDER = {
    "boot": 0,
    "service": 1,
    "file": 2,
    "package": 3,
    "source_package": 4,
    "vendor": 5,
    "repository": 6,
    "signing_key": 7,
}


def weaker(a: Confidence, b: Confidence) -> Confidence:
    """The lower of two confidence tiers."""
    return a if CONFIDENCE_RANK[a] <= CONFIDENCE_RANK[b] else b


def _looks_like_library(path: str) -> bool:
    base = posixpath.basename(path)
    return base.endswith(".so") or ".so." in base


def is_language_package(pkg: Package) -> bool:
    """``True`` for embedded language-ecosystem packages (PyPI, npm, Go, ...)."""
    return pkg.type in _LANG_TYPES


# --------------------------------------------------------------------------- running set
class _Canon:
    """Canonicalise in-image paths (through the target's symlinks when ``fs`` is given)."""

    def __init__(self, fs: RootFS | None) -> None:
        self._fs = fs
        self._cache: dict[str, str] = {}

    def __call__(self, path: str) -> str:
        hit = self._cache.get(path)
        if hit is None:
            try:
                norm = normalize(path)
            except RootFSError:  # hostile path strings (NUL bytes)
                norm = path
            hit = (self._fs.try_resolve(norm) if self._fs is not None else None) or norm
            self._cache[path] = hit
        return hit


@dataclass(slots=True)
class RunningSet:
    """What actually runs: services, the files they execute and the code they load."""

    services: dict[str, Service] = field(default_factory=dict)  # non-masked, by id
    automatic: set[str] = field(default_factory=set)  # ids starting without a human
    executables: dict[str, set[str]] = field(default_factory=dict)  # path → service ids
    libraries: dict[str, set[str]] = field(default_factory=dict)  # path → service ids
    file_owner: dict[str, str] = field(default_factory=dict)  # path → package id
    package_services: dict[str, set[str]] = field(default_factory=dict)  # pkg → service ids
    binaries: dict[str, Binary] = field(default_factory=dict)  # canonical path → Binary
    canon: _Canon = field(default_factory=lambda: _Canon(None))

    @property
    def boot_packages(self) -> set[str]:
        """Packages owning an executable of an automatic service or a library it loads."""
        return {p for p, sids in self.package_services.items() if sids & self.automatic}

    def services_of_file(self, path: str) -> set[str]:
        return self.executables.get(path, set()) | self.libraries.get(path, set())


def compute_running(
    report: Report, owners: FileOwnerIndex | None = None, fs: RootFS | None = None
) -> RunningSet:
    """Derive the :class:`RunningSet` of ``report`` (pure; never touches package data)."""
    canon = _Canon(fs)
    rs = RunningSet(canon=canon)
    for binary in report.binaries:
        rs.binaries.setdefault(canon(binary.path), binary)
    for svc in report.services:
        if svc.masked:
            continue
        rs.services[svc.id] = svc
        if svc.starts_automatically:
            rs.automatic.add(svc.id)
        exes = [*svc.executables, *(c.executable for c in svc.commands if c.executable)]
        for exe in exes:
            if exe:
                rs.executables.setdefault(canon(exe), set()).add(svc.id)
        if len(set(map(canon, filter(None, exes)))) == 1 and len(svc.packages) == 1:
            rs.file_owner.setdefault(canon(next(e for e in exes if e)), svc.packages[0])
    for path, rec in rs.binaries.items():
        sids = {s for s in rec.used_by if s in rs.services}
        # a shared library "used by" a service is loaded, not executed: leave it to links
        if sids and (path in rs.executables or not _looks_like_library(path)):
            rs.executables.setdefault(path, set()).update(sids)
    # code loaded by each executable (transitively through library Binary records)
    for exe, sids in sorted(rs.executables.items()):
        seen = {exe}
        queue: deque[tuple[str, int]] = deque([(exe, 0)])
        while queue:
            cur, depth = queue.popleft()
            b = rs.binaries.get(cur)
            if b is None or depth >= MAX_LOAD_DEPTH:
                continue
            if b.package:
                rs.file_owner.setdefault(cur, b.package)
            loaded: list[tuple[str, str | None]] = [
                (canon(lk.path), lk.package) for lk in b.libraries if lk.path
            ]
            if b.interpreter:
                loaded.append((canon(b.interpreter), None))
            for lib, pkg in loaded:
                if lib == exe:
                    continue
                rs.libraries.setdefault(lib, set()).update(sids)
                if pkg:
                    rs.file_owner.setdefault(lib, pkg)
                if lib not in seen:
                    seen.add(lib)
                    queue.append((lib, depth + 1))
    for path in sorted(set(rs.executables) | set(rs.libraries)):
        owner = rs.file_owner.get(path)
        if owner is None and owners is not None:
            owner = owners.owner(path)
            if owner:
                rs.file_owner[path] = owner
        if owner:
            rs.package_services.setdefault(owner, set()).update(rs.services_of_file(path))
    return rs


# --------------------------------------------------------------------------- graph
@dataclass(slots=True)
class VendorGraph:
    """Mutable graph with de-duplicated nodes and edges (strongest confidence wins)."""

    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], GraphEdge] = field(default_factory=dict)
    truncated: bool = False

    def add_node(self, node_id: str, kind: str, label: str) -> bool:
        if node_id in self.nodes:
            return True
        if len(self.nodes) >= MAX_NODES:
            self.truncated = True
            return False
        self.nodes[node_id] = GraphNode(id=node_id, kind=kind, label=label[:200])
        return True

    def add_edge(
        self, source: str, target: str, kind: str, confidence: Confidence = Confidence.HIGH
    ) -> None:
        if source == target or source not in self.nodes or target not in self.nodes:
            return
        key = (source, target, kind)
        old = self.edges.get(key)
        if old is not None:
            if CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[old.confidence]:
                old.confidence = confidence
            return
        if len(self.edges) >= MAX_EDGES:
            self.truncated = True
            return
        self.edges[key] = GraphEdge(source=source, target=target, kind=kind, confidence=confidence)

    def sorted_nodes(self) -> list[GraphNode]:
        return sorted(self.nodes.values(), key=lambda n: (_KIND_ORDER.get(n.kind, 99), n.id))

    def sorted_edges(self) -> list[GraphEdge]:
        return [self.edges[k] for k in sorted(self.edges)]


def source_node_id(pkg: Package) -> str:
    """Stable id of the source package that built ``pkg``."""
    name = pkg.source_name or pkg.name
    version = pkg.source_version or pkg.version
    namespace: str | None = None
    if pkg.purl:
        try:
            namespace = PackageURL.from_string(pkg.purl).namespace
        except ValueError:
            namespace = None
    arch = "src" if pkg.type is PackageType.RPM else "source"
    try:
        return str(
            PackageURL(
                type=pkg.type.value,
                namespace=namespace,
                name=name,
                version=version or None,
                qualifiers={"arch": arch},
            ).to_string()
        )
    except ValueError:
        return f"source:{pkg.type.value}/{name}@{version}"


_DEP_SPLIT = re.compile(r"[,|]")
_DEP_NAME = re.compile(r"[\s(<>=!~\[]")


def dependency_names(dep: str) -> list[str]:
    """Package/provide names referenced by one dependency expression (any manager)."""
    out: list[str] = []
    for alt in _DEP_SPLIT.split(dep):
        tok = alt.strip().lstrip("!")
        if not tok:
            continue
        name = _DEP_NAME.split(tok, maxsplit=1)[0]
        name = name.split(":", 1)[0] if not name.startswith(("so:", "cmd:", "pc:")) else name
        if name:
            out.append(name)
    return out


def _link_edges(
    b: Binary,
    bpath: str,
    rs: RunningSet,
    direct: dict[str, set[str]],
) -> list[tuple[str, str, str, Confidence]]:
    """Edges ``(loader, loaded, kind, confidence)`` contributed by one Binary record.

    Link analysis may flatten the closure; a depth-``n`` link is attached to its
    explicit ``parent`` when present, else to a depth-``n-1`` library known to need
    it (from that library's own Binary record), else to the only depth-``n-1``
    library, else directly to the binary with confidence capped at medium.
    """
    canon = rs.canon
    out: list[tuple[str, str, str, Confidence]] = []
    by_depth: dict[int, list[LibraryLink]] = defaultdict(list)
    for lk in b.libraries:
        if lk.path:
            by_depth[lk.depth].append(lk)
    for lk in b.libraries:
        if not lk.path:
            continue
        target = canon(lk.path)
        kind = VIA_KIND.get(lk.via, "links")
        conf = lk.confidence
        parent = getattr(lk, "parent", None)
        sources: list[str]
        if isinstance(parent, str) and parent:
            sources = [canon(parent)]
        elif lk.depth <= 1 or lk.via == "preload":
            sources = [bpath]
        else:
            cands = sorted({canon(p.path) for p in by_depth.get(lk.depth - 1, []) if p.path})
            known = [c for c in cands if lk.soname in direct.get(c, ())]
            if known:
                sources = known
            elif len(cands) == 1:
                sources = cands
            else:
                sources = [bpath]
                conf = weaker(conf, Confidence.MEDIUM)
        out.extend((src, target, kind, conf) for src in sources if src != target)
    if b.interpreter:
        out.append((bpath, canon(b.interpreter), "interprets", Confidence.HIGH))
    return out


def build_graph(
    report: Report,
    running: RunningSet,
    *,
    flagged: Iterable[str] = (),
    vendor_of: dict[str, str] | None = None,
) -> VendorGraph:
    """Build the vendor-chain graph of ``report``.

    ``flagged`` are package ids that must be kept even when nothing running uses
    them (e.g. subjects of provenance findings); vulnerable packages and packages
    with ``provenance_flags`` are kept automatically.  ``vendor_of`` maps package
    ids to normalised vendor names (see :mod:`startup_sbom.supplychain.vendors`).
    """
    g = VendorGraph()
    pkgs = report.package_by_id()
    vendor_of = vendor_of or {}

    # services and boot
    g.add_node(BOOT_NODE, "boot", "system boot")
    for sid in sorted(running.services):
        svc = running.services[sid]
        g.add_node(sid, "service", svc.name)
        if sid in running.automatic:
            strong = {Activation.BOOT, Activation.ENTRYPOINT} & set(svc.activation)
            g.add_edge(
                BOOT_NODE, sid, "starts_at_boot", Confidence.HIGH if strong else Confidence.MEDIUM
            )
    for exe in sorted(running.executables):
        g.add_node(exe, "file", posixpath.basename(exe) or exe)
        for sid in sorted(running.executables[exe]):
            g.add_edge(sid, exe, "executes", Confidence.HIGH)

    # code-loading edges, walking Binary records reachable from service executables
    direct: dict[str, set[str]] = {}
    for path, rec in running.binaries.items():
        direct[path] = set(rec.needed) | {lk.soname for lk in rec.libraries if lk.depth <= 1}
    visited: set[str] = set()
    queue: deque[str] = deque(sorted(running.executables))
    while queue:
        cur = queue.popleft()
        if cur in visited:
            continue
        visited.add(cur)
        b = running.binaries.get(cur)
        if b is None:
            continue
        for src, dst, kind, conf in _link_edges(b, cur, running, direct):
            g.add_node(src, "file", posixpath.basename(src) or src)
            g.add_node(dst, "file", posixpath.basename(dst) or dst)
            g.add_edge(src, dst, kind, conf)
            if dst not in visited:
                queue.append(dst)

    # packages: owners of file nodes + vulnerable + flagged
    keep: set[str] = set(flagged)
    keep.update(v.package for v in report.vulnerabilities)
    keep.update(p.id for p in report.packages if p.provenance_flags)
    file_nodes = sorted(n.id for n in g.nodes.values() if n.kind == "file")
    ships: list[tuple[str, str]] = []
    for path in file_nodes:
        owner = running.file_owner.get(path)
        if owner:
            ships.append((owner, path))
            keep.add(owner)
    for pid in sorted(keep):
        pkg = pkgs.get(pid)
        if pkg is None:
            continue
        if not g.add_node(pid, "package", f"{pkg.name}@{pkg.version}"):
            break
        src_id = source_node_id(pkg)
        g.add_node(src_id, "source_package", pkg.source_name or pkg.name)
        g.add_edge(src_id, pid, "builds", Confidence.HIGH)
        vendor = vendor_of.get(pid)
        if vendor:
            vid = f"vendor:{vendor}"
            g.add_node(vid, "vendor", vendor)
            g.add_edge(vid, src_id, "maintains", Confidence.HIGH)
        if pkg.repository:
            for repo in pkg.repository.split(","):
                rid = f"repo:{repo.strip()}"
                g.add_node(rid, "repository", repo.strip())
                g.add_edge(pid, rid, "from_repo", Confidence.HIGH)
        if pkg.signing_key:
            kid = f"key:{pkg.signing_key.lower()}"
            g.add_node(kid, "signing_key", pkg.signing_key)
            g.add_edge(pid, kid, "signed_by", Confidence.HIGH)
    for owner, path in ships:
        g.add_edge(owner, path, "ships", Confidence.HIGH)

    # weak structural dependency edges between included packages
    provider: dict[str, set[str]] = defaultdict(set)
    included = [pkgs[n] for n in g.nodes if n in pkgs]
    for pkg in included:
        provider[pkg.name].add(pkg.id)
        for prov in pkg.provides:
            for name in dependency_names(prov):
                provider[name].add(pkg.id)
    for pkg in sorted(included, key=lambda p: p.id):
        for dep in pkg.depends:
            for name in dependency_names(dep):
                for target in sorted(provider.get(name, ())):
                    g.add_edge(pkg.id, target, "depends", Confidence.LOW)
    return g
