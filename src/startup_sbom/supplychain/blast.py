"""Blast radius: how an issue in one package propagates to what actually runs.

For every vulnerable or high-risk package the graph is traversed *backwards*
along code-loading edges — the package ships a file, which is loaded by a
library or binary, which is executed by a service — with a strongest-path
(confidence-weighted, Dijkstra-style) search.  Exactly one example path is kept
per affected service, e.g.::

    pkg:deb/debian/xz-utils@5.6.1-1?arch=source
    pkg:deb/debian/liblzma5@5.6.1-1?arch=amd64
    /usr/lib/x86_64-linux-gnu/liblzma.so.5
    /usr/lib/x86_64-linux-gnu/libsystemd.so.0
    /usr/sbin/sshd
    systemd:ssh.service

Package ``depends`` edges are only a weak (low-confidence) fallback; ELF linkage
is what finds the xz → libsystemd → sshd chain.
"""

from __future__ import annotations

import heapq
import math
from collections import defaultdict
from collections.abc import Iterable

from startup_sbom.models import (
    BlastRadius,
    Confidence,
    GraphEdge,
    GraphNode,
    Report,
    Service,
    Severity,
    SupplyChain,
    SupplyChainFinding,
)
from startup_sbom.supplychain.graph import CODE_EDGE_KINDS, CONFIDENCE_WEIGHT, VendorGraph
from startup_sbom.supplychain.vendors import open_vulnerabilities

MAX_EXAMPLE_PATHS = 10
MAX_BINARIES = 200
MAX_PATH_LEN = 40
MAX_EXPANSIONS = 250_000
DEPENDS_WEIGHT = CONFIDENCE_WEIGHT[Confidence.LOW]

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.UNKNOWN: 0.4,
    Severity.NONE: 0.1,
}
KEV_MULTIPLIER = 1.5


def service_criticality(svc: Service | None) -> float:
    """Relative weight of a service: automatic start, network exposure, root."""
    if svc is None:
        return 0.5
    weight = 1.0 if svc.starts_automatically else 0.25
    if svc.network_exposed:
        weight *= 3.0
    if svc.hardening.runs_as_root:
        weight *= 1.5
    return weight


class _Adjacency:
    """Reverse ("who is affected by") adjacency built from nodes and edges."""

    def __init__(self, nodes: Iterable[GraphNode], edges: Iterable[GraphEdge]) -> None:
        self.kind: dict[str, str] = {n.id: n.kind for n in nodes}
        self.forward: dict[str, list[tuple[str, float]]] = defaultdict(list)
        self.source_of: dict[str, str] = {}
        self.vendor_of_source: dict[str, str] = {}
        self.executed: set[str] = set()
        for e in edges:
            w = CONFIDENCE_WEIGHT[e.confidence]
            if e.kind == "ships":
                self.forward[e.source].append((e.target, w))
            elif e.kind in CODE_EDGE_KINDS:
                self.forward[e.target].append((e.source, w))
            elif e.kind == "executes":
                self.forward[e.target].append((e.source, w))
                self.executed.add(e.target)
            elif e.kind == "depends":
                self.forward[e.target].append((e.source, min(w, DEPENDS_WEIGHT)))
            elif e.kind == "builds":
                self.source_of.setdefault(e.target, e.source)
            elif e.kind == "maintains":
                self.vendor_of_source.setdefault(e.target, e.source)
        for lst in self.forward.values():
            lst.sort()

    def vendor(self, package: str) -> str | None:
        src = self.source_of.get(package)
        vid = self.vendor_of_source.get(src or package) or self.vendor_of_source.get(package)
        if vid is None:
            return None
        return vid.removeprefix("vendor:")


def _strongest_paths(adj: _Adjacency, seed: str) -> dict[str, tuple[float, tuple[str, ...]]]:
    """Best ``(strength, path)`` from ``seed`` to every node reachable in reverse."""
    best: dict[str, tuple[float, tuple[str, ...]]] = {}
    heap: list[tuple[float, int, tuple[str, ...]]] = [(-1.0, 1, (seed,))]
    expansions = 0
    while heap and expansions < MAX_EXPANSIONS:
        neg, _length, path = heapq.heappop(heap)
        node = path[-1]
        if node in best:
            continue
        best[node] = (-neg, path)
        expansions += 1
        if adj.kind.get(node) == "service" or len(path) >= MAX_PATH_LEN:
            continue
        for nxt, w in adj.forward.get(node, ()):
            if nxt in best or nxt in path:
                continue
            # package → package hops are only meaningful from a package node
            if adj.kind.get(nxt) == "package" and adj.kind.get(node) != "package":
                continue
            heapq.heappush(heap, (neg * w, len(path) + 1, (*path, nxt)))
    return best


def _seeds(
    report: Report, findings: Iterable[SupplyChainFinding]
) -> dict[str, tuple[list[str], float, bool]]:
    """``package id → (vulnerability ids, severity weight, kev)`` for every seed."""
    pkg_ids = {p.id for p in report.packages}
    seeds: dict[str, tuple[list[str], float, bool]] = {}
    for pid, vid, sev, kev in open_vulnerabilities(report):
        vids, weight, has_kev = seeds.get(pid, ([], 0.0, False))
        if vid not in vids:
            vids.append(vid)
        seeds[pid] = (vids, max(weight, SEVERITY_WEIGHT[sev]), has_kev or kev)
    for f in findings:
        if f.subject in pkg_ids and f.severity.rank >= Severity.HIGH.rank:
            vids, weight, has_kev = seeds.get(f.subject, ([], 0.0, False))
            seeds[f.subject] = (vids, max(weight, SEVERITY_WEIGHT[f.severity]), has_kev)
    return seeds


def blast_radius(
    report: Report,
    graph: VendorGraph | SupplyChain,
    *,
    findings: Iterable[SupplyChainFinding] | None = None,
) -> list[BlastRadius]:
    """Blast radius of every vulnerable package or package with a high-severity finding.

    ``findings`` defaults to ``report.supply_chain.findings``.  The score (0–100)
    grows with the number and criticality of affected services (automatic start,
    network exposure, root) weighted by path strength, times the worst
    vulnerability/finding severity, times 1.5 when a vulnerability is in CISA KEV.
    """
    if isinstance(graph, VendorGraph):
        adj = _Adjacency(graph.nodes.values(), graph.edges.values())
    else:
        adj = _Adjacency(graph.nodes, graph.edges)
    services = report.service_by_id()
    seeds = _seeds(report, report.supply_chain.findings if findings is None else findings)
    out: list[BlastRadius] = []
    for pid in sorted(seeds):
        vids, sev_weight, kev = seeds[pid]
        best = _strongest_paths(adj, pid) if pid in adj.kind else {pid: (1.0, (pid,))}
        prefix: tuple[str, ...] = ()
        src = adj.source_of.get(pid)
        if src is not None:
            prefix = (src,)
        hits: list[tuple[float, str, tuple[str, ...]]] = []
        files: set[str] = set()
        for node, (strength, path) in best.items():
            kind = adj.kind.get(node)
            if kind == "service":
                crit = service_criticality(services.get(node)) * strength
                hits.append((crit, node, path))
            elif kind == "file" and (node in adj.executed or len(path) > 2):
                files.add(node)
        hits.sort(key=lambda h: (-h[0], h[1]))
        total = sum(h[0] for h in hits)
        reach = 1.0 - math.exp(-total / 3.0)
        score = round(min(100.0, 100.0 * reach * sev_weight * (KEV_MULTIPLIER if kev else 1.0)), 2)
        out.append(
            BlastRadius(
                package=pid,
                vendor=adj.vendor(pid),
                services=sorted(h[1] for h in hits),
                binaries=sorted(files)[:MAX_BINARIES],
                example_paths=[list(prefix + h[2]) for h in hits[:MAX_EXAMPLE_PATHS]],
                vulnerabilities=sorted(vids),
                score=score,
            )
        )
    out.sort(key=lambda b: (-b.score, -len(b.services), b.package))
    return out
