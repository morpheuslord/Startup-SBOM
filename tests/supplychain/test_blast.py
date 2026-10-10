"""Vendor-chain graph and blast radius (the xz → liblzma → libsystemd → sshd case)."""

from __future__ import annotations

import random
from collections.abc import Callable

import pytest
from sc_helpers import LIB, link, pkg, report, service, vuln, xz_report

from startup_sbom.context import ScanContext
from startup_sbom.models import Binary, Severity
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.rootfs import RootFS
from startup_sbom.supplychain import analyze, blast_radius, build_graph
from startup_sbom.supplychain.graph import compute_running, source_node_id
from startup_sbom.supplychain.vendors import vendor_map

XZ_SRC = "pkg:deb/debian/xz-utils@5.6.1-1?arch=source"
LZMA = "pkg:deb/debian/liblzma5@5.6.1-1?arch=amd64"
EXPECTED_PATH = [
    XZ_SRC,
    LZMA,
    f"{LIB}/liblzma.so.5",
    f"{LIB}/libsystemd.so.0",
    "/usr/sbin/sshd",
    "systemd:ssh.service",
]


@pytest.mark.parametrize(
    ("libsystemd_record", "extra_direct"),
    [(True, False), (True, True), (False, False)],
    ids=["library-record", "library-record-ambiguous", "single-parent-inference"],
)
def test_xz_blast_radius_without_depends(libsystemd_record: bool, extra_direct: bool) -> None:
    rep = xz_report(libsystemd_record=libsystemd_record, extra_direct=extra_direct)
    assert all(not p.depends for p in rep.packages)
    running = compute_running(rep)
    graph = build_graph(rep, running, vendor_of=vendor_map(rep.packages, None))
    assert not any(e.kind == "depends" for e in graph.edges.values())
    radius = blast_radius(rep, graph, findings=[])
    by_pkg = {b.package: b for b in radius}
    xz = by_pkg[LZMA]
    assert xz.services == ["systemd:ssh.service"]
    assert xz.example_paths == [EXPECTED_PATH]
    assert xz.vulnerabilities == ["CVE-2024-3094"]
    assert "/usr/sbin/sshd" in xz.binaries
    assert xz.score > 50
    assert "systemd:cron.service" not in xz.services


def test_ambiguous_parent_falls_back_to_medium_direct_edge() -> None:
    rep = xz_report(libsystemd_record=False, extra_direct=True)
    graph = build_graph(rep, compute_running(rep))
    edge = graph.edges[("/usr/sbin/sshd", f"{LIB}/liblzma.so.5", "links")]
    assert edge.confidence == "medium"
    radius = blast_radius(rep, graph, findings=[])
    assert radius[0].example_paths == [
        [XZ_SRC, LZMA, f"{LIB}/liblzma.so.5", "/usr/sbin/sshd", "systemd:ssh.service"]
    ]


def test_depends_is_only_a_weak_fallback() -> None:
    libfoo = pkg("libfoo1", "1.0-1")
    daemon = pkg("food", "1.0-1", depends=["libfoo1 (>= 1.0)", "libc6 | libc6.1"])
    rep = report(
        [libfoo, daemon],
        services=[service("food.service", "/usr/sbin/food", packages=[daemon.id])],
        binaries=[
            Binary(path="/usr/sbin/food", package=daemon.id, used_by=["systemd:food.service"])
        ],
        vulns=[vuln(libfoo, "CVE-2026-0001", Severity.HIGH)],
    )
    graph = build_graph(rep, compute_running(rep))
    edge = graph.edges[(daemon.id, libfoo.id, "depends")]
    assert edge.confidence == "low"
    (radius,) = blast_radius(rep, graph, findings=[])
    assert radius.services == ["systemd:food.service"]
    assert radius.example_paths[0] == [
        source_node_id(libfoo),
        libfoo.id,
        daemon.id,
        "/usr/sbin/food",
        "systemd:food.service",
    ]
    linked = xz_report(libsystemd_record=True)
    linked_score = blast_radius(linked, build_graph(linked, compute_running(linked)), findings=[])
    assert radius.score < linked_score[0].score


def test_unreached_vulnerable_package_has_zero_score() -> None:
    lonely = pkg("libunused", "1")
    rep = report([lonely], vulns=[vuln(lonely, "CVE-1", Severity.CRITICAL)])
    (radius,) = blast_radius(rep, build_graph(rep, compute_running(rep)), findings=[])
    assert radius.services == []
    assert radius.score == 0.0


def test_preload_reaches_every_dynamic_executable() -> None:
    evil = pkg("evil", "1")
    rep = xz_report(libsystemd_record=True)
    rep.packages.append(evil)
    for b in rep.binaries:
        if b.used_by:
            b.libraries.append(link("libevil.so", "/usr/lib/libevil.so", evil.id, via="preload"))
    rep.vulnerabilities.append(vuln(evil, "MAL-1", Severity.CRITICAL))
    radius = {
        b.package: b for b in blast_radius(rep, build_graph(rep, compute_running(rep)), findings=[])
    }
    assert radius[evil.id].services == ["systemd:cron.service", "systemd:ssh.service"]


def _analyze(rep_factory: Callable[[], object], ctx: ScanContext) -> str:
    rep = rep_factory()
    owners = FileOwnerIndex(ctx.fs)
    sc = analyze(rep, [], ctx, owners)  # type: ignore[arg-type]
    return sc.model_dump_json()


def test_analyze_is_deterministic(
    make_dir_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(make_dir_fs({"/etc/os-release": "ID=debian\n"}))

    def shuffled() -> object:
        rep = xz_report(libsystemd_record=True)
        rng = random.Random(len(rep.packages))  # noqa: S311 - deterministic shuffle
        rng.shuffle(rep.packages)
        rep.services.reverse()
        rep.binaries.reverse()
        return rep

    first = _analyze(lambda: xz_report(libsystemd_record=True), ctx)
    second = _analyze(shuffled, ctx)
    assert first == second


def test_analyze_end_to_end_xz(
    make_dir_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(make_dir_fs({"/etc/os-release": "ID=debian\n"}))
    rep = xz_report(libsystemd_record=True)
    ctx.os = rep.os
    sc = analyze(rep, [], ctx, FileOwnerIndex(ctx.fs))
    kinds = {f.kind for f in sc.findings}
    assert "suspicious_version" in kinds
    top = sc.blast_radius[0]
    assert top.package == LZMA
    assert top.vendor == "Debian"
    assert top.example_paths[0] == EXPECTED_PATH
    node_ids = {n.id for n in sc.nodes}
    assert {"boot", "systemd:ssh.service", XZ_SRC, "vendor:Debian"} <= node_ids
    assert any(e.kind == "starts_at_boot" and e.target == "systemd:ssh.service" for e in sc.edges)
    debian = next(v for v in sc.vendors if v.vendor == "Debian")
    assert debian.critical == 1
    assert debian.kev == 1
    assert debian.boot_packages == 5
    assert "suspicious_version" in next(p for p in rep.packages if p.id == LZMA).provenance_flags


def test_library_used_by_service_is_not_treated_as_executed() -> None:
    rep = xz_report(libsystemd_record=True)
    for b in rep.binaries:
        if b.path.endswith("libsystemd.so.0"):
            b.used_by = ["systemd:ssh.service"]
    graph = build_graph(rep, compute_running(rep))
    assert ("systemd:ssh.service", f"{LIB}/libsystemd.so.0", "executes") not in graph.edges
    radius = {b.package: b for b in blast_radius(rep, graph, findings=[])}
    assert radius[LZMA].example_paths == [EXPECTED_PATH]
