"""Supply-chain / vendor-chain analysis (pipeline step 9).

:func:`analyze` answers two questions for a scanned root filesystem:

* **Where does the code come from?**  Repository provenance per package
  (third-party repositories, unsigned/locally built packages, packages absent from
  every configured repository, superseded versions, modified files, unmanaged
  binaries, known-compromised releases, an end-of-life distribution).
* **How far does an issue in one vendor/package reach?**  A vendor → source →
  binary package → file → service graph and, for every vulnerable or high-risk
  package, the services it reaches through code-loading edges (the xz → liblzma →
  libsystemd → sshd class of chain), with one example path per service.

The distribution EOL lookup is network-backed and therefore separate:
:func:`~startup_sbom.supplychain.eol.lookup_eol` should populate
``report.os.eol`` before :func:`analyze` runs.
"""

from __future__ import annotations

from collections.abc import Iterable

from startup_sbom.context import ScanContext
from startup_sbom.models import Report, Severity, SupplyChain
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.supplychain.blast import blast_radius
from startup_sbom.supplychain.eol import lookup_eol
from startup_sbom.supplychain.graph import VendorGraph, build_graph, compute_running
from startup_sbom.supplychain.integrity import IntegrityResult, verify_integrity
from startup_sbom.supplychain.provenance import build_findings
from startup_sbom.supplychain.repos import analyze_repositories
from startup_sbom.supplychain.vendors import summarize_vendors, vendor_map

__all__ = [
    "VendorGraph",
    "analyze",
    "blast_radius",
    "build_graph",
    "lookup_eol",
]


def analyze(
    report: Report,
    records: list[PackageRecord],
    ctx: ScanContext,
    owners: FileOwnerIndex,
    *,
    unmanaged_executables: Iterable[str] = (),
) -> SupplyChain:
    """Run the supply-chain analysis and return the :class:`SupplyChain` section.

    Mutates ``report.packages`` in place: ``repository`` is filled when the
    package reader left it empty and ``provenance_flags`` gains the provenance
    flags found (``third_party_repo``, ``unsigned``, ``local_build``,
    ``not_in_repository``, ``repo_version_mismatch``, ``repo_checksum_mismatch``,
    ``unknown_signing_key``, ``modified_file``, ``suspicious_version``).
    ``report.supply_chain`` itself is *not* assigned; the caller does that.
    Limitations and warnings are recorded on ``ctx``.
    """
    running = compute_running(report, owners, ctx.fs)
    repos = analyze_repositories(ctx, report.packages, records)
    repos.apply(report.packages)

    integrity: IntegrityResult | None = None
    if ctx.options.integrity_check:
        integrity = verify_integrity(
            ctx, records, running, owners, extra_paths=(b.path for b in report.binaries)
        )

    ownership_known = any(r.files for r in records) or not records
    findings = build_findings(
        report,
        repos,
        running,
        integrity=integrity,
        unmanaged_executables=unmanaged_executables,
        fs=ctx.fs,
        ownership_known=ownership_known,
    )
    if not ownership_known:
        ctx.limit(
            "package databases record no file lists; unowned running files were not "
            "classified as unmanaged"
        )

    vendors = vendor_map(report.packages, repos.trust)
    flagged = {f.subject for f in findings if f.severity.rank >= Severity.MEDIUM.rank} & set(
        vendors
    )
    graph = build_graph(report, running, flagged=flagged, vendor_of=vendors)
    if graph.truncated:
        ctx.limit("supply-chain graph truncated at its node/edge budget")
    radius = blast_radius(report, graph, findings=findings)
    return SupplyChain(
        vendors=summarize_vendors(report, running, vendors),
        findings=findings,
        blast_radius=radius,
        nodes=graph.sorted_nodes(),
        edges=graph.sorted_edges(),
    )
