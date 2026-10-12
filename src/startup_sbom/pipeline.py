"""Scan orchestration: target → inventory → services → linkage → vulns → threats → chains."""

from __future__ import annotations

import logging
import threading
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

from startup_sbom import __version__
from startup_sbom.context import ScanContext, ScanOptions
from startup_sbom.errors import ScanCancelledError
from startup_sbom.models import (
    Activation,
    Binary,
    Coverage,
    Package,
    Report,
    ScanMetadata,
    Service,
    Severity,
    SSVCDecision,
    Summary,
    VulnStatus,
)
from startup_sbom.net import HttpClient
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """Emitted when a pipeline stage starts (``index`` is 1-based)."""

    stage: str
    index: int
    total: int


ProgressFn = Callable[[ProgressEvent], None]


def _stage_count(options: ScanOptions) -> int:
    optional = (
        options.language_packages,
        bool(options.vuln_sources),
        options.eol,
        options.prefetch_intel,
    )
    return 8 + sum(optional)


class _Stages:
    """Runs pipeline stages, isolating failures so one broken stage never sinks a scan."""

    def __init__(
        self,
        ctx: ScanContext,
        progress: ProgressFn | None,
        *,
        strict: bool,
        cancel: threading.Event | None = None,
    ) -> None:
        self.ctx = ctx
        self.progress = progress
        self.strict = strict
        self.cancel = cancel
        self.index = 0
        self.total = _stage_count(ctx.options)

    @contextmanager
    def stage(self, title: str) -> Iterator[None]:
        if self.cancel is not None and self.cancel.is_set():
            raise ScanCancelledError(f"scan cancelled before: {title}")
        self.index += 1
        if self.progress is not None:
            self.progress(ProgressEvent(title, self.index, self.total))
        log.info("stage %d/%d: %s", self.index, self.total, title)
        try:
            yield
        except ScanCancelledError:
            raise
        except Exception as exc:
            if self.strict:
                raise
            log.debug("stage %r failed", title, exc_info=True)
            self.ctx.warn(f"{title} failed: {type(exc).__name__}: {exc}")
            self.ctx.limit(f"{title} did not complete; results are partial")


def scan(
    target: str,
    options: ScanOptions | None = None,
    *,
    http: HttpClient | None = None,
    progress: ProgressFn | None = None,
    strict: bool = False,
    cancel: threading.Event | None = None,
) -> Report:
    """Analyse ``target`` and return a complete :class:`~startup_sbom.models.Report`.

    ``target`` uses the scheme syntax of the CLI (``dir:/mnt/root``, ``tar:x.tar``,
    ``docker:web``, ``oci-dir:./img`` …).  The scan never executes, mounts or
    modifies anything in the target.  With ``strict=True`` stage failures raise
    instead of being recorded as warnings.  Setting ``cancel`` stops the scan at
    the next stage boundary with :class:`~startup_sbom.errors.ScanCancelledError`.
    """
    from startup_sbom.sources import open_target

    options = options or ScanOptions()
    started = datetime.now(UTC)
    owns_http = http is None
    client = http or HttpClient(
        offline=options.offline, cache_dir=options.cache_dir, timeout=options.http_timeout
    )
    try:
        with open_target(target, platform=options.platform) as acquired:
            ctx = ScanContext(fs=acquired.fs, options=options, container=acquired.container)
            report = Report(
                metadata=ScanMetadata(
                    tool_version=__version__,
                    scan_id=str(uuid.uuid4()),
                    started=started,
                    target=acquired.target,
                ),
                container=acquired.container,
            )
            stages = _Stages(ctx, progress, strict=strict, cancel=cancel)
            _run(report, ctx, client, stages, acquired.live_host)
            report.warnings = sorted(
                set(ctx.warnings + acquired.fs.warnings + list(acquired.warnings))
            )
            report.metadata.coverage.limitations = sorted(set(ctx.limitations))
    finally:
        if owns_http:
            client.close()
    report.metadata.finished = datetime.now(UTC)
    return report


def _run(
    report: Report, ctx: ScanContext, http: HttpClient, stages: _Stages, live_host: bool
) -> None:
    from startup_sbom import binaries, distro, initsys, langpkgs, pkgdb, threat, vulns
    from startup_sbom import supplychain as sc

    opts = ctx.options
    coverage: Coverage = report.metadata.coverage
    coverage.offline = opts.offline
    records: list[PackageRecord] = []
    owners = FileOwnerIndex(ctx.fs)
    services: list[Service] = []
    bins: dict[str, Binary] = {}
    unmanaged: list[str] = []

    with stages.stage("Identifying operating system"):
        ctx.os = distro.identify(ctx.fs)
        report.os = ctx.os
        coverage.vulnerability_ecosystems = list(ctx.os.vuln_ecosystems)

    with stages.stage("Reading package databases"):
        records, dbs = pkgdb.read_all(ctx)
        coverage.package_databases = sorted(dbs)
        if not dbs:
            ctx.limit("no supported package database found; ownership cannot be attributed")
        owners.add_records(records)

    with stages.stage("Discovering services"):
        services = initsys.discover_all(ctx)
        coverage.init_systems = sorted({s.init_system.value for s in services})
        _attach_boot_timing(ctx, services, live_host)
        for svc in services:
            pkgs: list[str] = []
            for exe in svc.executables:
                for owner in owners.owners(exe):
                    if owner not in pkgs:
                        pkgs.append(owner)
            svc.packages = pkgs

    exec_users: dict[str, list[str]] = defaultdict(list)
    for svc in services:
        for exe in svc.executables:
            exec_users[exe].append(svc.id)

    with stages.stage("Analysing executables and linked libraries"):
        bins = binaries.analyze_executables(
            ctx, sorted(exec_users), owners, max_depth=opts.max_link_depth, used_by=exec_users
        )
        for priv in binaries.find_privileged(ctx, records, owners):
            existing = bins.get(priv.path)
            if existing is None:
                bins[priv.path] = priv
            else:
                existing.setuid = existing.setuid or priv.setuid
                existing.setgid = existing.setgid or priv.setgid
                existing.capabilities = sorted(set(existing.capabilities) | set(priv.capabilities))
        unmanaged = binaries.find_unmanaged_executables(ctx, owners)

    if opts.language_packages:
        with stages.stage("Inventorying embedded language packages"):
            lang = langpkgs.scan(ctx, owners, executables=sorted(exec_users))
            records.extend(lang)
            for rec in lang:
                owners.add(rec.package.id, rec.files)

    report.packages = _dedupe_packages(records, ctx)
    report.services = services
    report.binaries = list(bins.values())

    if opts.vuln_sources:
        with stages.stage("Matching vulnerabilities"):
            report.vulnerabilities = vulns.match_vulnerabilities(ctx, report.packages, http)
            coverage.vulnerability_sources = sorted(
                {s for v in report.vulnerabilities for s in v.sources} | ctx.vuln_sources_used
            )
    else:
        ctx.limit("vulnerability matching disabled")

    if opts.eol:
        with stages.stage("Checking end-of-life status"):
            report.os.eol = sc.eol.lookup_eol(ctx.os, http)

    with stages.stage("Analysing supply chain"):
        report.supply_chain = sc.analyze(
            report, records, ctx, owners, unmanaged_executables=unmanaged
        )

    with stages.stage("Reversing vulnerabilities into threats"):
        report.threats = threat.reverse_vulnerabilities(report, ctx)

    if opts.prefetch_intel and report.threats:
        with stages.stage("Prefetching vulnerability intelligence"):
            from startup_sbom import intel

            report.intel = intel.prefetch(report, ctx, http)
            if report.intel:
                # Re-reverse with intel in hand: public PoC / active exploitation
                # can only raise SSVC exploitation and risk, never lower them.
                report.threats = threat.reverse_vulnerabilities(report, ctx)

    with stages.stage("Mapping chained attacks"):
        report.attack_chains = threat.build_attack_chains(report, report.threats, ctx)

    with stages.stage("Explaining results"):
        _explain(report)

    _finalize(report)


def _explain(report: Report) -> None:
    try:
        from startup_sbom.explain import explain_report
    except ImportError:  # pragma: no cover - module still landing
        return
    explain_report(report)


def _attach_boot_timing(ctx: ScanContext, services: list[Service], live_host: bool) -> None:
    from startup_sbom.boottime import load_boot_timing
    from startup_sbom.sources.host import live_boot_timing

    timings: dict[str, float] = {}
    if ctx.options.boot_timing_file is not None:
        timings = load_boot_timing(ctx.options.boot_timing_file)
    elif live_host:
        timings = live_boot_timing()
    if not timings:
        return
    for svc in services:
        value = timings.get(svc.name)
        if value is None and "." not in svc.name:
            value = timings.get(svc.name + ".service")
        if value is not None:
            svc.start_time_ms = value


def _dedupe_packages(records: list[PackageRecord], ctx: ScanContext) -> list[Package]:
    seen: dict[str, Package] = {}
    for rec in records:
        pkg = rec.package
        if pkg.id in seen:
            if seen[pkg.id] != pkg:
                ctx.warn(f"duplicate package id {pkg.id}; keeping the first occurrence")
            continue
        seen[pkg.id] = pkg
    return list(seen.values())


_ACTIVE = (VulnStatus.AFFECTED, VulnStatus.NO_FIX_AVAILABLE, VulnStatus.UNDER_INVESTIGATION)


def _finalize(report: Report) -> None:
    """Sort everything canonically and compute the summary."""
    report.packages.sort(key=lambda p: (p.type.value, p.name, p.id))
    report.services.sort(key=lambda s: s.id)
    report.binaries.sort(key=lambda b: b.path)
    report.vulnerabilities.sort(key=lambda v: (-v.severity.rank, v.id, v.package))
    report.threats.sort(key=lambda t: (-t.risk_score, t.id))
    report.attack_chains.sort(key=lambda c: (-c.score, c.id))

    pkg_services: set[str] = {
        p for s in report.services if s.starts_automatically for p in s.packages
    }
    for b in report.binaries:
        if b.used_by:
            pkg_services.update(lnk.package for lnk in b.libraries if lnk.package)
    active = [v for v in report.vulnerabilities if v.status in _ACTIVE]
    severities = Counter(v.severity.value for v in active)
    decisions = Counter(t.ssvc.decision for t in report.threats if t.ssvc is not None)
    report.summary = Summary(
        packages=len(report.packages),
        boot_packages=len(pkg_services),
        services=len(report.services),
        boot_services=sum(1 for s in report.services if Activation.BOOT in s.activation),
        network_services=sum(1 for s in report.services if s.network_exposed),
        vulnerabilities=len(active),
        by_severity={s.value: severities.get(s.value, 0) for s in Severity},
        kev=sum(1 for v in active if v.kev is not None),
        threats=len(report.threats),
        act=decisions.get(SSVCDecision.ACT, 0),
        attend=decisions.get(SSVCDecision.ATTEND, 0),
        attack_chains=len(report.attack_chains),
        supply_chain_findings=len(report.supply_chain.findings),
    )
