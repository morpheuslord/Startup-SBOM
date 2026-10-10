"""Vulnerability matching orchestration: sources -> dedupe -> EPSS/KEV enrichment.

Every gap is surfaced: a distro OSV does not cover, a source that failed, data
missing from the offline cache -- each becomes a ``ctx.limit`` entry so a report
never presents "no data" as "no vulnerabilities".
"""

from __future__ import annotations

import time
from collections import Counter
from datetime import UTC, datetime

from startup_sbom.context import ScanContext
from startup_sbom.errors import NetworkError
from startup_sbom.models import Package, PackageType, Vulnerability
from startup_sbom.net import HttpClient
from startup_sbom.vulns.arch import ArchTrackerSource, load_arch_groups
from startup_sbom.vulns.base import VulnerabilitySource
from startup_sbom.vulns.epss import EPSS_TTL, fetch_epss_csv, load_epss, parse_epss_csv
from startup_sbom.vulns.kev import KEV_TTL, KEV_URL, load_kev, parse_kev
from startup_sbom.vulns.normalize import is_cve, merge_vulnerabilities
from startup_sbom.vulns.nvd import NvdSource
from startup_sbom.vulns.osv import OS_TYPES, OsvSource

KNOWN_SOURCES = ("osv", "arch", "nvd")
_UNSUPPORTED = {
    "fedora": "Fedora",
    "amzn": "Amazon Linux",
    "ol": "Oracle Linux",
    "centos": "CentOS / CentOS Stream",
    "photon": "Photon OS",
    "gentoo": "Gentoo",
    "clear-linux-os": "Clear Linux",
    "void": "Void Linux",
    "nixos": "NixOS",
    "slackware": "Slackware",
}
_RECOVERABLE = (NetworkError, ValueError, KeyError, TypeError, AttributeError)


def _os_label(ctx: ScanContext) -> str:
    os = ctx.os
    return os.pretty_name or (f"{os.id} {os.version_id}" if os.version_id else os.id)


def select_sources(
    ctx: ScanContext, packages: list[Package], http: HttpClient
) -> list[VulnerabilitySource]:
    """Primary sources enabled by ``ctx.options.vuln_sources`` (NVD is handled as fallback).

    The Arch tracker is the only data for ``alpm`` packages, so it is enabled whenever
    OSV is, rather than leaving Arch systems silently unassessed.
    """
    wanted = tuple(s.lower() for s in ctx.options.vuln_sources)
    for unknown in sorted(set(wanted) - set(KNOWN_SOURCES)):
        ctx.warn(f"unknown vulnerability source ignored: {unknown}")
    sources: list[VulnerabilitySource] = []
    if "osv" in wanted:
        sources.append(OsvSource(http))
    has_alpm = any(p.type == PackageType.ALPM for p in packages)
    if "arch" in wanted or ("osv" in wanted and has_alpm):
        sources.append(ArchTrackerSource(http))
    return sources


def _run(ctx: ScanContext, source: VulnerabilitySource, pkgs: list[Package]) -> list[Vulnerability]:
    try:
        return source.match(ctx, pkgs)
    except _RECOVERABLE as exc:
        ctx.warn(f"{source.name}: vulnerability matching failed: {exc}")
        if ctx.options.offline or "offline" in str(exc):
            ctx.limit(
                f"offline: no cached {source.name} vulnerability data for {len(pkgs)} packages;"
                " run `startup-sbom db update` online first"
            )
        else:
            ctx.limit(f"{source.name}: {len(pkgs)} packages not assessed ({exc})")
        return []


def _uncovered_limits(ctx: ScanContext, uncovered: list[Package]) -> None:
    by_type = Counter(p.type for p in uncovered)
    for ptype, count in sorted(by_type.items()):
        if ptype in OS_TYPES:
            name = _UNSUPPORTED.get(ctx.os.id)
            if name or not ctx.os.vuln_ecosystems:
                label = name or _os_label(ctx)
                ctx.limit(
                    f"vulnerabilities not assessed for {count} {ptype} packages: {label} is not"
                    " covered by OSV.dev (no distro advisory source; NVD CPE matching is"
                    " available as an opt-in approximation)"
                )
            else:
                ctx.limit(
                    f"vulnerabilities not assessed for {count} {ptype} packages: no OSV ecosystem"
                    f" of {_os_label(ctx)} ({', '.join(ctx.os.vuln_ecosystems)}) fits {ptype}"
                )
        elif ptype == PackageType.ALPM:
            ctx.limit(f"vulnerabilities not assessed for {count} alpm packages (arch source off)")
        else:
            ctx.limit(f"vulnerabilities not assessed for {count} {ptype} packages (no source)")


def match_vulnerabilities(
    ctx: ScanContext, packages: list[Package], http: HttpClient
) -> list[Vulnerability]:
    """Match ``packages`` against the enabled sources, dedupe by CVE and enrich.

    Network problems never raise: they become ``ctx.warn`` + ``ctx.limit`` entries
    and whatever succeeded is returned.  Output is sorted by ``(package, id)``.
    """
    if not ctx.options.vuln_sources:
        ctx.limit("vulnerability matching disabled (no vulnerability sources selected)")
        return []
    results: list[Vulnerability] = []
    covered: set[str] = set()
    for source in select_sources(ctx, packages, http):
        pkgs = source.applicable(ctx, packages)
        if not pkgs:
            continue
        covered.update(p.id for p in pkgs)
        results.extend(_run(ctx, source, pkgs))
    uncovered = [p for p in packages if p.id not in covered]
    if "nvd" in (s.lower() for s in ctx.options.vuln_sources) and uncovered:
        nvd = NvdSource(http, ctx.options.nvd_api_key)
        pkgs = nvd.applicable(ctx, uncovered)
        if pkgs:
            covered.update(p.id for p in pkgs)
            results.extend(_run(ctx, nvd, pkgs))
        uncovered = [p for p in uncovered if p.id not in covered]
    if uncovered:
        _uncovered_limits(ctx, uncovered)
    merged = merge_vulnerabilities(results, {p.id: p.type for p in packages})
    return enrich(ctx, merged, http)


def enrich(ctx: ScanContext, vulns: list[Vulnerability], http: HttpClient) -> list[Vulnerability]:
    """Attach EPSS score/percentile and CISA KEV data (per ``ctx.options``)."""
    cves = sorted({v.id for v in vulns if is_cve(v.id)})
    if not cves:
        return vulns
    kev = {}
    if ctx.options.kev:
        try:
            kev = load_kev(http).entries
        except NetworkError as exc:
            ctx.warn(f"kev: CISA KEV catalog unavailable: {exc}")
            ctx.limit("kev: known-exploited status not assessed (CISA KEV catalog unavailable)")
    epss: dict[str, tuple[float, float]] = {}
    if ctx.options.epss:
        try:
            epss = load_epss(http, cves)
        except NetworkError as exc:
            ctx.warn(f"epss: EPSS scores unavailable: {exc}")
            ctx.limit("epss: exploit prediction scores not assessed (EPSS data unavailable)")
    if not kev and not epss:
        return vulns
    out = []
    for v in vulns:
        update: dict[str, object] = {}
        if v.id in kev:
            update["kev"] = kev[v.id]
        if v.id in epss:
            update["epss"], update["epss_percentile"] = epss[v.id]
        out.append(v.model_copy(update=update) if update else v)
    return out


# --------------------------------------------------------------------------- feeds
def update_feeds(http: HttpClient, *, arch: bool = False) -> dict[str, str]:
    """Refresh the KEV catalog and EPSS scores (and optionally the Arch tracker) in the
    cache, for ``startup-sbom db update``.  Returns a status line per feed."""
    status: dict[str, str] = {}
    try:
        cat = load_kev(http, force=True)
        status["kev"] = f"ok: catalog {cat.version or '?'}, {len(cat.entries)} entries"
    except NetworkError as exc:
        status["kev"] = f"error: {exc}"
    try:
        raw, day = fetch_epss_csv(http, force=True)
        data = parse_epss_csv(raw)
        status["epss"] = f"ok: scores {data.score_date or day}, {len(data.scores)} CVEs"
    except NetworkError as exc:
        status["epss"] = f"error: {exc}"
    if arch:
        try:
            groups = load_arch_groups(http, force=True)
            status["arch"] = f"ok: {len(groups)} advisory groups"
        except NetworkError as exc:
            status["arch"] = f"error: {exc}"
    return status


def feed_status(http: HttpClient) -> dict[str, str]:
    """Describe what the cache holds for each feed without touching the network."""
    view = HttpClient(offline=True, cache_dir=http.cache_dir)
    status: dict[str, str] = {}
    try:
        try:
            resp = view.get(KEV_URL, ttl=KEV_TTL)
            cat = parse_kev(resp.content)
            status["kev"] = f"cached: catalog {cat.version or '?'}, {len(cat.entries)} entries"
            if resp.stale:
                status["kev"] += " (stale)"
        except NetworkError:
            status["kev"] = "missing"
        pointer = view.cache_get_json("epss", "latest", float("inf"))
        if isinstance(pointer, dict) and isinstance(pointer.get("date"), str):
            age = time.time() - float(pointer.get("fetched", 0))
            fetched = datetime.fromtimestamp(float(pointer.get("fetched", 0)), UTC)
            status["epss"] = (
                f"cached: scores {pointer['date']} (fetched {fetched:%Y-%m-%d %H:%M} UTC)"
                + (" (stale)" if age > EPSS_TTL else "")
            )
        else:
            status["epss"] = "missing"
        try:
            groups = load_arch_groups(view)
            status["arch"] = f"cached: {len(groups)} advisory groups"
        except NetworkError:
            status["arch"] = "missing"
    finally:
        view.close()
    return status
