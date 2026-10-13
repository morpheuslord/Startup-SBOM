"""Native JSON report, its JSON Schema, render options and shared report helpers.

Every other format renders from a :func:`canonical` copy of the :class:`Report`, so
list order (and therefore every output) is independent of analysis order.  The
helpers here hold the cross-format semantics (severity, reachability, in-image
locations, stable ids) so that SARIF, VEX, CycloneDX and the human reports agree.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from startup_sbom.errors import OutputError
from startup_sbom.models import (
    Activation,
    Coverage,
    Package,
    PackageType,
    Reachability,
    Report,
    Service,
    Severity,
    Threat,
    Vulnerability,
)

SCHEMA_ID = "https://github.com/morpheuslord/Startup-SBOM/schema/report-2.0.json"
PROJECT_URL = "https://github.com/morpheuslord/Startup-SBOM"
CDX_SPECS = ("1.5", "1.6", "1.7")

#: Reachability verdicts that place a package on an observed execution path.
REACHABLE: frozenset[Reachability] = frozenset(set(Reachability) - {Reachability.INSTALLED})

_REACH_RANK = {r: i for i, r in enumerate(Reachability)}  # declaration order = strongest first
_SEVERITY_SCORE = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.0,
}
_PACKAGE_DB = {
    PackageType.DEB: "/var/lib/dpkg/status",
    PackageType.RPM: "/var/lib/rpm/rpmdb.sqlite",
    PackageType.APK: "/lib/apk/db/installed",
}


@dataclass(frozen=True, slots=True)
class RenderOptions:
    """Format-specific knobs shared by every renderer."""

    cdx_spec: str = "1.6"  # CycloneDX spec version: 1.5 | 1.6 | 1.7
    vex_not_affected_unreachable: bool = False  # opt-in: installed-only => not_affected
    trivy_compat: bool = True  # add aquasecurity:trivy:Src* component properties
    sarif_min_severity: Severity = Severity.UNKNOWN  # UNKNOWN keeps every result

    def __post_init__(self) -> None:
        if self.cdx_spec not in CDX_SPECS:
            raise OutputError(
                f"unsupported CycloneDX spec {self.cdx_spec!r} (choose {', '.join(CDX_SPECS)})"
            )
        given: object = self.sarif_min_severity  # tolerate plain strings from CLIs
        if not isinstance(given, Severity):
            object.__setattr__(self, "sarif_min_severity", Severity.parse(str(given)))


# --------------------------------------------------------------------------- canonical form
def canonical(report: Report) -> Report:
    """Return a deep copy of ``report`` with every list in canonical order.

    The input is never mutated.  Ordered sequences (attack steps, boot paths,
    commands, reachability paths) keep their order; set-like lists are sorted.
    """
    r = report.model_copy(deep=True)
    for p in r.packages:
        p.cpes.sort()
        p.provides.sort()
        p.depends.sort()
        p.provenance_flags.sort()
    r.packages.sort(key=lambda p: (p.id, p.name, p.version))
    for s in r.services:
        s.activation.sort()
        s.executables.sort()
        s.packages.sort()
        s.listens.sort(key=lambda x: (x.protocol, x.address or "", x.port or 0, x.path or ""))
    r.services.sort(key=lambda s: s.id)
    for b in r.binaries:
        b.needed.sort()
        b.unresolved.sort()
        b.used_by.sort()
        b.capabilities.sort()
        b.libraries.sort(key=lambda lib: (lib.depth, lib.soname, lib.path or ""))
    r.binaries.sort(key=lambda b: b.path)
    for v in r.vulnerabilities:
        for lst in (v.aliases, v.advisories, v.sources, v.cwes, v.references, v.fixed_versions):
            lst.sort()
        v.cvss.sort(key=lambda c: (c.version, c.vector))
    r.vulnerabilities.sort(key=lambda v: (v.id, v.package))
    for t in r.threats:
        t.services.sort()
        t.binaries.sort()
        t.mitigations.sort()
        t.stride.sort()
        t.consequences.sort()
        t.reachability_paths.sort()
        t.attack_techniques.sort(key=lambda a: a.id)
    r.threats.sort(key=lambda t: t.id)
    r.attack_chains.sort(key=lambda c: c.id)
    sc = r.supply_chain
    sc.vendors.sort(key=lambda v: v.vendor)
    sc.findings.sort(key=lambda f: f.id)
    for br in sc.blast_radius:
        br.services.sort()
        br.binaries.sort()
        br.vulnerabilities.sort()
        br.example_paths.sort()
    sc.blast_radius.sort(key=lambda b: b.package)
    sc.nodes.sort(key=lambda n: n.id)
    sc.edges.sort(key=lambda e: (e.source, e.target, e.kind))
    cov = r.metadata.coverage
    for lst in (
        cov.package_databases,
        cov.init_systems,
        cov.vulnerability_sources,
        cov.vulnerability_ecosystems,
    ):
        lst.sort()
    cov.limitations[:] = _dedupe(cov.limitations)
    r.warnings[:] = _dedupe(r.warnings)
    return r


def _dedupe(items: list[str]) -> list[str]:
    return sorted(set(items))


def render_native(report: Report, options: RenderOptions) -> str:
    """Render the canonical native JSON report."""
    del options
    return canonical(report).model_dump_json(indent=2, exclude_none=False) + "\n"


def json_schema() -> str:
    """Return the JSON Schema (draft 2020-12) of the native report."""
    schema = Report.model_json_schema()
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_ID,
        "title": "Startup-SBOM report 2.0",
        **{k: v for k, v in schema.items() if k != "title"},
    }
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- shared helpers
def utc(dt: datetime) -> datetime:
    """Return ``dt`` as an aware UTC datetime (naive values are taken as UTC)."""
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def timestamp(report: Report) -> datetime:
    """Document timestamp: when the scan started, in UTC, without microseconds."""
    return utc(report.metadata.started).replace(microsecond=0)


def iso_z(dt: datetime) -> str:
    """Format as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return utc(dt).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: str | None) -> datetime | None:
    """Parse an ISO-8601 date/time string; ``None`` when absent or invalid."""
    if not value:
        return None
    try:
        return utc(datetime.fromisoformat(value.strip().replace("Z", "+00:00")))
    except ValueError:
        return None


def scan_uuid(report: Report, purpose: str = "sbom") -> uuid.UUID:
    """Deterministic UUID derived from the scan id (stable across re-renders)."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f"{PROJECT_URL}#{report.metadata.scan_id}:{purpose}")


def short_hash(*parts: str, length: int = 16) -> str:
    """Stable hex digest of ``parts`` (used for surrogate ids)."""
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()[:length]


def vuln_score(v: Vulnerability) -> float | None:
    """Highest CVSS base score of ``v`` (``None`` when unscored)."""
    scores = [c.base_score for c in v.cvss if c.base_score is not None]
    return max(scores) if scores else None


def vuln_severity(v: Vulnerability) -> Severity:
    """Severity of ``v``: the recorded one, else derived from its CVSS score."""
    if v.severity is not Severity.UNKNOWN:
        return v.severity
    return Severity.from_score(vuln_score(v))


def severity_score(sev: Severity, score: float | None = None) -> float | None:
    """A numeric 0-10 score: the CVSS score when known, else a severity midpoint."""
    if score is not None and score > 0:
        return score
    return _SEVERITY_SCORE.get(sev)


def reach_rank(r: Reachability) -> int:
    """Lower is stronger (network service = 0, installed = last)."""
    return _REACH_RANK[r]


def threat_sort_key(t: Threat) -> tuple[float, str]:
    """Highest risk first, then id."""
    return (-t.risk_score, t.id)


def service_reachability(s: Service) -> Reachability | None:
    """How a service makes its packages reachable (``None`` when not started)."""
    if s.masked:
        return None
    acts = set(s.activation)
    if s.network_exposed and acts - {Activation.MANUAL}:
        return Reachability.NETWORK_SERVICE
    if acts & {Activation.BOOT, Activation.ENTRYPOINT}:
        return Reachability.BOOT_SERVICE
    if acts & {Activation.SOCKET, Activation.TIMER, Activation.PATH, Activation.DBUS}:
        return Reachability.ON_DEMAND_SERVICE
    return None


def package_reachability(report: Report) -> dict[str, Reachability]:
    """Strongest observed reachability of every package (default: installed)."""
    best: dict[str, Reachability] = {p.id: Reachability.INSTALLED for p in report.packages}

    def bump(pkg: str | None, r: Reachability | None) -> None:
        if pkg is None or r is None:
            return
        cur = best.get(pkg, Reachability.INSTALLED)
        if reach_rank(r) < reach_rank(cur):
            best[pkg] = r

    svc_reach = {s.id: service_reachability(s) for s in report.services}
    for s in report.services:
        for pkg in s.packages:
            bump(pkg, svc_reach[s.id])
    for b in report.binaries:
        users = [svc_reach.get(u) for u in b.used_by]
        started = [u for u in users if u is not None]
        if started:
            bump(b.package, min(started, key=reach_rank))
            for lib in b.libraries:
                bump(lib.package, Reachability.LINKED_BY_SERVICE)
        if b.setuid or b.setgid or b.capabilities:
            bump(b.package, Reachability.SETUID)
    for t in report.threats:
        bump(t.package, t.reachability)
    return best


def threats_by_vuln(report: Report) -> dict[tuple[str, str], list[Threat]]:
    """Threats keyed by ``(vulnerability id, package id)``, strongest first."""
    out: dict[tuple[str, str], list[Threat]] = {}
    for t in report.threats:
        out.setdefault((t.vulnerability, t.package), []).append(t)
    for lst in out.values():
        lst.sort(key=lambda t: (reach_rank(t.reachability), -t.risk_score, t.id))
    return out


def vuln_reachability(
    report: Report,
    v: Vulnerability,
    *,
    threats: dict[tuple[str, str], list[Threat]] | None = None,
    pkg_reach: dict[str, Reachability] | None = None,
) -> Reachability:
    """Reachability of one vulnerability: its strongest threat, else its package's."""
    threats = threats if threats is not None else threats_by_vuln(report)
    found = threats.get((v.id, v.package))
    if found:
        return found[0].reachability
    pkg_reach = pkg_reach if pkg_reach is not None else package_reachability(report)
    return pkg_reach.get(v.package, Reachability.INSTALLED)


def package_db_path(pkg: Package) -> str:
    """Absolute in-image path of the database/manifest that recorded ``pkg``."""
    if pkg.location and pkg.location.startswith("/"):
        return pkg.location
    if pkg.type is PackageType.ALPM:
        return posixpath.join("/var/lib/pacman/local", f"{pkg.name}-{pkg.version}", "desc")
    return _PACKAGE_DB.get(pkg.type, "/")


def package_label(pkg: Package | None, fallback: str) -> str:
    """``name version`` (plus ``:arch`` for multi-arch disambiguation)."""
    if pkg is None:
        return fallback
    arch = f":{pkg.arch}" if pkg.arch else ""
    return f"{pkg.name}{arch} {pkg.version}"


def listen_text(protocol: str, address: str | None, port: int | None, path: str | None) -> str:
    """Human form of a listener: ``tcp 0.0.0.0:22`` / ``unix /run/x.sock``."""
    if path:
        return f"{protocol} {path}"
    host = address or "*"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{protocol} {host}:{port}" if port is not None else f"{protocol} {host}"


def trigger_label(threat: Threat) -> str:
    """Strongest activation trigger of ``threat`` in a few words (``none`` if nothing runs it).

    ``setuid /usr/bin/passwd (local user)`` / ``boot systemd:ssh.service (network)``.
    """
    if not threat.triggers:
        return "none"
    t = threat.triggers[0]
    more = f" +{len(threat.triggers) - 1}" if len(threat.triggers) > 1 else ""
    return f"{t.kind.value} {t.subject} ({t.fired_by}){more}"


def analysis_mode_label(coverage: Coverage) -> str:
    """``static`` or ``chroot (probes: loader, packages, systemd)``."""
    if coverage.analysis_mode == "chroot" and coverage.runtime_probes:
        return f"chroot (sandboxed probes: {', '.join(coverage.runtime_probes)})"
    return coverage.analysis_mode
