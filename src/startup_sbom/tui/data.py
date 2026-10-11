"""Report indexes for the results browser: filtering, sorting and search (no Textual import)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Generic, TypeVar

from startup_sbom.models import (
    IntelBundle,
    Package,
    Report,
    Service,
    Severity,
    Threat,
    Vulnerability,
)

ROW_CAP = 1000
PAGE_SIZE = 500
THREAT_SORTS: tuple[str, ...] = ("risk", "epss", "severity")
ANY = "any"

T = TypeVar("T")


def _blob(parts: Iterable[object]) -> str:
    return " ".join(str(p) for p in parts if p).lower()


def vuln_index(report: Report) -> dict[tuple[str, str], Vulnerability]:
    """``(vulnerability id, package id) → Vulnerability``."""
    return {(v.id, v.package): v for v in report.vulnerabilities}


def intel_for(report: Report, cve: str) -> IntelBundle | None:
    """The prefetched intel bundle for ``cve`` (exact id match)."""
    for bundle in report.intel:
        if bundle.cve == cve:
            return bundle
    return None


def merge_intel(report: Report, bundle: IntelBundle) -> None:
    """Replace or append ``bundle`` in ``report.intel``."""
    report.intel = [b for b in report.intel if b.cve != bundle.cve] + [bundle]
    report.intel.sort(key=lambda b: b.cve)


@dataclass(frozen=True, slots=True)
class ThreatRow:
    """A threat with the columns the table shows and a lowercase search key."""

    threat: Threat
    vuln: Vulnerability | None
    package_name: str
    severity: Severity
    epss: float | None
    kev: bool
    blob: str

    @property
    def ssvc(self) -> str:
        return self.threat.ssvc.decision.value if self.threat.ssvc else "-"


class ThreatIndex:
    """Filter and sort a report's threats."""

    def __init__(self, report: Report) -> None:
        vulns = vuln_index(report)
        by_id = {v.id: v for v in report.vulnerabilities}
        pkgs = report.package_by_id()
        self.rows: list[ThreatRow] = []
        for t in report.threats:
            vuln = vulns.get((t.vulnerability, t.package)) or by_id.get(t.vulnerability)
            pkg = pkgs.get(t.package)
            name = pkg.name if pkg is not None else t.package
            self.rows.append(
                ThreatRow(
                    threat=t,
                    vuln=vuln,
                    package_name=name,
                    severity=vuln.severity if vuln is not None else Severity.UNKNOWN,
                    epss=vuln.epss if vuln is not None else None,
                    kev=vuln is not None and vuln.kev is not None,
                    blob=_blob(
                        [t.id, t.title, t.vulnerability, t.package, name, *t.services]
                        + (list(vuln.aliases) if vuln is not None else [])
                    ),
                )
            )

    def filter(
        self,
        *,
        needle: str = "",
        ssvc: str = ANY,
        reach: str = ANY,
        severity: str = ANY,
        kev_only: bool = False,
        sort: str = "risk",
        reverse: bool = True,
    ) -> list[ThreatRow]:
        """Rows matching every filter, sorted by ``sort`` (risk | epss | severity | column)."""
        terms = needle.lower().split()
        out = [
            r
            for r in self.rows
            if all(term in r.blob for term in terms)
            and (ssvc in (ANY, r.ssvc))
            and (reach in (ANY, r.threat.reachability.value))
            and (severity in (ANY, r.severity.value))
            and (not kev_only or r.kev)
        ]
        out.sort(key=lambda r: _threat_key(r, sort), reverse=reverse)
        return out


_SSVC_RANK = {"Act": 4, "Attend": 3, "Track*": 2, "Track": 1, "-": 0}


def _threat_key(row: ThreatRow, sort: str) -> tuple[object, ...]:
    t = row.threat
    primary: object
    if sort == "epss":
        primary = row.epss if row.epss is not None else -1.0
    elif sort == "severity":
        primary = row.severity.rank
    elif sort == "ssvc":
        primary = _SSVC_RANK.get(row.ssvc, 0)
    elif sort == "kev":
        primary = row.kev
    elif sort == "reach":
        primary = t.reachability.value
    elif sort == "package":
        primary = row.package_name.lower()
    elif sort == "title":
        primary = t.title.lower()
    else:
        primary = t.risk_score
    return (primary, t.risk_score, t.id)


class SearchIndex(Generic[T]):
    """Generic needle search over precomputed lowercase keys."""

    def __init__(self, items: Sequence[T], keys: Sequence[str]) -> None:
        self.items = list(items)
        self.keys = [k.lower() for k in keys]

    def filter(self, needle: str) -> list[T]:
        terms = needle.lower().split()
        if not terms:
            return list(self.items)
        return [
            item
            for item, key in zip(self.items, self.keys, strict=True)
            if all(t in key for t in terms)
        ]


def package_index(report: Report) -> SearchIndex[Package]:
    """Search packages by name, version, type, vendor, repository, purl and flags."""
    keys = [
        _blob(
            [
                p.name,
                p.version,
                p.type.value,
                p.arch,
                p.vendor,
                p.repository,
                p.purl or p.id,
                *p.provenance_flags,
            ]
        )
        for p in report.packages
    ]
    return SearchIndex(report.packages, keys)


def vuln_search_index(report: Report) -> SearchIndex[Vulnerability]:
    """Search vulnerabilities by id, aliases, package, status, severity and summary."""
    keys = [
        _blob(
            [
                v.id,
                *v.aliases,
                v.package_name,
                v.status.value,
                v.severity.value,
                v.summary,
                "kev" if v.kev else "",
            ]
        )
        for v in report.vulnerabilities
    ]
    return SearchIndex(report.vulnerabilities, keys)


def service_listeners(service: Service) -> str:
    """Compact listener summary, e.g. ``tcp/22, unix:/run/x.sock``."""
    parts: list[str] = []
    for listen in service.listens:
        if listen.port is not None:
            parts.append(f"{listen.protocol}/{listen.port}")
        elif listen.path:
            parts.append(f"{listen.protocol}:{listen.path}")
        else:
            parts.append(listen.protocol)
    return ", ".join(parts)


def best_cvss(vuln: Vulnerability) -> str:
    """Best CVSS base score as text."""
    best = vuln.best_cvss
    if best is None or best.base_score is None:
        return "-"
    return f"{best.base_score:.1f}"


def fmt_epss(value: float | None) -> str:
    """EPSS probability as a percentage."""
    return "-" if value is None else f"{value * 100:.1f}%"
