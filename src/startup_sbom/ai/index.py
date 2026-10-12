"""Read-only, pre-indexed view of one report: the agents' only window on the scan.

Every query returns compact, JSON-safe, sanitised data (control/bidi characters
removed, strings length-bounded) so the same functions back the agent tools and
the MCP server.  Unknown ids raise :class:`UnknownIdError` with a discovery hint.
Pure Python: no pydantic-ai import.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from startup_sbom.models import (
    AttackChain,
    AttackStep,
    BlastRadius,
    IntelBundle,
    Package,
    Report,
    Service,
    Severity,
    SupplyChainFinding,
    Threat,
    Vulnerability,
)
from startup_sbom.textsafe import clean

MAX_PAGE = 50
MAX_STR = 2_000
ARTICLE_CHARS = 4_000

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

ID_KINDS = (
    "threat",
    "vulnerability",
    "package",
    "service",
    "chain",
    "supply_chain_finding",
    "attack_step",
)


class UnknownIdError(KeyError):
    """An id that does not exist in the report."""

    def __init__(self, kind: str, ident: str, hint: str) -> None:
        super().__init__(ident)
        self.kind = kind
        self.ident = ident
        self.hint = hint

    def __str__(self) -> str:
        return f"unknown {self.kind} id {clean(self.ident, max_len=120)!r}; {self.hint}"


def sanitize(obj: Any, *, max_str: int = MAX_STR) -> Any:
    """Recursively turn ``obj`` into JSON-safe data with sanitised, bounded strings."""
    if obj is None or isinstance(obj, bool | int | float):
        return obj
    if isinstance(obj, str):
        return clean(obj, max_len=max_str, keep_newlines=True)
    if isinstance(obj, dict):
        return {clean(k, max_len=200): sanitize(v, max_str=max_str) for k, v in obj.items()}
    if isinstance(obj, list | tuple | set | frozenset):
        return [sanitize(v, max_str=max_str) for v in obj]
    if hasattr(obj, "model_dump"):
        return sanitize(obj.model_dump(mode="json", exclude_none=True), max_str=max_str)
    return clean(str(obj), max_len=max_str)


def _clean_dict(obj: dict[str, Any], *, max_str: int = MAX_STR) -> dict[str, Any]:
    """:func:`sanitize` for a query result that is known to be a dict."""
    return cast("dict[str, Any]", sanitize(obj, max_str=max_str))


def _page(limit: int, offset: int) -> tuple[int, int]:
    return max(1, min(int(limit), MAX_PAGE)), max(0, int(offset))


def _key(ident: str) -> str:
    return clean(ident).strip()


@dataclass
class ReportIndex:
    """Dicts by id over one :class:`Report` plus the id/number sets used for grounding."""

    report: Report
    threats: dict[str, Threat] = field(init=False, default_factory=dict)
    vulns: dict[str, list[Vulnerability]] = field(init=False, default_factory=dict)
    packages: dict[str, Package] = field(init=False, default_factory=dict)
    services: dict[str, Service] = field(init=False, default_factory=dict)
    chains: dict[str, AttackChain] = field(init=False, default_factory=dict)
    steps: dict[str, AttackStep] = field(init=False, default_factory=dict)
    findings: dict[str, SupplyChainFinding] = field(init=False, default_factory=dict)
    blast: dict[str, BlastRadius] = field(init=False, default_factory=dict)
    intel: dict[str, IntelBundle] = field(init=False, default_factory=dict)
    vuln_alias: dict[str, str] = field(init=False, default_factory=dict)  # upper alias -> id
    ids_by_kind: dict[str, set[str]] = field(init=False, default_factory=dict)
    cves: set[str] = field(init=False, default_factory=set)  # upper-case ids + aliases
    cwes: set[str] = field(init=False, default_factory=set)
    techniques: set[str] = field(init=False, default_factory=set)
    _alias: dict[tuple[str, str], str] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        r = self.report
        self.threats = {t.id: t for t in r.threats}
        for v in r.vulnerabilities:
            self.vulns.setdefault(v.id, []).append(v)
            for alias in (v.id, *v.aliases, *v.advisories):
                self.vuln_alias.setdefault(alias.upper(), v.id)
            self.cwes.update(c.upper() for c in v.cwes)
        self.cves = set(self.vuln_alias)
        self.packages = {p.id: p for p in r.packages}
        self.services = {s.id: s for s in r.services}
        self.chains = {c.id: c for c in r.attack_chains}
        for chain in r.attack_chains:
            for step in chain.steps:
                if step.id:
                    self.steps.setdefault(step.id, step)
                if step.technique:
                    self.techniques.add(step.technique.id)
        for t in r.threats:
            self.techniques.update(a.id for a in t.attack_techniques)
        self.findings = {f.id: f for f in r.supply_chain.findings}
        self.blast = {b.package: b for b in r.supply_chain.blast_radius}
        self.intel = {b.cve.upper(): b for b in r.intel}
        kinds: dict[str, Iterable[str]] = {
            "threat": self.threats,
            "vulnerability": self.vuln_alias.values(),
            "package": self.packages,
            "service": self.services,
            "chain": self.chains,
            "supply_chain_finding": self.findings,
            "attack_step": self.steps,
        }
        for kind, idents in kinds.items():
            self.ids_by_kind[kind] = set(idents)
            for ident in idents:
                self._alias.setdefault((kind, ident), ident)
                self._alias.setdefault((kind, _key(ident)), ident)
        for alias, vid in self.vuln_alias.items():
            self._alias.setdefault(("vulnerability", alias), vid)

    # ------------------------------------------------------------------ id helpers
    def resolve(self, kind: str, ident: str) -> str | None:
        """The canonical id of ``ident`` (raw, sanitised or alias form) or ``None``."""
        ident = ident.strip()
        if kind == "vulnerability":
            ident = ident.upper() if (kind, ident) not in self._alias else ident
        return self._alias.get((kind, ident)) or self._alias.get((kind, _key(ident)))

    def kind_of(self, ref: str) -> str | None:
        """Which id kind ``ref`` belongs to (first match in :data:`ID_KINDS`)."""
        return next((k for k in ID_KINDS if self.resolve(k, ref) is not None), None)

    def known(self, ref: str) -> bool:
        return self.kind_of(ref) is not None

    def numeric(self, ref: str, field_name: str) -> tuple[bool, float | None]:
        """``(ref_known, value)`` for a numeric field of a report object."""
        kind = self.kind_of(ref)
        if kind is None:
            return False, None
        f = field_name.strip().lower()
        if kind == "threat":
            t = self.threats[self.resolve(kind, ref) or ref]
            if f in ("risk_score", "risk", "score"):
                return True, t.risk_score
            if f.startswith("score_factors."):
                return True, t.score_factors.get(f.split(".", 1)[1])
            vulns = self.vulns.get(t.vulnerability, [])
            return True, self._vuln_number(vulns, f)
        if kind == "vulnerability":
            vid = self.resolve(kind, ref) or ref
            return True, self._vuln_number(self.vulns.get(vid, []), f)
        if kind == "chain":
            c = self.chains[self.resolve(kind, ref) or ref]
            value = {"likelihood": c.likelihood, "impact": c.impact, "score": c.score}.get(f)
            return True, value
        if kind == "attack_step":
            step = self.steps[self.resolve(kind, ref) or ref]
            return True, step.likelihood if f == "likelihood" else None
        if kind == "package":
            b = self.blast.get(self.resolve(kind, ref) or ref)
            if b is not None and f in ("blast_radius", "blast_score", "score"):
                return True, b.score
            return True, None
        if kind == "service":
            svc = self.services[self.resolve(kind, ref) or ref]
            if f in ("exposure", "hardening.exposure"):
                return True, svc.hardening.exposure
            return True, None
        return True, None

    @staticmethod
    def _vuln_number(vulns: Sequence[Vulnerability], f: str) -> float | None:
        if not vulns:
            return None
        v = vulns[0]
        if f == "epss":
            return v.epss
        if f in ("epss_percentile", "percentile"):
            return v.epss_percentile
        if f in ("cvss", "cvss_score", "base_score", "cvss.base_score"):
            best = v.best_cvss
            return best.base_score if best else None
        return None

    def _get(self, kind: str, ident: str, hint: str) -> str:
        resolved = self.resolve(kind, ident)
        if resolved is None:
            raise UnknownIdError(kind, ident, hint)
        return resolved

    def _kev(self, vuln_id: str) -> bool:
        return any(v.kev is not None for v in self.vulns.get(vuln_id, []))

    # ------------------------------------------------------------------ queries
    def summary(self) -> dict[str, Any]:
        """Scan metadata, OS, coverage gaps and headline counts."""
        r = self.report
        system = r.explanations.system if r.explanations else None
        return _clean_dict(
            {
                "scan_id": r.metadata.scan_id,
                "target": r.metadata.target.model_dump(mode="json"),
                "os": r.os.model_dump(
                    mode="json", include={"id", "pretty_name", "version_id", "family", "eol"}
                ),
                "container": (
                    r.container.model_dump(
                        mode="json",
                        include={"kind", "image", "user", "privileged", "exposed_ports"},
                    )
                    if r.container
                    else None
                ),
                "summary": r.summary.model_dump(mode="json"),
                "coverage": r.metadata.coverage.model_dump(mode="json"),
                "system_risk": system.system_risk if system else None,
                "top_drivers": (
                    [d.model_dump(mode="json") for d in system.drivers[:5]] if system else []
                ),
                "intel_cves": sorted(self.intel)[:50],
                "warnings": r.warnings[:20],
            }
        )

    def list_threats(
        self,
        *,
        min_risk: float = 0.0,
        ssvc: Sequence[str] | None = None,
        reachability: Sequence[str] | None = None,
        network_exposed: bool | None = None,
        kev_only: bool = False,
        package: str | None = None,
        service: str | None = None,
        query: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Risk-ordered compact threat rows with filters and paging."""
        limit, offset = _page(limit, offset)
        wanted_ssvc = {s.lower() for s in ssvc or ()}
        wanted_reach = {s.lower() for s in reachability or ()}
        pkg = self.resolve("package", package) if package else None
        svc = self.resolve("service", service) if service else None
        q = query.lower() if query else None
        rows = []
        for t in sorted(self.threats.values(), key=lambda t: (-t.risk_score, t.id)):
            decision = t.ssvc.decision.value if t.ssvc else None
            if t.risk_score < min_risk:
                continue
            if wanted_ssvc and (decision or "").lower() not in wanted_ssvc:
                continue
            if wanted_reach and t.reachability.value not in wanted_reach:
                continue
            if network_exposed is not None and t.network_exposed != network_exposed:
                continue
            if kev_only and not self._kev(t.vulnerability):
                continue
            if package and t.package != pkg:
                continue
            if service and svc not in t.services:
                continue
            if q and q not in f"{t.title} {t.vulnerability} {t.package}".lower():
                continue
            rows.append(
                {
                    "id": t.id,
                    "vulnerability": t.vulnerability,
                    "title": t.title,
                    "risk_score": t.risk_score,
                    "ssvc": decision,
                    "reachability": t.reachability.value,
                    "network_exposed": t.network_exposed,
                    "kev": self._kev(t.vulnerability),
                    "postcondition": t.postcondition,
                }
            )
        page = rows[offset : offset + limit]
        return _clean_dict(
            {
                "total": len(rows),
                "offset": offset,
                "limit": limit,
                "next_offset": offset + limit if offset + limit < len(rows) else None,
                "items": page,
            },
            max_str=300,
        )

    def get_threat(self, threat_id: str) -> dict[str, Any]:
        """One threat with its vulnerability record(s) and explanation factors."""
        tid = self._get("threat", threat_id, "use list_threats to discover threat ids")
        t = self.threats[tid]
        vulns = [
            v.model_dump(mode="json", exclude={"references"}) | {"references": v.references[:5]}
            for v in self.vulns.get(t.vulnerability, [])
        ]
        return _clean_dict(
            {
                "threat": t.model_dump(mode="json", exclude={"explanation"}),
                "vulnerabilities": vulns,
                "explanation": (
                    t.explanation.model_dump(mode="json") if t.explanation is not None else None
                ),
                "intel_available": t.vulnerability.upper() in self.intel,
            }
        )

    def explain_threat(self, threat_id: str) -> dict[str, Any]:
        """Risk-score decomposition, SSVC decision traces and the cited evidence."""
        tid = self._get("threat", threat_id, "use list_threats to discover threat ids")
        t = self.threats[tid]
        cited = set(t.evidence)
        if t.explanation is not None:
            for f in t.explanation.factors:
                cited.update(f.evidence)
        evidence = [e for e in self.report.evidence if e.id in cited][:30]
        derivations = [d for d in self.report.derivations if d.id in cited][:30]
        return _clean_dict(
            {
                "threat_id": t.id,
                "risk_score": t.risk_score,
                "score_factors": t.score_factors,
                "explanation": t.explanation.model_dump(mode="json") if t.explanation else None,
                "ssvc": t.ssvc.model_dump(mode="json") if t.ssvc else None,
                "confidence": t.confidence.value,
                "evidence": [e.model_dump(mode="json") for e in evidence],
                "derivations": [d.model_dump(mode="json") for d in derivations],
                "narrative": t.narrative,
                "remediation": t.remediation,
            }
        )

    def list_chains(
        self,
        *,
        min_score: float = 0.0,
        goal: str | None = None,
        include_mitigated: bool = True,
        limit: int = 10,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Attack chains (entry -> goal), best first, compact."""
        limit, offset = _page(limit, offset)
        rows = [
            {
                "id": c.id,
                "entry": c.entry,
                "goal": c.goal,
                "score": c.score,
                "likelihood": c.likelihood,
                "impact": c.impact,
                "ssvc": c.ssvc_decision.value,
                "mitigated": c.mitigated,
                "steps": len(c.steps),
                "threats": [s.threat for s in c.steps if s.threat],
            }
            for c in sorted(self.chains.values(), key=lambda c: (-c.score, c.id))
            if c.score >= min_score
            and (goal is None or c.goal == goal)
            and (include_mitigated or not c.mitigated)
        ]
        return _clean_dict(
            {"total": len(rows), "offset": offset, "items": rows[offset : offset + limit]},
            max_str=300,
        )

    def get_chain(self, chain_id: str) -> dict[str, Any]:
        """One attack chain with every step."""
        cid = self._get("chain", chain_id, "use list_attack_chains to discover chain ids")
        return _clean_dict(self.chains[cid].model_dump(mode="json"))

    def blast_radius(
        self, package_id: str | None = None, *, limit: int = 10, offset: int = 0
    ) -> dict[str, Any]:
        """Supply-chain blast radius: one package, or the top entries by score."""
        if package_id:
            pid = self._get("package", package_id, "use lookup_package to find package ids")
            b = self.blast.get(pid)
            if b is None:
                return _clean_dict({"package": pid, "blast_radius": None})
            data = b.model_dump(mode="json")
            data["example_paths"] = data["example_paths"][:5]
            return _clean_dict(data)
        limit, offset = _page(limit, offset)
        items = sorted(self.blast.values(), key=lambda b: (-b.score, b.package))
        return _clean_dict(
            {
                "total": len(items),
                "offset": offset,
                "items": [
                    b.model_dump(mode="json", exclude={"example_paths"})
                    for b in items[offset : offset + limit]
                ],
            }
        )

    def list_supply_chain_findings(
        self,
        *,
        kind: str | None = None,
        min_severity: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Provenance / vendor-chain findings, most severe first."""
        limit, offset = _page(limit, offset)
        floor = Severity.parse(min_severity).rank if min_severity else 0
        items = [
            f
            for f in sorted(self.findings.values(), key=lambda f: (-f.severity.rank, f.id))
            if (kind is None or f.kind == kind) and f.severity.rank >= floor
        ]
        vendors = [v.model_dump(mode="json") for v in self.report.supply_chain.vendors[:10]]
        return _clean_dict(
            {
                "total": len(items),
                "offset": offset,
                "items": [f.model_dump(mode="json") for f in items[offset : offset + limit]],
                "top_vendors": vendors,
            }
        )

    def lookup_package(self, query: str, *, limit: int = 20) -> dict[str, Any]:
        """Package detail by exact id, or a name search returning ids."""
        pid = self.resolve("package", query)
        if pid is not None:
            p = self.packages[pid]
            vulns = sorted({v.id for vs in self.vulns.values() for v in vs if v.package == pid})
            services = [s.id for s in self.services.values() if pid in s.packages]
            return _clean_dict(
                {
                    "package": p.model_dump(mode="json", exclude={"depends", "provides"})
                    | {"depends": p.depends[:20]},
                    "vulnerabilities": vulns,
                    "services": services,
                    "threats": [t.id for t in self.threats.values() if t.package == pid],
                    "blast_radius_score": self.blast[pid].score if pid in self.blast else None,
                }
            )
        q = query.lower().strip()
        if not q:
            raise UnknownIdError("package", query, "pass a package id or part of a name")
        limit = max(1, min(limit, MAX_PAGE))
        hits = [
            {"id": p.id, "name": p.name, "version": p.version, "type": p.type.value}
            for p in sorted(self.packages.values(), key=lambda p: p.id)
            if q in p.name.lower() or q in (p.source_name or "").lower()
        ]
        return _clean_dict({"total": len(hits), "matches": hits[:limit]}, max_str=400)

    def lookup_service(self, query: str, *, limit: int = 20) -> dict[str, Any]:
        """Service detail by exact id, or a name search returning ids."""
        sid = self.resolve("service", query)
        if sid is not None:
            s = self.services[sid]
            return _clean_dict(
                {
                    "service": s.model_dump(mode="json"),
                    "threats": [t.id for t in self.threats.values() if sid in t.services],
                }
            )
        q = query.lower().strip()
        if not q:
            raise UnknownIdError("service", query, "pass a service id or part of a name")
        limit = max(1, min(limit, MAX_PAGE))
        hits = [
            {
                "id": s.id,
                "name": s.name,
                "init_system": s.init_system.value,
                "enabled": s.enabled,
                "network_exposed": s.network_exposed,
                "user": s.hardening.user,
            }
            for s in sorted(self.services.values(), key=lambda s: s.id)
            if q in s.name.lower() or q in s.id.lower()
        ]
        return _clean_dict({"total": len(hits), "matches": hits[:limit]}, max_str=400)

    def get_intel(self, cve: str, *, include_articles: bool = True) -> dict[str, Any]:
        """Prefetched intel bundle for a CVE (exploit maturity, KEV, EPSS trend, advisories)."""
        vid = self.resolve("vulnerability", cve)
        if vid is None:
            raise UnknownIdError("vulnerability", cve, "only CVEs present in the report have intel")
        bundle = self.intel.get(vid.upper()) or self.intel.get(cve.upper())
        if bundle is None:
            return _clean_dict(
                {"cve": vid, "intel": None, "note": "no intel prefetched for this CVE"}
            )
        data = bundle.model_dump(mode="json", exclude={"advisories", "articles"})
        records = [*bundle.advisories, *bundle.articles][:10] if include_articles else []
        data["records"] = [
            {
                "id": rec.id,
                "kind": rec.kind,
                "source": rec.source,
                "title": rec.title,
                "site": rec.site,
                "published": rec.published,
                "snippet": rec.snippet,
                "trust": rec.trust,
                "text": _article_text(rec.text_ref) if rec.text_ref else None,
            }
            for rec in records
        ]
        return _clean_dict({"cve": vid, "intel": data}, max_str=ARTICLE_CHARS)

    def fix_plan(self) -> dict[str, Any]:
        """Minimal fix set(s), single-fix what-ifs and the fix catalogue."""
        ex = self.report.explanations
        if ex is None:
            remediations = [
                {"threat": t.id, "remediation": t.remediation}
                for t in sorted(self.threats.values(), key=lambda t: -t.risk_score)
                if t.remediation
            ][:MAX_PAGE]
            return _clean_dict(
                {"fix_plan": [], "what_if": [], "fixes": [], "remediations": remediations}
            )
        return _clean_dict(
            {
                "fix_plan": [w.model_dump(mode="json") for w in ex.fix_plan[:10]],
                "what_if": [w.model_dump(mode="json") for w in ex.what_if[:20]],
                "fixes": [f.model_dump(mode="json") for f in ex.fixes[:MAX_PAGE]],
                "system": ex.system.model_dump(mode="json") if ex.system else None,
            }
        )


def _article_text(text_ref: str) -> str | None:
    """Cached cleaned article text via ``startup_sbom.intel.article_text`` (if present)."""
    try:
        mod = importlib.import_module("startup_sbom.intel")
    except ImportError:
        return None
    fn = getattr(mod, "article_text", None)
    if not callable(fn):
        return None
    try:
        text = fn(text_ref)
    except Exception:  # noqa: BLE001 - optional cache; never fail a query over it
        return None
    return clean(text, max_len=ARTICLE_CHARS, keep_newlines=True) if text else None
