"""Report -> sanitised, JSON-serialisable view model for the Typst PDF template.

Every decision (ordering, truncation, link validation, anchor ids, chart geometry)
is made here in typed Python.  The template only lays out values it receives as
JSON through ``sys.inputs``; it never evaluates them as markup.  All text from the
scan, advisories or an AI agent passes through :mod:`startup_sbom.textsafe`.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from typing import Any
from urllib.parse import urlsplit

from startup_sbom.models import (
    AIEvidenceRef,
    AttackChain,
    AttackStep,
    AttackTechnique,
    Explanation,
    IntelBundle,
    Report,
    SSVCDecision,
    SSVCTrace,
    Threat,
    WhatIf,
)
from startup_sbom.report.native import (
    canonical,
    iso_z,
    listen_text,
    package_label,
    package_reachability,
    service_reachability,
    threat_sort_key,
    threats_by_vuln,
    vuln_reachability,
    vuln_severity,
)
from startup_sbom.textsafe import clean, safe_block

JSON = dict[str, Any]

SEVERITIES = ("critical", "high", "medium", "low", "none", "unknown")
DECISIONS = (SSVCDecision.ACT, SSVCDecision.ATTEND, SSVCDecision.TRACK_STAR, SSVCDecision.TRACK)
DECISION_TONE = {"Act": "critical", "Attend": "high", "Track*": "medium", "Track": "low"}
REACH_LABEL = {
    "network_service": "network-exposed service",
    "boot_service": "boot service",
    "linked_by_service": "library loaded by a service",
    "on_demand_service": "on-demand service",
    "setuid": "setuid / capability binary",
    "kernel": "kernel",
    "installed": "installed only",
}
MAX_TEXT = 4000
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_VULN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,80}$")


# --------------------------------------------------------------------------- primitives
def txt(value: object, limit: int = 300) -> str:
    """Single-line, display-safe text (controls, bidi and zero-width removed)."""
    return "" if value is None else clean(value, max_len=limit)


def opt(value: object, limit: int = 300) -> str | None:
    """Like :func:`txt` but ``None`` for absent or empty values."""
    s = txt(value, limit)
    return s or None


def paras(value: object, limit: int = MAX_TEXT) -> list[str]:
    """Display-safe paragraphs (blank-line separated; single newlines folded)."""
    if value is None:
        return []
    block = safe_block(value, max_len=limit)
    out = [" ".join(p.split()) for p in re.split(r"\n\s*\n", block)]
    return [p for p in out if p]


def https_url(url: object) -> str | None:
    """``url`` when it is a plain ``https://host/...`` link, else ``None``."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        return None
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        return None
    if clean(url) != url or any(ch in url for ch in '"<>\\`'):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname or "@" in parts.netloc:
        return None
    return url


def fmt_num(value: float, digits: int = 1) -> str:
    """Fixed-precision number text (``-0.0`` normalised)."""
    s = f"{value:.{digits}f}"
    return "0." + "0" * digits if s.lstrip("-").strip("0.") == "" else s


def pct(value: float) -> str:
    """A 0..1 fraction as a percentage."""
    return f"{value * 100:.0f}%"


def frac(value: float) -> float:
    """Clamp to 0..1 and round for stable JSON."""
    return round(min(1.0, max(0.0, value)), 4)


def technique(t: AttackTechnique | None) -> JSON | None:
    """An ATT&CK technique with its attack.mitre.org link when the id is well formed."""
    if t is None:
        return None
    url = None
    if _TECHNIQUE.match(t.id):
        url = "https://attack.mitre.org/techniques/" + t.id.replace(".", "/") + "/"
    return {"id": txt(t.id, 20), "name": txt(t.name, 120), "tactic": opt(t.tactic, 60), "url": url}


def vuln_url(vid: str, references: Sequence[str] = ()) -> str | None:
    """First https reference, else the OSV page of a well-formed id."""
    for ref in references:
        url = https_url(ref)
        if url:
            return url
    return f"https://osv.dev/vulnerability/{vid}" if _VULN_ID.match(vid) else None


class Anchors:
    """Unique, label-safe Typst anchors plus an evidence-id resolver."""

    def __init__(self) -> None:
        self._used: set[str] = set()
        self.linked: dict[str, str] = {}  # report id -> anchor of its rendered element
        self.known: set[str] = set()  # ids that exist in the report (linked or not)

    def make(self, kind: str, *parts: str) -> str:
        """A fresh anchor ``kind-<12 hex>``; collisions get a numeric suffix."""
        base = (
            f"{kind}-"
            + hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()[:12]
        )
        anchor, n = base, 2
        while anchor in self._used:
            anchor, n = f"{base}-{n}", n + 1
        self._used.add(anchor)
        return anchor

    def link(self, ref: str, anchor: str) -> None:
        """Make ``ref`` resolve to ``anchor`` (first registration wins)."""
        self.known.add(ref)
        self.linked.setdefault(ref, anchor)

    def ref(self, ref: str) -> JSON:
        """Evidence reference: ``linked`` (has anchor), ``known`` or ``unknown``."""
        anchor = self.linked.get(ref)
        state = "linked" if anchor else ("known" if ref in self.known else "unknown")
        return {"id": txt(ref, 160), "anchor": anchor, "state": state}


# --------------------------------------------------------------------------- charts
def bar_rows(pairs: Iterable[tuple[str, int, str]]) -> list[JSON]:
    """Horizontal bar rows ``label | bar | count`` with bars scaled to the maximum."""
    items = list(pairs)
    top = max([1, *(n for _, n, _ in items)])
    return [
        {"label": label, "count": n, "frac": frac(n / top), "tone": tone}
        for label, n, tone in items
    ]


def waterfall(exp: Explanation) -> JSON:
    """Geometry of a "why this score" waterfall from an exact additive explanation."""
    points = [exp.baseline]
    for f in exp.factors:
        points.append(points[-1] + f.contribution)
    lo = min(0.0, *points)
    hi = max(100.0 if exp.total <= 100 else exp.total, *points)
    span = hi - lo or 1.0

    def geom(a: float, b: float) -> JSON:
        return {"x0": frac((min(a, b) - lo) / span), "w": max(frac(abs(b - a) / span), 0.003)}

    rows: list[JSON] = [
        {
            "label": "Baseline",
            "detail": "",
            "delta": fmt_num(exp.baseline),
            "tone": "base",
            **geom(0.0, exp.baseline),
        }
    ]
    for i, f in enumerate(exp.factors):
        detail = "" if f.value is None else txt(f.value, 40)
        if f.multiplier is not None:
            detail = (detail + " " if detail else "") + f"×{fmt_num(f.multiplier, 2)}"
        sign = "+" if f.contribution >= 0 else ""
        rows.append(
            {
                "label": txt(f.label or f.name, 80),
                "detail": detail,
                "delta": sign + fmt_num(f.contribution),
                "tone": "up" if f.contribution >= 0 else "down",
                **geom(points[i], points[i + 1]),
            }
        )
    rows.append(
        {
            "label": "Total",
            "detail": "",
            "delta": fmt_num(exp.total),
            "tone": "total",
            **geom(0.0, exp.total),
        }
    )
    alt = (
        f"Waterfall chart: baseline {fmt_num(exp.baseline)}, "
        + ", ".join(f"{r['label']} {r['delta']}" for r in rows[1:-1])
        + f", total {fmt_num(exp.total)}."
    )
    return {
        "rows": rows,
        "formula": txt(exp.formula, 300),
        "method": exp.method.value,
        "exact": True,
        "limits": [txt(x, 300) for x in exp.limits],
        "alt": txt(alt, 1500),
    }


def factor_waterfall(factors: dict[str, float], total: float) -> JSON | None:
    """Fallback waterfall from ``Threat.score_factors`` (not guaranteed exact)."""
    if not factors:
        return None
    points = [0.0]
    for v in factors.values():
        points.append(points[-1] + v)
    lo, hi = min(0.0, *points), max(100.0, total, *points)
    span = hi - lo or 1.0
    rows: list[JSON] = []
    for i, (k, v) in enumerate(factors.items()):
        a, b = points[i], points[i + 1]
        rows.append(
            {
                "label": txt(k, 80),
                "detail": "",
                "delta": ("+" if v >= 0 else "") + fmt_num(v),
                "tone": "up" if v >= 0 else "down",
                "x0": frac((min(a, b) - lo) / span),
                "w": max(frac(abs(b - a) / span), 0.003),
            }
        )
    rows.append(
        {
            "label": "Risk score",
            "detail": "",
            "delta": fmt_num(total),
            "tone": "total",
            "x0": frac(-lo / span),
            "w": max(frac(total / span), 0.003),
        }
    )
    alt = "Score factors: " + ", ".join(f"{r['label']} {r['delta']}" for r in rows)
    return {
        "rows": rows,
        "formula": "",
        "method": "score_factors",
        "exact": False,
        "limits": [],
        "alt": txt(alt, 1500),
    }


# --------------------------------------------------------------------------- sections
def _trace(trace: SSVCTrace | None) -> JSON | None:
    if trace is None:
        return None
    return {
        "tree": txt(trace.tree, 80),
        "outcome": txt(trace.outcome, 40),
        "row": trace.row,
        "path": [
            {
                "point": txt(n.decision_point, 60),
                "value": txt(n.value, 40),
                "alternatives": [txt(a, 40) for a in n.alternatives],
                "rationale": txt(n.rationale, 400),
                "source": n.source,
            }
            for n in trace.path
        ],
        "flips": [txt(f, 300) for f in trace.flips],
    }


def _intel(bundle: IntelBundle | None, summary: str | None) -> JSON | None:
    if bundle is None and not summary:
        return None
    out: JSON = {"summary": paras(summary, 2000), "bundle": None}
    if bundle is None:
        return out
    exploits = [
        {
            "source": txt(e.source, 30),
            "id": txt(e.id, 60),
            "title": opt(e.title, 160),
            "url": https_url(e.url),
            "verified": e.verified,
        }
        for e in (*bundle.metasploit, *bundle.exploitdb, *bundle.nuclei)
    ][:12]
    out["bundle"] = {
        "maturity": txt(bundle.exploit_maturity, 30),
        "exploitation": txt(bundle.exploitation, 30),
        "available": bundle.exploit_available,
        "sources": [txt(s, 40) for s in bundle.exploit_sources],
        "exploits": exploits,
        "poc_count": bundle.poc_repos_count,
        "pocs": [
            {"name": txt(p.full_name, 120), "url": https_url(p.url), "stars": p.stars}
            for p in bundle.poc_repos_top[:5]
        ],
        "vendors": [
            {
                "vendor": txt(v.vendor, 40),
                "severity": opt(v.severity, 30),
                "status": opt(v.status, 60),
                "statement": opt(v.statement, 400),
                "url": https_url(v.url),
            }
            for v in bundle.vendor_status[:8]
        ],
        "advisories": [
            {
                "title": txt(r.title or r.url, 160),
                "site": opt(r.site, 60),
                "url": https_url(r.final_url or r.url),
            }
            for r in (*bundle.advisories, *bundle.articles)[:6]
        ],
        "kev": bundle.kev is not None,
        "epss_last": fmt_num(bundle.epss_trend[-1][1], 3) if bundle.epss_trend else None,
        "fetched": iso_z(bundle.fetched_at),
        "errors": len(bundle.errors),
    }
    return out


class _Builder:
    def __init__(self, report: Report, max_rows: int, top_threats: int, top_chains: int) -> None:
        self.r = report
        self.max_rows = max_rows
        self.top_threats = top_threats
        self.top_chains = top_chains
        self.a = Anchors()
        self.pkgs = report.package_by_id()
        self.svcs = report.service_by_id()

    # ---- naming
    def name(self, ref: str) -> str:
        """Human label for a package / service id, else the id itself."""
        if ref in self.pkgs:
            return package_label(self.pkgs[ref], ref)
        if ref in self.svcs:
            return self.svcs[ref].name
        return ref

    def _short(self, ref: str, fallback: str) -> str:
        pkg = self.pkgs.get(ref)
        return fallback if pkg is None else (f"{pkg.name}:{pkg.arch}" if pkg.arch else pkg.name)

    def register_known(self) -> None:
        r = self.r
        ids: list[str] = [p.id for p in r.packages]
        ids += [s.id for s in r.services] + [b.path for b in r.binaries]
        ids += [t.id for t in r.threats] + [c.id for c in r.attack_chains]
        for v in r.vulnerabilities:
            ids += [v.id, *v.aliases]
        for c in r.attack_chains:
            ids += [s.id for s in c.steps if s.id]
        ids += [f.id for f in r.supply_chain.findings]
        ids += [e.id for e in r.evidence] + [d.id for d in r.derivations]
        if r.explanations:
            ids += [f.id for f in r.explanations.fixes]
        self.a.known.update(ids)

    # ---- inventory (anchors first so other sections can link to rows)
    def vulns(self) -> tuple[list[JSON], dict[str, int]]:
        r = self.r
        tbv = threats_by_vuln(r)
        reach = package_reachability(r)
        counts = dict.fromkeys(SEVERITIES, 0)
        rows: list[JSON] = []
        order = sorted(
            r.vulnerabilities,
            key=lambda v: (
                -vuln_severity(v).rank,
                v.kev is None,
                -(v.epss or 0.0),
                v.id,
                v.package,
            ),
        )
        for v in order:
            sev = vuln_severity(v).value
            counts[sev] = counts.get(sev, 0) + 1
            if len(rows) >= self.max_rows:
                continue
            anchor = self.a.make("vuln", v.id, v.package)
            for ref in (v.id, *v.aliases):
                self.a.link(ref, anchor)
            rows.append(
                {
                    "id": txt(v.id, 80),
                    "anchor": anchor,
                    "url": vuln_url(v.id, v.references),
                    "severity": sev,
                    "kev": v.kev is not None,
                    "package": txt(self._short(v.package, v.package_name), 120),
                    "installed": txt(v.installed_version, 80),
                    "fixed": opt(v.fixed_versions[0], 80) if v.fixed_versions else None,
                    "epss": fmt_num(v.epss, 3) if v.epss is not None else "–",
                    "status": v.status.value.replace("_", " "),
                    "reach": REACH_LABEL[
                        vuln_reachability(r, v, threats=tbv, pkg_reach=reach).value
                    ],
                    "summary": txt(v.summary or "", 300),
                }
            )
        return rows, counts

    # ---- threats
    def threat_anchors(self, threats: list[Threat]) -> dict[str, str]:
        out: dict[str, str] = {}
        for t in threats:
            out[t.id] = self.a.make("threat", t.id)
            self.a.linked[t.id] = out[t.id]  # a threat id links to its section, not a row
            self.a.known.add(t.id)
        return out

    def threat(self, t: Threat, anchor: str) -> JSON:
        r = self.r
        intel = next((b for b in r.intel if b.cve == t.vulnerability), None)
        vuln = next(
            (v for v in r.vulnerabilities if v.id == t.vulnerability and v.package == t.package),
            None,
        )
        ssvc = None
        if t.ssvc is not None:
            ssvc = {
                "decision": t.ssvc.decision.value,
                "tone": DECISION_TONE[t.ssvc.decision.value],
                "inputs": [
                    {"point": "Exploitation", "value": txt(t.ssvc.exploitation, 30)},
                    {"point": "Automatable", "value": txt(t.ssvc.automatable, 30)},
                    {"point": "Technical impact", "value": txt(t.ssvc.technical_impact, 30)},
                    {"point": "Exposure", "value": txt(t.ssvc.exposure, 30)},
                ],
                "trace": _trace(t.ssvc.trace),
                "bod": _trace(t.ssvc.bod_26_04),
            }
        chart: JSON | None
        if t.explanation is not None:
            chart = waterfall(t.explanation)
        else:
            chart = factor_waterfall(t.score_factors, t.risk_score)
        return {
            "id": txt(t.id, 80),
            "anchor": anchor,
            "title": txt(t.title, 200),
            "vuln": self.a.ref(t.vulnerability),
            "vuln_url": vuln_url(t.vulnerability, vuln.references if vuln else ()),
            "severity": vuln_severity(vuln).value if vuln else "unknown",
            "package": txt(self.name(t.package), 160),
            "risk": fmt_num(t.risk_score),
            "confidence": t.confidence.value,
            "reach": REACH_LABEL[t.reachability.value],
            "pre": txt(t.precondition, 80),
            "post": txt(t.postcondition, 80),
            "vector": txt(t.attack_vector, 20),
            "privileges": txt(t.privileges_required, 20),
            "run_as": opt(t.run_as, 60),
            "exposed": t.network_exposed,
            "listeners": [
                txt(listen_text(x.protocol, x.address, x.port, x.path), 120) for x in t.listens
            ],
            "consequences": [c.value.replace("_", " ") for c in t.consequences],
            "paths": [[txt(self.name(p), 120) for p in path] for path in t.reachability_paths[:4]],
            "techniques": [x for x in (technique(tq) for tq in t.attack_techniques) if x],
            "stride": [txt(s, 30) for s in t.stride],
            "mitigations": [txt(m, 300) for m in t.mitigations],
            "narrative": paras(t.narrative),
            "remediation": paras(t.remediation, 1500),
            "ssvc": ssvc,
            "chart": chart,
            "intel": _intel(intel, t.intel_summary),
        }

    def threat_row(self, t: Threat) -> JSON:
        return {
            "ref": self.a.ref(t.id),
            "title": txt(t.title, 160),
            "vuln": self.a.ref(t.vulnerability),
            "risk": fmt_num(t.risk_score),
            "decision": t.ssvc.decision.value if t.ssvc else "–",
            "reach": REACH_LABEL[t.reachability.value],
        }

    # ---- chains
    def step(self, s: AttackStep) -> JSON:
        return {
            "title": txt(s.title, 120),
            "technique": technique(s.technique),
            "likelihood": pct(s.likelihood),
            "mitigated": bool(s.mitigated_by),
            "mitigated_by": [txt(m, 200) for m in s.mitigated_by],
            "threat": self.a.ref(s.threat) if s.threat else None,
            "vuln": self.a.ref(s.vulnerability) if s.vulnerability else None,
            "service": opt(self.name(s.service), 120) if s.service else None,
            "evidence": [txt(e, 200) for e in s.evidence[:4]],
        }

    def chain(self, c: AttackChain, anchor: str) -> JSON:
        states = (
            [c.steps[0].from_state, *(s.to_state for s in c.steps)]
            if c.steps
            else [c.entry, c.goal]
        )
        steps = [self.step(s) for s in c.steps]
        nodes = [
            {"label": txt(s, 60), "entry": i == 0, "goal": i == len(states) - 1}
            for i, s in enumerate(states)
        ]
        alt_steps = "; ".join(
            f"{nodes[i]['label']} to {nodes[i + 1]['label']} via {st['title']}"
            + (f" ({st['technique']['id']})" if st["technique"] else "")
            + (" [mitigated]" if st["mitigated"] else "")
            for i, st in enumerate(steps)
        )
        return {
            "id": txt(c.id, 80),
            "anchor": anchor,
            "score": fmt_num(c.score),
            "likelihood": pct(c.likelihood),
            "impact": fmt_num(c.impact, 2),
            "decision": c.ssvc_decision.value,
            "tone": DECISION_TONE[c.ssvc_decision.value],
            "mitigated": c.mitigated,
            "entry": txt(c.entry, 60),
            "goal": txt(c.goal, 60),
            "layout": "row" if len(nodes) <= 4 else "column",
            "nodes": nodes,
            "steps": steps,
            "narrative": paras(c.narrative),
            "chart": waterfall(c.explanation) if c.explanation else None,
            "alt": txt(
                f"Attack chain {c.id} from {c.entry} to {c.goal}: {alt_steps or 'no steps'}.", 1500
            ),
        }

    # ---- explanations
    def system(self) -> JSON | None:
        ex = self.r.explanations
        if ex is None or ex.system is None:
            return None
        g = ex.system
        drivers = sorted(g.drivers, key=lambda d: (-d.contribution, d.id))[:10]
        top = max([1e-9, *(d.contribution for d in drivers)])
        rows = [
            {
                "label": txt(d.label, 100),
                "kind": d.kind,
                "ref": self.a.ref(d.id),
                "value": fmt_num(d.contribution),
                "share": pct(d.share),
                "cumulative": pct(d.cumulative),
                "frac": frac(d.contribution / top),
            }
            for d in drivers
        ]
        alt = (
            f"Bar chart of the top risk drivers of system risk {fmt_num(g.system_risk)}: "
            + ", ".join(f"{x['label']} {x['share']}" for x in rows)
        )
        pareto = ", ".join(f"{n} {txt(k, 30)}" for k, n in sorted(g.pareto_80.items()))
        return {
            "risk": fmt_num(g.system_risk),
            "risk_frac": frac(g.system_risk / 100),
            "tone": "critical"
            if g.system_risk >= 80
            else "high"
            if g.system_risk >= 60
            else "medium"
            if g.system_risk >= 30
            else "low",
            "formula": txt(g.formula, 300),
            "method": g.method.value,
            "drivers": rows,
            "pareto": pareto,
            "alt": txt(alt, 1500),
        }

    def fixes(self) -> JSON | None:
        ex = self.r.explanations
        if ex is None or not (ex.fix_plan or ex.what_if or ex.fixes):
            return None
        by_id = {f.id: f for f in ex.fixes}
        fix_rows = []
        for f in sorted(ex.fixes, key=lambda f: f.id):
            anchor = self.a.make("fix", f.id)
            self.a.link(f.id, anchor)
            fix_rows.append(
                {
                    "id": txt(f.id, 80),
                    "anchor": anchor,
                    "kind": f.kind,
                    "target": txt(self.name(f.target), 120),
                    "action": txt(f.action, 300),
                    "cost": fmt_num(f.cost),
                    "resolves": len(f.resolves),
                    "breaks": len(f.breaks),
                }
            )

        def plan(w: WhatIf) -> JSON:
            return {
                "fixes": [
                    {
                        "ref": self.a.ref(fid),
                        "action": txt(by_id[fid].action, 200) if fid in by_id else "",
                    }
                    for fid in w.fixes
                ],
                "chains": [self.a.ref(c) for c in w.chains_broken],
                "threats": [self.a.ref(t) for t in w.threats_resolved],
                "before": fmt_num(w.risk_before),
                "after": fmt_num(w.risk_after),
                "before_frac": frac(w.risk_before / 100),
                "after_frac": frac(w.risk_after / 100),
                "method": w.method.replace("_", " "),
                "note": txt(w.note, 300),
            }

        what_if = sorted(ex.what_if, key=lambda w: (w.risk_after, w.fixes))
        return {
            "plans": [plan(w) for w in ex.fix_plan],
            "what_if": [plan(w) for w in what_if[:15]],
            "fixes": fix_rows,
        }

    # ---- supply chain
    def tree_rows(self, paths: Iterable[list[str]]) -> list[JSON]:
        trie: dict[str, Any] = {}
        for path in paths:
            node = trie
            for part in path:
                node = node.setdefault(txt(self.name(part), 120), {})
        rows: list[JSON] = []

        def walk(node: dict[str, Any], prefix: str, root: bool) -> None:
            items = sorted(node.items())
            for i, (label, child) in enumerate(items):
                last = i == len(items) - 1
                if root:
                    rows.append({"prefix": "", "label": label})
                    walk(child, "", False)
                else:
                    rows.append({"prefix": prefix + ("└── " if last else "├── "), "label": label})
                    walk(child, prefix + ("    " if last else "│   "), False)

        walk(trie, "", True)
        return rows[:80]

    def supply(self) -> JSON:
        sc = self.r.supply_chain
        findings = []
        for f in sorted(sc.findings, key=lambda f: (-f.severity.rank, f.id)):
            anchor = self.a.make("sc", f.id)
            self.a.link(f.id, anchor)
            findings.append(
                {
                    "id": txt(f.id, 80),
                    "anchor": anchor,
                    "severity": f.severity.value,
                    "kind": txt(f.kind, 40).replace("_", " "),
                    "subject": txt(self.name(f.subject), 160),
                    "title": txt(f.title, 200),
                    "detail": txt(f.detail or "", 400),
                }
            )
        blast = []
        for b in sorted(sc.blast_radius, key=lambda b: (-b.score, b.package))[:6]:
            anchor = self.a.make("blast", b.package)
            if b.package not in self.a.linked:
                self.a.link(b.package, anchor)
            blast.append(
                {
                    "anchor": anchor,
                    "package": txt(self.name(b.package), 160),
                    "vendor": opt(b.vendor, 80),
                    "score": fmt_num(b.score),
                    "services": len(b.services),
                    "binaries": len(b.binaries),
                    "vulns": [self.a.ref(v) for v in b.vulnerabilities[:8]],
                    "rows": self.tree_rows(b.example_paths),
                }
            )
        vendors = [
            {
                "vendor": txt(v.vendor, 80),
                "packages": v.packages,
                "boot": v.boot_packages,
                "services": v.services,
                "vulns": v.vulnerabilities,
                "critical": v.critical,
                "high": v.high,
                "kev": v.kev,
            }
            for v in sorted(
                sc.vendors, key=lambda v: (-v.critical, -v.vulnerabilities, -v.packages, v.vendor)
            )[:25]
        ]
        return {"vendors": vendors, "findings": findings, "blast": blast}

    # ---- services
    def services(self) -> tuple[list[JSON], int]:
        rows = []
        manual = 0
        ordered = sorted(
            self.r.services,
            key=lambda s: (not s.network_exposed, -(s.hardening.exposure or 0.0), s.name, s.id),
        )
        for s in ordered:
            if service_reachability(s) is None:
                manual += 1
                continue
            anchor = self.a.make("svc", s.id)
            self.a.link(s.id, anchor)
            h = s.hardening
            user = "dynamic" if h.dynamic_user else txt(h.user, 40)
            listeners = sorted(
                s.listens,
                key=lambda x: (x.scope != "network", x.protocol, x.port or 0, x.path or ""),
            )
            rows.append(
                {
                    "anchor": anchor,
                    "name": txt(s.name, 120),
                    "init": s.init_system.value,
                    "activation": ", ".join(a.value for a in s.activation),
                    "user": user,
                    "root": h.runs_as_root,
                    "exposure": (
                        fmt_num(h.exposure)
                        + (f" {txt(h.exposure_rating, 20)}" if h.exposure_rating else "")
                    )
                    if h.exposure is not None
                    else "–",
                    "listeners": [
                        {
                            "text": txt(listen_text(x.protocol, x.address, x.port, x.path), 120),
                            "network": x.scope == "network",
                        }
                        for x in listeners[:6]
                    ],
                    "network": s.network_exposed,
                }
            )
        return rows, manual

    # ---- AI
    def ai(self) -> JSON | None:
        ai = self.r.ai
        if ai is None:
            return None
        unknown: set[str] = set()

        def ev(refs: Sequence[AIEvidenceRef]) -> list[JSON]:
            out = []
            for e in refs:
                item = self.a.ref(e.ref)
                if item["state"] == "unknown":
                    unknown.add(item["id"])
                out.append({**item, "kind": txt(e.kind, 30), "note": opt(e.note, 200)})
            return out

        def ids(refs: Sequence[str]) -> list[JSON]:
            out = [self.a.ref(x) for x in refs]
            unknown.update(i["id"] for i in out if i["state"] == "unknown")
            return out

        findings = []
        for f in sorted(ai.findings, key=lambda f: (f.priority, f.title)):
            threat = ids([f.threat_id])[0] if f.threat_id else None
            findings.append(
                {
                    "title": txt(f.title, 200),
                    "priority": txt(f.priority, 10),
                    "tone": {"P1": "critical", "P2": "high", "P3": "medium"}.get(f.priority, "low"),
                    "agrees": f.agrees_with_scanner,
                    "threat": threat,
                    "evidence": ev(f.evidence),
                    "rationale": paras(f.rationale, 2000),
                    "confidence": pct(f.confidence),
                    "counterfactuals": [
                        {"condition": txt(c.condition, 200), "effect": txt(c.effect, 200)}
                        for c in f.counterfactuals
                    ],
                }
            )
        plan = [
            {
                "n": i,
                "title": txt(s.title, 200),
                "commands": [txt(c, 300) for c in s.commands[:8]],
                "fixes": ids(s.fixes),
                "evidence": ev(s.evidence),
                "rationale": paras(s.rationale, 1500),
                "confidence": pct(s.confidence),
            }
            for i, s in enumerate(ai.remediation_plan, start=1)
        ]
        g = ai.grounding
        return {
            "provider": txt(ai.provider, 60),
            "model": txt(ai.model, 80),
            "agents": [txt(a, 40) for a in ai.agents],
            "generated": iso_z(ai.generated),
            "input_sha256": txt(ai.input_sha256, 80)[:16],
            "audience": ai.audience,
            "disclaimer": txt(ai.disclaimer, 400),
            "summary": paras(ai.executive_summary, 4000),
            "grounding": {
                "passed": g.passed,
                "ratio": pct(g.grounded_ratio),
                "issues": [
                    {
                        "claim": "summary" if i.claim < 0 else str(i.claim),
                        "code": i.code.replace("_", " "),
                        "detail": txt(i.detail, 300),
                    }
                    for i in g.issues[:30]
                ],
            },
            "findings": findings,
            "plan": plan,
            "claims": len(ai.claims),
            "caveats": [txt(c, 300) for c in ai.caveats],
            "unknown": sorted(unknown),
        }


def _kpis(report: Report, counts: dict[str, int], threats: Sequence[Threat]) -> list[JSON]:
    s = report.summary
    decisions = [t.ssvc.decision for t in threats if t.ssvc]
    act = s.act or decisions.count(SSVCDecision.ACT)
    attend = s.attend or decisions.count(SSVCDecision.ATTEND)
    vulns = len(report.vulnerabilities) or s.vulnerabilities
    kev = sum(1 for v in report.vulnerabilities if v.kev) or s.kev
    boot = s.boot_services or sum(1 for x in report.services if service_reachability(x) is not None)
    net = s.network_services or sum(
        1 for x in report.services if x.network_exposed and service_reachability(x)
    )
    chains = len(report.attack_chains) or s.attack_chains
    sc = len(report.supply_chain.findings) or s.supply_chain_findings
    return [
        {
            "label": "Packages",
            "value": str(len(report.packages) or s.packages),
            "sub": f"{s.boot_packages} on boot path",
            "tone": "neutral",
        },
        {
            "label": "Boot services",
            "value": str(boot),
            "sub": f"{len(report.services) or s.services} services total",
            "tone": "neutral",
        },
        {
            "label": "Network services",
            "value": str(net),
            "sub": "listening beyond loopback",
            "tone": "high" if net else "neutral",
        },
        {
            "label": "Vulnerabilities",
            "value": str(vulns),
            "sub": f"{counts['critical']} critical · {counts['high']} high",
            "tone": "critical" if counts["critical"] else "high" if counts["high"] else "neutral",
        },
        {
            "label": "Known exploited",
            "value": str(kev),
            "sub": "CISA KEV entries",
            "tone": "critical" if kev else "neutral",
        },
        {
            "label": "SSVC Act / Attend",
            "value": f"{act} / {attend}",
            "sub": f"of {len(threats) or s.threats} threats",
            "tone": "critical" if act else "high" if attend else "neutral",
        },
        {
            "label": "Attack chains",
            "value": str(chains),
            "sub": "multi-step paths",
            "tone": "high" if chains else "neutral",
        },
        {
            "label": "Supply chain",
            "value": str(sc),
            "sub": "provenance findings",
            "tone": "medium" if sc else "neutral",
        },
    ]


def build_view_model(
    report: Report,
    *,
    max_rows: int = 5000,
    top_threats: int = 10,
    top_chains: int = 6,
) -> JSON:
    """Build the template's data: plain JSON values only, every string sanitised."""
    r = canonical(report)
    b = _Builder(r, max_rows, top_threats, top_chains)
    b.register_known()
    vuln_rows, counts = b.vulns()

    threats = sorted(r.threats, key=threat_sort_key)
    shown = threats[:top_threats]
    t_anchor = b.threat_anchors(shown)
    chains = sorted(r.attack_chains, key=lambda c: (-c.score, c.id))
    c_shown = chains[:top_chains]
    c_anchor = {c.id: b.a.make("chain", c.id) for c in c_shown}
    for cid, anchor in c_anchor.items():
        b.a.link(cid, anchor)
    services, manual = b.services()
    supply = b.supply()
    fixes = b.fixes()
    system = b.system()

    sev_tone = {"none": "neutral", "unknown": "neutral"}
    sev_rows = bar_rows((s, counts[s], sev_tone.get(s, s)) for s in SEVERITIES)
    decisions = [t.ssvc.decision for t in threats if t.ssvc]
    ssvc_rows = bar_rows((d.value, decisions.count(d), DECISION_TONE[d.value]) for d in DECISIONS)

    md = r.metadata
    eol = r.os.eol
    eol_status = "unknown"
    if eol is not None and eol.is_eol is not None:
        eol_status = "eol" if eol.is_eol else "supported"
    cov = md.coverage
    vm: JSON = {
        "title": "Startup-SBOM Security Report",
        "meta": {
            "tool": txt(md.tool, 40),
            "tool_version": txt(md.tool_version, 40),
            "schema": txt(md.schema_version, 10),
            "scan_id": txt(md.scan_id, 80),
            "target": txt(md.target.reference, 200),
            "target_kind": txt(md.target.kind, 30),
            "digest": opt(md.target.digest, 100),
            "platform": opt(md.target.platform, 40),
            "started": iso_z(md.started),
            "finished": iso_z(md.finished) if md.finished else None,
            "date": md.started.strftime("%Y-%m-%d"),
            "image": opt(r.container.image, 200) if r.container else None,
        },
        "os": {
            "name": txt(r.os.pretty_name or r.os.name or r.os.id, 120),
            "family": opt(r.os.family, 30),
            "eol_status": eol_status,
            "eol_date": opt(eol.eol_date, 30) if eol else None,
        },
        "kpis": _kpis(r, counts, threats),
        "severity": {
            "rows": sev_rows,
            "alt": "Bar chart of vulnerabilities by severity: "
            + ", ".join(f"{x['label']} {x['count']}" for x in sev_rows),
        },
        "ssvc": {
            "rows": ssvc_rows,
            "alt": "Bar chart of threats by SSVC decision: "
            + ", ".join(f"{x['label']} {x['count']}" for x in ssvc_rows),
        },
        "system": system,
        "threats": [b.threat(t, t_anchor[t.id]) for t in shown],
        "other_threats": [b.threat_row(t) for t in threats[top_threats:][:200]],
        "chains": [b.chain(c, c_anchor[c.id]) for c in c_shown],
        "other_chains": [
            {
                "ref": b.a.ref(c.id),
                "score": fmt_num(c.score),
                "decision": c.ssvc_decision.value,
                "path": txt(f"{c.entry} → {c.goal}", 120),
                "steps": len(c.steps),
            }
            for c in chains[top_chains:][:100]
        ],
        "fixes": fixes,
        "supply": supply,
        "services": services,
        "services_manual": manual,
        "vulns": vuln_rows,
        "vulns_truncated": max(0, len(r.vulnerabilities) - len(vuln_rows)),
        "coverage": {
            "databases": [txt(x, 40) for x in cov.package_databases],
            "init_systems": [txt(x, 40) for x in cov.init_systems],
            "sources": [txt(x, 40) for x in cov.vulnerability_sources],
            "ecosystems": [txt(x, 40) for x in cov.vulnerability_ecosystems],
            "offline": cov.offline,
            "limitations": [txt(x, 400) for x in cov.limitations],
        },
        "warnings": [txt(w, 400) for w in r.warnings[:100]],
        "warnings_truncated": max(0, len(r.warnings) - 100),
        "has_intel": bool(r.intel) or any(t.intel_summary for t in r.threats),
    }
    vm["ai"] = b.ai()  # last: every anchor is registered by now
    return vm


__all__ = ["JSON", "Anchors", "build_view_model", "https_url", "paras", "txt", "waterfall"]
