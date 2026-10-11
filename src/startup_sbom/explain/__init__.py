"""Explainable-AI layer: exact, evidence-backed explanations of every verdict.

Startup-SBOM is a glass-box system (closed-form risk formula, published SSVC
tables, forward-chaining rules), so explanations are computed *from the model
itself* rather than approximated post hoc.  :func:`explain_report` fills:

* ``Threat.explanation`` (exact ``sequential+lmdi`` breakdown, mirrored in
  ``Threat.score_factors``), ``Threat.evidence`` and weakest-link ``confidence``;
* ``SSVC.trace`` / ``SSVC.bod_26_04`` decision paths with flips;
* ``AttackStep.id`` / ``derivation`` and ``AttackChain.explanation`` (LMDI);
* ``Report.evidence`` / ``derivations`` (content-addressed provenance graph);
* ``Report.explanations``: system risk drivers, candidate fixes, single-fix
  what-ifs and the minimal fix plan(s).

It also consumes prefetched exploit intelligence (``Report.intel``): the SSVC
*Exploitation* input is raised (never lowered) and an ``exploit_maturity`` factor
is added to the risk formula transparently.

NIST IR 8312 (Four Principles of Explainable AI) mapping:

* **Explanation** — every score, decision and chain step carries its reasons and
  cites evidence ids.
* **Meaningful** — the same data is rendered as tables, trees, waterfalls and
  charts (``startup_sbom.viz``) with plain-language labels.
* **Explanation accuracy** — decompositions are validator-enforced to be exact;
  SSVC traces read the table row actually used.
* **Knowledge limits** — ``Explanation.limits``, ``DecisionNode.source``,
  weakest-link confidence and reported bounds/residuals.
"""

from __future__ import annotations

import contextlib
import math
from collections import defaultdict
from collections.abc import Iterator
from typing import TYPE_CHECKING, Literal

from startup_sbom.explain.attribution import (
    MAX_EXPLOITABILITY,
    ChainStepInput,
    ThreatInputs,
    explain_chain,
    inputs_from_explanation,
    likelihood_of,
)
from startup_sbom.explain.counterfactual import (
    ChainItem,
    exact_hitting_set,
    generate_fixes,
    greedy_hitting_set,
    min_cut,
    what_if,
)
from startup_sbom.explain.global_ import global_explanation
from startup_sbom.explain.provenance import Provenance, weakest
from startup_sbom.explain.ssvc_trace import Point, trace_bod_26_04, trace_coordinator
from startup_sbom.models import (
    SSVC,
    AttackChain,
    Confidence,
    EvidenceKind,
    Explanations,
    IntelBundle,
    Report,
    SSVCDecision,
    Threat,
    Vulnerability,
    WhatIf,
)

if TYPE_CHECKING:
    from startup_sbom.threat.cvss import VectorFacts

__all__ = ["explain_report", "intel_summary"]

_MITIGATION_MULTIPLIER = {
    "NoNewPrivileges=yes": 0.5,
    "DynamicUser=yes": 0.7,
    "CapabilityBoundingSet drops dangerous capabilities": 0.7,
    "RestrictSUIDSGID=yes": 0.85,
    "SystemCallFilter set": 0.8,
    "ProtectSystem=strict": 0.9,
}
_MAX_LIST = 3


def explain_report(report: Report) -> None:
    """Fill every explanation field of ``report`` in place (idempotent, never raises)."""
    try:
        engine = _Engine(report)
    except Exception as exc:  # noqa: BLE001 - explanations must never break a scan
        _warn(report, f"explain: skipped ({type(exc).__name__})")
        return
    engine.run()


def intel_summary(bundle: IntelBundle, *, kev: bool = False) -> str:
    """One-line exploit-intelligence summary, e.g. ``Metasploit module, 2 Exploit-DB
    entries, 88 PoC repos (unverified), KEV``."""
    parts: list[str] = []
    if bundle.metasploit:
        n = len(bundle.metasploit)
        parts.append("Metasploit module" if n == 1 else f"{n} Metasploit modules")
    if bundle.exploitdb:
        n = len(bundle.exploitdb)
        parts.append(f"{n} Exploit-DB entr{'y' if n == 1 else 'ies'}")
    if bundle.nuclei:
        n = len(bundle.nuclei)
        parts.append(f"{n} Nuclei template{'' if n == 1 else 's'}")
    if bundle.poc_repos_count:
        n = bundle.poc_repos_count
        parts.append(f"{n} PoC repo{'' if n == 1 else 's'} (unverified)")
    if kev or bundle.kev is not None:
        parts.append("KEV")
    return ", ".join(parts) if parts else "no public exploit references found"


def _warn(report: Report, message: str) -> None:
    if message not in report.warnings:
        report.warnings.append(message)


class _Engine:
    """One explanation pass over a report."""

    def __init__(self, report: Report) -> None:
        self.r = report
        self.prov = Provenance(report.evidence, report.derivations)
        self.vulns = {(v.id, v.package): v for v in report.vulnerabilities}
        self.pkgs = report.package_by_id()
        self.svcs = report.service_by_id()
        self.intel: dict[str, IntelBundle] = {}
        for b in sorted(report.intel, key=lambda b: (b.cve, b.fetched_at)):
            self.intel[b.cve.upper()] = b
        self.risk_dv: dict[str, str] = {}
        self.likelihood: dict[str, float] = {}
        self.decisions: dict[str, SSVCDecision] = {}

    # ------------------------------------------------------------------ driver
    def run(self) -> None:
        for t in self.r.threats:
            with self._guard(f"threat {t.id}"):
                self._threat(t)
        for c in self.r.attack_chains:
            with self._guard(f"chain {c.id}"):
                self._chain(c)
        self.r.threats.sort(key=lambda t: (-t.risk_score, t.id))
        self.r.attack_chains.sort(key=lambda c: (c.mitigated, -c.score, c.id))
        with self._guard("counterfactuals"):
            self._system()
        self.r.evidence = self.prov.sorted_evidence()
        self.r.derivations = self.prov.sorted_derivations()
        s = self.r.summary
        if s.threats == len(self.r.threats) and self.r.threats:
            decisions = [t.ssvc.decision for t in self.r.threats if t.ssvc is not None]
            s.act = decisions.count(SSVCDecision.ACT)
            s.attend = decisions.count(SSVCDecision.ATTEND)

    @contextlib.contextmanager
    def _guard(self, what: str) -> Iterator[None]:
        try:
            yield
        except Exception as exc:  # noqa: BLE001 - one bad item must not stop the rest
            _warn(self.r, f"explain: {what} not explained ({type(exc).__name__})")

    # ------------------------------------------------------------------ threats
    def _bundle(self, t: Threat, vuln: Vulnerability | None) -> IntelBundle | None:
        ids = [t.vulnerability, *(vuln.aliases if vuln else [])]
        for i in ids:
            if (b := self.intel.get(i.upper())) is not None:
                return b
        return None

    def _threat(self, t: Threat) -> None:
        from startup_sbom.threat import cvss, scoring

        vuln = self.vulns.get((t.vulnerability, t.package))
        bundle = self._bundle(t, vuln)
        facts = cvss.best(vuln) if vuln is not None else cvss.UNKNOWN
        kev = (vuln.kev is not None if vuln is not None else False) or (
            bundle is not None and bundle.kev is not None
        )
        factor_ev, premises = self._threat_evidence(t, vuln, facts, bundle, kev)
        inputs = self._inputs(t, vuln, facts)
        if vuln is not None:
            inputs.epss = vuln.epss
            inputs.exploitability = facts.exploitability
            inputs.kev = kev
        else:
            inputs.kev = inputs.kev or kev
        inputs.exploit_maturity = bundle.exploit_maturity if bundle is not None else None
        inputs.evidence = factor_ev
        risk, expl = scoring.explain(inputs)
        risk_dv = self.prov.derive(t.id, "risk/1", premises)
        self.risk_dv[t.id] = risk_dv
        conf = self.prov.confidence(risk_dv)
        t.explanation = expl.model_copy(update={"confidence": conf})
        t.risk_score = risk
        t.score_factors = {f.name: round(f.contribution, 3) for f in expl.factors}
        t.confidence = conf
        cited = {risk_dv, *(e for ids in factor_ev.values() for e in ids)}
        self.likelihood[t.id] = likelihood_of(expl)
        t.intel_summary = intel_summary(bundle, kev=kev) if bundle is not None else None
        self._ssvc(t, vuln, facts, bundle, kev, factor_ev, cited)
        t.evidence = sorted(cited)

    def _inputs(self, t: Threat, vuln: Vulnerability | None, facts: VectorFacts) -> ThreatInputs:
        if t.explanation is not None and (base := inputs_from_explanation(t.explanation)):
            base.subject = t.id
            return base
        if (legacy := self._legacy_inputs(t)) is not None:
            return legacy
        from startup_sbom.threat import scoring
        from startup_sbom.threat.reverse import mitigation_factors

        consequences = set(t.consequences)
        svc = self.svcs.get(t.services[0]) if t.services else None
        mits = mitigation_factors(svc, t.reachability, consequences)
        inputs = scoring.build_inputs(
            t.id,
            epss=vuln.epss if vuln is not None else None,
            kev=vuln is not None and vuln.kev is not None,
            facts=facts,
            level=t.reachability,
            network_exposed=t.network_exposed,
            link_confidence=self._link_confidence(t),
            in_container=False,
            consequences=consequences,
            precondition=t.precondition,
            postcondition=t.postcondition,
            mitigations=[(m[0], m[1]) for m in mits],
        )
        inputs.limits.append("risk inputs reconstructed from report fields (no recorded factors)")
        return inputs

    def _legacy_inputs(self, t: Threat) -> ThreatInputs | None:
        sf = t.score_factors
        if "likelihood" not in sf or "reachability" not in sf:
            return None
        from startup_sbom.threat import scoring

        x = sf.get("exploitability")
        mitigation = sf.get("mitigation", 1.0)
        split: list[tuple[str, float]] = []
        for label in t.mitigations:
            m = 0.7 if label.startswith("User=") else _MITIGATION_MULTIPLIER.get(label)
            if m is not None:
                split.append((label, m))
        if not math.isclose(math.prod(m for _, m in split), mitigation, abs_tol=1e-3):
            split = [("hardening", mitigation)] if not math.isclose(mitigation, 1.0) else []
        cons = set(t.consequences)
        return ThreatInputs(
            subject=t.id,
            epss=None if sf.get("epss_missing") else sf.get("epss"),
            exploitability=(
                None if sf.get("exploitability_unknown") or x is None else x * MAX_EXPLOITABILITY
            ),
            kev=bool(sf.get("kev_floor")),
            reachability=(t.reachability.value, sf["reachability"]),
            impact=(scoring.impact_label(cons), sf.get("impact", scoring.impact(cons))),
            privilege_gain=(
                scoring.privilege_label(t.precondition, t.postcondition),
                sf.get("privilege_gain", 1.0),
            ),
            mitigations=split,
            limits=["risk inputs converted from a legacy factor map"],
        )

    def _link_confidence(self, t: Threat) -> Confidence | None:
        levels = [
            lib.confidence
            for b in self.r.binaries
            if b.path in t.binaries
            for lib in b.libraries
            if lib.package == t.package
        ]
        return weakest(levels) if levels else None

    # ------------------------------------------------------------------ evidence
    def _threat_evidence(
        self,
        t: Threat,
        vuln: Vulnerability | None,
        facts: VectorFacts,
        bundle: IntelBundle | None,
        kev: bool,
    ) -> tuple[dict[str, list[str]], list[str]]:
        from startup_sbom.threat.reachability import describe_listen

        p = self.prov
        ev: dict[str, list[str]] = defaultdict(list)
        premises: list[str] = []
        pkg = self.pkgs.get(t.package)
        pname = pkg.name if pkg else t.package
        pkg_ev = p.fact(
            EvidenceKind.PACKAGE_DB,
            f"{pname} {pkg.version} installed" if pkg else f"{t.package} installed",
            (pkg.location if pkg and pkg.location else "package database"),
            locator=f"Package: {pname}",
        )
        # -- vulnerability match
        if vuln is not None:
            src = vuln.advisories[0] if vuln.advisories else f"{(vuln.sources or ['osv'])[0]}"
            fixed = f" (fixed in {', '.join(sorted(vuln.fixed_versions)[:2])})"
            adv = p.fact(
                EvidenceKind.ADVISORY,
                f"{vuln.id} affects {vuln.package_name} {vuln.installed_version}"
                + (fixed if vuln.fixed_versions else ""),
                f"{src}:{vuln.id}" if ":" not in src else src,
                retrieved=vuln.modified,
                confidence=vuln.match_confidence,
            )
            premises.append(p.derive(f"{vuln.id}@{t.package}", "vuln.match", [pkg_ev, adv]))
            # -- feeds
            if vuln.epss is not None:
                pct = (
                    f", percentile {vuln.epss_percentile:.2f}"
                    if vuln.epss_percentile is not None
                    else ""
                )
                e = p.fact(EvidenceKind.FEED, f"EPSS {vuln.epss:.5f}{pct}", "epss")
                ev["epss"].append(e)
                premises.append(e)
            else:
                ev["epss"].append(
                    p.fact(
                        EvidenceKind.DEFAULT,
                        "EPSS unavailable: EPSS term counted as 0",
                        "default",
                        confidence=Confidence.MEDIUM,
                    )
                )
            if vuln.kev is not None:
                added = f" (added {vuln.kev.date_added})" if vuln.kev.date_added else ""
                e = p.fact(EvidenceKind.FEED, f"{vuln.id} listed in CISA KEV{added}", "kev")
                ev["kev_floor"].append(e)
                premises.append(e)
        if facts.vector:
            cv = p.fact(
                EvidenceKind.ADVISORY,
                f"CVSS {facts.version} {facts.vector}",
                "cvss",
                locator=t.vulnerability,
            )
        else:
            cv = p.fact(
                EvidenceKind.DEFAULT,
                f"no CVSS vector for {t.vulnerability}: exploitability assumed half of maximum",
                "default",
                confidence=Confidence.LOW,
            )
        ev["exploitability"].append(cv)
        premises.append(cv)
        # -- intel
        if bundle is not None:
            verified = bool(bundle.metasploit or bundle.exploitdb or bundle.nuclei or bundle.kev)
            e = p.fact(
                EvidenceKind.FEED,
                f"exploit intelligence for {bundle.cve}: {intel_summary(bundle, kev=kev)}; "
                f"maturity {bundle.exploit_maturity}, exploitation {bundle.exploitation}",
                "intel:" + (",".join(sorted(bundle.exploit_sources)) or "prefetch"),
                retrieved=bundle.fetched_at.date().isoformat(),
                confidence=Confidence.HIGH if verified else Confidence.MEDIUM,
            )
            ev["exploit_maturity"].append(e)
            if bundle.kev is not None and not ev["kev_floor"]:
                ev["kev_floor"].append(e)
            premises.append(e)
        # -- reachability
        reach: list[str] = [pkg_ev]
        link_conf = self._link_confidence(t) or Confidence.HIGH
        for sid in t.services[:_MAX_LIST]:
            svc = self.svcs.get(sid)
            source = (svc.unit_path if svc and svc.unit_path else sid) or sid
            acts = ", ".join(a.value for a in svc.activation) if svc else "unknown activation"
            reach.append(p.fact(EvidenceKind.FILE, f"{sid} starts via {acts}", source))
        reach.extend(
            p.fact(EvidenceKind.FILE, f"listens on {describe_listen(li)}", li.source)
            for li in t.listens[:_MAX_LIST]
        )
        reach.extend(
            p.fact(
                EvidenceKind.FILE,
                "execution path " + " -> ".join(path),
                path[0],
                confidence=link_conf,
            )
            for path in t.reachability_paths[:1]
            if path
        )
        reach.extend(
            p.fact(EvidenceKind.FILE, f"{b} is shipped by {pname}", b)
            for b in t.binaries[:_MAX_LIST]
        )
        reach_dv = p.derive(f"{t.id}#reachability", f"reach.{t.reachability.value}", reach)
        ev["reachability"].append(reach_dv)
        premises.append(reach_dv)
        # -- impact / privilege / mitigations
        if vuln is not None and vuln.cwes:
            ev["impact"].append(
                p.fact(
                    EvidenceKind.ADVISORY,
                    f"weaknesses {', '.join(sorted(vuln.cwes)[:4])} -> "
                    + ", ".join(c.value for c in t.consequences),
                    "cwe",
                    locator=t.vulnerability,
                )
            )
        else:
            ev["impact"].append(cv)
        svc0 = self.svcs.get(t.services[0]) if t.services else None
        if t.run_as and svc0 is not None:
            ev["privilege_gain"].append(
                p.fact(
                    EvidenceKind.FILE,
                    f"{svc0.id} runs as {t.run_as}",
                    svc0.unit_path or svc0.id,
                )
            )
        for m in t.mitigations:
            if svc0 is not None:
                ev[f"mitigation:{m}"].append(
                    p.fact(EvidenceKind.FILE, f"{svc0.id}: {m}", svc0.unit_path or svc0.id)
                )
        return {k: sorted(set(v)) for k, v in ev.items()}, premises

    # ------------------------------------------------------------------ SSVC
    def _ssvc(
        self,
        t: Threat,
        vuln: Vulnerability | None,
        facts: VectorFacts,
        bundle: IntelBundle | None,
        kev: bool,
        factor_ev: dict[str, list[str]],
        cited: set[str],
    ) -> None:
        from startup_sbom.threat import ssvc as tssvc

        cur = t.ssvc
        if cur is None:
            if vuln is None:
                return
            cur, _ = tssvc.assess(
                vuln, facts, set(t.consequences), t.reachability, t.network_exposed
            )
        old = cur.decision
        # Exploitation: computed from the vulnerability, raised (never lowered) by intel.
        if vuln is not None:
            expl_v, why = tssvc.exploitation(vuln)
        else:
            expl_v, why = cur.exploitation, "recorded in the report"
        expl_ev = list(factor_ev.get("kev_floor", []) or factor_ev.get("epss", []))
        source: Literal["cisa_adp", "computed", "user", "default"] = "computed"
        rank = tssvc.EXPLOITATION_RANK
        if bundle is not None:
            raised = bundle.exploitation if bundle.exploitation in rank else "none"
            adp = bundle.cisa_ssvc.get("Exploitation", "").strip().lower().replace(" ", "_")
            if rank.get(raised, 0) > rank.get(expl_v, 0):
                expl_v = raised
                why = f"raised by exploit intelligence: {intel_summary(bundle, kev=kev)}"
                expl_ev = list(factor_ev.get("exploit_maturity", []))
            if adp in rank and rank[adp] > rank.get(expl_v, 0):
                expl_v, why, source = adp, "CISA ADP SSVC option in the CVE record", "cisa_adp"
                expl_ev = list(factor_ev.get("exploit_maturity", []))
        auto = cur.automatable
        auto_why = (
            "AV:N/AC:L/PR:N/UI:N: unauthenticated, low-complexity network exploit"
            if auto == "yes"
            else (
                "not reliably automatable: " + tssvc.not_automatable_reason(facts)
                if vuln is not None
                else "recorded in the report"
            )
        )
        cvss_ev = factor_ev.get("exploitability", [])
        ti = cur.technical_impact
        ti_why = (
            "code execution or privilege gain with high confidentiality and integrity impact"
            if ti == "total"
            else "partial control or disclosure only"
        )
        mission = tssvc.EXPOSURE_TO_MISSION.get(cur.exposure, "medium")
        exposure_ev = factor_ev.get("reachability", [])
        decision = tssvc.decide(expl_v, auto, ti, cur.exposure)
        coord = trace_coordinator(
            Point(expl_v, why, expl_ev, source),
            Point(auto, auto_why, cvss_ev),
            Point(ti, ti_why, factor_ev.get("impact", [])),
            Point(
                mission,
                f"Mission & Well-Being cannot be observed in an image; proxy from system "
                f"exposure '{cur.exposure}' -> {mission}",
                exposure_ev,
                "default",
            ),
        )
        bod = trace_bod_26_04(
            Point(
                "yes" if kev else "no",
                "listed in the CISA KEV catalog" if kev else "not listed in the CISA KEV catalog",
                factor_ev.get("kev_floor", []),
            ),
            Point(
                "yes" if cur.exposure == "open" else "no",
                "reachable from the network (non-loopback listener)"
                if cur.exposure == "open"
                else "no network-reachable listener observed (static analysis)",
                exposure_ev,
            ),
            Point(auto, auto_why, cvss_ev),
            Point(ti, ti_why, factor_ev.get("impact", [])),
        )
        t.ssvc = SSVC(
            exploitation=expl_v,
            automatable=auto,
            technical_impact=ti,
            exposure=cur.exposure,
            decision=decision,
            trace=coord,
            bod_26_04=bod,
        )
        self.decisions[t.id] = decision
        cited.update(n for node in coord.path for n in node.evidence)
        if decision is not old:
            t.narrative = t.narrative.replace(
                f"SSVC decision: {old.value}.", f"SSVC decision: {decision.value}."
            )

    # ------------------------------------------------------------------ chains
    def _chain(self, c: AttackChain) -> None:
        from startup_sbom.threat.chains import narrate, step_id, step_input
        from startup_sbom.threat.rules import MITIGATION_DOWNGRADE
        from startup_sbom.threat.ssvc import RANK

        p = self.prov
        inputs: list[ChainStepInput] = []
        confs: list[Confidence] = []
        worst: SSVCDecision | None = None
        for s in c.steps:
            if not s.id:
                s.id = step_id(s.rule, s.from_state, s.to_state, s.threat or s.service or "")
            premises: list[str] = []
            if s.threat and s.threat in self.risk_dv:
                premises.append(self.risk_dv[s.threat])
            else:
                kind = (
                    EvidenceKind.CONTAINER_CONFIG
                    if s.rule == "R9" and not s.service
                    else EvidenceKind.DEFAULT
                    if s.rule == "R11"
                    else EvidenceKind.FILE
                )
                source = s.service or ("container config" if s.rule == "R9" else "rule engine")
                premises += [p.fact(kind, e, source) for e in s.evidence[:5]]
                if not premises:
                    premises.append(
                        p.fact(
                            EvidenceKind.DEFAULT,
                            f"rule {s.rule} fired: {s.title}",
                            "rule engine",
                            confidence=Confidence.MEDIUM,
                        )
                    )
            s.derivation = p.derive(s.id, f"attack.{s.rule}", premises)
            confs.append(p.confidence(s.derivation))
            down = MITIGATION_DOWNGRADE if s.mitigated_by else 1.0
            if s.threat and s.threat in self.likelihood:
                base = self.likelihood[s.threat]
            else:
                base = s.likelihood / down
            s.likelihood = round(base * down, 4)
            inputs.append(step_input(s, base))
            if s.threat and (d := self.decisions.get(s.threat)) is not None:
                worst = d if worst is None or RANK[d] > RANK[worst] else worst
        expl = explain_chain(c.id, inputs, c.impact)
        before = (c.score, c.ssvc_decision)
        c.explanation = expl.model_copy(update={"confidence": weakest(confs)})
        c.likelihood = round(math.prod(i.likelihood * i.mitigation_multiplier for i in inputs), 4)
        c.score = round(max(0.0, min(100.0, expl.total)), 1)
        if worst is not None:
            c.ssvc_decision = worst
        c.mitigated = c.mitigated or any(s.mitigated_by for s in c.steps)
        if (c.score, c.ssvc_decision) != before:
            c.narrative = narrate(c)

    # ------------------------------------------------------------------ system
    def _system(self) -> None:
        r = self.r
        fixes = generate_fixes(r)
        fx = {f.id: f for f in fixes}
        items = [
            ChainItem(c.id, c.score, tuple((s.id or "", s.from_state, s.to_state) for s in c.steps))
            for c in r.attack_chains
        ]
        chained = {s.threat for c in r.attack_chains for s in c.steps if s.threat}
        standalone = {t.id: t.risk_score for t in r.threats if t.id not in chained}
        singles = sorted(
            (what_if(items, standalone, fx, [f.id], "single", f.action) for f in fixes),
            key=lambda w: (w.risk_after, w.fixes),
        )
        plans: list[WhatIf] = []
        n_break = sum(1 for c in items if any(c.step_ids & set(f.breaks) for f in fixes))
        residual = len(items) - n_break
        tail = f"; {residual} chain(s) have no known fix" if residual else ""
        exact = exact_hitting_set(items, fixes)
        for plan in exact[:3]:
            cost = math.fsum(fx[i].cost for i in plan)
            plans.append(
                what_if(
                    items,
                    standalone,
                    fx,
                    plan,
                    "exact_hitting_set",
                    f"minimum-cost plan (cost {cost:g}) breaking all {n_break} breakable "
                    f"chain(s){tail}",
                )
            )
        greedy = greedy_hitting_set(items, fixes)
        if greedy and greedy not in exact:
            plans.append(
                what_if(
                    items,
                    standalone,
                    fx,
                    greedy,
                    "greedy_set_cover",
                    f"greedy approximation (cost {math.fsum(fx[i].cost for i in greedy):g})" + tail,
                )
            )
        cut = min_cut(items, fixes)
        if cut is not None and cut[1]:
            value, edges = cut
            chosen = sorted(
                {
                    min((f for f in fixes if e in f.breaks), key=lambda f: (f.cost, f.id)).id
                    for e in edges
                }
            )
            plans.append(
                what_if(
                    items,
                    standalone,
                    fx,
                    chosen,
                    "min_cut",
                    f"min s-t cut value {value:g} over {len(edges)} step(s): cuts every "
                    "path, upper bound on plan cost",
                )
            )
        scores = {c.id: c.score for c in r.attack_chains} | standalone
        kinds: dict[str, Literal["chain", "threat"]] = {c.id: "chain" for c in r.attack_chains}
        kinds |= dict.fromkeys(standalone, "threat")
        members, labels = self._members(standalone)
        system = global_explanation(scores, kinds, members, labels) if scores else None
        r.explanations = Explanations(system=system, fix_plan=plans, what_if=singles, fixes=fixes)

    def _members(
        self, standalone: dict[str, float]
    ) -> tuple[dict[str, dict[str, list[str]]], dict[str, str]]:
        threats = {t.id: t for t in self.r.threats}
        pkg_m: dict[str, list[str]] = {}
        svc_m: dict[str, list[str]] = {}
        ven_m: dict[str, list[str]] = {}
        labels: dict[str, str] = {}

        def vendor(pid: str) -> str:
            if pid.startswith("config:"):
                return "configuration"
            pkg = self.pkgs.get(pid)
            return (pkg.vendor or pkg.maintainer or "unknown vendor") if pkg else "unknown vendor"

        def label_pkg(pid: str) -> None:
            pkg = self.pkgs.get(pid)
            labels.setdefault(pid, f"{pkg.name} {pkg.version}" if pkg else pid)

        for c in self.r.attack_chains:
            pk: list[str] = []
            sv: list[str] = []
            for s in c.steps:
                t = threats.get(s.threat or "")
                if t is not None:
                    pk.append(t.package)
                    sv.extend(t.services[:1])
                else:
                    pk.append(f"config:{s.service or s.rule}")
                if s.service:
                    sv.append(s.service)
            pkg_m[c.id], svc_m[c.id] = pk, sv
            ven_m[c.id] = [vendor(x) for x in pk]
            labels[c.id] = f"{c.entry} -> {c.goal} ({len(c.steps)} steps)"
            for x in pk:
                label_pkg(x)
        for tid in standalone:
            t = threats[tid]
            pkg_m[tid], svc_m[tid], ven_m[tid] = [t.package], list(t.services), [vendor(t.package)]
            pkg = self.pkgs.get(t.package)
            labels[tid] = f"{t.vulnerability} in {pkg.name if pkg else t.package}"
            label_pkg(t.package)
        for sid, svc in self.svcs.items():
            labels.setdefault(sid, svc.name)
        return {"package": pkg_m, "service": svc_m, "vendor": ven_m}, labels
