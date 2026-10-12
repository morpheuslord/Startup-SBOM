"""Detail-pane content: escaped Markdown and fallback rich renderables (no Textual import).

Every report string is sanitised (:mod:`startup_sbom.textsafe`) and Markdown-escaped
before interpolation.  The ``viz_*`` helpers prefer :mod:`startup_sbom.viz.terminal`
and fall back to simple built-in renderables when it is unavailable.
"""

from __future__ import annotations

from collections import Counter

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from rich.tree import Tree as RichTree

from startup_sbom.models import (
    AIAssessment,
    AttackChain,
    BlastRadius,
    Explanation,
    IntelBundle,
    Report,
    Service,
    Severity,
    SSVCDecision,
    SSVCTrace,
    SupplyChainFinding,
    Threat,
    Vulnerability,
)
from startup_sbom.tui import integrations
from startup_sbom.tui.data import best_cvss, fmt_epss, intel_for, service_listeners
from startup_sbom.tui.safe import md, md_block, txt, wrap_txt

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
    Severity.NONE: "dim",
    Severity.UNKNOWN: "dim",
}
SSVC_STYLE = {
    SSVCDecision.ACT: "bold red",
    SSVCDecision.ATTEND: "bold yellow",
    SSVCDecision.TRACK_STAR: "cyan",
    SSVCDecision.TRACK: "dim",
}
UNVERIFIED = "**\\[unverified\\]**"


def _bullets(items: list[str], empty: str = "-") -> str:
    return "\n".join(f"- {i}" for i in items) if items else empty


# --------------------------------------------------------------------------- threats
def threat_markdown(threat: Threat, report: Report, vuln: Vulnerability | None) -> str:
    """Narrative detail of one threat as escaped Markdown."""
    t = threat
    ssvc = t.ssvc.decision.value if t.ssvc else "-"
    lines = [
        f"# {md(t.title, 300)}",
        "",
        f"**Risk** {t.risk_score:.1f} · **SSVC** {md(ssvc)} · "
        f"**Reachability** {md(t.reachability.value)} · **Confidence** {md(t.confidence.value)}",
        "",
        f"**Vulnerability** {md(t.vulnerability)} in {md(t.package, 400)}",
    ]
    if vuln is not None:
        kev = "yes" if vuln.kev else "no"
        lines += [
            "",
            f"**Severity** {md(vuln.severity.value)} · **CVSS** {best_cvss(vuln)} · "
            f"**EPSS** {md(fmt_epss(vuln.epss))} · **KEV** {kev} · "
            f"**Installed** {md(vuln.installed_version)} · "
            f"**Fixed** {md(', '.join(vuln.fixed_versions) or 'none known')}",
        ]
        if vuln.summary:
            lines += ["", f"> {md(vuln.summary, 600)}"]
    lines += ["", "## Narrative", "", md_block(t.narrative) or "-"]
    lines += [
        "",
        "## Attacker state",
        "",
        f"{md(t.precondition)} → {md(t.postcondition)} "
        f"(vector {md(t.attack_vector)}, privileges {md(t.privileges_required)}, "
        f"user interaction {'yes' if t.user_interaction else 'no'}, "
        f"runs as {md(t.run_as or 'unknown')})",
    ]
    if t.consequences:
        lines += ["", "Consequences: " + ", ".join(md(c.value) for c in t.consequences)]
    paths = [" → ".join(md(p, 160) for p in path) for path in t.reachability_paths[:10]]
    lines += ["", "## Reachability path", "", _bullets(paths)]
    if t.services:
        lines += ["", "Services: " + ", ".join(md(s) for s in t.services[:20])]
    if t.listens:
        listens = [
            f"{md(x.protocol)} {md(x.address or x.path or '')}"
            + (f":{x.port}" if x.port is not None else "")
            + f" ({md(x.scope)})"
            for x in t.listens[:20]
        ]
        lines += ["", "Listeners: " + ", ".join(listens)]
    techniques = [
        f"{md(a.id)} {md(a.name)}" + (f" ({md(a.tactic)})" if a.tactic else "")
        for a in t.attack_techniques
    ]
    lines += ["", "## ATT&CK techniques", "", _bullets(techniques)]
    if t.stride:
        lines += ["", "STRIDE: " + ", ".join(md(s) for s in t.stride)]
    lines += ["", "## Mitigations", "", _bullets([md(m, 400) for m in t.mitigations], "none")]
    lines += ["", "## Remediation", "", md_block(t.remediation or "-")]
    if t.score_factors and t.explanation is None:
        factors = [f"{md(k)}: {v:g}" for k, v in sorted(t.score_factors.items())]
        lines += ["", "## Score factors", "", _bullets(factors)]
    bundle = intel_for(report, t.vulnerability)
    if t.intel_summary or bundle is not None:
        lines += ["", intel_markdown(bundle, t.intel_summary)]
    if vuln is not None and vuln.references:
        refs = [md(r, 300) for r in vuln.references[:15]]
        lines += ["", "## References (not opened automatically)", "", _bullets(refs)]
    return "\n".join(lines) + "\n"


def intel_markdown(bundle: IntelBundle | None, summary: str | None = None) -> str:
    """Prefetched threat intel as escaped Markdown (third-party content flagged)."""
    lines = ["## Threat intel"]
    if summary:
        lines += ["", f"_{md(summary, 800)}_"]
    if bundle is None:
        lines += ["", "No prefetched intel bundle (press **i** to look it up)."]
        return "\n".join(lines)
    lines += [
        "",
        f"Exploit maturity **{md(bundle.exploit_maturity)}** · exploitation "
        f"**{md(bundle.exploitation)}** · exploit available "
        f"**{'yes' if bundle.exploit_available else 'no'}**",
    ]
    refs = [
        f"{md(r.source)} {md(r.id)}: {md(r.title or '-')} {UNVERIFIED}"
        for r in [*bundle.metasploit, *bundle.exploitdb, *bundle.nuclei][:20]
    ]
    if refs:
        lines += ["", "### Exploits", "", _bullets(refs)]
    if bundle.poc_repos_count or bundle.poc_repos_top:
        pocs = [
            f"{md(p.full_name)} ★{p.stars} — {md(p.description or '', 200)} {UNVERIFIED}"
            for p in bundle.poc_repos_top[:10]
        ]
        lines += [
            "",
            f"### Public PoC repositories ({bundle.poc_repos_count}) — metadata only, "
            "never cloned or executed",
            "",
            _bullets(pocs),
        ]
    if bundle.vendor_status:
        vendors = [
            f"{md(v.vendor)}: {md(v.status or '-')} {md(v.severity or '')}"
            for v in bundle.vendor_status[:15]
        ]
        lines += ["", "### Vendor status", "", _bullets(vendors)]
    if bundle.articles or bundle.advisories:
        arts = [
            f"{md(a.title or a.url, 200)} — {md(a.site or a.source)}"
            + (f" ({md(a.published)})" if a.published else "")
            for a in [*bundle.advisories, *bundle.articles][:20]
        ]
        lines += [
            "",
            "### Articles and advisories (third-party, untrusted)",
            "",
            _bullets(arts),
            "",
            "Use **Read articles** to open the cached text.",
        ]
    if bundle.errors:
        lines += ["", "Intel errors: " + "; ".join(md(e, 200) for e in bundle.errors[:5])]
    return "\n".join(lines)


def factor_table(threat: Threat) -> RenderableType | None:
    """Fallback "why this score" table from the explanation or score factors."""
    exp: Explanation | None = threat.explanation
    table = Table(title="Why this score", expand=True, show_edge=False)
    table.add_column("Factor")
    table.add_column("Points", justify="right")
    if exp is not None:
        table.add_row(txt("baseline"), Text(f"{exp.baseline:+.1f}"))
        for f in exp.factors:
            table.add_row(txt(f.label or f.name), Text(f"{f.contribution:+.1f}"))
        table.add_row(Text("total", style="bold"), Text(f"{exp.total:.1f}", style="bold"))
        return table
    if threat.score_factors:
        for name, value in sorted(threat.score_factors.items()):
            table.add_row(txt(name), Text(f"{value:g}"))
        return table
    return None


def ssvc_trace_fallback(trace: SSVCTrace) -> RenderableType:
    """Fallback SSVC decision path."""
    tree = RichTree(txt(f"SSVC {trace.tree} → {trace.outcome}", "bold"))
    for node in trace.path:
        branch = tree.add(txt(f"{node.decision_point}: {node.value} ({node.source})"))
        branch.add(wrap_txt(node.rationale, "dim", max_len=400))
    for flip in trace.flips[:5]:
        tree.add(txt(f"would flip: {flip}", "italic"))
    return tree


def threat_visuals(threat: Threat, report: Report) -> list[RenderableType]:
    """Waterfall, SSVC path and why-tree for a threat (viz when available)."""
    out: list[RenderableType] = []
    waterfall = (
        integrations.viz("risk_waterfall", threat.explanation) if threat.explanation else None
    )
    if waterfall is None:
        waterfall = factor_table(threat)
    if waterfall is not None:
        out.append(waterfall)
    trace = threat.ssvc.trace if threat.ssvc else None
    if trace is not None:
        out.append(integrations.viz("ssvc_trace_tree", trace) or ssvc_trace_fallback(trace))
    why = integrations.viz("why_tree", threat, report)
    if why is not None:
        out.append(why)
    return out


# --------------------------------------------------------------------------- summary
def kpis(report: Report) -> list[tuple[str, int, str]]:
    """``(label, value, css class)`` for the summary tiles."""
    s = report.summary
    return [
        ("Packages", s.packages, ""),
        ("Boot packages", s.boot_packages, ""),
        ("Services", s.services, ""),
        ("Network services", s.network_services, "warn" if s.network_services else ""),
        ("Vulnerabilities", s.vulnerabilities, ""),
        ("KEV", s.kev, "bad" if s.kev else ""),
        ("Threats", s.threats, ""),
        ("Act", s.act, "bad" if s.act else ""),
        ("Attend", s.attend, "warn" if s.attend else ""),
        ("Attack chains", s.attack_chains, "warn" if s.attack_chains else ""),
        ("Supply-chain findings", s.supply_chain_findings, ""),
    ]


def os_badge(report: Report) -> Text:
    """OS name with an EOL badge and container line."""
    o = report.os
    text = Text()
    text.append_text(txt(o.pretty_name or o.name or o.id, "bold"))
    if o.eol is not None:
        if o.eol.is_eol:
            text.append("  EOL", style="bold white on red")
            text.append_text(txt(f" since {o.eol.eol_date or '?'}", "red"))
        elif o.eol.eol_date:
            text.append_text(txt(f"  supported until {o.eol.eol_date}", "green"))
    text.append("\n")
    text.append_text(txt(f"target {report.metadata.target.kind}: ", "dim"))
    text.append_text(txt(report.metadata.target.reference, max_len=300))
    if report.container is not None:
        c = report.container
        text.append("\n")
        text.append_text(
            txt(f"{c.kind} {c.image or c.name or c.id or ''} ({c.engine or '?'})", "dim")
        )
        if c.privileged:
            text.append("  privileged", style="bold red")
    return text


def _bars(title: str, counts: list[tuple[str, int, str]]) -> RenderableType:
    table = Table(title=title, show_header=False, show_edge=False, expand=True)
    table.add_column("label", width=10)
    table.add_column("bar", ratio=1)
    table.add_column("n", justify="right", width=6)
    peak = max((n for _, n, _ in counts), default=0) or 1
    for label, n, style in counts:
        table.add_row(
            Text(label, style=style), Text("█" * round(20 * n / peak), style=style), str(n)
        )
    return table


def severity_bars(report: Report) -> RenderableType:
    """Severity distribution (viz or fallback)."""
    viz = integrations.viz("severity_bars", report)
    if viz is not None:
        return viz
    by = report.summary.by_severity
    return _bars(
        "Vulnerabilities by severity",
        [(s.value, by.get(s.value, 0), SEVERITY_STYLE[s]) for s in Severity],
    )


def ssvc_bars(report: Report) -> RenderableType:
    """SSVC decision distribution (viz or fallback)."""
    viz = integrations.viz("ssvc_bars", report)
    if viz is not None:
        return viz
    counts = Counter(t.ssvc.decision for t in report.threats if t.ssvc is not None)
    return _bars(
        "Threats by SSVC decision",
        [(d.value, counts.get(d, 0), SSVC_STYLE[d]) for d in reversed(SSVCDecision)],
    )


def risk_drivers(report: Report) -> RenderableType | None:
    """Top system risk drivers (viz or fallback; ``None`` without explanations)."""
    viz = integrations.viz("risk_drivers", report)
    if viz is not None:
        return viz
    system = report.explanations.system if report.explanations else None
    if system is None or not system.drivers:
        return None
    table = Table(title=f"Risk drivers (system risk {system.system_risk:.1f})", expand=True)
    table.add_column("Kind", width=8)
    table.add_column("Driver", ratio=1)
    table.add_column("Share", justify="right", width=7)
    for d in system.drivers[:10]:
        table.add_row(txt(d.kind), txt(d.label), Text(f"{d.share * 100:.0f}%"))
    return table


def fix_plan(report: Report) -> RenderableType | None:
    """Minimal fix plan (viz or fallback; ``None`` without explanations)."""
    viz = integrations.viz("fix_plan_table", report)
    if viz is not None:
        return viz
    exp = report.explanations
    if exp is None or not exp.fix_plan:
        return None
    fixes = {f.id: f for f in exp.fixes}
    table = Table(title="Fix plan", expand=True)
    table.add_column("Fixes", ratio=1)
    table.add_column("Risk", justify="right", width=16)
    table.add_column("Chains broken", justify="right", width=13)
    for plan in exp.fix_plan[:10]:
        actions = "; ".join(fixes[f].action if f in fixes else f for f in plan.fixes)
        table.add_row(
            wrap_txt(actions, max_len=400),
            Text(f"{plan.risk_before:.1f} → {plan.risk_after:.1f}"),
            str(len(plan.chains_broken)),
        )
    return table


def coverage_text(report: Report) -> Text:
    """Coverage and limitations (never hidden)."""
    cov = report.metadata.coverage
    text = Text()
    rows = [
        ("Package databases", ", ".join(cov.package_databases) or "none"),
        ("Init systems", ", ".join(cov.init_systems) or "none"),
        ("Vulnerability sources", ", ".join(cov.vulnerability_sources) or "none"),
        ("Ecosystems", ", ".join(cov.vulnerability_ecosystems) or "none"),
        ("Offline", "yes" if cov.offline else "no"),
    ]
    for label, value in rows:
        text.append(f"{label}: ", style="bold")
        text.append_text(txt(value, max_len=400))
        text.append("\n")
    if cov.limitations:
        text.append("Limitations:\n", style="bold yellow")
        for lim in cov.limitations[:50]:
            text.append("  • ")
            text.append_text(txt(lim, max_len=400))
            text.append("\n")
    return text


# --------------------------------------------------------------------------- chains / supply chain
def chain_markdown(chain: AttackChain) -> str:
    """Attack chain narrative and steps."""
    lines = [
        f"## {md(chain.id)}: {md(chain.entry)} → {md(chain.goal)}",
        "",
        f"**Score** {chain.score:.1f} · **SSVC** {md(chain.ssvc_decision.value)} · "
        f"**Likelihood** {chain.likelihood:.2f} · **Impact** {chain.impact:.2f}"
        + (" · **mitigated**" if chain.mitigated else ""),
        "",
        md_block(chain.narrative),
        "",
        "### Steps",
        "",
    ]
    for i, step in enumerate(chain.steps, 1):
        tech = f" ({md(step.technique.id)})" if step.technique else ""
        lines.append(
            f"{i}. {md(step.from_state)} → {md(step.to_state)}: {md(step.title)}{tech}"
            + (f" — threat {md(step.threat)}" if step.threat else "")
        )
        lines += [f"   - evidence: {md(e, 300)}" for e in step.evidence[:5]]
        lines += [f"   - mitigated by: {md(m, 300)}" for m in step.mitigated_by[:5]]
    return "\n".join(lines) + "\n"


def chain_visual(chain: AttackChain) -> RenderableType:
    """Chain diagram (viz or a simple state sequence)."""
    viz = integrations.viz("attack_chain_diagram", chain)
    if viz is not None:
        return viz
    text = Text()
    text.append_text(txt(chain.entry, "bold"))
    for step in chain.steps:
        text.append("\n  │ ")
        text.append_text(txt(step.title, "dim"))
        text.append("\n  ▼\n")
        text.append_text(txt(step.to_state, "bold"))
    return text


def blast_visual(blast: BlastRadius, report: Report) -> RenderableType:
    """Blast-radius tree (viz or fallback)."""
    viz = integrations.viz("blast_radius_tree", blast, report)
    if viz is not None:
        return viz
    tree = RichTree(txt(f"{blast.package}  (score {blast.score:.1f})", "bold"))
    if blast.vulnerabilities:
        tree.add(txt("vulnerabilities: " + ", ".join(blast.vulnerabilities[:10])))
    svc = tree.add(Text("services", style="bold"))
    for s in blast.services[:30]:
        svc.add(txt(s))
    binaries = tree.add(Text("binaries", style="bold"))
    for b in blast.binaries[:30]:
        binaries.add(txt(b))
    paths = tree.add(Text("example paths", style="bold"))
    for p in blast.example_paths[:10]:
        paths.add(txt(" → ".join(p), max_len=400))
    return tree


def finding_markdown(finding: SupplyChainFinding) -> str:
    """Supply-chain finding detail."""
    lines = [
        f"## {md(finding.title)}",
        "",
        f"**{md(finding.severity.value)}** · {md(finding.kind)} · subject {md(finding.subject)}",
        "",
        md_block(finding.detail or ""),
        "",
        _bullets([md(e, 300) for e in finding.evidence[:20]], ""),
    ]
    return "\n".join(lines) + "\n"


def service_markdown(service: Service) -> str:
    """Service detail: hardening, commands, listeners, boot path."""
    h = service.hardening
    lines = [
        f"## {md(service.name)}",
        "",
        md(service.description or "", 400),
        "",
        f"**Init** {md(service.init_system.value)} · **Enabled** "
        f"{'yes' if service.enabled else 'no'}{' · **masked**' if service.masked else ''} · "
        f"**Activation** {md(', '.join(a.value for a in service.activation) or '-')}",
        "",
        f"**User** {md(h.user)} · **Exposure** "
        f"{'-' if h.exposure is None else f'{h.exposure:.1f}'} {md(h.exposure_rating or '')}",
    ]
    if service.unit_path:
        lines += ["", f"Unit: {md(service.unit_path, 400)}"]
    if service.boot_path:
        lines += ["", "Boot path: " + " → ".join(md(p) for p in service.boot_path)]
    lines += ["", "### Listeners", "", md(service_listeners(service) or "none", 600)]
    cmds = [
        f"{md(c.directive)}: {md(c.raw, 400)}"
        + (f" (wrapped by {md(', '.join(c.wrapped_by))})" if c.wrapped_by else "")
        for c in service.commands[:10]
    ]
    lines += ["", "### Commands", "", _bullets(cmds)]
    lines += ["", "### Hardening weaknesses", "", _bullets([md(w) for w in h.weaknesses[:30]])]
    lines += ["", "Packages: " + (", ".join(md(p, 200) for p in service.packages[:10]) or "-")]
    return "\n".join(lines) + "\n"


def vuln_markdown(vuln: Vulnerability) -> str:
    """Vulnerability detail."""
    lines = [
        f"## {md(vuln.id)} in {md(vuln.package_name)}",
        "",
        f"**{md(vuln.severity.value)}** · CVSS {best_cvss(vuln)} · EPSS {md(fmt_epss(vuln.epss))}"
        f" · status {md(vuln.status.value)} · KEV {'yes' if vuln.kev else 'no'}",
        "",
        md_block(vuln.summary or ""),
        "",
        f"Installed {md(vuln.installed_version)} · fixed "
        f"{md(', '.join(vuln.fixed_versions) or 'none known')}",
    ]
    if vuln.aliases:
        lines += ["", "Aliases: " + ", ".join(md(a) for a in vuln.aliases[:20])]
    if vuln.cwes:
        lines += ["", "CWE: " + ", ".join(md(c) for c in vuln.cwes)]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- AI
def assessment_markdown(ai: AIAssessment) -> str:
    """AI assessment (model output is untrusted and escaped)."""
    g = ai.grounding
    cost = ai.usage.get("est_cost_usd")
    lines = [
        "# AI analyst assessment",
        "",
        f"_{md(ai.disclaimer, 400)}_",
        "",
        f"**Provider** {md(ai.provider)} · **Model** {md(ai.model)} · **Audience** "
        f"{md(ai.audience)} · **Grounding** {'passed' if g.passed else 'FAILED'} "
        f"({g.grounded_ratio * 100:.0f}% grounded)"
        + (f" · **Cost** ≈ ${cost:.4f}" if isinstance(cost, int | float) else ""),
        "",
        "## Executive summary",
        "",
        md_block(ai.executive_summary),
    ]
    if ai.findings:
        lines += ["", "## Findings", ""]
        for f in ai.findings[:50]:
            agree = "" if f.agrees_with_scanner else " (disagrees with scanner)"
            refs = ", ".join(md(e.ref, 120) for e in f.evidence[:6])
            lines.append(
                f"- **{md(f.priority)}** {md(f.title)}{agree} — {md(f.rationale, 600)} "
                f"(confidence {f.confidence:.2f}; cites {refs or 'nothing'})"
            )
    if ai.remediation_plan:
        lines += ["", "## Remediation plan (suggestions only, never executed)", ""]
        for i, step in enumerate(ai.remediation_plan[:30], 1):
            lines.append(f"{i}. {md(step.title)} — {md(step.rationale, 400)}")
            lines += [f"   - `{md(c, 200)}`" for c in step.commands[:5]]
    if ai.caveats:
        lines += ["", "## Caveats", "", _bullets([md(c, 400) for c in ai.caveats[:20]])]
    if g.issues:
        issues = [f"claim {i.claim}: {md(i.code)} — {md(i.detail, 200)}" for i in g.issues[:20]]
        lines += ["", "## Grounding issues", "", _bullets(issues)]
    return "\n".join(lines) + "\n"


def ai_status(ai: AIAssessment) -> Text:
    """One-line grounding + cost status."""
    g = ai.grounding
    cost = ai.usage.get("est_cost_usd")
    text = Text()
    text.append(
        "grounding passed" if g.passed else "grounding FAILED", "green" if g.passed else "bold red"
    )
    text.append(f"  {g.grounded_ratio * 100:.0f}% grounded")
    if isinstance(cost, int | float):
        text.append(f"  cost ≈ ${cost:.4f}")
    text.append_text(txt(f"  {ai.provider}/{ai.model}", "dim"))
    return text


def group(items: list[RenderableType]) -> RenderableType:
    """Stack renderables (empty → blank text)."""
    return Group(*items) if items else Text("")
