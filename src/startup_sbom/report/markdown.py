"""GitHub-flavoured Markdown report with Mermaid attack-chain diagrams.

Renders on GitHub, in PR comments and Actions job summaries.  Every string from
the scanned system goes through :func:`md`, which neutralises Markdown/HTML
syntax, table pipes, newlines and ``@`` mentions.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from startup_sbom.models import Report, Severity
from startup_sbom.report.graphs import mermaid_chain, one_line
from startup_sbom.report.native import (
    RenderOptions,
    canonical,
    iso_z,
    listen_text,
    package_label,
    package_reachability,
    service_reachability,
    threat_sort_key,
    timestamp,
    vuln_reachability,
    vuln_score,
    vuln_severity,
)

TOP_THREATS = 25
MAX_VULN_ROWS = 300
_ESCAPES = str.maketrans(
    {
        "\\": "\\\\",
        "`": "\\`",
        "*": "\\*",
        "_": "\\_",
        "[": "\\[",
        "]": "\\]",
        "|": "\\|",
        "#": "\\#",
        "~": "\\~",
        "!": "\\!",
        "$": "\\$",
        "<": "&lt;",
        ">": "&gt;",
        "&": "&amp;",
        "@": "@\u200b",
    }
)


def md(text: object, limit: int = 200) -> str:
    """Escape untrusted text for inline Markdown (safe inside table cells)."""
    return one_line(str(text), limit).translate(_ESCAPES)


def table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> list[str]:
    """A GFM table; cells must already be escaped."""
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return out


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def _eol(report: Report) -> str:
    eol = report.os.eol
    if eol is None:
        return "unknown"
    if eol.is_eol:
        return f"**END OF LIFE** since {md(eol.eol_date or '?')}"
    if eol.eol_date:
        return f"supported until {md(eol.eol_date)}"
    return "supported"


def render_markdown(report: Report, options: RenderOptions) -> str:
    """Render the Markdown report."""
    del options
    r = canonical(report)
    md_ = r.metadata
    pkgs = r.package_by_id()
    svcs = r.service_by_id()
    pkg_reach = package_reachability(r)
    out: list[str] = []
    target = f"{md(md_.target.kind)} {md(md_.target.reference)}"
    out += [
        f"# Startup-SBOM report: {md(r.os.pretty_name or r.os.id)}",
        "",
        f"Target {target} · startup-sbom {md(md_.tool_version)} · "
        f"scan {md(md_.scan_id)} · {iso_z(timestamp(r))}",
        "",
    ]

    # ------------------------------------------------------------- executive summary
    sev_counts = dict.fromkeys(Severity, 0)
    for v in r.vulnerabilities:
        sev_counts[vuln_severity(v)] += 1
    sev_text = ", ".join(
        f"{n} {s.value}" for s, n in sev_counts.items() if n and s is not Severity.NONE
    )
    kev = sum(1 for v in r.vulnerabilities if v.kev is not None)
    decisions = {"Act": 0, "Attend": 0}
    for t in r.threats:
        if t.ssvc and t.ssvc.decision.value in decisions:
            decisions[t.ssvc.decision.value] += 1
    boot_svcs = [s for s in r.services if service_reachability(s) is not None]
    net_svcs = [s for s in boot_svcs if s.network_exposed]
    boot_pkgs = sum(1 for x in pkg_reach.values() if x.value != "installed")
    out += [
        "## Executive summary",
        "",
        f"- **{len(r.packages)}** packages ({boot_pkgs} on an observed execution path); "
        f"**{len(r.services)}** services ({len(boot_svcs)} started automatically, "
        f"{len(net_svcs)} network-exposed)",
        f"- **{len(r.vulnerabilities)}** vulnerabilities"
        + (f" ({sev_text})" if sev_text else "")
        + f"; **{kev}** listed in CISA KEV",
        f"- **{len(r.threats)}** threats in system context: **{decisions['Act']}** Act, "
        f"**{decisions['Attend']}** Attend",
        f"- **{len(r.attack_chains)}** attack chains; "
        f"**{len(r.supply_chain.findings)}** supply-chain findings",
        f"- Operating system: {md(r.os.pretty_name or r.os.id)}, {_eol(r)}",
    ]
    if r.attack_chains:
        top = max(r.attack_chains, key=lambda c: (c.score, c.id))
        out.append(
            f"- Highest-scoring chain: {md(top.entry)} → {md(top.goal)} "
            f"(score {top.score:.1f}, {md(top.ssvc_decision.value)})"
        )
    out.append("")

    # ------------------------------------------------------------- system
    o = r.os
    rows = [
        ["Target", target],
        ["Operating system", md(o.pretty_name or o.name or o.id)],
        ["OS id / version", f"{md(o.id)} {md(o.version_id or '-')}"],
        ["End of life", _eol(r)],
        ["Vulnerability ecosystems", md(", ".join(o.vuln_ecosystems) or "-")],
    ]
    if r.container is not None:
        c = r.container
        rows += [
            ["Image", md(c.image or c.name or "-")],
            ["Digest", md(c.image_digest or "-")],
            ["User", md(c.user or "root (default)")],
            ["Exposed ports", md(", ".join(c.exposed_ports) or "-")],
        ]
    out += ["## System", "", *table(["Field", "Value"], rows), ""]

    # ------------------------------------------------------------- threats
    threats = sorted(r.threats, key=threat_sort_key)
    vulns = {(v.id, v.package): v for v in r.vulnerabilities}
    out += ["## Top threats", ""]
    if threats:
        trows = []
        for t in threats[:TOP_THREATS]:
            tv = vulns.get((t.vulnerability, t.package))
            trows.append(
                [
                    f"{t.risk_score:.1f}",
                    md(t.ssvc.decision.value if t.ssvc else "-"),
                    md(t.vulnerability),
                    md(package_label(pkgs.get(t.package), t.package)),
                    md(t.reachability.value.replace("_", " ")),
                    f"{md(t.precondition)} → {md(t.postcondition)}",
                    _pct(tv.epss if tv else None),
                    "yes" if tv and tv.kev else "",
                ]
            )
        out += table(
            [
                "Risk",
                "SSVC",
                "Vulnerability",
                "Package",
                "Reachability",
                "Attacker gain",
                "EPSS",
                "KEV",
            ],
            trows,
        )
        if len(threats) > TOP_THREATS:
            out += ["", f"_{len(threats) - TOP_THREATS} more threats in report.json._"]
    else:
        out.append("No threats were derived.")
    out.append("")

    # ------------------------------------------------------------- attack chains
    out += ["## Attack chains", ""]
    if not r.attack_chains:
        out += ["No attack chains were found.", ""]
    for chain in sorted(r.attack_chains, key=lambda c: (-c.score, c.id)):
        flag = " (mitigated)" if chain.mitigated else ""
        out += [
            f"### {md(chain.id)}: {md(chain.entry)} → {md(chain.goal)}{flag}",
            "",
            f"Score **{chain.score:.1f}** · likelihood {chain.likelihood:.2f} · "
            f"impact {chain.impact:.2f} · SSVC **{md(chain.ssvc_decision.value)}**",
            "",
            md(chain.narrative, 1000),
            "",
            "```mermaid",
            mermaid_chain(chain).rstrip("\n"),
            "```",
            "",
        ]
        for i, step in enumerate(chain.steps, 1):
            tech = f" · {md(step.technique.id)} {md(step.technique.name)}" if step.technique else ""
            out.append(
                f"{i}. **{md(step.from_state)} → {md(step.to_state)}**: {md(step.title)}{tech}"
            )
            if step.service:
                svc = svcs.get(step.service)
                out.append(f"   - service: {md(svc.name if svc else step.service)}")
            if step.vulnerability:
                out.append(f"   - vulnerability: {md(step.vulnerability)}")
            out += [f"   - evidence: {md(e)}" for e in step.evidence]
            out += [f"   - mitigation: {md(m)}" for m in step.mitigated_by]
        out.append("")

    # ------------------------------------------------------------- supply chain
    sc = r.supply_chain
    out += ["## Supply chain", ""]
    if sc.blast_radius:
        brows = [
            [
                md(package_label(pkgs.get(b.package), b.package)),
                md(b.vendor or "-"),
                md(", ".join(svcs[s].name if s in svcs else s for s in b.services) or "-"),
                str(len(b.binaries)),
                md(", ".join(b.vulnerabilities) or "-"),
                f"{b.score:.1f}",
            ]
            for b in sorted(sc.blast_radius, key=lambda x: (-x.score, x.package))
        ]
        out += [
            "### Blast radius",
            "",
            *table(
                ["Package", "Vendor", "Services", "Binaries", "Vulnerabilities", "Score"], brows
            ),
            "",
        ]
    if sc.findings:
        frows = [
            [
                md(f.severity.value),
                md(f.kind),
                md(package_label(pkgs.get(f.subject), f.subject)),
                md(f.title),
            ]
            for f in sorted(sc.findings, key=lambda f: (-f.severity.rank, f.id))
        ]
        out += ["### Findings", "", *table(["Severity", "Kind", "Subject", "Finding"], frows), ""]
    if sc.vendors:
        vrows = [
            [
                md(v.vendor),
                str(v.packages),
                str(v.boot_packages),
                str(v.services),
                str(v.vulnerabilities),
                str(v.critical),
                str(v.high),
                str(v.kev),
            ]
            for v in sorted(sc.vendors, key=lambda v: (-v.packages, v.vendor))
        ]
        out += [
            "### Vendors",
            "",
            *table(
                ["Vendor", "Packages", "Boot", "Services", "Vulns", "Critical", "High", "KEV"],
                vrows,
            ),
            "",
        ]
    if not (sc.blast_radius or sc.findings or sc.vendors):
        out += ["No supply-chain data.", ""]

    # ------------------------------------------------------------- services
    out += ["## Boot services", ""]
    if boot_svcs:
        srows = []
        for s in sorted(boot_svcs, key=lambda s: (not s.network_exposed, s.name, s.id)):
            h = s.hardening
            exposure = (
                f"{md(h.exposure_rating or '')} {h.exposure:.1f}".strip()
                if h.exposure is not None
                else md(h.exposure_rating or "-")
            )
            srows.append(
                [
                    md(s.name),
                    md(s.init_system.value),
                    md(", ".join(a.value for a in s.activation) or "-"),
                    md(h.user),
                    exposure,
                    md(
                        ", ".join(
                            listen_text(x.protocol, x.address, x.port, x.path) for x in s.listens
                        )
                        or "-"
                    ),
                    md(", ".join(pkgs[p].name if p in pkgs else p for p in s.packages) or "-"),
                ]
            )
        out += table(
            ["Service", "Init", "Activation", "User", "Exposure", "Listeners", "Packages"], srows
        )
    else:
        out.append("No automatically started services were found.")
    out.append("")

    # ------------------------------------------------------------- vulnerabilities
    out += ["## Vulnerabilities", ""]
    if r.vulnerabilities:
        ordered = sorted(
            r.vulnerabilities,
            key=lambda v: (-vuln_severity(v).rank, -(vuln_score(v) or 0.0), v.id, v.package),
        )
        vrows = []
        for v in ordered[:MAX_VULN_ROWS]:
            score = vuln_score(v)
            vrows.append(
                [
                    md(v.id),
                    md(vuln_severity(v).value),
                    "-" if score is None else f"{score:.1f}",
                    md(package_label(pkgs.get(v.package), v.package_name)),
                    md(", ".join(v.fixed_versions) or "-"),
                    md(v.status.value),
                    md(vuln_reachability(r, v, pkg_reach=pkg_reach).value.replace("_", " ")),
                    _pct(v.epss),
                    "yes" if v.kev else "",
                ]
            )
        out += table(
            [
                "ID",
                "Severity",
                "CVSS",
                "Package",
                "Fixed in",
                "Status",
                "Reachability",
                "EPSS",
                "KEV",
            ],
            vrows,
        )
        if len(ordered) > MAX_VULN_ROWS:
            out += ["", f"_{len(ordered) - MAX_VULN_ROWS} more vulnerabilities in report.json._"]
    else:
        out.append("No vulnerabilities were matched.")
    out.append("")

    # ------------------------------------------------------------- coverage
    cov = md_.coverage
    out += [
        "## Coverage and limitations",
        "",
        f"- Package databases: {md(', '.join(cov.package_databases) or 'none')}",
        f"- Init systems: {md(', '.join(cov.init_systems) or 'none')}",
        f"- Vulnerability sources: {md(', '.join(cov.vulnerability_sources) or 'none')}"
        + (" (offline)" if cov.offline else ""),
    ]
    out += [f"- Limitation: {md(x, 500)}" for x in cov.limitations]
    if r.warnings:
        out += ["", "### Warnings", ""]
        out += [f"- {md(w, 500)}" for w in r.warnings]
    out.append("")
    return "\n".join(out)
