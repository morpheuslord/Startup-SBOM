"""Rich terminal summary of a report.

All strings from the scanned system are wrapped in :class:`rich.text.Text` (never
interpreted as console markup); only fixed, literal markup is used for styling.
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from startup_sbom.models import AttackChain, Report, Severity, SSVCDecision
from startup_sbom.report.graphs import one_line
from startup_sbom.report.native import (
    canonical,
    iso_z,
    listen_text,
    package_label,
    package_reachability,
    service_reachability,
    threat_sort_key,
    timestamp,
    vuln_severity,
)

TOP_THREATS = 15
TOP_CHAINS = 8
TOP_BLAST = 10

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.NONE: "dim",
    Severity.UNKNOWN: "dim",
}
SSVC_STYLE = {
    SSVCDecision.ACT: "bold white on red",
    SSVCDecision.ATTEND: "bold red",
    SSVCDecision.TRACK_STAR: "yellow",
    SSVCDecision.TRACK: "cyan",
}


def t(value: object, style: str = "", limit: int = 120) -> Text:
    """Untrusted text as a literal :class:`Text` (no markup, single line, bounded)."""
    return Text(one_line(str(value), limit), style=style)


def _eol_badge(report: Report) -> Text:
    eol = report.os.eol
    if eol is None:
        return Text(" EOL unknown ", style="dim")
    if eol.is_eol:
        return Text(
            f" END OF LIFE since {one_line(eol.eol_date or '?', 20)} ", style="bold white on red"
        )
    until = f" until {one_line(eol.eol_date, 20)}" if eol.eol_date else ""
    return Text(f" supported{until} ", style="bold black on green")


def _header(r: Report) -> Panel:
    md = r.metadata
    sev_counts = dict.fromkeys(Severity, 0)
    for v in r.vulnerabilities:
        sev_counts[vuln_severity(v)] += 1
    boot = [s for s in r.services if service_reachability(s) is not None]
    act = sum(1 for x in r.threats if x.ssvc and x.ssvc.decision is SSVCDecision.ACT)
    attend = sum(1 for x in r.threats if x.ssvc and x.ssvc.decision is SSVCDecision.ATTEND)
    title = Text.assemble(t(r.os.pretty_name or r.os.name or r.os.id, "bold"), " ", _eol_badge(r))
    target = Text.assemble(
        ("Target  ", "dim"), t(md.target.kind), ": ", t(md.target.reference, limit=200)
    )
    if r.container is not None and (r.container.image or r.container.name):
        target.append_text(
            Text.assemble("  ", ("image ", "dim"), t(r.container.image or r.container.name))
        )
    vulns = Text.assemble(("Vulns   ", "dim"), (str(len(r.vulnerabilities)), "bold"), "  ")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        if sev_counts[sev]:
            vulns.append(f" {sev_counts[sev]} {sev.value} ", style=SEVERITY_STYLE[sev])
            vulns.append(" ")
    kev = sum(1 for v in r.vulnerabilities if v.kev is not None)
    if kev:
        vulns.append(f" {kev} KEV ", style="bold white on dark_red")
    counts = Text.assemble(
        ("System  ", "dim"),
        (str(len(r.packages)), "bold"),
        " packages · ",
        (str(len(r.services)), "bold"),
        f" services ({len(boot)} auto-start, "
        f"{sum(1 for s in boot if s.network_exposed)} network) · ",
        (str(len(r.binaries)), "bold"),
        " binaries analysed",
    )
    threats = Text.assemble(
        ("Threats ", "dim"),
        (str(len(r.threats)), "bold"),
        "  ",
        (f" {act} Act ", SSVC_STYLE[SSVCDecision.ACT] if act else "dim"),
        " ",
        (f" {attend} Attend ", SSVC_STYLE[SSVCDecision.ATTEND] if attend else "dim"),
        " · ",
        (str(len(r.attack_chains)), "bold"),
        " attack chains · ",
        (str(len(r.supply_chain.findings)), "bold"),
        " supply-chain findings",
    )
    footer = Text.assemble(
        ("startup-sbom ", "dim"),
        t(md.tool_version, "dim"),
        (" · scan ", "dim"),
        t(md.scan_id, "dim"),
        (" · ", "dim"),
        (iso_z(timestamp(r)), "dim"),
    )
    return Panel(
        Group(target, counts, vulns, threats, footer),
        title=title,
        title_align="left",
        border_style="blue",
        box=box.ROUNDED,
    )


def _services(r: Report) -> Table | None:
    boot = [s for s in r.services if service_reachability(s) is not None]
    if not boot:
        return None
    pkgs = r.package_by_id()
    table = Table(title="Boot services", title_justify="left", box=box.SIMPLE_HEAD, expand=True)
    for col in ("Service", "Activation", "User", "Exposure", "Listeners", "Package"):
        table.add_column(col, overflow="fold")
    for s in sorted(boot, key=lambda s: (not s.network_exposed, s.name, s.id)):
        h = s.hardening
        exp = Text()
        if h.exposure is not None:
            style = "red" if h.exposure >= 7 else "yellow" if h.exposure >= 4 else "green"
            exp = Text.assemble(t(h.exposure_rating or "", style), f" {h.exposure:.1f}")
        elif h.exposure_rating:
            exp = t(h.exposure_rating)
        user = t(h.user, "bold red" if h.runs_as_root else "")
        listeners = Text("\n").join(
            t(
                listen_text(x.protocol, x.address, x.port, x.path),
                "red" if x.scope == "network" else "",
            )
            for x in s.listens
        ) or Text("-", style="dim")
        table.add_row(
            t(s.name, "bold"),
            t(", ".join(a.value for a in s.activation) or "-"),
            user,
            exp,
            listeners,
            t(", ".join(pkgs[p].name if p in pkgs else p for p in s.packages) or "-"),
        )
    return table


def _threats(r: Report, limit: int | None) -> Table | None:
    if not r.threats:
        return None
    pkgs = r.package_by_id()
    vulns = {(v.id, v.package): v for v in r.vulnerabilities}
    ordered = sorted(r.threats, key=threat_sort_key)
    shown = ordered if limit is None else ordered[:limit]
    title = "Top threats" if len(shown) < len(ordered) else "Threats"
    table = Table(title=title, title_justify="left", box=box.SIMPLE_HEAD, expand=True)
    table.add_column("Risk", justify="right")
    table.add_column("SSVC")
    table.add_column("Vulnerability", overflow="fold")
    table.add_column("Package", overflow="fold")
    table.add_column("Reachability", overflow="fold")
    table.add_column("Attacker gain", overflow="fold")
    table.add_column("EPSS / KEV")
    for th in shown:
        v = vulns.get((th.vulnerability, th.package))
        dec = th.ssvc.decision if th.ssvc else None
        sev = vuln_severity(v) if v else Severity.UNKNOWN
        epss = Text("-" if v is None or v.epss is None else f"{v.epss * 100:.1f}%")
        if v is not None and v.kev is not None:
            epss.append(" KEV", style="bold white on dark_red")
        table.add_row(
            Text(f"{th.risk_score:.1f}", style="bold"),
            Text(f" {dec.value} ", style=SSVC_STYLE[dec]) if dec else Text("-", style="dim"),
            t(th.vulnerability, SEVERITY_STYLE[sev]),
            t(package_label(pkgs.get(th.package), th.package)),
            t(th.reachability.value.replace("_", " ")),
            Text.assemble(t(th.precondition), (" → ", "dim"), t(th.postcondition, "bold")),
            epss,
        )
    if len(shown) < len(ordered):
        table.caption = f"{len(ordered) - len(shown)} more threats (use --verbose or report.json)"
    return table


def _chain_tree(r: Report, chain: AttackChain) -> Tree:
    svcs = r.service_by_id()
    dec_style = SSVC_STYLE.get(chain.ssvc_decision, "")
    label = Text.assemble(
        t(chain.id, "bold"),
        "  ",
        t(chain.entry, "bold red"),
        (" ⇒ ", "dim"),
        t(chain.goal, "bold red"),
        f"  score {chain.score:.1f} ",
        (f" {chain.ssvc_decision.value} ", dec_style),
    )
    if chain.mitigated:
        label.append("  mitigated", style="green")
    tree = Tree(label, guide_style="dim")
    for i, step in enumerate(chain.steps, 1):
        node_label = Text.assemble(
            (f"{i}. ", "dim"),
            t(step.from_state),
            (" → ", "dim"),
            t(step.to_state, "bold"),
            ": ",
            t(step.title),
        )
        if step.technique:
            node_label.append_text(
                Text.assemble("  ", t(f"{step.technique.id} {step.technique.name}", "magenta", 60))
            )
        node = tree.add(node_label)
        if step.service:
            svc = svcs.get(step.service)
            node.add(Text.assemble(("service ", "dim"), t(svc.name if svc else step.service)))
        if step.vulnerability:
            node.add(Text.assemble(("vulnerability ", "dim"), t(step.vulnerability)))
        for ev in step.evidence[:5]:
            node.add(Text.assemble(("evidence ", "dim"), t(ev, limit=160)))
        for m in step.mitigated_by:
            node.add(Text.assemble(("mitigation ", "green"), t(m, limit=160)))
    tree.add(Text.assemble(("goal reached: ", "dim"), t(chain.goal, "bold red")))
    return tree


def _supply(r: Report, verbose: bool) -> list[Table]:
    sc = r.supply_chain
    pkgs = r.package_by_id()
    svcs = r.service_by_id()
    out: list[Table] = []
    if sc.blast_radius:
        table = Table(
            title="Supply-chain blast radius",
            title_justify="left",
            box=box.SIMPLE_HEAD,
            expand=True,
        )
        for col in ("Package", "Vendor", "Services", "Binaries", "Vulnerabilities", "Score"):
            table.add_column(col, overflow="fold")
        ordered = sorted(sc.blast_radius, key=lambda b: (-b.score, b.package))
        for b in ordered if verbose else ordered[:TOP_BLAST]:
            table.add_row(
                t(package_label(pkgs.get(b.package), b.package), "bold"),
                t(b.vendor or "-"),
                t(", ".join(svcs[s].name if s in svcs else s for s in b.services) or "-"),
                str(len(b.binaries)),
                t(", ".join(b.vulnerabilities) or "-"),
                f"{b.score:.1f}",
            )
        out.append(table)
    if sc.findings:
        table = Table(
            title="Supply-chain findings", title_justify="left", box=box.SIMPLE_HEAD, expand=True
        )
        for col in ("Severity", "Kind", "Subject", "Finding"):
            table.add_column(col, overflow="fold")
        for f in sorted(sc.findings, key=lambda f: (-f.severity.rank, f.id)):
            table.add_row(
                Text(f.severity.value, style=SEVERITY_STYLE[f.severity]),
                t(f.kind),
                t(package_label(pkgs.get(f.subject), f.subject)),
                t(f.title, limit=200),
            )
        out.append(table)
    return out


def _packages(r: Report) -> Table:
    reach = package_reachability(r)
    table = Table(title="Packages", title_justify="left", box=box.SIMPLE_HEAD, expand=True)
    for col in ("Name", "Version", "Arch", "Source", "Reachability", "License"):
        table.add_column(col, overflow="fold")
    for p in r.packages:
        rv = reach.get(p.id)
        table.add_row(
            t(p.name, "bold"),
            t(p.version),
            t(p.arch or "-"),
            t(p.source_name or "-"),
            t(rv.value.replace("_", " ") if rv else "installed"),
            t(p.license or "-"),
        )
    return table


def print_console(report: Report, console: Console, *, verbose: bool = False) -> None:
    """Print a polished terminal summary of ``report`` to ``console``."""
    r = canonical(report)
    console.print(_header(r))
    if (svc := _services(r)) is not None:
        console.print(svc)
    if (thr := _threats(r, None if verbose else TOP_THREATS)) is not None:
        console.print(thr)
    if r.attack_chains:
        console.print(Text("Attack chains", style="bold"))
        chains = sorted(r.attack_chains, key=lambda c: (-c.score, c.id))
        for chain in chains if verbose else chains[:TOP_CHAINS]:
            console.print(_chain_tree(r, chain))
        if not verbose and len(chains) > TOP_CHAINS:
            console.print(
                Text(f"{len(chains) - TOP_CHAINS} more chains in report.json", style="dim")
            )
    for table in _supply(r, verbose):
        console.print(table)
    if verbose:
        console.print(_packages(r))
        for th in sorted(r.threats, key=threat_sort_key):
            body = Text(one_line(th.narrative, 4000))
            if th.remediation:
                body.append_text(
                    Text.assemble(("\nRemediation: ", "bold"), t(th.remediation, limit=500))
                )
            if th.mitigations:
                body.append_text(
                    Text.assemble(
                        ("\nMitigations: ", "bold"), t(", ".join(th.mitigations), limit=500)
                    )
                )
            console.print(
                Panel(
                    body,
                    title=Text.assemble(t(th.id, "bold"), " ", t(th.title, limit=100)),
                    title_align="left",
                    border_style="dim",
                )
            )
    cov = r.metadata.coverage
    notes: list[Text] = [
        Text.assemble(
            ("Package databases: ", "dim"),
            t(", ".join(cov.package_databases) or "none"),
            ("   init systems: ", "dim"),
            t(", ".join(cov.init_systems) or "none"),
            ("   vulnerability sources: ", "dim"),
            t(", ".join(cov.vulnerability_sources) or "none"),
            (" (offline)" if cov.offline else "", "yellow"),
        )
    ]
    notes += [Text.assemble(("limitation  ", "yellow"), t(x, limit=300)) for x in cov.limitations]
    notes += [Text.assemble(("warning     ", "red"), t(w, limit=300)) for w in r.warnings]
    console.print(Panel(Group(*notes), title="Coverage", title_align="left", border_style="yellow"))
