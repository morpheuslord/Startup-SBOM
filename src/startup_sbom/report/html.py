"""Single-file, offline HTML report.

Everything is inline: the stylesheet and script are authorised by SHA-256 hashes in
a ``default-src 'none'`` Content-Security-Policy, so the page makes no network
requests and no injected markup could run even if escaping failed.  Tables are
rendered server-side (readable without JavaScript); the script adds sorting,
filtering and an interactive SVG attack-graph / blast-radius view drawn from a
``<script type="application/json">`` block.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable, Sequence
from html import escape
from importlib import resources

from startup_sbom.models import Report, Severity, SSVCDecision, Threat
from startup_sbom.report.graphs import graph_json
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

Cell = str | tuple[str, str]  # escaped HTML, or (escaped HTML, raw sort key)

_ASSETS = resources.files("startup_sbom.report") / "assets"
CSS = (_ASSETS / "report.css").read_text(encoding="utf-8")
JS = (_ASSETS / "report.js").read_text(encoding="utf-8")


def e(text: object) -> str:
    """HTML-escape (quotes included)."""
    return escape(str(text), quote=True)


def _csp_hash(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def embed_json(data: object) -> str:
    """JSON safe inside ``<script type="application/json">`` (``<``, ``>``, ``&`` escaped)."""
    text = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    for ch, rep in (
        ("<", "\\u003c"),
        (">", "\\u003e"),
        ("&", "\\u0026"),
        (" ", "\\u2028"),
        (" ", "\\u2029"),
    ):
        text = text.replace(ch, rep)
    return text


def sev_badge(sev: Severity) -> tuple[str, str]:
    """Severity badge cell (sortable by rank)."""
    return (f'<span class="badge sev-{sev.value}">{e(sev.value)}</span>', str(sev.rank))


def ssvc_badge(decision: SSVCDecision | None) -> tuple[str, str]:
    """SSVC decision badge cell (sortable by urgency)."""
    if decision is None:
        return ("-", "0")
    cls = {"Track": "track", "Track*": "track-star", "Attend": "attend", "Act": "act"}
    rank = {"Track": "1", "Track*": "2", "Attend": "3", "Act": "4"}
    v = decision.value
    return (f'<span class="badge ssvc-{cls[v]}">{e(v)}</span>', rank[v])


def table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Cell]],
    *,
    table_id: str | None = None,
    sortable: bool = True,
) -> str:
    """An HTML table; string cells must already be escaped."""
    attrs = f' id="{e(table_id)}"' if table_id else ""
    cls = ' class="sortable"' if sortable else ""
    parts = [f'<div class="tbl"><table{attrs}{cls}><thead><tr>']
    parts += [f'<th scope="col">{e(h)}</th>' for h in headers]
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>")
        for cell in row:
            if isinstance(cell, tuple):
                parts.append(f'<td data-sort="{e(cell[1])}">{cell[0]}</td>')
            else:
                parts.append(f"<td>{cell}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table></div>")
    return "".join(parts)


def _pct(v: float | None) -> Cell:
    return ("-", "-1") if v is None else (f"{v * 100:.1f}%", f"{v:.6f}")


def _card(n: object, label: str) -> str:
    return f'<div class="card"><div class="n">{e(n)}</div><div class="l">{e(label)}</div></div>'


def _eol_badge(report: Report) -> str:
    eol = report.os.eol
    if eol is None:
        return '<span class="badge sev-unknown">EOL unknown</span>'
    if eol.is_eol:
        return f'<span class="badge eol-yes">END OF LIFE since {e(eol.eol_date or "?")}</span>'
    until = f" until {e(eol.eol_date)}" if eol.eol_date else ""
    return f'<span class="badge eol-no">supported{until}</span>'


def _top_explained_threats(r: Report, n: int = 3) -> list[Threat]:
    return [t for t in sorted(r.threats, key=threat_sort_key) if t.explanation is not None][:n]


def _explanations_section(r: Report) -> str:
    """The Explanations section: system drivers, fix plans and per-threat waterfalls."""
    from startup_sbom.viz.svg import drivers_chart_svg, waterfall_svg

    ex = r.explanations
    parts = ['<section id="explain"><h2>Explanations</h2>']
    if ex is not None and ex.system is not None:
        g = ex.system
        parts.append(
            f"<p>System risk <strong>{g.system_risk:.1f}</strong>/100 "
            f"(noisy-OR over attack chains and un-chained threats). "
            f"Formula: <code>{e(g.formula)}</code></p>"
        )
        parts.append(f'<div class="chart">{drivers_chart_svg(r)}</div>')
        parts.append("<h3>Risk drivers</h3>")
        parts.append(
            table(
                ["Kind", "Driver", "Points", "Share", "Cumulative"],
                [
                    [
                        e(d.kind),
                        e(d.label),
                        (f"{d.contribution:.1f}", f"{d.contribution:.4f}"),
                        (f"{d.share:.0%}", f"{d.share:.4f}"),
                        (f"{d.cumulative:.0%}", f"{d.cumulative:.4f}"),
                    ]
                    for d in g.drivers
                    if d.kind in ("package", "vendor")
                ],
            )
        )
    actions = {f.id: f.action for f in ex.fixes} if ex is not None else {}
    if ex is not None and ex.fix_plan:
        parts.append("<h3>Minimal fix plan</h3>")
        parts.append(
            table(
                ["Method", "Fixes", "Chains broken", "Risk before", "Risk after"],
                [
                    [
                        e(w.method),
                        e("; ".join(actions.get(i, i) for i in w.fixes)),
                        e(", ".join(w.chains_broken) or "-"),
                        (f"{w.risk_before:.1f}", f"{w.risk_before:.2f}"),
                        (f"{w.risk_after:.1f}", f"{w.risk_after:.2f}"),
                    ]
                    for w in ex.fix_plan
                ],
                sortable=False,
            )
        )
    if ex is not None and ex.what_if:
        parts.append("<h3>What if? (single fixes)</h3>")
        parts.append(
            table(
                ["Fix", "Chains broken", "Threats resolved", "Risk before", "Risk after"],
                [
                    [
                        e("; ".join(actions.get(i, i) for i in w.fixes)),
                        e(", ".join(w.chains_broken) or "-"),
                        (str(len(w.threats_resolved)), str(len(w.threats_resolved))),
                        (f"{w.risk_before:.1f}", f"{w.risk_before:.2f}"),
                        (f"{w.risk_after:.1f}", f"{w.risk_after:.2f}"),
                    ]
                    for w in ex.what_if
                ],
            )
        )
    whys = _top_explained_threats(r)
    if whys:
        parts.append("<h3>Why these scores</h3>")
    for t in whys:
        expl = t.explanation
        if expl is None:  # pragma: no cover - whys is filtered on explanation above
            continue
        parts.append(
            f'<details class="chain" open><summary>{e(t.id)}: {e(t.vulnerability)} · '
            f"risk {t.risk_score:.1f}</summary>"
            f'<div class="chart">{waterfall_svg(expl)}</div>'
        )
        if t.ssvc is not None and t.ssvc.trace is not None:
            tr = t.ssvc.trace
            path = " · ".join(
                f"{e(n.decision_point.split(' v')[0])}: {e(n.value)}" for n in tr.path
            )
            parts.append(
                f'<p class="small">SSVC {e(tr.tree)} → <strong>{e(tr.outcome)}</strong> '
                f"(row {tr.row}): {path}</p>"
            )
            if tr.flips:
                flips = "".join(f"<li>{e(x)}</li>" for x in tr.flips)
                parts.append(f'<ul class="plain small">{flips}</ul>')
        if expl.limits:
            lims = "".join(f"<li>{e(x)}</li>" for x in expl.limits)
            parts.append(
                f'<p class="small">Knowledge limits:</p><ul class="plain small">{lims}</ul>'
            )
        parts.append("</details>")
    if len(parts) == 1:
        parts.append("<p>No explanation data (run the scan with explanations enabled).</p>")
    parts.append("</section>")
    return "".join(parts)


def render_html(report: Report, options: RenderOptions) -> str:
    """Render the self-contained HTML report."""
    del options
    r = canonical(report)
    md_ = r.metadata
    pkgs = r.package_by_id()
    svcs = r.service_by_id()
    pkg_reach = package_reachability(r)
    vulns = {(v.id, v.package): v for v in r.vulnerabilities}
    boot_svcs = [s for s in r.services if service_reachability(s) is not None]
    title = f"Startup-SBOM: {r.os.pretty_name or r.os.id} ({md_.target.reference})"
    body: list[str] = []

    body.append(
        "<header>"
        f"<h1>{e(r.os.pretty_name or r.os.name or r.os.id)} {_eol_badge(r)}</h1>"
        f'<div class="meta">{e(md_.target.kind)}: {e(md_.target.reference)} · startup-sbom '
        f"{e(md_.tool_version)} · scan {e(md_.scan_id)} · {e(iso_z(timestamp(r)))}</div>"
        "</header>"
    )
    nav = [
        ("summary", "Summary"),
        ("threats", "Threats"),
        ("explain", "Explanations"),
        ("graph", "Attack graph"),
        ("chains", "Attack chains"),
        ("supply", "Supply chain"),
        ("services", "Services"),
        ("vulns", "Vulnerabilities"),
        ("packages", "Packages"),
        ("coverage", "Coverage"),
    ]
    body.append("<nav>" + "".join(f'<a href="#{a}">{e(t)}</a>' for a, t in nav) + "</nav><main>")

    # ------------------------------------------------------------- summary
    sev_counts = dict.fromkeys(Severity, 0)
    for v in r.vulnerabilities:
        sev_counts[vuln_severity(v)] += 1
    act = sum(1 for t in r.threats if t.ssvc and t.ssvc.decision is SSVCDecision.ACT)
    attend = sum(1 for t in r.threats if t.ssvc and t.ssvc.decision is SSVCDecision.ATTEND)
    cards = [
        _card(len(r.packages), "packages"),
        _card(len(boot_svcs), "services started automatically"),
        _card(sum(1 for s in boot_svcs if s.network_exposed), "network-exposed services"),
        _card(len(r.vulnerabilities), "vulnerabilities"),
        _card(sev_counts[Severity.CRITICAL], "critical"),
        _card(sev_counts[Severity.HIGH], "high"),
        _card(sum(1 for v in r.vulnerabilities if v.kev), "in CISA KEV"),
        _card(act, "threats: SSVC Act"),
        _card(attend, "threats: SSVC Attend"),
        _card(len(r.attack_chains), "attack chains"),
        _card(len(r.supply_chain.findings), "supply-chain findings"),
    ]
    sys_rows: list[list[Cell]] = [
        ["Target", f"{e(md_.target.kind)}: {e(md_.target.reference)}"],
        ["Operating system", e(r.os.pretty_name or r.os.id)],
        ["OS id / version", f"{e(r.os.id)} {e(r.os.version_id or '-')}"],
        ["End of life", _eol_badge(r)],
        ["Vulnerability ecosystems", e(", ".join(r.os.vuln_ecosystems) or "-")],
    ]
    if r.container is not None:
        c = r.container
        sys_rows += [
            ["Image", e(c.image or c.name or "-")],
            ["Digest", e(c.image_digest or "-")],
            ["User", e(c.user or "root (default)")],
            ["Exposed ports", e(", ".join(c.exposed_ports) or "-")],
        ]
    from startup_sbom.viz.svg import attack_graph_svg, severity_chart_svg, ssvc_chart_svg

    charts = ""
    if r.vulnerabilities or r.threats:
        charts = (
            f'<div class="charts"><div class="chart">{severity_chart_svg(r)}</div>'
            f'<div class="chart">{ssvc_chart_svg(r)}</div></div>'
        )
    body.append(
        '<section id="summary"><h2>Summary</h2><div class="cards">'
        + "".join(cards)
        + "</div>"
        + charts
        + "<h3>System</h3>"
        + table(["Field", "Value"], sys_rows, sortable=False)
        + "</section>"
    )

    # ------------------------------------------------------------- threats
    trows: list[list[Cell]] = []
    for t in sorted(r.threats, key=threat_sort_key):
        tv = vulns.get((t.vulnerability, t.package))
        kev = ' <span class="badge kev">KEV</span>' if tv and tv.kev else ""
        trows.append(
            [
                (f"{t.risk_score:.1f}", f"{t.risk_score:.3f}"),
                ssvc_badge(t.ssvc.decision if t.ssvc else None),
                e(t.vulnerability) + kev,
                e(package_label(pkgs.get(t.package), t.package)),
                e(t.reachability.value.replace("_", " ")),
                f"{e(t.precondition)} → {e(t.postcondition)}",
                e(", ".join(svcs[s].name if s in svcs else s for s in t.services) or "-"),
                _pct(tv.epss if tv else None),
                e(t.title),
            ]
        )
    body.append(
        '<section id="threats"><h2>Threats</h2>'
        '<input class="filter" type="search" placeholder="Filter threats" data-filter="t-threats" '
        'aria-label="Filter threats">'
        + table(
            [
                "Risk",
                "SSVC",
                "Vulnerability",
                "Package",
                "Reachability",
                "Attacker gain",
                "Services",
                "EPSS",
                "Title",
            ],
            trows,
            table_id="t-threats",
        )
        + "</section>"
    )

    # ------------------------------------------------------------- explanations
    body.append(_explanations_section(r))

    # ------------------------------------------------------------- graph
    static_graph = attack_graph_svg(r) if r.attack_chains else ""
    body.append(
        '<section id="graph"><h2>Attack graph and blast radius</h2>'
        '<div class="tabs"><button type="button" data-view="attack" aria-pressed="true">'
        'Attack graph</button><button type="button" data-view="supply" aria-pressed="false">'
        "Supply-chain blast radius</button></div>"
        '<div class="graph-wrap"><div class="graph-box" id="graph-box">'
        '<noscript><p class="small">Enable JavaScript for the interactive graph; a static view '
        f"follows and the attack chains are listed below.</p>{static_graph}</noscript></div>"
        '<aside class="graph-detail" id="graph-detail" aria-live="polite"></aside></div></section>'
    )

    # ------------------------------------------------------------- chains
    chain_html = ['<section id="chains"><h2>Attack chains</h2>']
    if not r.attack_chains:
        chain_html.append("<p>No attack chains were found.</p>")
    for chain in sorted(r.attack_chains, key=lambda c: (-c.score, c.id)):
        badge, _ = ssvc_badge(chain.ssvc_decision)
        mitig = ' <span class="badge eol-no">mitigated</span>' if chain.mitigated else ""
        chain_html.append(
            f'<details class="chain" open><summary>{e(chain.id)}: {e(chain.entry)} → '
            f"{e(chain.goal)} · score {chain.score:.1f} {badge}{mitig}</summary>"
            f'<p>{e(chain.narrative)}</p><p class="small">likelihood {chain.likelihood:.2f} · '
            f"impact {chain.impact:.2f}</p><ol>"
        )
        for step in chain.steps:
            tech = (
                f' <span class="small">{e(step.technique.id)} {e(step.technique.name)}</span>'
                if step.technique
                else ""
            )
            extra = []
            if step.service:
                s = svcs.get(step.service)
                extra.append(f"service: {e(s.name if s else step.service)}")
            if step.vulnerability:
                extra.append(f"vulnerability: {e(step.vulnerability)}")
            extra += [f"evidence: {e(x)}" for x in step.evidence]
            extra += [f"mitigation: {e(x)}" for x in step.mitigated_by]
            sub = "".join(f"<li>{x}</li>" for x in extra)
            chain_html.append(
                f"<li><strong>{e(step.from_state)} → {e(step.to_state)}</strong>: "
                f"{e(step.title)}{tech}"
                + (f'<ul class="plain small">{sub}</ul>' if sub else "")
                + "</li>"
            )
        chain_html.append("</ol></details>")
    chain_html.append("</section>")
    body.append("".join(chain_html))

    # ------------------------------------------------------------- supply chain
    sc = r.supply_chain
    sc_html = ['<section id="supply"><h2>Supply chain</h2>']
    if sc.blast_radius:
        sc_html.append("<h3>Blast radius</h3>")
        sc_html.append(
            table(
                ["Package", "Vendor", "Services", "Binaries", "Vulnerabilities", "Score"],
                [
                    [
                        e(package_label(pkgs.get(b.package), b.package)),
                        e(b.vendor or "-"),
                        e(", ".join(svcs[s].name if s in svcs else s for s in b.services) or "-"),
                        (str(len(b.binaries)), str(len(b.binaries))),
                        e(", ".join(b.vulnerabilities) or "-"),
                        (f"{b.score:.1f}", f"{b.score:.3f}"),
                    ]
                    for b in sorted(sc.blast_radius, key=lambda x: (-x.score, x.package))
                ],
            )
        )
    if sc.findings:
        sc_html.append("<h3>Findings</h3>")
        sc_html.append(
            table(
                ["Severity", "Kind", "Subject", "Finding", "Detail"],
                [
                    [
                        sev_badge(f.severity),
                        e(f.kind),
                        e(package_label(pkgs.get(f.subject), f.subject)),
                        e(f.title),
                        e(f.detail or ""),
                    ]
                    for f in sorted(sc.findings, key=lambda f: (-f.severity.rank, f.id))
                ],
            )
        )
    if sc.vendors:
        sc_html.append("<h3>Vendors</h3>")
        sc_html.append(
            table(
                ["Vendor", "Packages", "Boot", "Services", "Vulns", "Critical", "High", "KEV"],
                [
                    [e(v.vendor)]
                    + [
                        (str(x), str(x))
                        for x in (
                            v.packages,
                            v.boot_packages,
                            v.services,
                            v.vulnerabilities,
                            v.critical,
                            v.high,
                            v.kev,
                        )
                    ]
                    for v in sorted(sc.vendors, key=lambda v: (-v.packages, v.vendor))
                ],
            )
        )
    if not (sc.blast_radius or sc.findings or sc.vendors):
        sc_html.append("<p>No supply-chain data.</p>")
    sc_html.append("</section>")
    body.append("".join(sc_html))

    # ------------------------------------------------------------- services
    srows: list[list[Cell]] = []
    for s in sorted(r.services, key=lambda s: (service_reachability(s) is None, s.name, s.id)):
        h = s.hardening
        exp: Cell = (
            (f"{e(h.exposure_rating or '')} {h.exposure:.1f}".strip(), f"{h.exposure:.2f}")
            if h.exposure is not None
            else (e(h.exposure_rating or "-"), "-1")
        )
        srows.append(
            [
                e(s.name),
                e(s.init_system.value),
                e(", ".join(a.value for a in s.activation) or "-"),
                "yes" if service_reachability(s) is not None else "no",
                e(h.user),
                exp,
                e(
                    ", ".join(listen_text(x.protocol, x.address, x.port, x.path) for x in s.listens)
                    or "-"
                ),
                e(", ".join(pkgs[p].name if p in pkgs else p for p in s.packages) or "-"),
            ]
        )
    body.append(
        '<section id="services"><h2>Services</h2>'
        + table(
            [
                "Service",
                "Init",
                "Activation",
                "Auto-start",
                "User",
                "Exposure",
                "Listeners",
                "Packages",
            ],
            srows,
        )
        + "</section>"
    )

    # ------------------------------------------------------------- vulnerabilities
    vrows: list[list[Cell]] = []
    for v in sorted(
        r.vulnerabilities, key=lambda v: (-vuln_severity(v).rank, -(vuln_score(v) or 0), v.id)
    ):
        score = vuln_score(v)
        vrows.append(
            [
                e(v.id) + (' <span class="badge kev">KEV</span>' if v.kev else ""),
                sev_badge(vuln_severity(v)),
                ("-", "-1") if score is None else (f"{score:.1f}", f"{score:.2f}"),
                e(package_label(pkgs.get(v.package), v.package_name)),
                e(", ".join(v.fixed_versions) or "-"),
                e(v.status.value),
                e(vuln_reachability(r, v, pkg_reach=pkg_reach).value.replace("_", " ")),
                _pct(v.epss),
                e(v.summary or ""),
            ]
        )
    body.append(
        '<section id="vulns"><h2>Vulnerabilities</h2>'
        '<input class="filter" type="search" placeholder="Filter vulnerabilities" '
        'data-filter="t-vulns" aria-label="Filter vulnerabilities">'
        + table(
            [
                "ID",
                "Severity",
                "CVSS",
                "Package",
                "Fixed in",
                "Status",
                "Reachability",
                "EPSS",
                "Summary",
            ],
            vrows,
            table_id="t-vulns",
        )
        + "</section>"
    )

    # ------------------------------------------------------------- packages
    prows: list[list[Cell]] = [
        [
            e(p.name),
            e(p.version),
            e(p.arch or "-"),
            e(p.type.value),
            e(p.source_name or "-"),
            e(pkg_reach.get(p.id, "installed").replace("_", " ")),
            e(p.license or "-"),
            e(p.vendor or p.maintainer or "-"),
        ]
        for p in r.packages
    ]
    body.append(
        f'<section id="packages"><h2>Packages</h2><details><summary>{len(r.packages)} packages'
        "</summary>"
        '<input class="filter" type="search" placeholder="Filter packages" data-filter="t-pkgs" '
        'aria-label="Filter packages">'
        + table(
            ["Name", "Version", "Arch", "Type", "Source", "Reachability", "License", "Supplier"],
            prows,
            table_id="t-pkgs",
        )
        + "</details></section>"
    )

    # ------------------------------------------------------------- coverage
    cov = md_.coverage
    items = [
        f"Package databases: {e(', '.join(cov.package_databases) or 'none')}",
        f"Init systems: {e(', '.join(cov.init_systems) or 'none')}",
        f"Vulnerability sources: {e(', '.join(cov.vulnerability_sources) or 'none')}"
        + (" (offline)" if cov.offline else ""),
    ]
    items += [f"Limitation: {e(x)}" for x in cov.limitations]
    cov_html = '<section id="coverage"><h2>Coverage and limitations</h2><ul class="plain">'
    cov_html += "".join(f"<li>{x}</li>" for x in items) + "</ul>"
    if r.warnings:
        cov_html += '<h3>Warnings</h3><ul class="plain">'
        cov_html += "".join(f"<li>{e(w)}</li>" for w in r.warnings) + "</ul>"
    body.append(cov_html + "</section></main>")
    body.append(
        "<footer>Generated offline by startup-sbom. Machine-readable data: report.json, "
        "sbom.cdx.json, results.sarif.</footer>"
    )

    data = {"graph": graph_json(r), "scanId": md_.scan_id}
    csp = (
        f"default-src 'none'; style-src {_csp_hash(CSS)}; script-src {_csp_hash(JS)}; "
        "img-src data:; base-uri 'none'; form-action 'none'"
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{e(csp)}">'
        '<meta name="referrer" content="no-referrer">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        f"<title>{e(title)}</title><style>{CSS}</style></head><body>\n"
        + "\n".join(body)
        + f'\n<script type="application/json" id="ssbom-data">{embed_json(data)}</script>'
        + f"\n<script>{JS}</script>\n</body></html>\n"
    )
