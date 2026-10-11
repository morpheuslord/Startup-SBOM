"""Standalone SVG charts for the HTML and PDF reports (zero dependencies).

One tiny scene graph (``Rect``/``Line``/``Bezier``/``Poly``/``Circle``/``Label``) is
built per chart and emitted as a self-contained SVG 1.1 string: every text node is
XML-escaped *after* :func:`startup_sbom.textsafe.safe` strips control characters
(raw C0 bytes are not even legal XML), colours and fonts are presentation
attributes (CSP-safe: no ``style=`` attributes, no scripts, no external
references), and every document carries ``<title>`` and ``<desc>``.

The attack graph uses an own Sugiyama-lite layered layout with dummy nodes so
edges spanning several layers route around intermediate boxes.
"""

from __future__ import annotations

import itertools
import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from xml.sax.saxutils import escape, quoteattr

from startup_sbom.models import Explanation, Report, Severity
from startup_sbom.textsafe import safe

__all__ = [
    "attack_graph_svg",
    "drivers_chart_svg",
    "severity_chart_svg",
    "ssvc_chart_svg",
    "to_svg",
    "waterfall_svg",
]

FONT = "DejaVu Sans, Helvetica, Arial, sans-serif"
INK = "#1f2328"
MUTED = "#59636e"
GRID = "#d0d7de"
UP = "#cf222e"
DOWN = "#1a7f37"
TOTAL = "#6639ba"
SEV_COLOR: Mapping[str, str] = {
    "critical": "#a40e26",
    "high": "#cf222e",
    "medium": "#bf8700",
    "low": "#0969da",
    "none": "#8c959f",
    "unknown": "#8c959f",
}
SSVC_COLOR: Mapping[str, str] = {
    "Act": "#a40e26",
    "Attend": "#cf222e",
    "Track*": "#bf8700",
    "Track": "#0969da",
}
_SEV_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
_MAX_GRAPH_EDGES = 40
_MAX_DRIVERS = 10


def text_width(s: str, size: float) -> float:
    """Approximate Helvetica string width (enough for layout margins)."""
    return 0.56 * size * len(s)


# --------------------------------------------------------------------------- scene graph
@dataclass(slots=True)
class Rect:
    x: float
    y: float
    w: float
    h: float
    fill: str = "none"
    stroke: str | None = None
    rx: float = 0.0
    sw: float = 1.0


@dataclass(slots=True)
class Line:
    x1: float
    y1: float
    x2: float
    y2: float
    stroke: str = INK
    sw: float = 1.0
    dash: tuple[float, ...] | None = None


@dataclass(slots=True)
class Bezier:
    """Cubic Bézier: start, control 1, control 2, end."""

    pts: tuple[tuple[float, float], tuple[float, float], tuple[float, float], tuple[float, float]]
    stroke: str = INK
    sw: float = 1.2
    dash: tuple[float, ...] | None = None


@dataclass(slots=True)
class Poly:
    pts: tuple[tuple[float, float], ...]
    fill: str = INK


@dataclass(slots=True)
class Circle:
    cx: float
    cy: float
    r: float
    fill: str = INK
    stroke: str | None = "#ffffff"


@dataclass(slots=True)
class Label:
    x: float
    y: float
    s: str
    size: float = 9.0
    anchor: str = "start"
    fill: str = INK
    bold: bool = False


Item = Rect | Line | Bezier | Poly | Circle | Label


@dataclass(slots=True)
class Scene:
    """A fixed-size canvas of primitives in top-left coordinates."""

    w: float
    h: float
    title: str = ""
    desc: str = ""
    items: list[Item] = field(default_factory=list)

    def add(self, *xs: Item) -> Scene:
        self.items.extend(xs)
        return self


def _txt(s: str) -> str:
    """Sanitise then XML-escape untrusted text for an SVG text node.

    Quotes are escaped too (defence in depth: the string can never terminate an
    attribute even if a future caller interpolates it into one).
    """
    return escape(safe(s, 200), {'"': "&quot;", "'": "&#39;"})


def to_svg(sc: Scene) -> str:
    """Emit the scene as a self-contained SVG 1.1 document string."""
    o = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {sc.w:g} {sc.h:g}" '
        f'width="{sc.w:g}" height="{sc.h:g}" font-family={quoteattr(FONT)} role="img">'
    ]
    o.append(f"<title>{_txt(sc.title or 'chart')}</title>")
    o.append(f"<desc>{_txt(sc.desc or sc.title or 'startup-sbom chart')}</desc>")
    for it in sc.items:
        if isinstance(it, Rect):
            st = f' stroke="{it.stroke}" stroke-width="{it.sw:g}"' if it.stroke else ""
            o.append(
                f'<rect x="{it.x:.2f}" y="{it.y:.2f}" width="{it.w:.2f}" height="{it.h:.2f}" '
                f'rx="{it.rx:g}" fill="{it.fill}"{st}/>'
            )
        elif isinstance(it, Line):
            d = f' stroke-dasharray="{" ".join(f"{x:g}" for x in it.dash)}"' if it.dash else ""
            o.append(
                f'<line x1="{it.x1:.2f}" y1="{it.y1:.2f}" x2="{it.x2:.2f}" y2="{it.y2:.2f}" '
                f'stroke="{it.stroke}" stroke-width="{it.sw:g}"{d}/>'
            )
        elif isinstance(it, Bezier):
            a, b, c, e = it.pts
            dash = f' stroke-dasharray="{" ".join(f"{x:g}" for x in it.dash)}"' if it.dash else ""
            o.append(
                f'<path d="M{a[0]:.2f},{a[1]:.2f} C{b[0]:.2f},{b[1]:.2f} {c[0]:.2f},{c[1]:.2f} '
                f'{e[0]:.2f},{e[1]:.2f}" fill="none" stroke="{it.stroke}" '
                f'stroke-width="{it.sw:g}"{dash}/>'
            )
        elif isinstance(it, Poly):
            pts = " ".join(f"{x:.2f},{y:.2f}" for x, y in it.pts)
            o.append(f'<polygon points="{pts}" fill="{it.fill}"/>')
        elif isinstance(it, Circle):
            st = f' stroke="{it.stroke}"' if it.stroke else ""
            o.append(
                f'<circle cx="{it.cx:.2f}" cy="{it.cy:.2f}" r="{it.r:g}" fill="{it.fill}"{st}/>'
            )
        else:
            w = ' font-weight="bold"' if it.bold else ""
            o.append(
                f'<text x="{it.x:.2f}" y="{it.y:.2f}" font-size="{it.size:g}" '
                f'text-anchor="{it.anchor}" fill="{it.fill}"{w}>{_txt(it.s)}</text>'
            )
    o.append("</svg>")
    return "\n".join(o)


def arrowhead(x: float, y: float, angle: float, size: float = 6.0, fill: str = INK) -> Poly:
    """A small triangle pointing along ``angle`` ending at ``(x, y)``."""
    a1, a2 = angle + math.pi - 0.4, angle + math.pi + 0.4
    return Poly(
        (
            (x, y),
            (x + size * math.cos(a1), y + size * math.sin(a1)),
            (x + size * math.cos(a2), y + size * math.sin(a2)),
        ),
        fill,
    )


# --------------------------------------------------------------------------- basic charts
def _hbars(
    rows: Sequence[tuple[str, float, str]], *, title: str, desc: str, fmt: str = "{:g}"
) -> Scene:
    width, row_h, lw = 380.0, 16.0, 110.0
    n = max(1, len(rows))
    sc = Scene(width, n * row_h + 26, title=title, desc=desc)
    sc.add(Label(0, 11, title, 10, bold=True))
    if not rows:
        sc.add(Label(lw, 30, "none", 9, "start", MUTED))
        return sc
    mx = max(r[1] for r in rows) or 1.0
    for i, (label, value, color) in enumerate(rows):
        y = 18 + i * row_h
        w = (width - lw - 44) * value / mx
        sc.add(
            Label(lw - 6, y + row_h * 0.68, safe(label, 24), 9, "end"),
            Rect(lw, y + 2, max(0.5, w), row_h - 5, color, rx=1.5),
            Label(lw + w + 4, y + row_h * 0.68, fmt.format(value), 9, "start", MUTED),
        )
    return sc


def severity_chart_svg(report: Report) -> str:
    """Vulnerability counts by effective severity as an SVG bar chart."""
    from startup_sbom.report.native import vuln_severity

    counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for v in report.vulnerabilities:
        counts[vuln_severity(v)] += 1
    rows = [
        (sev.value, float(counts[sev]), SEV_COLOR[sev.value]) for sev in _SEV_ORDER if counts[sev]
    ]
    desc = (
        "; ".join(f"{int(n)} {label}" for label, n, _ in rows) or "no vulnerabilities were matched"
    )
    return to_svg(_hbars(rows, title="Vulnerabilities by severity", desc=desc))


def ssvc_chart_svg(report: Report) -> str:
    """Threat counts by SSVC decision as an SVG bar chart."""
    counts: dict[str, int] = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
    for t in report.threats:
        if t.ssvc is not None:
            counts[t.ssvc.decision.value] += 1
    rows = [(name, float(n), SSVC_COLOR[name]) for name, n in counts.items() if n]
    desc = "; ".join(f"{int(n)} {name}" for name, n, _ in rows) or "no threats were derived"
    return to_svg(_hbars(rows, title="Threats by SSVC decision", desc=desc))


def waterfall_svg(explanation: Explanation) -> str:
    """An exact score decomposition as an SVG waterfall chart."""
    e = explanation
    width, row_h, lw, vw, pad = 480.0, 18.0, 180.0, 46.0, 8.0
    bw = width - lw - vw - 2 * pad
    n = len(e.factors) + 1
    subject = safe(e.subject, 60)
    sc = Scene(
        width,
        n * row_h + 40,
        title=f"Risk waterfall {subject}",
        desc=f"baseline {e.baseline:g} plus factor contributions equals {e.total:.1f}",
    )
    scale = max(100.0, e.baseline, e.total)
    k = bw / scale
    x0 = lw + vw + pad
    for v in (0, 25, 50, 75, 100):
        sc.add(
            Line(x0 + v * k, 4, x0 + v * k, n * row_h + 8, GRID, 0.6),
            Label(x0 + v * k, n * row_h + 20, str(v), 8, "middle", MUTED),
        )
    run = e.baseline
    for i, f in enumerate([*list(e.factors), None]):
        y = 8 + i * row_h
        if f is None:
            a, b = 0.0, max(0.0, e.total)
            color, lab, val = TOTAL, "= score", f"{e.total:.1f}"
        else:
            a, b = sorted((run, run + f.contribution))
            color = MUTED if abs(f.contribution) < 0.05 else UP if f.contribution > 0 else DOWN
            mult = f" x{f.multiplier:.2f}" if f.multiplier is not None else ""
            lab, val = safe(f.label, 34) + mult, f"{f.contribution:+.1f}"
            run += f.contribution
        sc.add(
            Label(lw, y + row_h * 0.62, lab, 9, "end", INK, bold=f is None),
            Label(lw + vw, y + row_h * 0.62, val, 9, "end", color, bold=True),
        )
        if b - a > 1e-9:
            sc.add(Rect(x0 + a * k, y + 2, max(0.8, (b - a) * k), row_h - 5, color, rx=1.5))
        if f is not None and i + 1 < n:  # connector to the next bar
            xc = x0 + run * k
            sc.add(Line(xc, y + row_h - 3, xc, y + row_h + 2, MUTED, 0.6, (2, 2)))
    return to_svg(sc)


def drivers_chart_svg(report: Report) -> str:
    """Top system-risk drivers (packages, then vendors) as an SVG bar chart."""
    ex = report.explanations
    drivers = list(ex.system.drivers) if ex is not None and ex.system is not None else []
    shown = [d for d in drivers if d.kind == "package"][:_MAX_DRIVERS]
    if not shown:
        shown = [d for d in drivers if d.kind in ("chain", "threat")][:_MAX_DRIVERS]
    rows = [
        (f"{d.label}", d.contribution, SEV_COLOR["high"] if d.share >= 0.25 else SEV_COLOR["low"])
        for d in shown
    ]
    risk = ex.system.system_risk if ex is not None and ex.system is not None else 0.0
    desc = f"system risk {risk:.1f} of 100; " + (
        "; ".join(f"{safe(d.label, 40)} {d.share:.0%}" for d in shown) or "no drivers"
    )
    return to_svg(_hbars(rows, title="What drives system risk", desc=desc, fmt="{:.1f}"))


# --------------------------------------------------------------------------- attack graph
def layered_layout(
    nodes: Sequence[str],
    edges: Sequence[tuple[str, str]],
    rank: Mapping[str, int] | None = None,
    sweeps: int = 4,
) -> dict[str, tuple[int, float]]:
    """Sugiyama-lite layout: longest-path layers + barycenter crossing reduction."""
    preds: dict[str, list[str]] = defaultdict(list)
    succ: dict[str, list[str]] = defaultdict(list)
    for a, b in edges:
        succ[a].append(b)
        preds[b].append(a)
    ranks: dict[str, int] = dict(rank) if rank is not None else {}
    if not ranks:
        indeg = {n: len(preds[n]) for n in nodes}
        frontier = sorted(n for n in nodes if indeg[n] == 0)
        for n in frontier:
            ranks[n] = 0
        while frontier:
            n = frontier.pop(0)
            for s in sorted(succ[n]):
                ranks[s] = max(ranks.get(s, 0), ranks[n] + 1)
                indeg[s] -= 1
                if indeg[s] == 0:
                    frontier.append(s)
            frontier.sort()
        for n in nodes:  # nodes on a cycle (should not happen): last layer
            ranks.setdefault(n, max(ranks.values(), default=0))
    layers: dict[int, list[str]] = defaultdict(list)
    for n in nodes:
        layers[ranks[n]].append(n)
    order = {n: i for layer in layers.values() for i, n in enumerate(sorted(layer))}
    for it in range(sweeps):
        sweep = sorted(layers) if it % 2 == 0 else sorted(layers, reverse=True)
        neighbours = preds if it % 2 == 0 else succ

        def bary(n: str, nb: dict[str, list[str]] = neighbours) -> float:
            ns = [order[m] for m in nb[n] if m in order]
            return sum(ns) / len(ns) if ns else float(order[n])

        for r in sweep:
            layers[r].sort(key=lambda n: (bary(n), n))
            order.update({n: i for i, n in enumerate(layers[r])})
    return {n: (ranks[n], order[n] - (len(layers[ranks[n]]) - 1) / 2) for n in nodes}


def attack_graph_scene(
    nodes: Sequence[str],
    edges: Sequence[tuple[str, str, str, bool]],
    kinds: Mapping[str, str] | None = None,
) -> Scene:
    """Layered left-to-right attack graph; edges are ``(src, dst, label, blocked)``."""
    base = layered_layout(nodes, [(a, b) for a, b, _, _ in edges])
    rank = {n: r for n, (r, _) in base.items()}
    all_nodes = list(nodes)
    flat: list[tuple[str, str]] = []
    routes: list[tuple[list[str], str, bool]] = []
    r2 = dict(rank)
    for k, (a, b, lab, blocked) in enumerate(edges):
        lo, hi = rank[a], rank[b]
        chain = [a]
        if hi > lo + 1:  # dummy nodes so the edge routes around intermediate layers
            for layer in range(lo + 1, hi):
                d = f"__d{k}_{layer}"
                all_nodes.append(d)
                r2[d] = layer
                chain.append(d)
        chain.append(b)
        flat += list(itertools.pairwise(chain))
        routes.append((chain, lab, blocked))
    pos = layered_layout(all_nodes, flat, r2)
    box = {n: (0.0 if n.startswith("__d") else max(70.0, text_width(n, 9) + 18)) for n in all_nodes}
    max_box = max(box.values(), default=70.0)
    lab_w = max((text_width(lab, 7.5) for _, lab, _ in routes), default=60.0)
    col_w = max(150.0, lab_w * 0.7 + max_box)
    row_h = 64.0
    nlayers = max((r for r, _ in pos.values()), default=0) + 1
    span = max((abs(o) for _, o in pos.values()), default=0.0)
    width = (nlayers - 1) * col_w + max_box + 40
    height = (2 * span + 1) * row_h + 40
    sc = Scene(
        width,
        height,
        title="Attack graph",
        desc=f"{len(nodes)} privilege states, {len(edges)} attack steps",
    )

    def cx(n: str) -> float:
        return 20 + max_box / 2 + pos[n][0] * col_w

    def cy(n: str) -> float:
        return height / 2 + pos[n][1] * row_h

    seen: dict[tuple[str, str], int] = defaultdict(int)
    total: dict[tuple[str, str], int] = defaultdict(int)
    for chain, *_ in routes:
        total[(chain[0], chain[-1])] += 1
    for chain, lab, blocked in routes:
        key = (chain[0], chain[-1])
        j = seen[key]
        seen[key] += 1
        off = (j - (total[key] - 1) / 2) * 30
        color = MUTED if blocked else UP
        for i, (a, b) in enumerate(itertools.pairwise(chain)):
            x1, y1 = cx(a) + box[a] / 2, cy(a) + (off * 0.5 if box[a] else 0)
            x2, y2 = cx(b) - box[b] / 2 - (2 if box[b] else 0), cy(b) + (off * 0.5 if box[b] else 0)
            dx = (x2 - x1) * 0.45
            c1 = (x1 + dx, y1 + (0.0 if not box[a] else off))
            c2 = (x2 - dx, y2 + (0.0 if not box[b] else off))
            sc.add(Bezier(((x1, y1), c1, c2, (x2, y2)), color, 1.3, (4, 3) if blocked else None))
            if i == len(chain) - 2:
                sc.add(arrowhead(x2, y2, math.atan2(y2 - c2[1], x2 - c2[0]), 7, color))
            if i == 0:
                mx = 0.125 * x1 + 0.375 * c1[0] + 0.375 * c2[0] + 0.125 * x2
                my = 0.125 * y1 + 0.375 * c1[1] + 0.375 * c2[1] + 0.125 * y2
                tw = text_width(lab, 7.5)
                sc.add(
                    Rect(mx - tw / 2 - 3, my - 8, tw + 6, 11, "#ffffff", rx=2),
                    Label(mx, my, lab, 7.5, "middle", MUTED if blocked else INK),
                )
    fills = {"entry": "#ddf4ff", "goal": "#ffebe9"}
    for n in nodes:
        kind = (kinds or {}).get(n, "")
        sc.add(
            Rect(cx(n) - box[n] / 2, cy(n) - 13, box[n], 26, fills.get(kind, "#f6f8fa"), INK, 6, 1),
            Label(cx(n), cy(n) + 3.5, n, 9, "middle", INK, bold=bool(kind)),
        )
    return sc


def attack_graph_svg(report: Report) -> str:
    """The merged privilege-state graph of all attack chains as a layered SVG DAG."""
    seen: set[str] = set()
    edges: list[tuple[str, str, str, bool]] = []
    entries: set[str] = set()
    goals: set[str] = set()
    for chain in sorted(report.attack_chains, key=lambda c: (-c.score, c.id)):
        entries.add(safe(chain.entry, 40))
        goals.add(safe(chain.goal, 40))
        for s in chain.steps:
            key = s.id or f"{s.rule}|{s.from_state}|{s.to_state}|{s.threat or s.service or ''}"
            if key in seen or len(edges) >= _MAX_GRAPH_EDGES:
                continue
            seen.add(key)
            tech = s.technique.id if s.technique else s.rule
            label = safe(f"{tech} {s.vulnerability or s.title}", 44)
            blocked = bool(s.mitigated_by)
            edges.append((safe(s.from_state, 40), safe(s.to_state, 40), label, blocked))
    if not edges:
        sc = Scene(320, 40, title="Attack graph", desc="no attack chains were found")
        sc.add(Label(8, 24, "No attack chains were found.", 10, "start", MUTED))
        return to_svg(sc)
    nodes = sorted({e[0] for e in edges} | {e[1] for e in edges})
    kinds = {n: "entry" for n in nodes if n in entries and n not in goals}
    kinds |= {n: "goal" for n in nodes if n in goals}
    return to_svg(attack_graph_scene(nodes, edges, kinds))
