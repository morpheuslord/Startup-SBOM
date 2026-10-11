"""Rich renderables for explanations and charts (terminal and Textual ``Static``).

Design rules (research track 12):

1. Untrusted text only ever enters as ``safe_text(s)`` / ``safe(s)`` — never markup,
   never interpolated into markup (``rich.text.Text`` alone does *not* strip ESC).
2. Colour is never the only channel (WCAG 1.4.1, ``NO_COLOR``): increases carry a
   ``+`` sign and full blocks, decreases a ``−`` sign and shaded blocks, blocked
   edges a ``✗`` label.
3. Everything adapts to ``options.max_width`` and falls back to pure ASCII glyphs
   when the console encoding cannot carry box drawing (``options.ascii_only``).

Every public function takes report/explanation models and returns a rich
renderable, so the same visuals serve the console report and the TUI.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.measure import Measurement
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from startup_sbom.explain.provenance import Provenance, WhyNode
from startup_sbom.models import (
    AttackChain,
    BlastRadius,
    Explanation,
    Report,
    Severity,
    SSVCTrace,
    Threat,
)
from startup_sbom.textsafe import safe, safe_text

__all__ = [
    "attack_chain_diagram",
    "blast_radius_tree",
    "epss_impact_quadrant",
    "fix_plan_table",
    "privilege_graph",
    "risk_drivers",
    "risk_waterfall",
    "severity_bars",
    "ssvc_bars",
    "ssvc_trace_tree",
    "why_tree",
]


# --------------------------------------------------------------------------- glyphs
@dataclass(frozen=True, slots=True)
class Glyphs:
    """Drawing characters for one console capability level."""

    full: str
    eighths: str  # index 0..7 = left-aligned partial blocks
    right_half: str
    light: str
    shades: str
    arrow: str
    hline: str
    vline: str
    tee: str
    elbow: str
    branch: str
    cross: str
    box: tuple[str, str, str, str]  # tl tr bl br
    blocked: str
    down: str
    wrap: str


UNI = Glyphs(
    full="█",
    eighths=" ▏▎▍▌▋▊▉",
    right_half="▐",
    light="░",
    shades=" ░▒▓█",
    arrow="▶",
    hline="─",
    vline="│",
    tee="┬",
    elbow="└",
    branch="├",
    cross="┼",
    box=("╭", "╮", "╰", "╯"),
    blocked="✗",
    down="▼",
    wrap="↳ ",
)
ASC = Glyphs(
    full="#",
    eighths="        ",
    right_half="#",
    light="-",
    shades=" .:*#",
    arrow=">",
    hline="-",
    vline="|",
    tee="+",
    elbow="`",
    branch="|",
    cross="+",
    box=("+", "+", "+", "+"),
    blocked="x",
    down="v",
    wrap="> ",
)

SEVERITY_STYLE: Mapping[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "none": "dim",
    "unknown": "dim",
}
SSVC_STYLE: Mapping[str, str] = {
    "act": "bold red",
    "attend": "red",
    "track*": "yellow",
    "track": "cyan",
}
_SEV_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
_QUADRANT_POINTS = 12
_MAX_SINGLE_WHAT_IF = 8


def caps(console: Console, options: ConsoleOptions) -> tuple[Glyphs, bool]:
    """``(glyph set, colour available)`` for this console."""
    color = console.color_system is not None and not console.no_color
    return (ASC if options.ascii_only else UNI), color


def bar_cells(a: float, b: float, width: int, g: Glyphs, fill: str | None = None) -> str:
    """A floating bar covering ``[a, b)`` cell units (1/8 resolution on the right edge)."""
    out: list[str] = []
    for c in range(width):
        lo, hi = max(a, float(c)), min(b, float(c + 1))
        cov = max(0.0, hi - lo)
        if cov >= 0.999:
            out.append(fill or g.full)
        elif cov <= 0.06:
            out.append(" ")
        elif fill is not None:  # shaded fill: no partial blocks, round to the cell
            out.append(fill if cov >= 0.5 else " ")
        elif lo <= c + 1e-9:  # starts at the cell's left edge -> partial eighths
            out.append(
                g.eighths[max(1, min(7, round(cov * 8)))]
                if g is UNI
                else (g.full if cov >= 0.5 else " ")
            )
        else:  # starts inside the cell -> right-aligned half block
            out.append(g.right_half if cov >= 0.25 else " ")
    return "".join(out)


def _fit(label: str, width: int) -> str:
    s = safe(label, max(4, width))
    return s.ljust(width) if len(s) <= width else s[: width - 1] + "…"


# --------------------------------------------------------------------------- bars
class HBars:
    """Horizontal bar chart: ``(label, value, style)`` rows."""

    def __init__(
        self,
        rows: Sequence[tuple[str, float, str]],
        *,
        title: str | None = None,
        fmt: str = "{:g}",
        label_width: int = 18,
    ) -> None:
        self.rows = list(rows)
        self.title = title
        self.fmt = fmt
        self.lw = label_width
        self.max = max((r[1] for r in self.rows), default=1.0) or 1.0

    def __rich_measure__(self, console: Console, options: ConsoleOptions) -> Measurement:
        return Measurement(min(self.lw + 12, options.max_width), options.max_width)

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        g, color = caps(console, options)
        if self.title:
            yield safe_text(self.title, "bold")
        if not self.rows:
            yield Text("none", style="dim")
            return
        lw = min(self.lw, max(6, options.max_width // 3))
        vw = max(len(self.fmt.format(r[1])) for r in self.rows)
        bw = max(4, options.max_width - lw - vw - 3)
        for label, value, style in self.rows:
            line = Text(no_wrap=True)
            line.append(safe(label, lw).rjust(lw))
            line.append(" ")
            cells = bar_cells(0.0, value / self.max * bw, bw, g).rstrip()
            line.append(cells, style=style if color else "")
            line.append(" " + self.fmt.format(value), style="bold")
            yield line


class StackedBar:
    """One-line proportional distribution plus legend (shade-coded for ``NO_COLOR``)."""

    def __init__(self, segments: Sequence[tuple[str, int, str]], title: str | None = None) -> None:
        self.segments = [s for s in segments if s[1] >= 0]
        self.title = title

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        g, color = caps(console, options)
        if self.title:
            yield safe_text(self.title, "bold")
        total = sum(s[1] for s in self.segments)
        if not total:
            yield Text("none", style="dim")
            return
        w = max(10, min(options.max_width, 100))
        shades = [g.full] * 4 if color else [g.full, g.shades[3], g.shades[2], g.shades[1]]
        raw = [s[1] / total * w for s in self.segments]
        cells = [math.floor(x) for x in raw]
        order = sorted(range(len(raw)), key=lambda i: (cells[i] - raw[i], i))
        for i in order[: w - sum(cells)]:  # largest remainder: cells sum to w exactly
            cells[i] += 1
        line = Text(no_wrap=True)
        legend = Text()
        for (label, n, style), k, shade in zip(self.segments, cells, shades * 8, strict=False):
            line.append(shade * k, style=style if color else "")
            legend.append(shade * 2 + " ", style=style if color else "")
            legend.append(safe(f"{label} {n} ({n / total:.0%})", 40))
            legend.append("   ")
        yield line
        yield legend


# --------------------------------------------------------------------------- waterfall
class Waterfall:
    """An :class:`Explanation` as a floating-bar waterfall on a 0..100 axis."""

    def __init__(self, explanation: Explanation, *, title: str | None = None) -> None:
        self.e = explanation
        self.title = title

    def __rich_measure__(self, console: Console, options: ConsoleOptions) -> Measurement:
        return Measurement(min(30, options.max_width), options.max_width)

    def _rows(self) -> list[tuple[str, float, float | None]]:
        return [(f.label, f.contribution, f.multiplier) for f in self.e.factors]

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        g, color = caps(console, options)
        e = self.e
        width = options.max_width
        lw = min(26, max(10, width // 3))
        mw = 6 if width >= 50 else 0  # "x0.50" multiplier column
        vw = 7
        bw = width - lw - vw - mw - 2
        if self.title:
            yield safe_text(self.title, "bold")
        if bw < 12:  # too narrow for bars: degrade to a plain two-column table
            for label, contribution, _ in self._rows():
                yield Text.assemble((_fit(label, lw), ""), (f"{contribution:+7.1f}", "bold"))
            yield Text.assemble(("= score".ljust(lw), "bold"), (f"{e.total:7.1f}", "bold"))
            return
        scale = max(100.0, e.baseline, e.total)
        k = bw / scale
        run = e.baseline
        for label, contribution, multiplier in self._rows():
            a, b = sorted((run, run + contribution))
            up = contribution >= 0
            style = ("red" if up else "green") if color else ""
            fill = None if (up or color) else g.light  # NO_COLOR: decreases are shaded
            line = Text(no_wrap=True)
            line.append(_fit(label, lw))
            line.append(f"{contribution:+6.1f} ", style=style or "bold")
            if mw:
                mcol = f"x{multiplier:.2f} " if multiplier is not None else " " * mw
                line.append(mcol[:mw].ljust(mw), style="dim")
            line.append(bar_cells(a * k, b * k, bw, g, fill), style=style)
            yield line
            run += contribution
        total_line = Text(no_wrap=True)
        total_line.append("= score".ljust(lw), style="bold")
        total_line.append(f"{e.total:6.1f} " + " " * mw, style="bold")
        total_line.append(
            bar_cells(0.0, max(0.0, e.total) * k, bw, g), style="bold magenta" if color else "bold"
        )
        yield total_line
        axis = [g.hline] * bw
        labels = [" "] * (bw + 4)
        for v in (0, 25, 50, 75, 100):
            x = min(bw - 1, round(v * k))
            axis[x] = g.tee
            for i, ch in enumerate(str(v)):
                if x + i < len(labels):
                    labels[x + i] = ch
        pad = " " * (lw + vw + mw)
        yield Text(pad + "".join(axis), style="dim")
        yield Text(pad + "".join(labels).rstrip(), style="dim")


# --------------------------------------------------------------------------- quadrant
@dataclass(frozen=True, slots=True)
class QuadrantPoint:
    """One scatter point: ``x`` = EPSS (0..1), ``y`` = impact in context (0..1)."""

    id: str
    x: float
    y: float
    severity: str


class Quadrant:
    """EPSS × impact scatter with ACT NOW / WATCH / BACKLOG quadrant labels."""

    def __init__(
        self,
        points: Sequence[QuadrantPoint],
        *,
        x_split: float = 0.1,
        y_split: float = 0.5,
        height: int = 12,
    ) -> None:
        self.points = list(points)
        self.xs = x_split
        self.ys = y_split
        self.h = height

    @staticmethod
    def _fx(x: float) -> float:
        return math.sqrt(max(0.0, min(1.0, x)))  # sqrt scale spreads small EPSS values

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        g, color = caps(console, options)
        if not self.points:
            yield Text("no threats to plot", style="dim")
            return
        width = min(options.max_width, 100)
        gw = max(20, width - 8)
        height = self.h if width >= 60 else max(6, self.h // 2)
        grid = [[" "] * gw for _ in range(height)]
        styles: dict[tuple[int, int], str] = {}
        sx = min(gw - 1, round(self._fx(self.xs) * (gw - 1)))
        sy = height - 1 - round(self.ys * (height - 1))
        for r in range(height):
            grid[r][sx] = g.vline
        for c in range(gw):
            grid[sy][c] = g.cross if c == sx else g.hline
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        legend: list[tuple[str, QuadrantPoint]] = []
        ordered = sorted(self.points, key=lambda p: (-(p.x * p.y), p.id))
        for i, p in enumerate(ordered):
            c = min(gw - 1, round(self._fx(p.x) * (gw - 1)))
            r = height - 1 - round(min(1.0, max(0.0, p.y)) * (height - 1))
            if r == sy:  # never sit on the split line: nudge to the true side
                r = max(0, sy - 1) if p.y >= self.ys else min(height - 1, sy + 1)
            if c == sx:
                c = min(gw - 1, sx + 1) if p.x >= self.xs else max(0, sx - 1)
            mark = letters[i] if i < len(letters) else "+"
            occupied = grid[r][c] not in (" ", g.vline, g.hline, g.cross)
            grid[r][c] = "+" if occupied else mark
            styles[(r, c)] = SEVERITY_STYLE.get(p.severity, "")
            legend.append((mark, p))
        for txt, r, c in (
            ("WATCH", 0, 1),
            ("ACT NOW", 0, max(1, gw - 8)),
            ("BACKLOG", height - 1, 1),
            ("LIKELY/LOW", height - 1, max(1, gw - 11)),
        ):
            if c + len(txt) <= gw and all(grid[r][c + i] == " " for i in range(len(txt))):
                for i, ch in enumerate(txt):
                    grid[r][c + i] = ch
                    styles[(r, c + i)] = "dim"
        yield safe_text("impact in context ^", "bold")
        for r in range(height):
            margin = "1.0 " if r == 0 else ("0.0 " if r == height - 1 else "    ")
            line = Text(margin + g.vline, no_wrap=True, style="dim")
            for c in range(gw):
                default = "dim" if grid[r][c] in (g.vline, g.hline, g.cross) else ""
                st = styles.get((r, c), default)
                line.append(grid[r][c], style=st if (color or st == "dim") else "")
            yield line
        yield Text("    " + g.elbow + g.hline * gw, style="dim")
        ticks = [" "] * (gw + 6)
        for v in (0.0, 0.01, 0.1, 0.5, 1.0):
            x = round(self._fx(v) * (gw - 1))
            for i, ch in enumerate(f"{v:g}"):
                if 5 + x + i < len(ticks):
                    ticks[5 + x + i] = ch
        yield Text("".join(ticks).rstrip(), style="dim")
        yield Text(
            f"     EPSS (exploit probability) {g.arrow}  "
            f"(sqrt scale; split at EPSS {self.xs:g}, impact {self.ys:g})",
            style="dim",
        )
        table = Table.grid(padding=(0, 1))
        cols = min(3, max(1, width // 34))
        for _ in range(cols):
            table.add_column()
        cells = [
            Text.assemble(
                (mark, "bold " + (SEVERITY_STYLE.get(p.severity, "") if color else "")),
                " ",
                safe_text(p.id, max_len=24),
                f" {p.x:.2f}/{p.y:.2f}",
            )
            for mark, p in legend
        ]
        for i in range(0, len(cells), cols):
            table.add_row(*cells[i : i + cols])
        yield table


# --------------------------------------------------------------------------- chain diagram
@dataclass(frozen=True, slots=True)
class ChainEdge:
    """One rendered chain step between two privilege states."""

    technique: str
    label: str
    detail: str
    blocked_by: str | None = None


class ChainDiagram:
    """Boxes and labelled arrows left-to-right, wrapping; vertical below 50 columns."""

    def __init__(
        self, states: Sequence[str], edges: Sequence[ChainEdge], title: str | None = None
    ) -> None:
        if len(states) != len(edges) + 1:
            raise ValueError("a chain diagram needs exactly one more state than edges")
        self.states = list(states)
        self.edges = list(edges)
        self.title = title

    def _box(self, s: str, g: Glyphs, maxw: int) -> list[str]:
        s = safe(s, max(4, maxw - 4))
        w = len(s) + 2
        tl, tr, bl, br = g.box
        return [tl + g.hline * w + tr, g.vline + " " + s + " " + g.vline, bl + g.hline * w + br]

    def _arrow(self, e: ChainEdge, g: Glyphs, maxw: int) -> list[str]:
        mid = safe(f"{e.technique} {e.label}".strip(), max(4, maxw - 6))
        raw_det = e.detail if not e.blocked_by else f"{g.blocked} {e.blocked_by}"
        det = safe(raw_det, max(4, maxw - 4))
        w = max(len(mid), len(det)) + 4
        return [
            " " + mid.center(w - 2) + " ",
            g.hline * (w - 1) + g.arrow,
            " " + det.center(w - 2) + " ",
        ]

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        g, color = caps(console, options)
        width = options.max_width
        if self.title:
            yield safe_text(self.title, "bold")
        pieces: list[tuple[list[str], str, bool]] = []
        for i, state in enumerate(self.states):
            bold = i in (0, len(self.states) - 1)
            pieces.append((self._box(state, g, width), "bold" if bold else "", False))
            if i < len(self.edges):
                e = self.edges[i]
                style = (
                    ("dim strike" if e.blocked_by else "red")
                    if color
                    else ("dim" if e.blocked_by else "")
                )
                pieces.append((self._arrow(e, g, width), style, True))
        if width < 50 or max(len(p[0][0]) for p in pieces) > width:  # vertical fallback
            for lines, style, is_arrow in pieces:
                if is_arrow:
                    yield Text("  " + g.vline + " " + lines[0].strip(), style=style)
                    yield Text("  " + g.vline + " " + lines[2].strip(), style="dim")
                    yield Text("  " + g.down, style=style)
                else:
                    for ln in lines:
                        yield Text(ln, style=style)
            return
        rows: list[list[tuple[list[str], str, bool]]] = [[]]
        used = 0
        for piece in pieces:
            w = len(piece[0][0])
            if used + w > width - 2 and rows[-1]:
                rows.append([])
                used = 2
            rows[-1].append(piece)
            used += w
        for k, row in enumerate(rows):
            for idx in range(3):
                t = Text(no_wrap=True)
                if k > 0:
                    t.append(g.wrap if idx == 1 else "  ", style="dim")
                for lines, style, _ in row:
                    use = style if not (idx != 1 and style.startswith("red")) else ""
                    t.append(lines[idx], style=use)
                yield t


# --------------------------------------------------------------------------- fan-out graph
class FanoutGraph:
    """A whole privilege graph as topologically ordered fan-outs (any width)."""

    def __init__(self, edges: Sequence[tuple[str, str, ChainEdge]], order: Sequence[str]) -> None:
        self.edges = list(edges)
        self.order = list(order)

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        g, color = caps(console, options)
        if not self.edges:
            yield Text("no attack-graph edges", style="dim")
            return
        for src in self.order:
            out = [e for e in self.edges if e[0] == src]
            if not out:
                continue
            pad = len(safe(src)) + 1
            dw = max(len(safe(d)) for _, d, _ in out)
            for i, (_, dst, ce) in enumerate(out):
                t = Text(no_wrap=True, overflow="ellipsis")
                if i == 0:
                    t.append(safe(src, 40), style="bold")
                    fork = g.tee if len(out) > 1 else g.hline
                    t.append(" " + g.hline + fork + g.hline + g.arrow + " ")
                else:
                    joint = g.elbow if i == len(out) - 1 else g.branch
                    t.append(" " * pad + " " + joint + g.hline + g.arrow + " ")
                st = (
                    ("dim strike" if ce.blocked_by else "")
                    if color
                    else ("dim" if ce.blocked_by else "")
                )
                t.append(safe(dst).ljust(dw), style="bold")
                t.append("  ")
                t.append(safe(f"{ce.technique} {ce.label}".strip(), 60), style=st)
                if ce.detail:
                    t.append("  " + safe(ce.detail, 20), style="dim")
                if ce.blocked_by:
                    t.append(
                        f"  {g.blocked} {safe(ce.blocked_by, 40)}",
                        style="green" if color else "",
                    )
                yield t


def _topological(nodes: Sequence[str], edges: Sequence[tuple[str, str]]) -> list[str]:
    """Kahn topological order (deterministic; cycles appended sorted at the end)."""
    succ: dict[str, list[str]] = defaultdict(list)
    indeg: dict[str, int] = dict.fromkeys(nodes, 0)
    for a, b in edges:
        succ[a].append(b)
        indeg[b] = indeg.get(b, 0) + 1
        indeg.setdefault(a, 0)
    frontier = sorted(n for n, d in indeg.items() if d == 0)
    order: list[str] = []
    while frontier:
        n = frontier.pop(0)
        order.append(n)
        for m in sorted(succ[n]):
            indeg[m] -= 1
            if indeg[m] == 0:
                frontier.append(m)
        frontier.sort()
    order += sorted(n for n in indeg if n not in order)
    return order


# --------------------------------------------------------------------------- public API
def risk_waterfall(explanation: Explanation) -> RenderableType:
    """The exact additive decomposition of one score as a waterfall chart."""
    return Waterfall(
        explanation,
        title=f"Why {safe(explanation.subject, 60)} scores {explanation.total:.1f}",
    )


def severity_bars(report: Report) -> RenderableType:
    """Vulnerability counts by effective severity as horizontal bars."""
    from startup_sbom.report.native import vuln_severity

    counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for v in report.vulnerabilities:
        counts[vuln_severity(v)] += 1
    rows = [
        (sev.value, float(counts[sev]), SEVERITY_STYLE.get(sev.value, ""))
        for sev in _SEV_ORDER
        if counts[sev]
    ]
    return HBars(rows, title="Vulnerabilities by severity", fmt="{:g}", label_width=9)


def ssvc_bars(report: Report) -> RenderableType:
    """SSVC decision distribution over all threats as a one-line stacked bar."""
    counts: dict[str, int] = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
    for t in report.threats:
        if t.ssvc is not None:
            counts[t.ssvc.decision.value] += 1
    segments = [(name, n, SSVC_STYLE.get(name.lower(), "")) for name, n in counts.items() if n]
    return StackedBar(segments, title=f"SSVC decisions ({len(report.threats)} threats)")


def epss_impact_quadrant(report: Report) -> RenderableType:
    """Threats as EPSS × impact-in-context points (top ``_QUADRANT_POINTS`` by risk)."""
    from startup_sbom.report.native import vuln_severity

    vulns = {(v.id, v.package): v for v in report.vulnerabilities}
    points: list[QuadrantPoint] = []
    ordered = sorted(report.threats, key=lambda t: (-t.risk_score, t.id))
    for t in ordered[:_QUADRANT_POINTS]:
        v = vulns.get((t.vulnerability, t.package))
        x = v.epss if v is not None and v.epss is not None else 0.0
        if t.explanation is not None:
            y = math.prod(
                f.multiplier
                for f in t.explanation.factors
                if f.multiplier is not None
                and f.name in ("reachability", "impact", "privilege_gain")
            )
        else:
            y = t.risk_score / 100.0
        sev = vuln_severity(v).value if v is not None else "unknown"
        points.append(QuadrantPoint(id=t.vulnerability, x=x, y=y, severity=sev))
    return Quadrant(points)


def _chain_edge(
    step_title: str,
    technique: str | None,
    vulnerability: str | None,
    likelihood: float,
    mitigated_by: Sequence[str],
) -> ChainEdge:
    label = vulnerability or step_title
    return ChainEdge(
        technique=technique or "",
        label=label,
        detail=f"p={likelihood:.2f}",
        blocked_by=mitigated_by[0] if mitigated_by else None,
    )


def attack_chain_diagram(chain: AttackChain) -> RenderableType:
    """One attack chain as a boxes-and-arrows diagram."""
    if not chain.steps:
        return safe_text(f"{chain.id}: empty chain", "dim")
    states = [chain.steps[0].from_state, *(s.to_state for s in chain.steps)]
    edges = [
        _chain_edge(
            s.title,
            s.technique.id if s.technique else None,
            s.vulnerability,
            s.likelihood,
            s.mitigated_by,
        )
        for s in chain.steps
    ]
    return ChainDiagram(states, edges, title=f"{safe(chain.id, 40)}  score {chain.score:.1f}")


def privilege_graph(report: Report) -> RenderableType:
    """Every distinct attack-graph edge, grouped by source privilege state."""
    seen: set[str] = set()
    edges: list[tuple[str, str, ChainEdge]] = []
    for chain in sorted(report.attack_chains, key=lambda c: c.id):
        for s in chain.steps:
            key = s.id or f"{s.rule}|{s.from_state}|{s.to_state}|{s.threat or s.service or ''}"
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                (
                    s.from_state,
                    s.to_state,
                    _chain_edge(
                        s.title,
                        s.technique.id if s.technique else None,
                        s.vulnerability,
                        s.likelihood,
                        s.mitigated_by,
                    ),
                )
            )
    edges.sort(key=lambda e: (e[0], e[1], e[2].label))
    nodes = sorted({e[0] for e in edges} | {e[1] for e in edges})
    order = _topological(nodes, [(a, b) for a, b, _ in edges])
    title = safe_text("Privilege graph (all chains)", "bold")
    return Group(title, FanoutGraph(edges, order))


def blast_radius_tree(blast: BlastRadius, report: Report) -> RenderableType:
    """A package's blast radius (code-loading paths to binaries and services)."""
    pkgs = report.package_by_id()
    svcs = report.service_by_id()
    binaries = {b.path for b in report.binaries}
    pkg = pkgs.get(blast.package)
    name = f"{pkg.name} {pkg.version}" if pkg is not None else blast.package
    label = Text.assemble(
        ("pkg ", "dim"),
        safe_text(name, "bold red"),
        ("  vendor ", "dim"),
        safe_text(blast.vendor or "unknown"),
        ("  blast score ", "dim"),
        (f"{blast.score:.0f}", "bold"),
    )
    root = Tree(label, guide_style="dim")

    def kind_of(node: str) -> str:
        if node in svcs or node.split(":", 1)[-1] in svcs:
            return "svc"
        if node in binaries:
            return "bin"
        if ".so" in node:
            return "lib"
        return "pkg" if node in pkgs else "bin"

    children: dict[tuple[str, ...], Tree] = {}

    def attach(prefix: tuple[str, ...], node: str) -> Tree:
        key = (*prefix, node)
        if key in children:
            return children[key]
        parent = children.get(prefix, root)
        kind = kind_of(node)
        style = "bold yellow" if kind == "svc" else ""
        branch = parent.add(Text.assemble((kind + " ", "dim"), safe_text(node, style, max_len=120)))
        children[key] = branch
        return branch

    for path in sorted(blast.example_paths):
        prefix: tuple[str, ...] = ()
        for node in path:
            if prefix == () and (node in (blast.package, name)):
                continue  # the root already shows the package itself
            attach(prefix, node)
            prefix = (*prefix, node)
    if not blast.example_paths:
        for svc_id in blast.services:
            attach((), svc_id)
    if blast.vulnerabilities:
        root.add(
            Text.assemble(
                ("vulnerabilities ", "dim"),
                safe_text(", ".join(sorted(blast.vulnerabilities)), max_len=200),
            )
        )
    return root


def ssvc_trace_tree(trace: SSVCTrace) -> RenderableType:
    """An SSVC decision path with alternatives, rationale, evidence and flips."""
    style = SSVC_STYLE.get(trace.outcome.lower(), "bold")
    root = Tree(
        Text.assemble(
            ("SSVC ", "dim"),
            safe_text(trace.tree),
            ("  ->  ", "dim"),
            (safe(trace.outcome.upper(), 40), style),
            (f"  (table row {trace.row})", "dim"),
        ),
        guide_style="dim",
    )
    for n in trace.path:
        opts = Text()
        for i, alt in enumerate(n.alternatives):
            if i:
                opts.append(" | ", style="dim")
            if alt == n.value:
                opts.append(f"[{safe(alt, 30)}]", style="bold reverse")
            else:
                opts.append(safe(alt, 30), style="dim")
        point = safe(n.decision_point.split(" v")[0], 60)
        node = root.add(Text.assemble((point + ": ", "bold"), opts, (f"   ({n.source})", "dim")))
        node.add(Text.assemble(("why: ", "dim"), safe_text(n.rationale, max_len=160)))
        if n.evidence:
            node.add(
                Text.assemble(
                    ("evidence: ", "dim"), safe_text(", ".join(n.evidence), "cyan", max_len=120)
                )
            )
    if trace.flips:
        flips = root.add(Text("would change if:", style="italic"))
        for flip in trace.flips[:8]:
            flips.add(safe_text(flip, max_len=120))
    return root


def why_tree(threat: Threat, report: Report) -> RenderableType:
    """The provenance proof tree ("why?") behind one threat's risk derivation."""
    prov = Provenance(report.evidence, report.derivations)
    root = Tree(
        Text.assemble(
            ("why? ", "dim"),
            safe_text(threat.id, "bold"),
            " ",
            safe_text(threat.title, max_len=100),
        ),
        guide_style="dim",
    )

    def add(parent: Tree, node: WhyNode) -> None:
        if node.evidence is not None:
            e = node.evidence
            locator = f" {e.locator}" if e.locator else ""
            parent.add(
                Text.assemble(
                    (e.kind.value + " ", "dim"),
                    safe_text(e.statement, max_len=100),
                    "  ",
                    safe_text(e.source + locator, "cyan", max_len=80),
                    (f"  [{e.confidence.value}]", "dim"),
                )
            )
            return
        if node.ref:
            parent.add(Text.assemble(("see above: ", "dim"), safe_text(node.id, "dim")))
            return
        if node.derivation is not None:
            d = node.derivation
            branch = parent.add(
                Text.assemble(
                    ("rule ", "dim"),
                    safe_text(d.rule, "bold"),
                    (f"  confidence {d.confidence.value}", "dim"),
                )
            )
            for child in node.children:
                add(branch, child)
            return
        if node.children:
            for child in node.children:
                add(parent, child)
        else:
            parent.add(safe_text(node.id, "dim"))

    add(root, prov.why(threat.id))
    return root


def fix_plan_table(report: Report) -> RenderableType:
    """Minimal fix plans and single-fix what-ifs as tables."""
    ex = report.explanations
    if ex is None or not (ex.fix_plan or ex.what_if):
        return Text("no fix plan (run the explanation pass)", style="dim")
    actions = {f.id: f.action for f in ex.fixes}
    parts: list[RenderableType] = []
    if ex.fix_plan:
        plans = Table(title="Minimal fix plan", title_justify="left", pad_edge=False, expand=False)
        for col in ("Method", "Fixes", "Chains broken", "System risk"):
            plans.add_column(col, overflow="fold")
        for w in ex.fix_plan:
            plans.add_row(
                safe_text(w.method),
                safe_text("; ".join(actions.get(i, i) for i in w.fixes), max_len=240),
                safe_text(", ".join(w.chains_broken) or "-", max_len=160),
                Text(f"{w.risk_before:.1f} -> {w.risk_after:.1f}", style="bold"),
            )
        parts.append(plans)
    if ex.what_if:
        singles = Table(
            title="Counterfactuals: single fixes",
            title_justify="left",
            pad_edge=False,
            expand=False,
        )
        for col in ("Fix", "Chains broken", "Threats resolved", "System risk"):
            singles.add_column(col, overflow="fold")
        for w in ex.what_if[:_MAX_SINGLE_WHAT_IF]:
            fix = actions.get(w.fixes[0], w.fixes[0]) if w.fixes else "-"
            singles.add_row(
                safe_text(fix, max_len=160),
                safe_text(", ".join(w.chains_broken) or "-", max_len=120),
                str(len(w.threats_resolved)),
                Text(f"{w.risk_before:.1f} -> {w.risk_after:.1f}"),
            )
        parts.append(singles)
    return Group(*parts)


class _ParetoCell:
    """A cumulative-share bar cell that adapts to the console's glyphs."""

    def __init__(self, cumulative: float, width: int = 12) -> None:
        self.cumulative = min(1.0, max(0.0, cumulative))
        self.width = width

    def __rich_measure__(self, console: Console, options: ConsoleOptions) -> Measurement:
        return Measurement(self.width, self.width)

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        g, color = caps(console, options)
        yield Text(
            bar_cells(0.0, self.cumulative * self.width, self.width, g).rstrip() or g.full,
            style="magenta" if color else "",
        )


def risk_drivers(report: Report) -> RenderableType:
    """What drives system risk: exact drivers with Pareto-cumulative bars."""
    ex = report.explanations
    if ex is None or ex.system is None or not ex.system.drivers:
        return Text("no system-risk drivers (run the explanation pass)", style="dim")
    g = ex.system
    table = Table(
        title=f"What drives system risk ({g.system_risk:.1f}/100, noisy-OR)",
        title_justify="left",
        pad_edge=False,
        expand=False,
    )
    table.add_column("kind", overflow="fold")
    table.add_column("driver", overflow="fold")
    table.add_column("pts", justify="right")
    table.add_column("share", justify="right")
    table.add_column("Pareto", overflow="crop")
    shown = [d for d in g.drivers if d.kind in ("package", "vendor")] or list(g.drivers)
    for d in shown:
        table.add_row(
            safe_text(d.kind, "dim"),
            safe_text(d.label, max_len=60),
            f"{d.contribution:.1f}",
            f"{d.share:.0%}",
            _ParetoCell(d.cumulative),
        )
    caption = ", ".join(f"{n} {kind}(s) explain 80%" for kind, n in sorted(g.pareto_80.items()))
    if caption:
        table.caption = caption
    return table
