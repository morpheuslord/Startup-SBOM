"""Combined attack graph and supply-chain blast-radius graph: model, DOT and Mermaid.

Privilege states are nodes and attack steps are labelled edges.  Every node gets
a surrogate id (``n0``, ``n1`` …) and every label is escaped for the target
language, so names taken from the scanned system can never inject syntax.
"""

from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from itertools import pairwise

from startup_sbom.models import AttackChain, Package, PackageType, Report
from startup_sbom.report.native import RenderOptions
from startup_sbom.textsafe import clean

MAX_LABEL = 80
_CTRL = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]+")
_MERMAID_ENTITIES = {
    "#": "#35;",
    '"': "#quot;",
    "<": "#lt;",
    ">": "#gt;",
    "&": "#amp;",
    "`": "#96;",
    "|": "#124;",
    "%": "#37;",
    "{": "#123;",
    "}": "#125;",
    "[": "#91;",
    "]": "#93;",
    "(": "#40;",
    ")": "#41;",
    "\\": "#92;",
    ";": "#59;",
}


@dataclass(frozen=True, slots=True)
class GraphNode:
    """A node: privilege state, package, binary or service."""

    id: str  # surrogate id (n0, n1, ...)
    key: str  # the underlying state / package id / path / service id
    label: str
    kind: str  # entry | goal | state | package | binary | service


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """A directed edge: an attack step (aggregated over chains) or a code-loading link."""

    source: str
    target: str
    label: str
    kind: str  # step | supply
    chains: tuple[str, ...] = ()
    technique: str | None = None
    likelihood: float = 0.0
    mitigated: bool = False
    evidence: tuple[str, ...] = ()


@dataclass(slots=True)
class Graph:
    """Nodes and edges in deterministic order."""

    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)


def one_line(text: str, limit: int = MAX_LABEL) -> str:
    """Collapse control characters/newlines to spaces and shorten to ``limit``."""
    s = " ".join(clean(_CTRL.sub(" ", text)).split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


@dataclass(slots=True)
class _StepAgg:
    chains: set[str] = field(default_factory=set)
    likelihood: float = 0.0
    mitigated: bool = True
    evidence: set[str] = field(default_factory=set)


def _step_label(title: str, technique: str | None) -> str:
    return f"{title} ({technique})" if technique else title


# --------------------------------------------------------------------------- labels
_PART = 32  # longest version / binary name / location hint kept in a label


def _tail(text: str, limit: int = _PART) -> str:
    """``text`` shortened from the left (the end is usually what tells items apart)."""
    s = one_line(text, 10_000)
    return s if len(s) <= limit else "…" + s[-(limit - 1) :]


def _fit(head: str, suffix: str) -> str:
    """``head + suffix`` within :data:`MAX_LABEL`, trimming ``head`` so ``suffix`` survives."""
    head = one_line(head, 10_000)
    room = MAX_LABEL - len(suffix)
    if len(head) > room:
        head = head[: max(room - 1, 1)] + "…"
    return head + suffix


def _pkg_label(p: Package) -> str:
    return f"{p.name}{':' + p.arch if p.arch else ''}"


def _go_binary(p: Package) -> str | None:
    """The binary a Go module was embedded in (``None`` for other ecosystems)."""
    if p.type != PackageType.GOLANG:
        return None
    return p.properties.get("binary") or p.location or None


def _versioned_label(p: Package) -> str:
    """Name plus version (``go``-prefixed for the Go stdlib) and, for Go, the binary."""
    suffix = ""
    if p.version:
        ver = p.version
        if p.type == PackageType.GOLANG and p.name == "stdlib" and ver[:1].isdigit():
            ver = "go" + ver
        suffix = " " + _tail(ver)
    binary = _go_binary(p)
    if binary:
        suffix += f" ({_tail(posixpath.basename(binary.rstrip('/')) or binary)})"
    return _fit(_pkg_label(p), suffix)


def _location_hints(paths: list[str]) -> list[str]:
    """The shortest path tails telling ``paths`` apart, after dropping a shared ending."""
    parts = [[c for c in path.split("/") if c] for path in paths]
    while all(len(x) > 1 for x in parts) and len({x[-1] for x in parts}) == 1:
        parts = [x[:-1] for x in parts]
    longest = max((len(x) for x in parts), default=0)
    depth = longest
    for k in range(1, longest + 1):
        if len({"/".join(x[-k:]) for x in parts}) == len(parts):
            depth = k
            break
    hints = []
    for x in parts:
        tail = "/".join(x[-depth:]) if x else ""
        hints.append(_tail(("/" if depth >= len(x) else "…/") + tail) if tail else "")
    return hints


def _collisions(labels: dict[str, str], keys: Iterable[str]) -> list[list[str]]:
    by_label: dict[str, list[str]] = defaultdict(list)
    for k in keys:
        by_label[labels[k]].append(k)
    return [sorted(v) for _lbl, v in sorted(by_label.items()) if len(v) > 1]


def _disambiguate(labels: dict[str, str], pkgs: dict[str, Package]) -> dict[str, str]:
    """Make the labels of distinct packages distinct.

    Packages sharing a label get their version (and, for Go modules, the binary
    they are embedded in); any still sharing one get the shortest distinguishing
    tail of their location, and a final ``#n`` ordinal if even that is equal.
    """
    out = dict(labels)
    keys = sorted(k for k in labels if k in pkgs)
    for group in _collisions(out, keys):
        for k in group:
            out[k] = _versioned_label(pkgs[k])
    for group in _collisions(out, keys):
        where = [_go_binary(pkgs[k]) or pkgs[k].location or "" for k in group]
        for k, hint in zip(group, _location_hints(where), strict=True):
            if hint:
                out[k] = _fit(out[k], f" in {hint}")
    for group in _collisions(out, keys):
        for i, k in enumerate(group, 1):
            out[k] = _fit(out[k], f" #{i}")
    return out


# --------------------------------------------------------------------------- model
def attack_graph(report: Report, *, include_supply_chain: bool = True) -> Graph:
    """Build the combined attack graph (+ optional blast-radius subgraph)."""
    entries = {c.entry for c in report.attack_chains}
    goals = {c.goal for c in report.attack_chains}
    states: set[str] = set(entries | goals)
    agg: dict[tuple[str, str, str, str], _StepAgg] = {}
    for chain in sorted(report.attack_chains, key=lambda c: c.id):
        for step in chain.steps:
            states.update((step.from_state, step.to_state))
            tech = step.technique.id if step.technique else ""
            key = (step.from_state, step.to_state, step.title, tech)
            slot = agg.setdefault(key, _StepAgg())
            slot.chains.add(chain.id)
            slot.likelihood = max(slot.likelihood, step.likelihood)
            slot.mitigated = slot.mitigated and bool(step.mitigated_by)
            slot.evidence.update(step.evidence)

    keyed: list[tuple[str, str, str, str]] = []  # (group, key, label, kind)
    for s in sorted(states):
        kind = "entry" if s in entries else "goal" if s in goals else "state"
        keyed.append(("a", s, s, kind))

    sc_edges: list[tuple[str, str, str]] = []
    if include_supply_chain:
        pkgs = report.package_by_id()
        svcs = report.service_by_id()
        sc_nodes: dict[str, tuple[str, str]] = {}

        def sc_node(item: str) -> str:
            if item in pkgs:
                sc_nodes[item] = (_pkg_label(pkgs[item]), "package")
            elif item in svcs:
                sc_nodes[item] = (svcs[item].name, "service")
            elif item.startswith("/"):
                sc_nodes[item] = (item, "binary")
            else:
                sc_nodes.setdefault(item, (item, "package"))
            return item

        for br in sorted(report.supply_chain.blast_radius, key=lambda b: b.package):
            sc_node(br.package)  # emitted only if it ends up on an edge (below)
            paths = [p for p in br.example_paths if len(p) >= 2]
            if paths:
                for path in paths:
                    sc_edges.extend((sc_node(a), sc_node(b), "loads") for a, b in pairwise(path))
            else:
                sc_edges.extend((br.package, sc_node(svc), "used by") for svc in br.services)
        # A blast-radius entry with no example path and no service has no edge;
        # drawing it would only add a free-floating node, so keep linked nodes only.
        linked = {a for a, _b, _l in sc_edges} | {b for _a, b, _l in sc_edges}
        sc_nodes = {k: v for k, v in sc_nodes.items() if k in linked}
        labels = _disambiguate({k: lbl for k, (lbl, _kind) in sc_nodes.items()}, pkgs)
        keyed += [("s", k, labels[k], kind) for k, (_lbl, kind) in sorted(sc_nodes.items())]

    ids = {(g, k): f"n{i}" for i, (g, k, _l, _k) in enumerate(keyed)}
    graph = Graph(nodes=[GraphNode(ids[(g, k)], k, lbl, kind) for g, k, lbl, kind in keyed])
    for (src, dst, title, tech), slot in sorted(agg.items()):
        graph.edges.append(
            GraphEdge(
                source=ids[("a", src)],
                target=ids[("a", dst)],
                label=_step_label(title, tech or None),
                kind="step",
                chains=tuple(sorted(slot.chains)),
                technique=tech or None,
                likelihood=slot.likelihood,
                mitigated=slot.mitigated,
                evidence=tuple(sorted(slot.evidence)),
            )
        )
    for a, b, label in sorted(set(sc_edges)):
        graph.edges.append(GraphEdge(ids[("s", a)], ids[("s", b)], label, "supply"))
    return graph


# --------------------------------------------------------------------------- DOT
def dot_quote(text: str) -> str:
    """A DOT double-quoted string with backslashes, quotes and newlines escaped."""
    s = one_line(text, 200).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


_DOT_STYLE = {
    "entry": 'shape=ellipse, fillcolor="#fde2e2", color="#b91c1c"',
    "goal": 'shape=doubleoctagon, fillcolor="#fecaca", color="#7f1d1d"',
    "state": 'shape=box, fillcolor="#fef3c7", color="#92400e"',
    "package": 'shape=component, fillcolor="#e0e7ff", color="#3730a3"',
    "binary": 'shape=note, fillcolor="#f1f5f9", color="#334155"',
    "service": 'shape=box3d, fillcolor="#dcfce7", color="#166534"',
}


def render_dot(report: Report, options: RenderOptions) -> str:
    """Render the combined graph as Graphviz DOT text (``dot -Tsvg`` to draw it)."""
    del options
    g = attack_graph(report)
    attack_ids = {n.id for n in g.nodes if n.kind in ("entry", "goal", "state")}
    lines = [
        "digraph startup_sbom {",
        '  graph [rankdir=LR, fontname="Helvetica", fontsize=11, '
        f"label={dot_quote('startup-sbom attack graph: ' + report.metadata.target.reference)}];",
        '  node [style="rounded,filled", fontname="Helvetica", fontsize=10];',
        '  edge [fontname="Helvetica", fontsize=9];',
        "  subgraph cluster_attack {",
        '    label="Attack graph (privilege states)";',
    ]
    lines += [
        f"    {n.id} [label={dot_quote(n.label)}, {_DOT_STYLE[n.kind]}];"
        for n in g.nodes
        if n.id in attack_ids
    ]
    if not g.nodes:
        lines.append(f"    none [label={dot_quote(EMPTY_GRAPH)}, {_DOT_STYLE['state']}];")
    lines.append("  }")
    sc = [n for n in g.nodes if n.id not in attack_ids]
    if sc:
        lines += ["  subgraph cluster_supply {", '    label="Supply-chain blast radius";']
        lines += [f"    {n.id} [label={dot_quote(n.label)}, {_DOT_STYLE[n.kind]}];" for n in sc]
        lines.append("  }")
    for e in g.edges:
        attrs = [f"label={dot_quote(e.label)}"]
        if e.kind == "step":
            attrs.append(f"tooltip={dot_quote('chains: ' + ', '.join(e.chains))}")
            attrs.append('color="#b91c1c"')
            if e.mitigated:
                attrs.append("style=dashed")
        else:
            attrs.append('color="#3730a3"')
        lines.append(f"  {e.source} -> {e.target} [{', '.join(attrs)}];")
    lines.append("}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- Mermaid
def mermaid_text(text: str, limit: int = MAX_LABEL) -> str:
    """Escape ``text`` for use inside a double-quoted Mermaid label."""
    return "".join(_MERMAID_ENTITIES.get(ch, ch) for ch in one_line(text, limit))


_MERMAID_SHAPE = {
    "entry": ('(["', '"])'),
    "goal": ('{{"', '"}}'),
    "state": ('["', '"]'),
    "package": ('[["', '"]]'),
    "binary": ('[/"', '"/]'),
    "service": ('[("', '")]'),
}
_MERMAID_CLASSES = [
    "  classDef entry fill:#fde2e2,stroke:#b91c1c,color:#111",
    "  classDef goal fill:#fecaca,stroke:#7f1d1d,color:#111",
    "  classDef state fill:#fef3c7,stroke:#92400e,color:#111",
    "  classDef package fill:#e0e7ff,stroke:#3730a3,color:#111",
    "  classDef binary fill:#f1f5f9,stroke:#334155,color:#111",
    "  classDef service fill:#dcfce7,stroke:#166534,color:#111",
]


def _mermaid_node(nid: str, label: str, kind: str) -> str:
    open_, close = _MERMAID_SHAPE[kind]
    return f"  {nid}{open_}{mermaid_text(label)}{close}:::{kind}"


def _mermaid_edge(src: str, dst: str, label: str, dashed: bool) -> str:
    arrow = "-.->" if dashed else "-->"
    return f'  {src} {arrow}|"{mermaid_text(label, 60)}"| {dst}'


#: Shown when no attack chain and no supply-chain path exists.
EMPTY_GRAPH = "no attack chain or supply-chain path was found"


def mermaid_graph(graph: Graph) -> str:
    """Mermaid ``flowchart LR`` source for a :class:`Graph`."""
    lines = ["flowchart LR", *_MERMAID_CLASSES]
    if not graph.nodes:
        # An empty flowchart renders as a blank box; say why there is nothing to draw.
        lines.append(_mermaid_node("none", EMPTY_GRAPH, "state"))
    lines += [_mermaid_node(n.id, n.label, n.kind) for n in graph.nodes]
    lines += [_mermaid_edge(e.source, e.target, e.label, e.mitigated) for e in graph.edges]
    return "\n".join(lines) + "\n"


def mermaid_chain(chain: AttackChain) -> str:
    """Mermaid flowchart of a single attack chain (states in step order)."""
    order: list[str] = [chain.entry]
    for step in chain.steps:
        for s in (step.from_state, step.to_state):
            if s not in order:
                order.append(s)
    if chain.goal not in order:
        order.append(chain.goal)
    ids = {s: f"n{i}" for i, s in enumerate(order)}
    lines = ["flowchart LR", *_MERMAID_CLASSES]
    for s in order:
        kind = "entry" if s == chain.entry else "goal" if s == chain.goal else "state"
        lines.append(_mermaid_node(ids[s], s, kind))
    for step in chain.steps:
        tech = step.technique.id if step.technique else None
        lines.append(
            _mermaid_edge(
                ids[step.from_state],
                ids[step.to_state],
                _step_label(step.title, tech),
                bool(step.mitigated_by),
            )
        )
    return "\n".join(lines) + "\n"


def render_mermaid(report: Report, options: RenderOptions) -> str:
    """Render the combined graph as Mermaid flowchart text."""
    del options
    return mermaid_graph(attack_graph(report))


def graph_json(report: Report) -> dict[str, object]:
    """JSON-ready graph data (raw labels; consumers must escape on display)."""
    g = attack_graph(report)
    return {
        "nodes": [{"id": n.id, "key": n.key, "label": n.label, "kind": n.kind} for n in g.nodes],
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "label": e.label,
                "kind": e.kind,
                "chains": list(e.chains),
                "technique": e.technique,
                "likelihood": e.likelihood,
                "mitigated": e.mitigated,
                "evidence": list(e.evidence),
            }
            for e in g.edges
        ],
    }
