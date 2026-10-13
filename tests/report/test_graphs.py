"""Attack-graph model: orphan supply-chain nodes and package label disambiguation."""

from __future__ import annotations

import re

from reportdata import LZMA

from startup_sbom.models import BlastRadius, Package, PackageType, Report
from startup_sbom.report import render
from startup_sbom.report.graphs import attack_graph, graph_json

SSH = "systemd:ssh.service"


def _go(name: str, version: str, binary: str) -> Package:
    pid = f"pkg:golang/{name}@{version}?file_path={binary}"
    return Package(
        id=pid,
        purl=f"pkg:golang/{name}@{version}",
        type=PackageType.GOLANG,
        name=name,
        version=version,
        location=binary,
        properties={"binary": binary, "go_version": f"go{version}"},
    )


def _pypi(name: str, version: str, location: str) -> Package:
    return Package(
        id=f"pkg:pypi/{name}@{version}?file_path={location}",
        purl=f"pkg:pypi/{name}@{version}",
        type=PackageType.PYPI,
        name=name,
        version=version,
        location=location,
    )


def _linked(report: Report, *pkgs: Package) -> None:
    """Add ``pkgs`` to ``report``, each with a blast-radius path to ssh.service."""
    report.packages.extend(pkgs)
    report.supply_chain.blast_radius.extend(
        BlastRadius(package=p.id, services=[SSH], example_paths=[[p.id, SSH]], score=10.0)
        for p in pkgs
    )


def _sc_labels(report: Report) -> dict[str, str]:
    return {n.key: n.label for n in attack_graph(report).nodes if n.kind == "package"}


def test_orphan_blast_radius_packages_are_not_rendered(report: Report) -> None:
    orphans = [_pypi(f"orphan{i}", "1.0", f"/opt/o{i}/METADATA") for i in range(3)]
    report.packages.extend(orphans)
    report.supply_chain.blast_radius.extend(BlastRadius(package=p.id) for p in orphans)
    # a single-element path is not an edge either
    report.supply_chain.blast_radius.append(
        BlastRadius(package=orphans[0].id, example_paths=[[orphans[0].id]])
    )
    g = attack_graph(report)
    keys = {n.key for n in g.nodes}
    assert not keys & {p.id for p in orphans}
    assert LZMA in keys  # the linked package is still drawn
    used = {e.source for e in g.edges} | {e.target for e in g.edges}
    attack_kinds = {"entry", "goal", "state"}
    assert all(n.id in used for n in g.nodes if n.kind not in attack_kinds)
    for fmt in ("mermaid", "dot"):
        assert "orphan" not in render(report, fmt)


def test_attack_state_nodes_are_unaffected(report: Report) -> None:
    with_sc = {(n.key, n.kind) for n in attack_graph(report).nodes if n.kind != "package"}
    without = {(n.key, n.kind) for n in attack_graph(report, include_supply_chain=False).nodes}
    assert without <= with_sc
    assert {k for _key, k in without} >= {"entry", "goal"}


def test_unique_names_keep_the_short_label(report: Report) -> None:
    _linked(report, _pypi("requests", "2.31.0", "/usr/lib/python3/dist-packages/x/METADATA"))
    labels = _sc_labels(report)
    assert labels[LZMA] == "liblzma5:amd64"
    assert "requests" in labels.values()


def test_duplicate_names_get_distinct_labels(report: Report) -> None:
    pips = [
        _pypi("pip", "23.0.1", "/usr/lib/python3/dist-packages/pip-23.0.1.dist-info/METADATA"),
        _pypi("pip", "24.0", "/opt/venv/lib/python3.11/site-packages/pip-24.0.dist-info/METADATA"),
        _pypi("idna", "3.6", "/usr/lib/python3/dist-packages/idna-3.6.dist-info/METADATA"),
        _pypi("idna", "3.6", "/opt/venv/lib/python3.11/site-packages/idna-3.6.dist-info/METADATA"),
    ]
    _linked(report, *pips)
    labels = _sc_labels(report)
    got = [labels[p.id] for p in pips]
    assert len(set(got)) == len(got)
    assert got[0] == "pip 23.0.1"
    assert got[1] == "pip 24.0"
    # same name and version: the location tells them apart
    assert got[2].startswith("idna 3.6 in ")
    assert "dist-packages" in got[2]
    assert got[3].startswith("idna 3.6 in ")
    assert "site-packages" in got[3]


def test_go_stdlib_label_includes_binary_name(report: Report) -> None:
    mods = [
        _go("stdlib", "1.18", "/usr/bin/mkcert"),
        _go("stdlib", "1.21.4", "/usr/bin/gobuster"),
        _go("stdlib", "1.21.4", "/usr/local/bin/ffuf"),
    ]
    _linked(report, *mods)
    labels = _sc_labels(report)
    assert labels[mods[0].id] == "stdlib go1.18 (mkcert)"
    assert labels[mods[1].id] == "stdlib go1.21.4 (gobuster)"
    assert labels[mods[2].id] == "stdlib go1.21.4 (ffuf)"


def test_same_binary_basename_falls_back_to_location(report: Report) -> None:
    a = _go("stdlib", "1.22", "/usr/bin/tool")
    b = _go("stdlib", "1.22", "/opt/x/tool")
    _linked(report, a, b)
    labels = _sc_labels(report)
    assert labels[a.id] != labels[b.id]
    assert all(labels[p.id].startswith("stdlib go1.22 (tool) in ") for p in (a, b))


def test_identical_packages_get_ordinals(report: Report) -> None:
    a = _pypi("six", "1.16", "")
    b = _pypi("six", "1.16", "")
    b.id += "#2"
    _linked(report, a, b)
    labels = _sc_labels(report)
    assert sorted((labels[a.id], labels[b.id])) == ["six 1.16 #1", "six 1.16 #2"]


def test_long_names_keep_the_disambiguating_suffix(report: Report) -> None:
    name = "github.com/" + "very-long-organisation/" * 5 + "module"
    mods = [_go(name, "v1.0.0", "/usr/bin/alpha"), _go(name, "v1.0.0", "/usr/bin/beta")]
    _linked(report, *mods)
    labels = _sc_labels(report)
    assert labels[mods[0].id].endswith("v1.0.0 (alpha)")
    assert labels[mods[1].id].endswith("v1.0.0 (beta)")
    assert all(len(labels[m.id]) <= 80 for m in mods)
    text = render(report, "mermaid")
    assert "v1.0.0 #40;alpha#41;" in text
    assert "v1.0.0 #40;beta#41;" in text


def test_disambiguated_labels_are_escaped_and_deterministic(report: Report) -> None:
    hostile = [
        _go("stdlib", "1.20", '/usr/bin/a"];x[["b'),
        _go("stdlib", "1.20", "/usr/bin/c\nd"),
    ]
    _linked(report, *hostile)
    mmd = render(report, "mermaid")
    assert mmd == render(report, "mermaid")
    node_lines = [ln for ln in mmd.splitlines() if ":::package" in ln]
    for ln in node_lines:
        assert re.fullmatch(r'  n\d+\[\["[^"\[\]\n]*"\]\]:::package', ln), ln
    dot = render(report, "dot")
    assert dot == render(report, "dot")
    assert '\\"];x[[\\"b' in dot
    data = graph_json(report)
    assert data == graph_json(report)
    nodes = data["nodes"]
    assert isinstance(nodes, list)
    pkg_labels = [n["label"] for n in nodes if n["kind"] == "package"]
    assert len(set(pkg_labels)) == len(pkg_labels)


def test_empty_graph_says_so() -> None:
    from startup_sbom.report.graphs import EMPTY_GRAPH, Graph, mermaid_graph

    text = mermaid_graph(Graph(nodes=[]))
    assert EMPTY_GRAPH in text
    assert text.startswith("flowchart LR")


def test_empty_dot_graph_says_so() -> None:
    from reportdata import build_report

    from startup_sbom.report import RenderOptions
    from startup_sbom.report.graphs import EMPTY_GRAPH, render_dot

    rep = build_report()
    rep.attack_chains = []
    rep.supply_chain.blast_radius = []
    assert EMPTY_GRAPH in render_dot(rep, RenderOptions())
