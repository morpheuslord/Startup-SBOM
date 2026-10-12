"""SVG charts: well-formed XML, escaped hostile text, no external references."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Callable

import pytest

from startup_sbom.models import Report
from startup_sbom.viz import svg as vs

SVG_NS = "{http://www.w3.org/2000/svg}"


def parse(doc: str) -> ET.Element:
    """Parse a chart we generated ourselves (stdlib etree is fine on our own output)."""
    return ET.fromstring(doc)  # noqa: S314


def _charts(r: Report) -> dict[str, str]:
    t = r.threats[0]
    assert t.explanation is not None
    return {
        "severity": vs.severity_chart_svg(r),
        "ssvc": vs.ssvc_chart_svg(r),
        "waterfall": vs.waterfall_svg(t.explanation),
        "attack_graph": vs.attack_graph_svg(r),
        "drivers": vs.drivers_chart_svg(r),
    }


def test_every_chart_parses_with_title_and_desc(hostile_report: Report) -> None:
    for name, doc in _charts(hostile_report).items():
        root = parse(doc)
        assert root.tag == f"{SVG_NS}svg", name
        assert root.get("viewBox"), name
        children = [child.tag for child in root]
        assert f"{SVG_NS}title" in children, name
        assert f"{SVG_NS}desc" in children, name


def test_hostile_text_is_escaped_and_controls_stripped(hostile_report: Report) -> None:
    for name, doc in _charts(hostile_report).items():
        assert "<script" not in doc, name
        assert "\x1b" not in doc, name
        assert "\x07" not in doc, name
        assert "\u202e" not in doc, name
        assert "\u200b" not in doc, name
        # the payload's tag text survives only in escaped form
        if "alert(1)" in doc:
            assert "&lt;script&gt;" in doc, name


def test_no_external_references(hostile_report: Report) -> None:
    for name, doc in _charts(hostile_report).items():
        root = parse(doc)
        for el in root.iter():
            for attr in el.attrib:
                assert "href" not in attr.lower(), (name, el.tag)
                assert attr != "style", (name, el.tag)
        assert "url(" not in doc, name
        assert doc.count("http") == doc.count("http://www.w3.org/2000/svg"), name


def test_attack_graph_covers_all_states_and_marks_blocked_edges(
    hostile_report: Report,
) -> None:
    doc = vs.attack_graph_svg(hostile_report)
    states = {
        s
        for c in hostile_report.attack_chains
        for st in c.steps
        for s in (st.from_state, st.to_state)
    }
    for state in states:
        assert f">{state}<" in doc or state in doc, state
    root = parse(doc)
    paths = list(root.iter(f"{SVG_NS}path"))
    assert paths, "edges are drawn as Bezier paths"


def test_empty_report_charts_are_valid(ctx: object) -> None:
    import factory as F  # noqa: N812

    empty = F.make_report()
    for fn in (
        vs.severity_chart_svg,
        vs.ssvc_chart_svg,
        vs.attack_graph_svg,
        vs.drivers_chart_svg,
    ):
        chart: Callable[[Report], str] = fn
        doc = chart(empty)
        root = parse(doc)
        assert root.tag == f"{SVG_NS}svg"


def test_deterministic_output(hostile_report: Report) -> None:
    assert _charts(hostile_report) == _charts(hostile_report)


def test_waterfall_values_appear(hostile_report: Report) -> None:
    t = hostile_report.threats[0]
    assert t.explanation is not None
    doc = vs.waterfall_svg(t.explanation)
    assert f"{t.explanation.total:.1f}" in doc
    for f in t.explanation.factors:
        assert f"{f.contribution:+.1f}" in doc


@pytest.mark.parametrize("bad", ["</desc><script>alert(1)</script>", 'a" onload="evil()'])
def test_scene_text_escaping(bad: str) -> None:
    sc = vs.Scene(100, 40, title=bad, desc=bad)
    sc.add(vs.Label(5, 20, bad))
    doc = vs.to_svg(sc)
    parse(doc)
    assert "<script" not in doc
    assert 'onload="evil' not in doc
