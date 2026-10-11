"""Terminal renderables: never raise, never leak ESC, degrade at every width."""

from __future__ import annotations

import io

import pytest
from rich.console import Console, RenderableType

from startup_sbom.models import Report
from startup_sbom.viz import terminal as vt

WIDTHS = (40, 80, 120)
#: Sequences that must never appear in any output, even with colour enabled.
FORBIDDEN = ("\x1b]", "\x07", "\x1b[2J", "\u202e", "\u200b")


class _AsciiIO(io.StringIO):
    encoding = "ascii"  # makes rich's ConsoleOptions.ascii_only true


def _all_renderables(r: Report) -> list[RenderableType]:
    t0 = r.threats[0]
    assert t0.explanation is not None
    assert t0.ssvc is not None
    assert t0.ssvc.trace is not None
    assert t0.ssvc.bod_26_04 is not None
    return [
        vt.risk_waterfall(t0.explanation),
        vt.severity_bars(r),
        vt.ssvc_bars(r),
        vt.epss_impact_quadrant(r),
        vt.attack_chain_diagram(r.attack_chains[0]),
        vt.privilege_graph(r),
        vt.blast_radius_tree(r.supply_chain.blast_radius[0], r),
        vt.ssvc_trace_tree(t0.ssvc.trace),
        vt.ssvc_trace_tree(t0.ssvc.bod_26_04),
        vt.why_tree(t0, r),
        vt.fix_plan_table(r),
        vt.risk_drivers(r),
    ]


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("no_color", [True, False])
@pytest.mark.parametrize("ascii_only", [True, False])
def test_renderables_never_raise_and_never_emit_escapes(
    hostile_report: Report, width: int, no_color: bool, ascii_only: bool
) -> None:
    file = _AsciiIO() if ascii_only else io.StringIO()
    console = Console(
        file=file,
        width=width,
        no_color=no_color,
        force_terminal=not no_color,
        legacy_windows=False,
    )
    assert console.options.ascii_only == ascii_only
    for renderable in _all_renderables(hostile_report):
        console.print(renderable)
    out = file.getvalue()
    assert out.strip()
    for seq in FORBIDDEN:
        assert seq not in out, f"hostile sequence {seq!r} leaked at width {width}"
    if no_color:
        assert "\x1b" not in out, "escape bytes with colour disabled"


def test_meaning_survives_no_color(hostile_report: Report) -> None:
    """Signs and glyphs carry the waterfall's meaning when colour is off."""
    t = hostile_report.threats[0]
    assert t.explanation is not None
    file = io.StringIO()
    Console(file=file, width=100, no_color=True, legacy_windows=False).print(
        vt.risk_waterfall(t.explanation)
    )
    out = file.getvalue()
    assert "+" in out
    assert "-" in out
    assert "= score" in out
    assert "x0." in out or "x1." in out  # multiplier column at width 100


def test_waterfall_degrades_to_table_when_very_narrow(hostile_report: Report) -> None:
    t = hostile_report.threats[0]
    assert t.explanation is not None
    file = io.StringIO()
    Console(file=file, width=30, no_color=True, legacy_windows=False).print(
        vt.risk_waterfall(t.explanation)
    )
    lines = [ln for ln in file.getvalue().splitlines() if ln.strip()]
    assert lines
    assert all(len(ln) <= 30 for ln in lines)


def test_chain_diagram_goes_vertical_below_fifty_columns(hostile_report: Report) -> None:
    file = io.StringIO()
    Console(file=file, width=44, no_color=True, legacy_windows=False).print(
        vt.attack_chain_diagram(hostile_report.attack_chains[0])
    )
    assert "▼" in file.getvalue()  # the vertical-arrow fallback


def test_empty_report_renders_placeholders(ctx: object) -> None:
    import factory as F  # noqa: N812

    empty = F.make_report()
    file = io.StringIO()
    console = Console(file=file, width=80, no_color=True, legacy_windows=False)
    console.print(vt.severity_bars(empty))
    console.print(vt.ssvc_bars(empty))
    console.print(vt.epss_impact_quadrant(empty))
    console.print(vt.privilege_graph(empty))
    console.print(vt.fix_plan_table(empty))
    console.print(vt.risk_drivers(empty))
    out = file.getvalue()
    assert "none" in out or "no " in out
    assert "\x1b" not in out


def test_renderables_compose_inside_textual_static(hostile_report: Report) -> None:
    textual = pytest.importorskip("textual")
    del textual
    import asyncio

    from textual.app import App, ComposeResult
    from textual.widgets import Static

    renderables = _all_renderables(hostile_report)

    class XApp(App[None]):
        def compose(self) -> ComposeResult:
            for renderable in renderables:
                yield Static(renderable)

    async def scenario() -> None:
        app = XApp()
        async with app.run_test(size=(100, 50)):
            pass

    asyncio.run(asyncio.wait_for(scenario(), timeout=60))


def test_deterministic_output(hostile_report: Report) -> None:
    def render() -> str:
        file = io.StringIO()
        console = Console(file=file, width=100, no_color=True, legacy_windows=False)
        for renderable in _all_renderables(hostile_report):
            console.print(renderable)
        return file.getvalue()

    assert render() == render()
