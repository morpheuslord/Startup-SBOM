"""Results browser: tabs, filters, hostile text, export, AI panel, intel, open report."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from rich.text import Text
from tuihelpers import results_ready, run_ui, wait_until

from startup_sbom.models import (
    AIAssessment,
    GroundingResult,
    IntelBundle,
    IntelRecord,
    Report,
)
from startup_sbom.tui import integrations
from startup_sbom.tui.app import StartupSbomApp
from startup_sbom.tui.screens.ai_panel import AIPanelScreen
from startup_sbom.tui.screens.article import ArticleScreen, _load
from startup_sbom.tui.screens.export import ExportScreen
from startup_sbom.tui.screens.home import HomeScreen
from startup_sbom.tui.screens.results import ResultsScreen

MakeApp = Callable[..., StartupSbomApp]
ESC = "\x1b"


async def open_results(app: StartupSbomApp, pilot: object, report: Report) -> ResultsScreen:
    app.show_report(report)
    await pilot.pause(0.2)  # type: ignore[attr-defined]
    screen = app.screen
    assert isinstance(screen, ResultsScreen)
    return screen


# --------------------------------------------------------------------- tabs
def test_all_tabs_build_without_optional_modules(make_app: MakeApp, report: Report) -> None:
    """Every tab renders with viz/explain/intel/ai unavailable (graceful degradation)."""
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(160, 50)) as pilot:
            screen = await open_results(app, pilot, report)
            from textual.widgets import DataTable, TabbedContent, Tree

            from startup_sbom.tui.screens.results import TABS

            tabs = screen.query_one("#tabs", TabbedContent)
            for key, tab in zip("12345678", [t for t, _ in TABS], strict=True):
                await pilot.press(key)
                await pilot.pause(0.05)
                assert tabs.active == tab
            assert screen.query_one("#chain-tree", Tree).root.children
            assert screen.query_one("#vendor-table", DataTable).row_count == 2
            assert screen.query_one("#service-table", DataTable).row_count == 3
            assert screen.query_one("#pkg-table", DataTable).row_count == len(report.packages)
            assert screen.query_one("#vuln-table", DataTable).row_count == len(
                report.vulnerabilities
            )

    run_ui(main())


def test_summary_kpis_and_eol_badge(make_app: MakeApp, report: Report) -> None:
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(160, 50)) as pilot:
            screen = await open_results(app, pilot, report)
            from textual.widgets import Static

            badge = screen.query_one("#os-badge", Static)
            text = str(badge.content)  # the rich Text set via update()
            assert "Debian GNU/Linux 12" in text
            assert "EOL" in text  # the fixture OS is end-of-life
            act = screen.query_one("#kpi-act", Static)
            assert act.has_class("kpi-bad")
            coverage = str(screen.query_one("#coverage", Static).content)
            assert "Socket activation" in coverage  # limitations are never hidden

    run_ui(main())


# --------------------------------------------------------------------- threats
def test_threat_filters_sort_and_search(make_app: MakeApp, report: Report) -> None:
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(160, 50)) as pilot:
            screen = await open_results(app, pilot, report)
            from textual.widgets import Checkbox, DataTable, Input, Select

            table = screen.query_one("#threat-table", DataTable)
            assert table.row_count == 4
            assert screen.threat_rows[0].threat.id == "TH-0001"  # highest risk first

            def ids() -> list[str]:
                return [r.threat.id for r in screen.threat_rows]

            # Filters apply on message round-trips and the search is debounced,
            # so poll instead of sleeping a fixed time (slow Windows runners).
            screen.query_one("#f-ssvc", Select).value = "Act"
            await wait_until(pilot, lambda: table.row_count == 1)
            assert screen.current_threat is not None
            assert screen.current_threat.threat.id == "TH-0001"
            screen.query_one("#f-ssvc", Select).value = "any"
            await wait_until(pilot, lambda: table.row_count == 4)
            screen.query_one("#f-kev", Checkbox).value = True
            await wait_until(pilot, lambda: ids() == ["TH-0001"])
            screen.query_one("#f-kev", Checkbox).value = False
            await wait_until(pilot, lambda: table.row_count == 4)
            search = screen.query_one("#threat-search", Input)
            search.value = "liblzma"
            await wait_until(pilot, lambda: ids() == ["TH-0002"])
            search.value = ""
            await wait_until(pilot, lambda: table.row_count == 4)
            screen.action_cycle_sort()  # risk -> epss
            await pilot.pause()
            assert screen.sort_key == "epss"
            assert screen.threat_rows[0].threat.id == "TH-0002"  # EPSS 0.86 tops
            screen.focus_threat("TH-0004")
            await pilot.pause()
            assert screen.current_threat is not None
            assert screen.current_threat.threat.id == "TH-0004"

    run_ui(main())


def test_detail_pane_survives_hostile_strings(make_app: MakeApp, hostile_report: Report) -> None:
    """Markup injection and terminal escapes never crash, style or escape the TUI."""
    hostile_report.threats[0].title += ESC + "]0;pwned" + "\x07" + "[/bad][link=https://x]x"
    hostile_report.packages[0].name += ESC + "[2J"
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(160, 50)) as pilot:
            screen = await open_results(app, pilot, hostile_report)
            from textual.widgets import DataTable, Markdown

            table = screen.query_one("#threat-table", DataTable)
            assert table.row_count == len(hostile_report.threats)
            for i in range(table.row_count):
                for cell in table.get_row_at(i):
                    assert isinstance(cell, Text)  # never parsed as markup
                    assert ESC not in cell.plain
                    assert not cell.spans
            md = screen.query_one("#threat-md", Markdown)
            assert ESC not in md.source
            assert "\x07" not in md.source
            # every tab still renders
            for key in "12345678":
                await pilot.press(key)
                await pilot.pause(0.05)
            # the packages tab shows the hostile name, sanitised
            pkg_table = screen.query_one("#pkg-table", DataTable)
            cells = [c for i in range(pkg_table.row_count) for c in pkg_table.get_row_at(i)]
            assert all(ESC not in c.plain for c in cells if isinstance(c, Text))

    run_ui(main())


# --------------------------------------------------------------------- export
def test_export_writes_json_and_markdown(make_app: MakeApp, report: Report, tmp_path: Path) -> None:
    app = make_app()
    out = tmp_path / "exported"

    async def main() -> None:
        async with app.run_test(size=(160, 50), notifications=True) as pilot:
            screen = await open_results(app, pilot, report)
            screen.action_export()
            await pilot.pause()
            dialog = app.screen
            assert isinstance(dialog, ExportScreen)
            from textual.widgets import Input, SelectionList

            assert set(dialog.query_one("#export-formats", SelectionList).selected) == {
                "json",
                "markdown",
            }
            dialog.query_one("#export-dir", Input).value = str(out)
            dialog.write()
            await wait_until(pilot, lambda: not isinstance(app.screen, ExportScreen))
            await wait_until(pilot, lambda: bool(app.recent.load()))

    run_ui(main())
    assert (out / "report.json").is_file()
    assert (out / "report.md").is_file()
    entries = app.recent.load()
    assert entries
    assert entries[0].path == str((out / "report.json").resolve())


def test_export_pdf_when_available(report: Report) -> None:
    from startup_sbom.report import FORMATS, render_bytes

    if "pdf" not in FORMATS:
        pytest.skip("pdf format not registered")
    try:
        payload = render_bytes(report, "pdf")
    except Exception as exc:  # noqa: BLE001 - optional extra missing: skip, no crash
        pytest.skip(f"pdf renderer unavailable: {exc}")
    assert payload[:4] == b"%PDF"


# --------------------------------------------------------------------- AI panel
def test_ai_panel_runs_streams_and_stores(
    make_app: MakeApp, report: Report, monkeypatch: pytest.MonkeyPatch
) -> None:
    assessment = AIAssessment(
        provider="testprov",
        model="model-1",
        generated=datetime.now(UTC),
        input_sha256="0" * 64,
        executive_summary="sshd is the dominant risk (TH-0001).",
        grounding=GroundingResult(passed=True, grounded_ratio=1.0),
        usage={"est_cost_usd": 0.0421},
    )
    chunks: list[str] = []

    def fake_analyze(
        rep: Report, settings: object, stream: Callable[[object], None] | None = None
    ) -> AIAssessment:
        assert rep is report
        if stream is not None:
            stream("## Thinking\n")
            stream("sshd first…")
            chunks.append("sent")
        return assessment

    monkeypatch.setattr(integrations, "ai_available", lambda: True)
    monkeypatch.setattr(integrations, "ai_analyze", fake_analyze)
    monkeypatch.setattr(integrations, "ai_providers", lambda: {"testprov": True})
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(160, 50), notifications=True) as pilot:
            screen = await open_results(app, pilot, report)
            screen.action_ai_panel()
            await pilot.pause()
            panel = app.screen
            assert isinstance(panel, AIPanelScreen)
            panel.action_run()
            await wait_until(pilot, lambda: report.ai is assessment)
            await pilot.pause(0.2)
            from textual.widgets import Markdown

            source = panel.query_one("#ai-md", Markdown).source
            assert "testprov" in source
            assert "dominant risk" in source
            assert "0.0421" in source  # cost surfaced
            # a (hostile) chunk stream was fed through the escaped Markdown stream
            assert chunks == ["sent"]

    run_ui(main())


def test_ai_panel_degrades_without_the_extra(make_app: MakeApp, report: Report) -> None:
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(160, 50), notifications=True) as pilot:
            screen = await open_results(app, pilot, report)
            screen.action_ai_panel()
            await pilot.pause()
            panel = app.screen
            assert isinstance(panel, AIPanelScreen)
            from textual.widgets import Markdown

            assert "not installed" in panel.query_one("#ai-md", Markdown).source
            panel.action_run()
            await pilot.pause()
            assert report.ai is None
            assert any("not installed" in n.message for n in app._notifications)

    run_ui(main())


# --------------------------------------------------------------------- intel
def _bundle(cve: str) -> IntelBundle:
    return IntelBundle(
        cve=cve,
        exploit_maturity="poc",
        exploit_available=True,
        articles=[
            IntelRecord(
                id="a1",
                source="ddg",
                url="https://example.invalid/writeup",
                kind="writeup",
                title="Exploiting " + cve,
                site="example.invalid",
                fetched_at=datetime.now(UTC),
                snippet="snippet text",
            )
        ],
        fetched_at=datetime.now(UTC),
    )


def test_intel_lookup_merges_into_report(
    make_app: MakeApp, report: Report, monkeypatch: pytest.MonkeyPatch
) -> None:
    looked_up: list[str] = []

    def fake_lookup(
        cve: str, *, offline: bool = False, cache_dir: Path | None = None
    ) -> IntelBundle:
        looked_up.append(cve)
        return _bundle(cve)

    monkeypatch.setattr(integrations, "intel_available", lambda: True)
    monkeypatch.setattr(integrations, "intel_lookup", fake_lookup)
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(160, 50), notifications=True) as pilot:
            screen = await open_results(app, pilot, report)
            assert screen.current_threat is not None  # TH-0001 / CVE-2024-6387
            screen.action_intel()
            await wait_until(pilot, lambda: bool(report.intel))
            await pilot.pause(0.2)
            assert looked_up == ["CVE-2024-6387"]
            assert report.intel[0].cve == "CVE-2024-6387"
            from textual.widgets import Markdown

            source = screen.query_one("#threat-md", Markdown).source
            assert "Threat intel" in source
            assert "poc" in source

    run_ui(main())


def test_intel_unavailable_notifies(make_app: MakeApp, report: Report) -> None:
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(160, 50), notifications=True) as pilot:
            screen = await open_results(app, pilot, report)
            screen.action_intel()
            await pilot.pause()
            assert not report.intel
            assert any("not available" in n.message for n in app._notifications)

    run_ui(main())


def test_article_reader_shows_cached_text(
    make_app: MakeApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(integrations, "article_text", lambda record: "CACHED CLEAN TEXT")
    bundle = _bundle("CVE-2024-6387")
    assert _load(bundle.articles[0]) == "CACHED CLEAN TEXT"
    monkeypatch.setattr(integrations, "article_text", lambda record: None)
    assert _load(bundle.articles[0]) == "snippet text"  # falls back to the snippet
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(160, 50)) as pilot:
            app.push_screen(ArticleScreen(bundle))
            await pilot.pause(0.3)
            screen = app.screen
            assert isinstance(screen, ArticleScreen)
            from textual.widgets import OptionList

            assert screen.query_one("#article-list", OptionList).option_count == 1
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, ArticleScreen)

    run_ui(main())


# --------------------------------------------------------------------- open report
def test_open_report_from_file(make_app: MakeApp, report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(140, 50)) as pilot:
            await pilot.press("ctrl+o")
            await pilot.pause(0.2)
            from textual.widgets import Input

            modal = app.screen
            modal.query_one("#open-path", Input).value = str(path)
            modal._typed()
            await wait_until(pilot, lambda: results_ready(app))
            results = app.screen
            assert isinstance(results, ResultsScreen)
            assert results.report.metadata.scan_id == report.metadata.scan_id
            await wait_until(pilot, lambda: bool(app.recent.load()))

    run_ui(main())


def test_open_report_rejects_bad_file(make_app: MakeApp, tmp_path: Path) -> None:
    path = tmp_path / "junk.json"
    path.write_text("{definitely not a report", encoding="utf-8")
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(140, 50), notifications=True) as pilot:
            app.open_report_path(path)
            await wait_until(
                pilot,
                lambda: any("Cannot open report" in n.message for n in app._notifications),
            )
            assert isinstance(app.screen, HomeScreen)  # stayed put

    run_ui(main())


def test_run_with_report_path_opens_results(report: Report, tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    app = StartupSbomApp(
        report_path=path,
        data_dir=tmp_path / "data",
        container_lister=lambda e: [],
        start_dir=tmp_path,
    )

    async def main() -> None:
        async with app.run_test(size=(140, 50)) as pilot:
            await wait_until(pilot, lambda: results_ready(app))

    run_ui(main())


def test_home_lists_and_opens_recent_scans(
    make_app: MakeApp, report: Report, tmp_path: Path
) -> None:
    path = tmp_path / "recent-report.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    from startup_sbom.tui.state import RecentStore, entry_for

    RecentStore(tmp_path / "tui-data").add(entry_for(report, path))
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(140, 50)) as pilot:
            from textual.widgets import DataTable

            home = app.screen
            assert isinstance(home, HomeScreen)
            table = home.query_one("#recent-table", DataTable)
            await wait_until(pilot, lambda: table.row_count == 1)
            table.focus()
            await pilot.press("enter")
            await wait_until(pilot, lambda: results_ready(app))

    run_ui(main())
