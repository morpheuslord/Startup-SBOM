"""Navigation, scan worker, cancellation, quit and the lazy package entry."""

from __future__ import annotations

import builtins
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from tuihelpers import results_ready, run_ui, wait_until

import startup_sbom.tui as tui_pkg
from startup_sbom.errors import ScanCancelledError, StartupSBOMError
from startup_sbom.models import Report
from startup_sbom.pipeline import ProgressEvent
from startup_sbom.tui.app import StartupSbomApp
from startup_sbom.tui.screens.home import HomeScreen
from startup_sbom.tui.screens.results import ResultsScreen
from startup_sbom.tui.screens.scan import ScanScreen
from startup_sbom.tui.screens.settings import SettingsScreen
from startup_sbom.tui.screens.target import TargetScreen

MakeApp = Callable[..., StartupSbomApp]

STAGES = [
    "Identifying operating system",
    "Reading package databases",
    "Discovering services",
    "Matching vulnerabilities",
    "Reversing vulnerabilities into threats",
]


def make_fake_scan(
    report: Report,
    *,
    stage_seconds: float = 0.0,
    seen: list[str] | None = None,
    threads: set[int] | None = None,
) -> Callable[..., Report]:
    def fake_scan(
        target: str,
        options: object = None,
        *,
        http: object = None,
        progress: Callable[[ProgressEvent], None] | None = None,
        strict: bool = False,
        cancel: threading.Event | None = None,
        activity: Callable[[Any], None] | None = None,
    ) -> Report:
        if threads is not None:
            threads.add(threading.get_ident())
        for i, stage in enumerate(STAGES, 1):
            if cancel is not None and cancel.is_set():
                raise ScanCancelledError(f"scan cancelled before: {stage}")
            if progress is not None:
                progress(ProgressEvent(stage, i, len(STAGES)))  # raises once cancelled
            if seen is not None:
                seen.append(stage)
            if stage_seconds:
                time.sleep(stage_seconds)
        return report

    return fake_scan


# ------------------------------------------------------------------- navigation
def test_navigation_home_target_settings_and_back(make_app: MakeApp, tmp_path: Path) -> None:
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(140, 50)) as pilot:
            assert isinstance(app.screen, HomeScreen)
            await pilot.press("ctrl+r")
            await pilot.pause()
            assert isinstance(app.screen, TargetScreen)
            target = app.screen
            from textual.widgets import Input

            target.query_one("#ref", Input).value = str(tmp_path)
            target.action_next()
            await pilot.pause()
            assert isinstance(app.screen, SettingsScreen)
            assert app.screen.values.target == f"dir:{tmp_path}"
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, TargetScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, HomeScreen)

    run_ui(main())


def test_target_validation_error_blocks(make_app: MakeApp, tmp_path: Path) -> None:
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(140, 50), notifications=True) as pilot:
            app.action_new_scan()
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, TargetScreen)
            from textual.widgets import Input

            screen.query_one("#ref", Input).value = str(tmp_path / "does-not-exist")
            screen.action_next()
            await pilot.pause()
            assert isinstance(app.screen, TargetScreen)  # did not advance
            assert any("Invalid target" in n.message for n in app._notifications)

    run_ui(main())


def test_settings_widgets_map_to_options_and_cli(make_app: MakeApp, tmp_path: Path) -> None:
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(160, 60)) as pilot:
            app.push_screen(SettingsScreen(_values_for(tmp_path)))
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, SettingsScreen)
            from textual.widgets import Checkbox, Input, Select, SelectionList, Static

            screen.query_one("#offline", Checkbox).value = True
            screen.query_one("#sources", SelectionList).deselect("arch")
            screen.query_one("#formats", SelectionList).select("sarif")
            screen.query_one("#output_dir", Input).value = str(tmp_path / "out")
            screen.query_one("#fail_on", Select).value = "high"
            # offline greys out NVD and the online-only intel/AI widgets; the
            # Changed handlers run asynchronously, so poll rather than sleep
            sources = screen.query_one("#sources", SelectionList)
            ai_enabled = screen.query_one("#ai_enabled", Checkbox)
            await wait_until(
                pilot,
                lambda: sources.get_option("nvd").disabled and ai_enabled.disabled,
                message="offline did not disable NVD and the AI toggle",
            )
            values, errors = screen.read_values()
            assert errors == []
            from startup_sbom.tui.state import build_request, equivalent_cli

            req = build_request(values, env={})
            assert req.options.offline is True
            assert req.options.vuln_sources == ("osv",)
            assert set(req.formats) == {"json", "sarif"}
            assert req.output_dir == tmp_path / "out"
            assert req.fail_on == "high"
            cli = equivalent_cli(values)
            assert "--offline" in cli
            assert "-f sarif" in cli
            assert "--fail-on high" in cli
            preview_widget = screen.query_one("#cli-preview", Static)
            await wait_until(pilot, lambda: "--offline" in str(preview_widget.content))
            assert "startup-sbom scan" in str(preview_widget.content)

    run_ui(main())


# ------------------------------------------------------------------- scan worker
def test_scan_flow_progress_results_and_written_report(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    threads: set[int] = set()
    monkeypatch.setattr(
        "startup_sbom.pipeline.scan", make_fake_scan(report, seen=seen, threads=threads)
    )
    app = make_app()
    out_dir = tmp_path / "scan-out"

    async def main() -> None:
        async with app.run_test(size=(140, 50)) as pilot:
            app.action_new_scan()
            await pilot.pause()
            from textual.widgets import Input

            target = app.screen
            assert isinstance(target, TargetScreen)
            target.query_one("#ref", Input).value = str(tmp_path)
            target.action_next()
            await pilot.pause()
            settings = app.screen
            assert isinstance(settings, SettingsScreen)
            settings.query_one("#output_dir", Input).value = str(out_dir)
            await pilot.pause(0.1)
            settings.action_start()
            # the instant fake scan may already have finished by the first pause
            await wait_until(pilot, lambda: results_ready(app))
            results = app.screen
            assert isinstance(results, ResultsScreen)
            assert results.report is report
            assert results.source == out_dir / "report.json"
            # last-used settings were remembered for the next scan
            assert app.form_values.target == f"dir:{tmp_path}"
            await wait_until(
                pilot, lambda: bool(app.recent.load()), message="recent store not updated"
            )

    run_ui(main())
    assert (out_dir / "report.json").is_file()
    assert seen == STAGES  # every stage reported progress
    assert threading.get_ident() not in threads  # scan ran off the event loop


def test_cancel_mid_scan_returns_promptly(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    monkeypatch.setattr(
        "startup_sbom.pipeline.scan", make_fake_scan(report, stage_seconds=0.4, seen=seen)
    )
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(140, 50)) as pilot:
            from startup_sbom.tui.state import FormValues, build_request

            values = FormValues(target=f"dir:{tmp_path}", formats=())
            app.push_screen(ScanScreen(build_request(values, env={}), values))
            await wait_until(pilot, lambda: isinstance(app.screen, ScanScreen))
            await pilot.pause(0.1)
            scan_screen = app.screen
            assert isinstance(scan_screen, ScanScreen)
            t0 = time.monotonic()
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, ScanScreen)  # back immediately
            assert time.monotonic() - t0 < 1.0
            assert scan_screen.cancel_event.is_set()

    run_ui(main())
    assert len(seen) < len(STAGES)  # the thread stopped at the next stage boundary


def test_quit_mid_scan_does_not_wait_for_the_thread(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("startup_sbom.pipeline.scan", make_fake_scan(report, stage_seconds=0.5))
    app = make_app()
    elapsed = 0.0
    cancel_events: list[threading.Event] = []

    async def main() -> None:
        nonlocal elapsed
        async with app.run_test(size=(140, 50)) as pilot:
            from startup_sbom.tui.state import FormValues, build_request

            values = FormValues(target=f"dir:{tmp_path}", formats=())
            app.push_screen(ScanScreen(build_request(values, env={}), values))
            await pilot.pause(0.2)
            screen = app.screen
            assert isinstance(screen, ScanScreen)
            cancel_events.append(screen.cancel_event)
            t0 = time.monotonic()
            await app.action_quit()
            await pilot.pause()
            elapsed = time.monotonic() - t0

    run_ui(main())
    assert elapsed < 2.0  # daemon thread: quit never blocks on a slow stage
    assert cancel_events
    assert cancel_events[0].is_set()


def test_scan_failure_is_shown_not_fatal(
    make_app: MakeApp, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*a: object, **kw: object) -> Report:
        raise RuntimeError("osv exploded")

    monkeypatch.setattr("startup_sbom.pipeline.scan", boom)
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(140, 50), notifications=True) as pilot:
            from startup_sbom.tui.state import FormValues, build_request

            values = FormValues(target=f"dir:{tmp_path}", formats=())
            app.push_screen(ScanScreen(build_request(values, env={}), values))
            await pilot.pause()
            await wait_until(
                pilot,
                lambda: any("osv exploded" in n.message for n in app._notifications),
                message="failure notification missing",
            )
            assert isinstance(app.screen, ScanScreen)  # stays for inspection

    run_ui(main())


# ------------------------------------------------------------------- entry point
def test_package_import_is_lazy() -> None:
    """``import startup_sbom.tui`` must not import textual."""
    code = "import startup_sbom.tui, sys; print('textual' in sys.modules)"
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert proc.stdout.strip() == "False"


def test_run_without_textual_raises_friendly_error(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "textual":
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return real_import(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "textual", raising=False)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(StartupSBOMError, match=r"startup-sbom\[tui\]"):
        tui_pkg.run()


def test_run_signature() -> None:
    import inspect

    params = inspect.signature(tui_pkg.run).parameters
    assert list(params) == ["report_path", "target"]
    assert params["report_path"].default is None
    assert params["target"].default is None


# ------------------------------------------------------------------- helpers
def _values_for(tmp_path: Path) -> Any:
    from startup_sbom.tui.state import FormValues

    return FormValues(target=f"dir:{tmp_path}")
