"""The Textual application: screen stack, global actions, shared state and themes.

Blocking work (scans, report IO, AI, intel) runs in daemon threads via
:func:`startup_sbom.tui.messages.run_background`, so quitting never waits for a
slow stage; cooperative cancellation goes through :attr:`StartupSbomApp.cancel_events`.
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any, ClassVar, cast

from textual.app import App, SystemCommand
from textual.binding import Binding, BindingType
from textual.screen import Screen

from startup_sbom.models import Report
from startup_sbom.tui.messages import TaskDone, run_background
from startup_sbom.tui.safe import plain
from startup_sbom.tui.screens.home import HomeScreen
from startup_sbom.tui.state import (
    AISettings,
    ContainerRow,
    FormValues,
    RecentStore,
    ScanRequest,
    default_data_dir,
    default_filename,
    entry_for,
    list_containers,
    load_report,
)

DARK_THEME = "textual-dark"
LIGHT_THEME = "textual-light"

ContainerLister = Callable[[str], list[ContainerRow]]


class StartupSbomApp(App[None]):
    """Interactive browser for scans and reports (``startup-sbom tui``)."""

    TITLE = "Startup-SBOM"
    CSS_PATH = "styles.tcss"
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("ctrl+r", "new_scan", "New scan"),
        Binding("ctrl+o", "open_report", "Open report"),
        Binding("ctrl+t", "toggle_theme", "Light/dark"),
    ]

    def __init__(
        self,
        report_path: Path | None = None,
        target: str | None = None,
        *,
        data_dir: Path | None = None,
        container_lister: ContainerLister | None = None,
        start_dir: Path | None = None,
    ) -> None:
        super().__init__()
        self.recent = RecentStore(data_dir if data_dir is not None else default_data_dir())
        self.container_lister: ContainerLister = container_lister or list_containers
        self.cancel_events: set[threading.Event] = set()
        self.form_values = FormValues(target=target or "")
        self.start_dir = (start_dir or Path.cwd()).resolve()
        self._initial_report = report_path

    # ------------------------------------------------------------------ screens
    def get_default_screen(self) -> Screen[None]:
        return HomeScreen()

    def on_ready(self) -> None:
        # After the first paint: pushing a screen while the default screen is
        # still mounting races Textual's Header/Tabs initialisation.
        if self._initial_report is not None:
            self.open_report_path(self._initial_report)
        elif self.form_values.target:
            self.action_new_scan()

    # ------------------------------------------------------------------ actions
    def action_new_scan(self) -> None:
        """Start the new-scan flow (target picker → settings → live scan)."""
        from startup_sbom.tui.screens.scan import ScanScreen
        from startup_sbom.tui.screens.target import TargetScreen

        if isinstance(self.screen, TargetScreen | ScanScreen):
            return
        self.push_screen(TargetScreen(self.form_values, start_dir=self.start_dir))

    def action_open_report(self) -> None:
        """Browse to an existing ``report.json`` and open it."""
        from startup_sbom.tui.screens.open_report import OpenReportScreen

        if isinstance(self.screen, OpenReportScreen):
            return

        def picked(path: Path | None) -> None:
            if path is not None:
                self.open_report_path(path)

        self.push_screen(OpenReportScreen(self.start_dir), picked)

    def action_toggle_theme(self) -> None:
        """Switch between the light and dark theme."""
        self.theme = LIGHT_THEME if self.current_theme.dark else DARK_THEME

    def action_home(self) -> None:
        """Pop every screen back to the launcher."""
        while len(self.screen_stack) > 1:
            self.pop_screen()

    async def action_quit(self) -> None:
        """Quit now: signal every running scan and exit without waiting for threads."""
        for cancel in list(self.cancel_events):
            cancel.set()
        self.exit()

    def get_system_commands(self, screen: Screen[Any]) -> Iterator[SystemCommand]:
        yield from super().get_system_commands(screen)
        yield SystemCommand("New scan", "Pick a target and scan it", self.action_new_scan)
        yield SystemCommand(
            "Open report", "Browse to an existing report.json", self.action_open_report
        )
        yield SystemCommand("Home", "Back to the launcher", self.action_home)

    # ------------------------------------------------------------------ reports
    def open_report_path(self, path: Path) -> None:
        """Load and validate ``path`` off the event loop, then show it."""
        self.notify(plain(f"Opening {path}…", 300), markup=False, timeout=3)
        run_background(self, "open-report", partial(_load_with_path, path))

    def on_task_done(self, message: TaskDone) -> None:
        if message.name != "open-report":
            return
        if message.error is not None:
            self.notify(
                plain(f"Cannot open report: {message.error}", 800),
                title="Open report",
                severity="error",
                markup=False,
                timeout=10,
            )
            return
        report, path = cast("tuple[Report, Path]", message.result)
        self.show_report(report, source=path)

    def show_report(
        self,
        report: Report,
        *,
        source: Path | None = None,
        fail_on: str = "none",
        policy_violated: bool = False,
        ai_settings: AISettings | None = None,
        replace: bool = False,
    ) -> None:
        """Push (or switch to) a results browser for ``report``."""
        from startup_sbom.tui.screens.results import ResultsScreen

        screen = ResultsScreen(
            report,
            source=source,
            fail_on=fail_on,
            policy_violated=policy_violated,
            ai_settings=ai_settings,
        )
        if replace:
            self.switch_screen(screen)
        else:
            self.push_screen(screen)
        if source is not None:
            self.remember(report, source)

    def scan_finished(self, outcome: object, request: ScanRequest) -> None:
        """A scan succeeded: replace the live-scan screen with the results browser."""
        from startup_sbom.tui.screens.scan import ScanOutcome, ScanScreen

        result = cast("ScanOutcome", outcome)
        json_name = default_filename("json")
        source = next((p for p in result.written if p.name == json_name), None)
        self.show_report(
            result.report,
            source=source,
            fail_on=request.fail_on,
            policy_violated=result.policy_violated,
            ai_settings=request.ai,
            replace=isinstance(self.screen, ScanScreen),
        )
        if result.policy_violated:
            self.notify(
                f"Policy --fail-on {plain(request.fail_on)} violated",
                severity="warning",
                markup=False,
            )
        else:
            self.notify("Scan finished", markup=False)

    def remember(self, report: Report, path: Path) -> None:
        """Record ``path`` in the recent-scans index (best-effort, off the loop)."""
        entry = entry_for(report, path)
        run_background(self, "remember", partial(self.recent.add, entry))

    def remember_values(self, values: FormValues) -> None:
        """Keep the last-used form values for the next new-scan flow."""
        self.form_values = dataclasses.replace(values)


def _load_with_path(path: Path) -> tuple[Report, Path]:
    return load_report(path), path
