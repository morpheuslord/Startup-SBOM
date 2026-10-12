"""Home / launcher: new scan, open report, recent scans."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Label, Static

from startup_sbom.tui.messages import TaskDone, run_background
from startup_sbom.tui.safe import txt
from startup_sbom.tui.state import RecentEntry
from startup_sbom.tui.widgets import SafeHeader

if TYPE_CHECKING:
    from startup_sbom.tui.app import StartupSbomApp

INTRO = (
    "Map what a Linux system or container runs at boot to its packages, reverse "
    "vulnerabilities into threats, chain attacks and trace supply-chain blast radius. "
    "Read-only: nothing in the target is executed, mounted or modified."
)


class HomeScreen(Screen[None]):
    """Launcher with the recent-scan history."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("n", "app.new_scan", "New scan"),
        Binding("o", "app.open_report", "Open report"),
        Binding("delete", "forget", "Forget entry"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.entries: list[RecentEntry] = []

    @property
    def sbom_app(self) -> StartupSbomApp:
        return cast("StartupSbomApp", self.app)

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Vertical(id="home"):
            yield Static(Text("Startup-SBOM 2.0", style="bold"), id="home-title")
            yield Static(Text(INTRO), id="home-intro")
            with Horizontal(id="home-actions"):
                yield Button("New scan (n)", id="home-new", variant="primary")
                yield Button("Open report (o)", id="home-open")
                yield Button("Quit (ctrl+q)", id="home-quit", variant="error")
            yield Label("Recent scans (enter to open, delete to forget)")
            yield DataTable(cursor_type="row", zebra_stripes=True, id="recent-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#recent-table", DataTable)
        table.add_column("When", width=17, key="when")
        table.add_column("Target", width=40, key="target")
        table.add_column("Act", width=5, key="act")
        table.add_column("Threats", width=8, key="threats")
        table.add_column("Report", key="path")
        self.reload()

    def on_screen_resume(self) -> None:
        self.reload()

    def reload(self) -> None:
        """Load the recent-scan index off the event loop."""
        store = self.sbom_app.recent
        run_background(self, "recent", store.load)

    def on_task_done(self, message: TaskDone) -> None:
        if message.name == "recent" and isinstance(message.result, list):
            self.show(cast("list[RecentEntry]", message.result))

    def show(self, entries: list[RecentEntry]) -> None:
        """Fill the recent table."""
        self.entries = entries
        table = self.query_one("#recent-table", DataTable)
        table.clear()
        for i, e in enumerate(entries):
            table.add_row(
                txt(e.when),
                txt(e.target),
                Text(str(e.act), style="bold red" if e.act else ""),
                Text(str(e.threats)),
                txt(e.path, max_len=300),
                key=str(i),
            )

    def _selected(self) -> RecentEntry | None:
        table = self.query_one("#recent-table", DataTable)
        if not self.entries or table.row_count == 0:
            return None
        row = table.cursor_row
        return self.entries[row] if 0 <= row < len(self.entries) else None

    @on(DataTable.RowSelected, "#recent-table")
    def _open_recent(self) -> None:
        entry = self._selected()
        if entry is not None:
            self.sbom_app.open_report_path(Path(entry.path))

    def action_forget(self) -> None:
        entry = self._selected()
        if entry is not None:
            self.show(self.sbom_app.recent.remove(entry.path))

    @on(Button.Pressed, "#home-new")
    def _new(self) -> None:
        self.sbom_app.action_new_scan()

    @on(Button.Pressed, "#home-open")
    def _open(self) -> None:
        self.sbom_app.action_open_report()

    @on(Button.Pressed, "#home-quit")
    async def _quit(self) -> None:
        await self.sbom_app.action_quit()
