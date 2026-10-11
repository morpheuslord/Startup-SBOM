"""Export dialog: choose formats and a directory, write atomically in the background."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select, SelectionList, Static
from textual.widgets.selection_list import Selection

from startup_sbom.models import Report
from startup_sbom.tui.messages import TaskDone, run_background
from startup_sbom.tui.safe import plain, txt, wrap_txt
from startup_sbom.tui.state import CDX_SPECS, DEFAULT_OUTPUT, available_formats, default_filename

if TYPE_CHECKING:
    from startup_sbom.tui.app import StartupSbomApp


def export_report(
    report: Report, formats: list[str], directory: Path, cdx_spec: str, vex_unreachable: bool
) -> list[Path]:
    """Write ``formats`` of ``report`` into ``directory`` (blocking, atomic per file)."""
    from startup_sbom.report import RenderOptions, write_reports

    opts = RenderOptions(cdx_spec=cdx_spec, vex_not_affected_unreachable=vex_unreachable)
    outputs = {f: directory / default_filename(f) for f in formats}
    return write_reports(report, outputs, opts)


class ExportScreen(ModalScreen[list[Path] | None]):
    """Write report files for the open report."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "dismiss(None)", "Close")]

    def __init__(self, report: Report, directory: str = DEFAULT_OUTPUT) -> None:
        super().__init__()
        self.report = report
        self.directory = directory
        self.formats = available_formats()
        self.busy = False

    @property
    def sbom_app(self) -> StartupSbomApp:
        return cast("StartupSbomApp", self.app)

    def compose(self) -> ComposeResult:
        with Vertical(id="export-dialog", classes="dialog"):
            yield Label("Export report", classes="section")
            yield SelectionList[str](
                *[Selection(Text(f), f, f in ("json", "markdown"), id=f) for f in self.formats],
                id="export-formats",
            )
            with Horizontal(classes="row"):
                yield Label("Directory")
                yield Input(self.directory, id="export-dir")
            with Horizontal(classes="row"):
                yield Label("CycloneDX spec")
                yield Select(
                    [(s, s) for s in CDX_SPECS], value="1.6", allow_blank=False, id="export-cdx"
                )
                yield Checkbox("VEX: unreachable → not_affected", id="export-vex")
            yield Static("", id="export-status")
            with Horizontal(classes="buttons"):
                yield Button("Write", id="export-write", variant="primary")
                yield Button("Cancel (esc)", id="export-cancel")

    @on(Button.Pressed, "#export-cancel")
    def _cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#export-write")
    def write(self) -> None:
        """Validate and write in a background thread."""
        if self.busy:
            return
        formats = list(self.query_one("#export-formats", SelectionList).selected)
        directory = self.query_one("#export-dir", Input).value.strip()
        status = self.query_one("#export-status", Static)
        if not formats:
            status.update(Text("Choose at least one format.", style="bold red"))
            return
        if not directory:
            status.update(Text("Choose an output directory.", style="bold red"))
            return
        cdx = self.query_one("#export-cdx", Select).value
        vex = self.query_one("#export-vex", Checkbox).value
        self.busy = True
        status.update(Text("writing…", style="dim"))
        report = self.report
        path = Path(directory).expanduser()
        spec = cdx if isinstance(cdx, str) else "1.6"
        run_background(self, "export", lambda: export_report(report, formats, path, spec, vex))

    def on_task_done(self, message: TaskDone) -> None:
        if message.name != "export":
            return
        self.busy = False
        status = self.query_one("#export-status", Static)
        if message.error is not None:
            text = plain(f"Export failed: {message.error}", 800)
            status.update(txt(text, "bold red", max_len=800))
            self.notify(text, severity="error", markup=False)
            return
        written = cast("list[Path]", message.result)
        status.update(wrap_txt("\n".join(f"wrote {p}" for p in written)))
        self.notify(
            "Wrote:\n" + "\n".join(plain(p, 400) for p in written), title="Export", markup=False
        )
        for p in written:
            if p.name == default_filename("json"):
                self.sbom_app.remember(self.report, p)
        self.dismiss(written)
