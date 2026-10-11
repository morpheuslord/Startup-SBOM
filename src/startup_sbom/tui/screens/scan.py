"""Live scan: progress bar, stage log, elapsed time and cooperative cancel."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Label, ProgressBar, RichLog, Static

from startup_sbom.errors import ScanCancelledError
from startup_sbom.models import Report
from startup_sbom.tui import integrations
from startup_sbom.tui.messages import ScanLog, ScanProgress, TaskDone, UILogHandler, run_background
from startup_sbom.tui.safe import plain, txt
from startup_sbom.tui.state import FormValues, ScanRequest, default_filename
from startup_sbom.tui.widgets import SafeHeader

if TYPE_CHECKING:
    from startup_sbom.pipeline import ProgressEvent
    from startup_sbom.tui.app import StartupSbomApp

log = logging.getLogger("startup_sbom.tui")


@dataclass(slots=True)
class ScanOutcome:
    """What the scan thread hands back to the UI."""

    report: Report
    written: list[Path] = field(default_factory=list)
    policy_violated: bool = False


def execute_scan(
    request: ScanRequest,
    cancel: threading.Event,
    progress: ProgressFn,
    note: NoteFn,
) -> ScanOutcome:
    """Blocking scan → optional AI → write reports.  Runs in a background thread."""
    from startup_sbom import pipeline

    report = pipeline.scan(request.target, request.options, progress=progress, cancel=cancel)
    if cancel.is_set():
        raise ScanCancelledError("scan cancelled")
    if request.ai.enabled:
        note("INFO", "running AI analysis…")
        try:
            report.ai = integrations.ai_analyze(report, request.ai)
            note("INFO", "AI analysis finished")
        except Exception as exc:  # noqa: BLE001 - AI failure must never sink a finished scan
            msg = f"AI analysis failed: {type(exc).__name__}: {exc}"
            report.warnings.append(plain(msg, 500))
            note("WARNING", msg)
    if cancel.is_set():
        raise ScanCancelledError("scan cancelled")
    written: list[Path] = []
    if request.formats:
        from startup_sbom.report import RenderOptions, write_reports

        opts = RenderOptions(
            cdx_spec=request.cdx_spec, vex_not_affected_unreachable=request.vex_unreachable
        )
        outputs = {f: request.output_dir / default_filename(f) for f in request.formats}
        written = write_reports(report, outputs, opts)
        for path in written:
            note("INFO", f"wrote {path}")
    violated = False
    if request.fail_on != "none":
        from startup_sbom.cli import policy_violated

        violated = policy_violated(report, request.fail_on)
    return ScanOutcome(report, written, violated)


if TYPE_CHECKING:
    from collections.abc import Callable

    ProgressFn = Callable[[ProgressEvent], None]
    NoteFn = Callable[[str, str], None]


class ScanScreen(Screen[None]):
    """Runs the scan in a daemon thread and streams progress through messages."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape,ctrl+x", "cancel", "Cancel scan")]

    def __init__(self, request: ScanRequest, values: FormValues | None = None) -> None:
        super().__init__()
        self.request = request
        self.values = values
        self.cancel_event = threading.Event()
        self.started = 0.0
        self.finished = False
        self.thread: threading.Thread | None = None
        self._handler: UILogHandler | None = None
        self._old_level = logging.NOTSET

    @property
    def sbom_app(self) -> StartupSbomApp:
        return cast("StartupSbomApp", self.app)

    def compose(self) -> ComposeResult:
        title = Text("Scanning ", style="bold")
        title.append_text(txt(self.request.target, max_len=300))
        yield SafeHeader()
        yield Static(title, id="scan-title")
        yield ProgressBar(total=None, show_eta=False, id="scan-bar")
        yield Label("Starting…", id="scan-stage")
        yield Label("elapsed 00:00", id="scan-elapsed")
        yield RichLog(max_lines=5000, markup=False, highlight=False, wrap=True, id="scan-log")
        with Horizontal(classes="buttons"):
            yield Button("Cancel (esc)", id="scan-cancel", variant="error")
        yield Footer()

    def on_mount(self) -> None:
        if self.values is not None:
            self.sbom_app.remember_values(self.values)
        logger = logging.getLogger("startup_sbom")
        self._handler = UILogHandler(self)
        logger.addHandler(self._handler)
        self._old_level = logger.level
        if logger.getEffectiveLevel() > logging.INFO:
            logger.setLevel(logging.INFO)
        self.started = time.monotonic()
        self.set_interval(1.0, self._tick)
        self.sbom_app.cancel_events.add(self.cancel_event)
        cancel = self.cancel_event

        def progress(event: ProgressEvent) -> None:
            if cancel.is_set():
                raise ScanCancelledError("scan cancelled")
            self.post_message(ScanProgress(str(event.stage), int(event.index), int(event.total)))

        def note(level: str, text: str) -> None:
            self.post_message(ScanLog(level, text))

        request = self.request
        self.thread = run_background(
            self, "scan", lambda: execute_scan(request, cancel, progress, note)
        )

    def on_unmount(self) -> None:
        self.cancel_event.set()
        self.sbom_app.cancel_events.discard(self.cancel_event)
        logger = logging.getLogger("startup_sbom")
        if self._handler is not None:
            logger.removeHandler(self._handler)
            self._handler = None
        logger.setLevel(self._old_level)

    def _tick(self) -> None:
        if self.finished:
            return
        secs = int(time.monotonic() - self.started)
        self.query_one("#scan-elapsed", Label).update(f"elapsed {secs // 60:02d}:{secs % 60:02d}")

    # -- messages from the scan thread ----------------------------------------
    def on_scan_progress(self, message: ScanProgress) -> None:
        bar = self.query_one("#scan-bar", ProgressBar)
        bar.update(total=max(message.total, 1), progress=max(message.index - 1, 0))
        label = Text(f"[{message.index}/{message.total}] ")
        label.append_text(txt(message.stage))
        self.query_one("#scan-stage", Label).update(label)
        self._write("STAGE", message.stage)

    def on_scan_log(self, message: ScanLog) -> None:
        self._write(message.level, message.text)

    def _write(self, level: str, text: str) -> None:
        style = {"WARNING": "yellow", "ERROR": "red", "STAGE": "bold cyan"}.get(level, "")
        line = Text(f"{level:<8}", style=style or "bold")
        line.append_text(txt(text, max_len=2000))
        self.query_one("#scan-log", RichLog).write(line)

    def on_task_done(self, message: TaskDone) -> None:
        if message.name != "scan":
            return
        self.finished = True
        self.sbom_app.cancel_events.discard(self.cancel_event)
        if isinstance(message.error, ScanCancelledError) or self.cancel_event.is_set():
            self.query_one("#scan-stage", Label).update("Cancelled")
            return
        if message.error is not None:
            err = message.error
            text = plain(f"{type(err).__name__}: {err}", 800)
            self.query_one("#scan-stage", Label).update(
                txt(f"Failed: {text}", "bold red", max_len=800)
            )
            self._write("ERROR", text)
            self.notify(text, title="Scan failed", severity="error", markup=False, timeout=10)
            self.query_one("#scan-cancel", Button).label = "Back (esc)"
            return
        outcome = cast("ScanOutcome", message.result)
        bar = self.query_one("#scan-bar", ProgressBar)
        bar.update(total=1, progress=1)
        # Defer until this screen has painted once: replacing a screen in the same
        # tick it mounts races the Header's title watcher inside Textual.
        self.call_after_refresh(self.sbom_app.scan_finished, outcome, self.request)

    # -- cancel ------------------------------------------------------------------
    @on(Button.Pressed, "#scan-cancel")
    def action_cancel(self) -> None:
        """Cancel (cooperatively, at the next stage boundary) and return to settings."""
        if not self.finished:
            self.cancel_event.set()
            self.notify("Scan cancelled", severity="warning", markup=False)
        self.app.pop_screen()
