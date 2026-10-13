"""Live scan: stage checklist, raw operations, live analyst, progress and cancel.

The scan runs in a daemon thread and reports through thread-safe messages
(:mod:`startup_sbom.tui.messages`): stage starts (``ScanProgress``), raw
operations, stage digests and failures (``ScanActivity``), log records
(``ScanLog``) and, when enabled, the live analyst's streamed thinking and
commentary (``ScanAnalyst``).  The screen buffers them and redraws at most
``1 / FRAME_SECONDS`` times a second, so a burst of thousands of operations never
stalls the event loop.

Everything shown here comes from the scanned target or from a model and is
untrusted: it only reaches widgets through :mod:`startup_sbom.tui.safe` helpers
and plain ``rich.text.Text`` (never markup).
"""

from __future__ import annotations

import contextlib
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Protocol, cast

from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Button, Footer, Label, ProgressBar, RichLog, Static

from startup_sbom.errors import ScanCancelledError, StartupSBOMError
from startup_sbom.models import Report
from startup_sbom.tui import integrations
from startup_sbom.tui.messages import (
    ScanActivity,
    ScanAnalyst,
    ScanLog,
    ScanProgress,
    TaskDone,
    UILogHandler,
    run_background,
)
from startup_sbom.tui.safe import plain, txt, wrap_txt
from startup_sbom.tui.state import AISettings, FormValues, ScanRequest, default_filename
from startup_sbom.tui.widgets import SafeHeader

if TYPE_CHECKING:
    from collections.abc import Callable

    from startup_sbom.pipeline import ActivityEvent, ProgressEvent
    from startup_sbom.tui.app import StartupSbomApp

    ProgressFn = Callable[[ProgressEvent], None]
    ActivityFn = Callable[[ActivityEvent], None]
    NoteFn = Callable[[str, str], None]
    PhaseFn = Callable[[str], None]
    PostFn = Callable[[str, str, str], None]

log = logging.getLogger("startup_sbom.tui")

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
FRAME_SECONDS = 0.125
OPS_MAX_LINES = 5000
OPS_PER_FRAME = 400  # older lines of a bigger burst are summarised, not drawn
THINKING_TAIL = 360
MAX_THINKING = 8_000
MAX_COMMENT = 4_000
ANALYST_WAIT = 45.0  # how long a finished scan waits for the analyst's last notes
_STAGE_RECORD = "stage %d/%d: %s"  # the pipeline's own stage log line (shown as a row)
_OPS_LOGGER = "startup_sbom.ops"
_HIGHLIGHTS: tuple[tuple[str, str], ...] = (
    (r"\b\d[\d,.]*(?:\s?(?:ms|s|kB|MB|KiB|MiB|GiB))?\b", "cyan"),
    (r"\[[^\]\n]{1,40}\]", "yellow"),
    (r"\b(?:GET|POST|HEAD|PUT)\b", "bold blue"),
    (r"→\s?2\d\d\b", "green"),
    (r"→\s?[45]\d\d\b", "bold red"),
)


@dataclass(slots=True)
class ScanOutcome:
    """What the scan thread hands back to the UI."""

    report: Report
    written: list[Path] = field(default_factory=list)
    policy_violated: bool = False
    analyst_notes: list[tuple[str, str]] = field(default_factory=list)  # display-only


# --------------------------------------------------------------------------- live analyst
class AnalystLike(Protocol):
    """What the screen needs from :class:`startup_sbom.ai.live.LiveAnalyst`."""

    label: str
    error: str | None
    commentary: list[tuple[str, str]]

    def start(self) -> None: ...
    def feed(self, event: ActivityEvent) -> None: ...
    def close(self, wait: float = ...) -> None: ...
    def cancel(self) -> None: ...


def make_live_analyst(sink: Callable[[Any], None], settings: AISettings) -> AnalystLike:
    """Build the live analyst (raises a ``StartupSBOMError`` without the extra or a key)."""
    from startup_sbom.ai.live import LiveAnalyst

    return LiveAnalyst(
        sink,
        provider=settings.provider,
        model=settings.model,
        profile=settings.profile,
        max_cost_usd=settings.max_cost_usd,
    )


def _reason(exc: BaseException) -> str:
    text = str(exc) if isinstance(exc, StartupSBOMError) else f"{type(exc).__name__}: {exc}"
    return plain(text, 400)


class AnalystLink:
    """Owns the optional live analyst of one scan; every method is thread-safe.

    The scan thread calls :meth:`open`, :meth:`feed` and :meth:`finish`; the UI
    calls :meth:`skip` and :meth:`cancel`.  Analyst output reaches the UI only
    through ``post`` (which must be thread-safe, i.e. ``post_message``).
    """

    def __init__(self, settings: AISettings, post: PostFn) -> None:
        self.settings = settings
        self._post = post
        self._lock = threading.Lock()
        self._analyst: AnalystLike | None = None
        self._cancelled = False
        self._skip = threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def open(self) -> bool:
        """Build and start the analyst; a failure is reported (``unavailable``), never raised."""
        try:
            analyst = make_live_analyst(self._sink, self.settings)
        except Exception as exc:  # noqa: BLE001 - the live analyst is optional
            self._post("", "unavailable", _reason(exc))
            return False
        with self._lock:
            if self._cancelled:
                return False
            self._analyst = analyst
        self._post("", "ready", plain(getattr(analyst, "label", "") or "model", 120))
        analyst.start()
        return True

    def _sink(self, event: object) -> None:
        self._post(
            str(getattr(event, "stage", "")),
            str(getattr(event, "kind", "")),
            str(getattr(event, "text", "")),
        )

    def feed(self, event: ActivityEvent) -> None:
        analyst = self._analyst
        if analyst is not None and not self._cancelled:
            with contextlib.suppress(Exception):  # the analyst never breaks a scan
                analyst.feed(event)

    def finish(self, cancel: threading.Event, wait: float = ANALYST_WAIT) -> list[tuple[str, str]]:
        """Let the analyst comment on the last stages; :meth:`skip` or cancel stop waiting."""
        analyst = self._analyst
        if analyst is None or self._cancelled:
            return []
        done = threading.Event()

        def closer() -> None:
            try:
                analyst.close(wait)
            finally:
                done.set()

        threading.Thread(target=closer, name="sbom-tui-analyst-close", daemon=True).start()
        deadline = time.monotonic() + wait + 1.0
        while not done.wait(0.05):
            if self._skip.is_set() or cancel.is_set() or time.monotonic() > deadline:
                self.cancel()
                break
        return list(analyst.commentary)

    def skip(self) -> None:
        """Stop waiting for the analyst's last notes (the scan result is kept)."""
        self._skip.set()

    def cancel(self) -> None:
        """Stop the analyst at once (idempotent)."""
        with self._lock:
            self._cancelled = True
            analyst = self._analyst
        if analyst is not None:
            with contextlib.suppress(Exception):
                analyst.cancel()


# --------------------------------------------------------------------------- scan thread
def execute_scan(
    request: ScanRequest,
    cancel: threading.Event,
    progress: ProgressFn,
    note: NoteFn,
    *,
    activity: ActivityFn | None = None,
    phase: PhaseFn | None = None,
    analyst: AnalystLink | None = None,
) -> ScanOutcome:
    """Blocking scan → optional AI → write reports.  Runs in a background thread."""
    from startup_sbom import pipeline

    def set_phase(text: str) -> None:
        if phase is not None:
            phase(text)

    live = analyst is not None and analyst.open()

    def on_activity(event: ActivityEvent) -> None:
        if activity is not None:
            activity(event)
        if live and analyst is not None:
            analyst.feed(event)

    try:
        report = pipeline.scan(
            request.target,
            request.options,
            progress=progress,
            cancel=cancel,
            activity=on_activity if activity is not None or live else None,
        )
    except BaseException:
        if analyst is not None:
            analyst.cancel()
        raise
    notes: list[tuple[str, str]] = []
    if live and analyst is not None and not cancel.is_set():
        set_phase("Live analyst is finishing its notes… (k skips)")
        notes = analyst.finish(cancel)
    if cancel.is_set():
        raise ScanCancelledError("scan cancelled")
    if request.ai.enabled:
        set_phase("Running AI analysis…")
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

        set_phase("Writing reports…")
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
    return ScanOutcome(report, written, violated, notes)


class _ScanLogHandler(UILogHandler):
    """Normal log records go to the notes log; stray ops records to the ops pane.

    While the pipeline captures operations (``activity=``) the ops logger stops
    propagating, so those never arrive here twice.  Operations logged outside the
    capture (acquiring the target) are routed to the ops pane, and the pipeline's
    own ``stage i/n`` record is dropped because the stage list already shows it.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.name == _OPS_LOGGER or record.name.startswith(_OPS_LOGGER + "."):
                self.target.post_message(ScanActivity("", "op", record.getMessage()))
                return
            if record.msg == _STAGE_RECORD:
                return
        except Exception:  # noqa: BLE001 - logging must never raise
            self.handleError(record)
            return
        super().emit(record)


# --------------------------------------------------------------------------- view state
@dataclass(slots=True)
class StageRow:
    """One pipeline stage as the checklist shows it."""

    title: str
    index: int
    started: float
    finished: float | None = None
    digest: str = ""
    failed: str = ""
    ops: int = 0
    last_op: str = ""
    noted: bool = False  # the live analyst commented on it


@dataclass(slots=True)
class Thought:
    """The live analyst's output for one stage (or a catch-up batch of stages)."""

    stage: str
    started: float
    thinking: str = ""
    text: str = ""
    done: bool = False
    took: float | None = None


def _fmt_ops(count: int) -> str:
    if count >= 100_000:
        return f"{count / 1000:.0f}k"
    if count >= 10_000:
        return f"{count / 1000:.1f}k"
    return f"{count:,}" if count else "–"


def _clock(secs: float) -> str:
    whole = int(secs)
    return f"{whole // 60:02d}:{whole % 60:02d}"


# --------------------------------------------------------------------------- screen
class ScanScreen(Screen[None]):
    """Runs the scan in a daemon thread and streams progress through messages."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape,ctrl+x", "cancel", "Cancel scan"),
        Binding("s", "toggle_pane('stages')", "Stages"),
        Binding("o", "toggle_pane('ops')", "Raw ops"),
        Binding("a", "toggle_pane('analyst')", "Analyst"),
        Binding("n", "toggle_pane('notes')", "Notes"),
        Binding("t", "toggle_thinking", "Thinking"),
        Binding("k", "skip_analyst", "Skip analyst"),
    ]
    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (110, "-wide")]  # noqa: RUF012
    VERTICAL_BREAKPOINTS = [(0, "-short"), (32, "-tall")]  # noqa: RUF012
    PANES: ClassVar[dict[str, str]] = {
        "stages": "#scan-stages-box",
        "ops": "#scan-ops",
        "analyst": "#scan-analyst-box",
        "notes": "#scan-log",
    }

    def __init__(self, request: ScanRequest, values: FormValues | None = None) -> None:
        super().__init__()
        self.request = request
        self.values = values
        self.cancel_event = threading.Event()
        self.started = 0.0
        self.ended: float | None = None
        self.finished = False
        self.thread: threading.Thread | None = None
        self.link: AnalystLink | None = None
        self._handler: UILogHandler | None = None
        self._old_level = logging.NOTSET
        # view state (UI thread only)
        self.rows: list[StageRow] = []
        self._rows_by_title: dict[str, StageRow] = {}
        self.total = 0
        self.op_count = 0
        self.warnings = 0
        self.thoughts: list[Thought] = []
        self.analyst_label = ""
        self.analyst_state = "off"
        self.analyst_error = ""
        self.show_thinking = False
        self._pending_ops: list[tuple[float, str, str]] = []
        self._frame = 0
        self._stages_dirty = True
        self._analyst_dirty = True

    @property
    def sbom_app(self) -> StartupSbomApp:
        return cast("StartupSbomApp", self.app)

    # ------------------------------------------------------------------ compose
    def compose(self) -> ComposeResult:
        title = Text("Scanning ", style="bold")
        title.append_text(txt(self.request.target, max_len=300))
        yield SafeHeader()
        yield Static(title, id="scan-title")
        with Horizontal(id="scan-status"):
            yield ProgressBar(total=None, show_eta=False, id="scan-bar")
            yield Label("Starting…", id="scan-stage")
            yield Label("00:00", id="scan-elapsed")
            yield Button("Cancel (esc)", id="scan-cancel", variant="error", compact=True)
        with VerticalScroll(id="scan-stages-box"):
            yield Static(Text("waiting for the first stage…", style="dim"), id="scan-stages")
        with Horizontal(id="scan-panes"):
            yield RichLog(
                max_lines=OPS_MAX_LINES, markup=False, highlight=False, wrap=True, id="scan-ops"
            )
            with VerticalScroll(id="scan-analyst-box"):
                yield Static("", id="scan-analyst")
        yield RichLog(max_lines=5000, markup=False, highlight=False, wrap=True, id="scan-log")
        yield Footer()

    def on_mount(self) -> None:
        if self.values is not None:
            self.sbom_app.remember_values(self.values)
        self.query_one("#scan-stages-box").border_title = Text("Stages")
        self.query_one("#scan-ops").border_title = Text("Raw operations")
        self.query_one("#scan-log").border_title = Text("Notes & warnings")
        box = self.query_one("#scan-analyst-box")
        box.border_title = Text("Live analyst")
        if self.request.ai.live:
            self.analyst_state = "starting"

            def post(stage: str, kind: str, text: str) -> None:
                self.post_message(ScanAnalyst(stage, kind, text))

            self.link = AnalystLink(self.request.ai, post)
        else:
            box.display = False
        logger = logging.getLogger("startup_sbom")
        self._handler = _ScanLogHandler(self)
        logger.addHandler(self._handler)
        self._old_level = logger.level
        if logger.getEffectiveLevel() > logging.INFO:
            logger.setLevel(logging.INFO)
        self.started = time.monotonic()
        self.set_interval(FRAME_SECONDS, self._on_frame)
        self.sbom_app.cancel_events.add(self.cancel_event)
        self._render_all()
        cancel = self.cancel_event

        def progress(event: ProgressEvent) -> None:
            if cancel.is_set():
                raise ScanCancelledError("scan cancelled")
            self.post_message(ScanProgress(str(event.stage), int(event.index), int(event.total)))

        def activity(event: ActivityEvent) -> None:
            # Never raise here: operations arrive through a logging handler.
            if not cancel.is_set():
                self.post_message(ScanActivity(str(event.stage), str(event.kind), event.message))

        def phase(text: str) -> None:
            self.post_message(ScanActivity("", "phase", text))

        def note(level: str, text: str) -> None:
            self.post_message(ScanLog(level, text))

        request, link = self.request, self.link
        self.thread = run_background(
            self,
            "scan",
            lambda: execute_scan(
                request, cancel, progress, note, activity=activity, phase=phase, analyst=link
            ),
        )

    def on_unmount(self) -> None:
        self.cancel_event.set()
        if self.link is not None:
            self.link.cancel()
        self.sbom_app.cancel_events.discard(self.cancel_event)
        logger = logging.getLogger("startup_sbom")
        if self._handler is not None:
            logger.removeHandler(self._handler)
            self._handler = None
        logger.setLevel(self._old_level)

    # ------------------------------------------------------------------ messages
    def on_scan_progress(self, message: ScanProgress) -> None:
        for row in self.rows:
            if row.finished is None:
                row.finished = message.at
        row = StageRow(plain(message.stage, 160), message.index, message.at)
        self.rows.append(row)
        self._rows_by_title[message.stage] = row
        self.total = max(message.total, len(self.rows))
        label = Text(f"[{message.index}/{message.total}] ", style="bold")
        label.append_text(txt(message.stage))
        self.query_one("#scan-stage", Label).update(label)
        self._pending_ops.append(
            (message.at, "stage", f"{message.index}/{message.total} {row.title}")
        )
        self._write("STAGE", message.stage)
        self._stages_dirty = True

    def on_scan_activity(self, message: ScanActivity) -> None:
        kind = message.kind
        if kind == "phase":
            self.query_one("#scan-stage", Label).update(txt(message.message, "bold"))
            return
        row = self._rows_by_title.get(message.stage) if message.stage else None
        if kind == "op":
            self.op_count += 1
            if row is not None:
                row.ops += 1
                row.last_op = message.message
        elif kind == "digest" and row is not None:
            row.digest = message.message
            row.finished = row.finished or message.at
        elif kind == "stage-failed" and row is not None:
            row.failed = message.message or "failed"
            row.finished = row.finished or message.at
        elif kind == "warning":
            self.warnings += 1
        self._pending_ops.append((message.at, kind, message.message))
        self._stages_dirty = True

    def on_scan_log(self, message: ScanLog) -> None:
        if message.level in ("WARNING", "ERROR", "CRITICAL"):
            self.warnings += 1
            self._stages_dirty = True
        self._write(message.level, message.text)

    def on_scan_analyst(self, message: ScanAnalyst) -> None:
        kind, text = message.kind, message.text
        current = self.thoughts[-1] if self.thoughts else None
        if kind == "ready":
            self.analyst_label = plain(text, 120)
            if self.analyst_state == "starting":
                self.analyst_state = "watching"
        elif kind == "info":
            self._write("INFO", text)
        elif kind == "start":
            self.thoughts.append(Thought(plain(message.stage, 160), message.at))
            self.analyst_state = "thinking"
        elif kind in ("thinking", "text"):
            if current is None or current.done:
                current = Thought(plain(message.stage, 160), message.at)
                self.thoughts.append(current)
            if kind == "thinking":
                current.thinking = (current.thinking + text)[-MAX_THINKING:]
            else:
                current.text = (current.text + text)[-MAX_COMMENT:]
                self.analyst_state = "writing"
        elif kind == "done":
            if current is None or current.done:
                current = Thought(plain(message.stage, 160), message.at)
                self.thoughts.append(current)
            current.text = text[-MAX_COMMENT:]
            current.done = True
            current.took = message.at - current.started
            row = self._rows_by_title.get(message.stage)
            if row is not None:
                row.noted = True
                self._stages_dirty = True
            self.analyst_state = "watching"
        elif kind in ("error", "unavailable"):
            self.analyst_error = plain(text, 400)
            if current is not None and not current.done:
                current.done = True
            self.analyst_state = "stopped" if kind == "error" else "unavailable"
            what = "stopped" if kind == "error" else "unavailable"
            msg = f"Live analyst {what}: {self.analyst_error}"
            self._write("WARNING", msg + " (the scan continues without it)")
            self.notify(
                plain(msg, 500) + "\nThe scan continues without it.",
                title="Live analyst",
                severity="warning",
                markup=False,
                timeout=8,
            )
        self._analyst_dirty = True

    def on_task_done(self, message: TaskDone) -> None:
        if message.name != "scan":
            return
        self.finished = True
        self.ended = time.monotonic()
        for row in self.rows:
            if row.finished is None:
                row.finished = self.ended
        if self.analyst_state in ("starting", "watching", "thinking", "writing"):
            self.analyst_state = "finished"
        self._render_all()
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

    # ------------------------------------------------------------------ drawing
    def _on_frame(self) -> None:
        self._frame += 1
        self._flush_ops()
        animating = not self.finished
        if self._stages_dirty or animating:
            self._render_stages()
        streaming = self.analyst_state in ("thinking", "writing", "starting")
        if self.link is not None and (self._analyst_dirty or streaming):
            self._render_analyst()
        if self._frame % 4 == 0 and not self.finished:
            self._render_elapsed()

    def _render_all(self) -> None:
        self._flush_ops()
        self._render_stages()
        self._render_analyst()
        self._render_elapsed()

    def _spin(self) -> str:
        return SPINNER[self._frame % len(SPINNER)]

    def _render_elapsed(self) -> None:
        now = self.ended or time.monotonic()
        text = Text(_clock(now - self.started) if self.started else "00:00", style="bold")
        text.append(f"  {self.op_count:,} ops", style="dim")
        self.query_one("#scan-elapsed", Label).update(text)

    def _render_stages(self) -> None:
        self._stages_dirty = False
        now = self.ended or time.monotonic()
        done = sum(1 for r in self.rows if r.finished is not None)
        box = self.query_one("#scan-stages-box", VerticalScroll)
        title = Text("Stages ")
        title.append(f"{done}/{self.total or '?'}", style="bold")
        box.border_title = title
        sub = Text(f"{self.op_count:,} ops", style="dim")
        if self.warnings:
            sub.append(f"  ⚠ {self.warnings} warning(s)", style="yellow")
        box.border_subtitle = sub
        if self.total:
            self.query_one("#scan-bar", ProgressBar).update(total=self.total, progress=done)
        if not self.rows:
            return
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=1, no_wrap=True)
        wide = self.size.width >= 110
        table.add_column(no_wrap=True, max_width=36 if wide else 24, overflow="ellipsis")
        table.add_column(justify="right", no_wrap=True, width=6)
        table.add_column(justify="right", no_wrap=True, width=6)
        table.add_column(ratio=1, overflow="fold")
        for row in self.rows:
            took = (row.finished or now) - row.started
            if row.failed:
                icon, style = Text("✗", style="bold red"), "red"
                detail = Text(plain(row.failed, 600), style="red")
            elif row.finished is None:
                icon, style = Text(self._spin(), style="bold cyan"), "bold cyan"
                detail = Text(plain(row.last_op or "working…", 300), style="dim italic")
            else:
                icon, style = Text("✓", style="green"), ""
                detail = Text(plain(row.digest, 600) if row.digest else "done", style="")
                if not row.digest:
                    detail.stylize("dim")
            if row.noted:
                detail.append(" ◆", style="magenta")
            table.add_row(
                icon,
                Text(row.title, style=style),
                Text(f"{took:5.1f}s", style="dim"),
                Text(_fmt_ops(row.ops), style="dim"),
                detail,
            )
        remaining = self.total - len(self.rows)
        if remaining > 0 and not self.finished:
            table.add_row(
                Text("·", style="dim"),
                Text(f"{remaining} more stage(s) to go", style="dim"),
                Text(""),
                Text(""),
                Text(""),
            )
        follow = box.scroll_y >= box.max_scroll_y - 1
        self.query_one("#scan-stages", Static).update(table)
        if follow:
            box.call_after_refresh(box.scroll_end, animate=False)

    def _flush_ops(self) -> None:
        if not self._pending_ops:
            return
        pending, self._pending_ops = self._pending_ops, []
        ops_log = self.query_one("#scan-ops", RichLog)
        skipped = 0
        if len(pending) > OPS_PER_FRAME:
            # Keep stage separators; summarise the oldest operations of a burst.
            cut = len(pending) - OPS_PER_FRAME
            skipped = sum(1 for _, kind, _ in pending[:cut] if kind == "op")
            pending = [p for p in pending[:cut] if p[1] != "op"] + pending[cut:]
        if skipped:
            ops_log.write(Text(f"… {skipped:,} more operation(s) scrolled past", style="dim"))
        for at, kind, msg in pending:
            ops_log.write(self._op_line(at, kind, msg))
        ops_log.border_title = Text(f"Raw operations · {self.op_count:,}")

    def _op_line(self, at: float, kind: str, msg: str) -> Text:
        stamp = max(at - self.started, 0.0) if self.started else 0.0
        if kind == "stage":
            return Text(f"── {plain(msg, 200)} ──", style="bold cyan")
        line = Text(f"{stamp:7.2f}s ", style="dim")
        body = Text(plain(msg, 600))
        if kind == "op":
            for pattern, style in _HIGHLIGHTS:
                body.highlight_regex(pattern, style)
        elif kind == "digest":
            line.append("✓ ", style="bold green")
            body.stylize("green")
        elif kind == "stage-failed":
            line.append("✗ ", style="bold red")
            body.stylize("red")
        elif kind == "warning":
            line.append("⚠ ", style="bold yellow")
            body.stylize("yellow")
        line.append_text(body)
        return line

    def _render_analyst(self) -> None:
        self._analyst_dirty = False
        box = self.query_one("#scan-analyst-box", VerticalScroll)
        title = Text("Live analyst")
        if self.analyst_label:
            title.append(" · ")
            title.append(self.analyst_label, style="bold magenta")
        box.border_title = title
        state = self.analyst_state
        status = Text(state, style="dim")
        if state in ("thinking", "writing", "starting"):
            status = Text(f"{self._spin()} {state}", style="magenta")
        elif state in ("stopped", "unavailable"):
            status = Text(state, style="yellow")
        box.border_subtitle = status
        parts: list[RenderableType] = []
        for th in self.thoughts:
            head = Text("▸ ", style="bold magenta")
            head.append(plain(th.stage, 160) or "scan", style="bold magenta")
            if th.done:
                head.append(f"  {th.took or 0:.1f}s", style="dim")
            parts.append(head)
            if th.thinking and (not th.done or self.show_thinking):
                tail = " ".join(th.thinking.split())
                if not self.show_thinking and len(tail) > THINKING_TAIL:
                    tail = "…" + tail[-THINKING_TAIL:]
                parts.append(
                    Padding(wrap_txt(tail, "dim italic", max_len=MAX_THINKING), (0, 0, 0, 2))
                )
            elif th.thinking:
                folded = Text(f"⋯ reasoned {len(th.thinking):,} chars (t shows)", style="dim")
                parts.append(Padding(folded, (0, 0, 0, 2)))
            if th.text.strip():
                parts.append(Padding(wrap_txt(th.text.strip(), max_len=MAX_COMMENT), (0, 0, 0, 2)))
            elif not th.done:
                waiting = Text(f"{self._spin()} …", style="dim")
                parts.append(Padding(waiting, (0, 0, 0, 2)))
        if self.analyst_error:
            what = "unavailable" if state == "unavailable" else "stopped"
            parts.append(Text(f"analyst {what}: {self.analyst_error}", style="yellow"))
        if not parts:
            if self.link is None:
                hint = (
                    "The live analyst is off.  Enable “Live analyst” in the scan settings "
                    "(needs the 'ai' extra and a provider key) to have a model comment on "
                    "each stage while the scan runs."
                )
            else:
                hint = "The analyst comments after each stage finishes…"
            parts.append(Text(hint, style="dim"))
        follow = box.scroll_y >= box.max_scroll_y - 1
        self.query_one("#scan-analyst", Static).update(Group(*parts))
        if follow:
            box.call_after_refresh(box.scroll_end, animate=False)

    def _write(self, level: str, text: str) -> None:
        style = {"WARNING": "yellow", "ERROR": "red", "STAGE": "bold cyan"}.get(level, "")
        line = Text(f"{level:<8}", style=style or "bold")
        line.append_text(txt(text, max_len=2000))
        self.query_one("#scan-log", RichLog).write(line)

    def analyst_text(self) -> str:
        """Plain text of the analyst pane (what a reader sees; used by tests)."""
        out: list[str] = []
        for th in self.thoughts:
            out.append(th.stage)
            if th.thinking and (not th.done or self.show_thinking):
                out.append(th.thinking)
            out.append(th.text)
        if self.analyst_error:
            out.append(self.analyst_error)
        return "\n".join(out)

    # ------------------------------------------------------------------ actions
    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action in ("toggle_thinking", "skip_analyst"):
            return self.link is not None
        return True

    def action_toggle_pane(self, pane: str) -> None:
        """Show or hide one pane (stages, ops, analyst, notes)."""
        selector = self.PANES.get(pane)
        if selector is None:
            return
        widget: Widget = self.query_one(selector)
        widget.display = not widget.display
        if pane == "analyst" and widget.display:
            self._render_analyst()

    def action_toggle_thinking(self) -> None:
        """Expand or collapse the model's reasoning for finished stages."""
        self.show_thinking = not self.show_thinking
        self._render_analyst()

    def action_skip_analyst(self) -> None:
        """Stop waiting for the analyst's last notes."""
        if self.link is not None:
            self.link.skip()
            self.notify("Skipping the live analyst's remaining notes", markup=False)

    @on(Button.Pressed, "#scan-cancel")
    def action_cancel(self) -> None:
        """Cancel (cooperatively, at the next stage boundary) and return to settings."""
        if not self.finished:
            self.cancel_event.set()
            if self.link is not None:
                self.link.cancel()
            self.notify("Scan cancelled", severity="warning", markup=False)
        self.app.pop_screen()
