"""Live scan dashboard for the CLI: stages, raw operations and the live analyst.

``ScanDashboard`` consumes the pipeline's :class:`~startup_sbom.pipeline.ProgressEvent`
and :class:`~startup_sbom.pipeline.ActivityEvent` streams plus, when enabled, the
live analyst's :class:`~startup_sbom.ai.live.AnalystEvent` stream, and draws them
with ``rich.live`` on stderr (report output on stdout is never touched).  When
stderr is not a terminal it degrades to plain, timestamped lines.

Everything shown comes from the scanned target and is therefore untrusted: all
text goes through :func:`~startup_sbom.textsafe.safe` and is rendered as plain
``Text`` (never parsed as markup).  A journal file can record every event as
JSON lines for later review.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import IO, TYPE_CHECKING

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from startup_sbom.textsafe import clean, safe

if TYPE_CHECKING:
    from startup_sbom.ai.live import AnalystEvent
    from startup_sbom.pipeline import ActivityEvent, ProgressEvent

OPS_LINES = 14
ANALYST_STAGES = 4
_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


@dataclass(slots=True)
class _Stage:
    title: str
    started: float
    finished: float | None = None
    digest: str = ""
    failed: str = ""
    ops: int = 0


@dataclass(slots=True)
class _Thought:
    stage: str
    thinking: str = ""
    text: str = ""
    done: bool = False


@dataclass(slots=True)
class _State:
    target: str
    total: int = 0
    stages: list[_Stage] = field(default_factory=list)
    ops: deque[tuple[float, str]] = field(default_factory=lambda: deque(maxlen=OPS_LINES))
    thoughts: deque[_Thought] = field(default_factory=lambda: deque(maxlen=ANALYST_STAGES))
    analyst: str | None = None  # label, when the live analyst is on
    analyst_error: str | None = None
    warnings: int = 0
    op_count: int = 0
    finished: bool = False


class ScanDashboard:
    """Thread-safe live view of a running scan.  Use as a context manager."""

    def __init__(
        self,
        target: str,
        console: Console | None = None,
        *,
        journal: Path | None = None,
        analyst: str | None = None,
        display: str = "auto",
    ) -> None:
        """``display``: ``auto`` (live on a terminal, plain lines otherwise), ``live``,
        ``plain`` or ``none`` (journal and analyst only, nothing drawn)."""
        self.console = console or Console(stderr=True)
        if display == "auto":
            display = "live" if self.console.is_terminal else "plain"
        if display == "live" and not self.console.is_terminal:
            display = "plain"
        self.display = display
        self.live_mode = display == "live"
        self._state = _State(safe(target, 200), analyst=analyst)
        self._lock = threading.Lock()
        self._t0 = time.monotonic()
        self._live: Live | None = None
        self._journal: IO[str] | None = None
        self._journal_path = journal

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> ScanDashboard:
        if self._journal_path is not None:
            # Owner-only, like the reports: the journal names the target's files.
            fd = os.open(self._journal_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o600)  # an existing file keeps its old mode otherwise
            self._journal = os.fdopen(fd, "w", encoding="utf-8")
        if self.live_mode:
            self._live = Live(
                self,
                console=self.console,
                refresh_per_second=8,
                transient=False,
                redirect_stdout=False,
            )
            self._live.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        with self._lock:
            self._state.finished = True
            now = time.monotonic()
            for st in self._state.stages:
                st.finished = st.finished or now
        if self._live is not None:
            self._live.__exit__(exc_type, exc, tb)
            self._live = None
        if self._journal is not None:
            self._journal.close()
            self._journal = None

    # ------------------------------------------------------------------ sinks
    def progress(self, event: ProgressEvent) -> None:
        now = time.monotonic()
        with self._lock:
            st = self._state
            st.total = event.total
            if st.stages and st.stages[-1].finished is None:
                st.stages[-1].finished = now
            st.stages.append(_Stage(safe(event.stage, 120), now))
        self._record("stage", event.stage, f"{event.index}/{event.total}")
        self._plain(f"[{event.index}/{event.total}] {event.stage}")

    def activity(self, event: ActivityEvent) -> None:
        msg = safe(event.message, 400)
        with self._lock:
            st = self._state
            stage = st.stages[-1] if st.stages else None
            if event.kind == "op":
                st.op_count += 1
                st.ops.append((time.monotonic() - self._t0, msg))
                if stage is not None:
                    stage.ops += 1
            elif event.kind == "digest" and stage is not None:
                stage.digest = msg
            elif event.kind == "stage-failed" and stage is not None:
                stage.failed = msg
            elif event.kind == "warning":
                st.warnings += 1
        self._record(event.kind, event.stage, event.message, dict(event.data))
        if event.kind in ("digest", "stage-failed", "warning"):
            self._plain(f"  {event.kind}: {msg}")

    def analyst_event(self, event: AnalystEvent) -> None:
        with self._lock:
            st = self._state
            if event.kind == "start":
                st.thoughts.append(_Thought(safe(event.stage, 120)))
            elif st.thoughts and event.kind in ("thinking", "text"):
                cur = st.thoughts[-1]
                chunk = clean(event.text, keep_newlines=True)  # model output is untrusted
                if event.kind == "thinking":
                    cur.thinking = (cur.thinking + chunk)[-600:]
                else:
                    cur.text = (cur.text + chunk)[-1500:]
            elif event.kind == "done" and st.thoughts:
                st.thoughts[-1].done = True
                st.thoughts[-1].text = clean(event.text, max_len=2000)
            elif event.kind == "error":
                st.analyst_error = safe(event.text, 300)
        if event.kind in ("done", "error", "info"):
            self._record(f"analyst-{event.kind}", event.stage, event.text)
            label = "analyst" if event.kind != "error" else "analyst error"
            self._plain(f"  {label}: {safe(event.text, 600)}")

    # ------------------------------------------------------------------ output
    def _record(
        self, kind: str, stage: str, message: str, data: dict[str, object] | None = None
    ) -> None:
        if self._journal is None:
            return
        row = {
            "t": round(time.monotonic() - self._t0, 3),
            "kind": kind,
            "stage": safe(stage, 200),
            "message": clean(message, max_len=4000),
        }
        if data:
            row["data"] = data
        with self._lock:
            if self._journal is not None:
                self._journal.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")

    def _plain(self, line: str) -> None:
        if self.display != "plain":
            return
        secs = time.monotonic() - self._t0
        self.console.print(Text(f"{secs:7.1f}s {safe(line, 800)}"), highlight=False)

    def __rich__(self) -> RenderableType:
        with self._lock:
            return self._render()

    def _render(self) -> RenderableType:
        st = self._state
        now = time.monotonic()
        done = sum(1 for s in st.stages if s.finished is not None)
        parts: list[RenderableType] = [self._header(st, now, done)]
        parts.append(self._stage_table(st, now))
        ops = Text()
        for t, line in st.ops:
            ops.append(f"{t:7.1f}s ", style="dim")
            ops.append(line + "\n")
        parts.append(
            Panel(
                ops or Text("waiting for the first operation…", style="dim"),
                title=f"raw operations ({st.op_count:,})",
                title_align="left",
                border_style="grey37",
            )
        )
        if st.analyst is not None:
            parts.append(self._analyst_panel(st, now))
        return Group(*parts)

    def _header(self, st: _State, now: float, done: int) -> RenderableType:
        elapsed = int(now - self._t0)
        head = Table.grid(expand=True)
        head.add_column(ratio=1)
        head.add_column(justify="right")
        title = Text("startup-sbom ", style="bold cyan")
        title.append(st.target, style="bold")
        status = "done" if st.finished else _SPIN[int(now * 8) % len(_SPIN)]
        right = Text(
            f"{status}  {done}/{st.total or '?'} stages  {elapsed // 60:02d}:{elapsed % 60:02d}"
        )
        if st.warnings:
            right.append(f"  {st.warnings} warning(s)", style="yellow")
        head.add_row(title, right)
        bar = ProgressBar(total=max(st.total, 1), completed=done, width=None)
        return Group(head, bar)

    def _stage_table(self, st: _State, now: float) -> RenderableType:
        table = Table.grid(padding=(0, 1))
        table.add_column(width=2)
        table.add_column(no_wrap=True, min_width=28)
        table.add_column(justify="right", width=7)
        table.add_column(ratio=1, overflow="fold")
        for s in st.stages:
            took = (s.finished or now) - s.started
            if s.failed:
                icon, style, detail = "✗", "red", Text(s.failed, style="red")
            elif s.finished is None:
                icon, style = _SPIN[int(now * 8) % len(_SPIN)], "bold cyan"
                detail = Text(f"{s.ops:,} operation(s) so far…", style="dim")
            else:
                icon, style, detail = "✓", "green", Text(s.digest or "", style="")
            table.add_row(
                Text(icon, style=style),
                Text(s.title, style=style),
                Text(f"{took:5.1f}s", style="dim"),
                detail,
            )
        return table

    def _analyst_panel(self, st: _State, now: float) -> RenderableType:
        body = Text()
        for th in st.thoughts:
            body.append(f"▸ {th.stage}\n", style="bold magenta")
            if th.thinking and not th.done:
                body.append("  thinking: " + th.thinking.strip()[-300:] + "\n", style="dim italic")
            if th.text:
                body.append("  " + th.text.strip() + "\n")
            elif not th.done:
                body.append("  " + _SPIN[int(now * 8) % len(_SPIN)] + " …\n", style="dim")
        if st.analyst_error:
            body.append(f"analyst stopped: {st.analyst_error}\n", style="yellow")
        if not body:
            body = Text("the analyst comments after each stage…", style="dim")
        return Panel(
            body,
            title=f"live analyst · {st.analyst}",
            title_align="left",
            border_style="magenta",
        )
