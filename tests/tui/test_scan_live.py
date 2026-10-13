"""Live scan screen: raw operations, stage digests, the live analyst and its failure paths."""

from __future__ import annotations

import io
import logging
import threading
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any, ClassVar

import pytest
from rich.console import Console
from tuihelpers import results_ready, run_ui, wait_until

from startup_sbom.ai import AIUnavailableError
from startup_sbom.errors import ScanCancelledError
from startup_sbom.models import Report
from startup_sbom.pipeline import ActivityEvent, ProgressEvent
from startup_sbom.tui.app import StartupSbomApp
from startup_sbom.tui.screens import scan as scan_mod
from startup_sbom.tui.screens.results import ResultsScreen
from startup_sbom.tui.screens.scan import ScanScreen
from startup_sbom.tui.state import FormValues, build_request

MakeApp = Callable[..., StartupSbomApp]

STAGES: list[tuple[str, list[str], str]] = [
    (
        "Identifying operating system",
        ["read /etc/os-release (212 B)"],
        "Debian GNU/Linux 12 (bookworm)",
    ),
    (
        "Reading package databases",
        ["dpkg: 1,115 installed package(s) read"],
        "1,115 OS packages from dpkg",
    ),
    (
        "Analysing executables and linked libraries",
        ["elf /usr/bin/sudo: 9 libraries [setuid]", "elf /usr/sbin/sshd: 23 libraries"],
        "412 executables, 37 privileged",
    ),
    (
        "Matching vulnerabilities",
        ["GET api.osv.dev/v1/querybatch → 200 (312 ms, 40.1 kB)"],
        "",  # this stage fails instead of producing a digest
    ),
]
PRE_OP = "acquire: dir target opened (pre-capture)"


def fake_scan_factory(
    report: Report,
    *,
    gate: threading.Event | None = None,
    stage_seconds: float = 0.0,
) -> Callable[..., Report]:
    """A pipeline.scan stand-in that emits progress and activity like the real one."""

    def fake_scan(
        target: str,
        options: object = None,
        *,
        http: object = None,
        progress: Callable[[ProgressEvent], None] | None = None,
        strict: bool = False,
        cancel: threading.Event | None = None,
        activity: Callable[[ActivityEvent], None] | None = None,
    ) -> Report:
        assert activity is not None, "the TUI must pass activity="
        # An operation logged before the pipeline starts capturing (target acquisition)
        # propagates to the startup_sbom logger: it must land in the ops pane only.
        logging.getLogger("startup_sbom.ops").info(PRE_OP)
        for i, (stage, ops, digest) in enumerate(STAGES, 1):
            if cancel is not None and cancel.is_set():
                raise ScanCancelledError(f"scan cancelled before: {stage}")
            if progress is not None:
                progress(ProgressEvent(stage, i, len(STAGES)))
            logging.getLogger("startup_sbom.pipeline").info(
                "stage %d/%d: %s", i, len(STAGES), stage
            )
            for op in ops:
                activity(ActivityEvent(stage, "op", op))
            if stage_seconds:
                time.sleep(stage_seconds)
            if digest:
                activity(ActivityEvent(stage, "digest", digest, {"count": 1}))
            else:
                activity(ActivityEvent(stage, "stage-failed", "TimeoutError: osv.dev timed out"))
        if gate is not None:
            gate.wait(20)
        return report

    return fake_scan


class FakeAnalyst:
    """Stands in for LiveAnalyst: comments synchronously on every digest."""

    instances: ClassVar[list[FakeAnalyst]] = []

    def __init__(
        self,
        sink: Callable[[Any], None],
        *,
        fail_on: str | None = None,
        block_close: bool = False,
    ) -> None:
        self.sink = sink
        self.label = "fake:narrator"
        self.error: str | None = None
        self.commentary: list[tuple[str, str]] = []
        self.fed: list[str] = []
        self.started = False
        self.cancelled = threading.Event()
        self.closed = False
        self.fail_on = fail_on
        self.block_close = block_close
        FakeAnalyst.instances.append(self)

    def _emit(self, stage: str, kind: str, text: str) -> None:
        from startup_sbom.ai.live import AnalystEvent

        self.sink(AnalystEvent(stage, kind, text))

    def start(self) -> None:
        self.started = True
        self._emit("", "info", f"live analyst: {self.label}")

    def feed(self, event: ActivityEvent) -> None:
        self.fed.append(event.kind)
        if event.kind != "digest" or self.cancelled.is_set():
            return
        stage = event.stage
        if stage == self.fail_on:
            self.error = "provider exploded"
            self.cancelled.set()  # like LiveAnalyst: an error ends the analyst
            self._emit(stage, "error", self.error)
            return
        self._emit(stage, "start", "")
        self._emit(stage, "thinking", f"pondering {stage} deeply")
        self._emit(stage, "text", "Looks ")
        self._emit(stage, "text", "fine.")
        note = f"Note on {stage}: looks fine."
        self.commentary.append((stage, note))
        self._emit(stage, "done", note)

    def close(self, wait: float = 60.0) -> None:
        if self.block_close:
            self.cancelled.wait(wait)
        self.closed = True

    def cancel(self) -> None:
        self.cancelled.set()


@pytest.fixture(autouse=True)
def _reset_fakes() -> None:
    FakeAnalyst.instances.clear()


def _push_scan(app: StartupSbomApp, tmp_path: Path, **values: Any) -> FormValues:
    form = FormValues(target=f"dir:{tmp_path}", formats=(), **values)
    app.push_screen(ScanScreen(build_request(form, env={}), form))
    return form


def _log_lines(screen: ScanScreen, selector: str) -> list[str]:
    from textual.widgets import RichLog

    log = screen.query_one(selector, RichLog)
    return ["".join(seg.text for seg in strip) for strip in log.lines]


def _static_text(screen: ScanScreen, selector: str, width: int = 160) -> str:
    from textual.widgets import Static

    console = Console(file=io.StringIO(), width=width, color_system=None)
    console.print(screen.query_one(selector, Static).content)
    return console.file.getvalue()  # type: ignore[attr-defined]


def _mounted(app: StartupSbomApp) -> bool:
    """The live-scan screen is on top and its ``on_mount`` has run."""
    screen = app.screen
    return isinstance(screen, ScanScreen) and screen.started > 0


def _scan_screen(app: StartupSbomApp) -> ScanScreen:
    screen = app.screen
    assert isinstance(screen, ScanScreen)
    return screen


# ------------------------------------------------------------------- activity
def test_ops_and_digests_render_without_duplicates(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = threading.Event()
    monkeypatch.setattr("startup_sbom.pipeline.scan", fake_scan_factory(report, gate=gate))
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            _push_scan(app, tmp_path)
            await wait_until(pilot, lambda: _mounted(app))
            screen = _scan_screen(app)
            await wait_until(
                pilot,
                lambda: len(screen.rows) == len(STAGES) and bool(screen.rows[-1].failed),
                message="stages never all reported",
            )
            await pilot.pause(0.3)  # one frame flushes the buffered ops
            ops = _log_lines(screen, "#scan-ops")
            joined = "\n".join(ops)
            assert "dpkg: 1,115 installed package(s) read" in joined
            assert "elf /usr/bin/sudo: 9 libraries [setuid]" in joined
            assert sum(PRE_OP in line for line in ops) == 1  # routed once, to the ops pane
            assert any("Reading package databases" in line and "──" in line for line in ops)
            notes = "\n".join(_log_lines(screen, "#scan-log"))
            assert PRE_OP not in notes
            assert "dpkg: 1,115" not in notes
            assert "stage 2/" not in notes  # the pipeline's stage record is a row now
            assert screen.op_count == 6
            rows = {r.title: r for r in screen.rows}
            assert rows["Reading package databases"].digest == "1,115 OS packages from dpkg"
            assert rows["Analysing executables and linked libraries"].ops == 2
            assert rows["Matching vulnerabilities"].failed.startswith("TimeoutError")
            table = _static_text(screen, "#scan-stages")
            assert "1,115 OS packages from dpkg" in table
            assert "412 executables, 37 privileged" in table
            assert "✗" in table
            assert "✓" in table
            # the analyst pane is hidden when the live analyst is off
            assert not screen.query_one("#scan-analyst-box").display
            gate.set()
            await wait_until(pilot, lambda: results_ready(app))

    run_ui(main())


def test_hostile_activity_text_is_sanitised(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = threading.Event()
    evil = "[bold red]boom[/] \x1b[31mred\x1b[0m"

    def scan(*a: object, **kw: Any) -> Report:
        kw["progress"](ProgressEvent("stage [b]x[/b]", 1, 1))
        kw["activity"](ActivityEvent("stage [b]x[/b]", "op", evil))
        kw["activity"](ActivityEvent("stage [b]x[/b]", "digest", evil))
        gate.wait(20)
        return report

    monkeypatch.setattr("startup_sbom.pipeline.scan", scan)
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            _push_scan(app, tmp_path)
            await wait_until(pilot, lambda: _mounted(app))
            screen = _scan_screen(app)
            await wait_until(pilot, lambda: bool(screen.rows) and bool(screen.rows[0].digest))
            await pilot.pause(0.3)
            ops = "\n".join(_log_lines(screen, "#scan-ops"))
            assert "[bold red]boom[/]" in ops  # shown literally, never parsed as markup
            assert "\x1b" not in ops
            assert "\x1b" not in _static_text(screen, "#scan-stages")
            gate.set()
            await wait_until(pilot, lambda: results_ready(app))

    run_ui(main())


# ------------------------------------------------------------------- live analyst
def test_live_analyst_thinking_text_and_done_render(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = threading.Event()
    monkeypatch.setattr("startup_sbom.pipeline.scan", fake_scan_factory(report, gate=gate))
    seen_settings: list[Any] = []

    def factory(sink: Callable[[Any], None], settings: Any) -> FakeAnalyst:
        seen_settings.append(settings)
        return FakeAnalyst(sink)

    monkeypatch.setattr(scan_mod, "make_live_analyst", factory)
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            _push_scan(app, tmp_path, ai_live=True, ai_provider="openai", ai_max_cost=0.5)
            await wait_until(pilot, lambda: _mounted(app))
            screen = _scan_screen(app)
            await wait_until(
                pilot,
                lambda: sum(t.done for t in screen.thoughts) == 3,
                message="analyst commentary never arrived",
            )
            await pilot.pause(0.3)
            assert screen.query_one("#scan-analyst-box").display
            assert screen.analyst_label == "fake:narrator"
            thought = screen.thoughts[1]
            assert thought.stage == "Reading package databases"
            assert thought.thinking == "pondering Reading package databases deeply"
            assert thought.text == "Note on Reading package databases: looks fine."
            pane = _static_text(screen, "#scan-analyst")
            assert "Note on Reading package databases: looks fine." in pane
            assert "reasoned" in pane  # finished thinking collapses…
            assert "pondering Reading" not in pane
            await pilot.press("t")  # …and t expands it again
            await pilot.pause()
            assert "pondering Reading package databases deeply" in _static_text(
                screen, "#scan-analyst"
            )
            assert "◆" in _static_text(screen, "#scan-stages")  # commented stages are marked
            fake = FakeAnalyst.instances[0]
            assert fake.started
            assert {"op", "digest", "stage-failed"} <= set(fake.fed)
            gate.set()
            await wait_until(pilot, lambda: results_ready(app))
            results = app.screen
            assert isinstance(results, ResultsScreen)
            assert ("Identifying operating system", fake.commentary[0][1]) in results.analyst_notes
            assert fake.closed
            assert results.report.ai is None  # display-only: nothing stored in the report

    run_ui(main())
    settings = seen_settings[0]
    assert settings.live is True
    assert settings.provider == "openai"
    assert settings.max_cost_usd == 0.5


def test_live_analyst_streaming_shows_thinking_before_done(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Directly drive analyst messages: streaming thinking is shown dim, then replaced."""
    gate = threading.Event()
    monkeypatch.setattr(
        "startup_sbom.pipeline.scan",
        lambda *a, **kw: (gate.wait(20), report)[1],
    )
    monkeypatch.setattr(scan_mod, "make_live_analyst", lambda sink, s: FakeAnalyst(sink))
    app = make_app()

    async def main() -> None:
        from startup_sbom.tui.messages import ScanAnalyst

        async with app.run_test(size=(120, 40)) as pilot:
            _push_scan(app, tmp_path, ai_live=True)
            await wait_until(pilot, lambda: _mounted(app))
            screen = _scan_screen(app)
            screen.post_message(ScanAnalyst("Discovering services", "start", ""))
            screen.post_message(ScanAnalyst("Discovering services", "thinking", "hmm, 42 "))
            screen.post_message(ScanAnalyst("Discovering services", "thinking", "units…"))
            await pilot.pause(0.3)
            pane = _static_text(screen, "#scan-analyst")
            assert "hmm, 42 units…" in pane
            assert screen.analyst_state == "thinking"
            screen.post_message(ScanAnalyst("Discovering services", "text", "Socket "))
            screen.post_message(ScanAnalyst("Discovering services", "text", "activation"))
            await pilot.pause(0.3)
            assert "Socket activation" in _static_text(screen, "#scan-analyst")
            assert screen.analyst_state == "writing"
            screen.post_message(
                ScanAnalyst("Discovering services", "done", "Socket activation everywhere.")
            )
            await pilot.pause(0.3)
            pane = _static_text(screen, "#scan-analyst")
            assert "Socket activation everywhere." in pane
            assert "hmm, 42" not in pane
            gate.set()
            await wait_until(pilot, lambda: results_ready(app))

    run_ui(main())


def test_real_live_analyst_with_function_model(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("pydantic_ai")
    from pydantic_ai.messages import ModelMessage
    from pydantic_ai.models.function import AgentInfo, DeltaThinkingPart, FunctionModel

    from startup_sbom.ai.live import LiveAnalyst

    async def narrator(messages: list[ModelMessage], info: AgentInfo) -> AsyncIterator[object]:
        yield {0: DeltaThinkingPart(content="weighing the digest")}
        yield "Model says: "
        yield "nothing alarming."

    def factory(sink: Callable[[Any], None], settings: Any) -> LiveAnalyst:
        return LiveAnalyst(sink, model_override=FunctionModel(stream_function=narrator))

    monkeypatch.setattr("startup_sbom.pipeline.scan", fake_scan_factory(report))
    monkeypatch.setattr(scan_mod, "make_live_analyst", factory)
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            _push_scan(app, tmp_path, ai_live=True)
            await wait_until(pilot, lambda: results_ready(app), timeout=30)
            results = app.screen
            assert isinstance(results, ResultsScreen)
            assert results.analyst_notes
            assert all("nothing alarming." in note for _, note in results.analyst_notes)

    run_ui(main())


def test_live_analyst_unavailable_notifies_and_scan_continues(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def factory(sink: Callable[[Any], None], settings: Any) -> FakeAnalyst:
        raise AIUnavailableError("the AI layer needs: pip install 'startup-sbom[ai]'")

    monkeypatch.setattr("startup_sbom.pipeline.scan", fake_scan_factory(report))
    monkeypatch.setattr(scan_mod, "make_live_analyst", factory)
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(120, 40), notifications=True) as pilot:
            _push_scan(app, tmp_path, ai_live=True)
            await wait_until(pilot, lambda: results_ready(app))
            assert any(
                "Live analyst unavailable" in n.message and "startup-sbom[ai]" in n.message
                for n in app._notifications
            )
            results = app.screen
            assert isinstance(results, ResultsScreen)
            assert results.analyst_notes == []

    run_ui(main())


def test_live_analyst_error_mid_scan_notifies_and_scan_continues(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = threading.Event()
    monkeypatch.setattr("startup_sbom.pipeline.scan", fake_scan_factory(report, gate=gate))
    monkeypatch.setattr(
        scan_mod,
        "make_live_analyst",
        lambda sink, s: FakeAnalyst(sink, fail_on="Reading package databases"),
    )
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(120, 40), notifications=True) as pilot:
            _push_scan(app, tmp_path, ai_live=True)
            await wait_until(pilot, lambda: _mounted(app))
            screen = _scan_screen(app)
            await wait_until(
                pilot,
                lambda: any("Live analyst stopped" in n.message for n in app._notifications),
                message="no analyst-stopped notification",
            )
            assert screen.analyst_state == "stopped"
            await pilot.pause(0.3)
            assert "provider exploded" in _static_text(screen, "#scan-analyst")
            assert any("provider exploded" in line for line in _log_lines(screen, "#scan-log"))
            gate.set()
            await wait_until(pilot, lambda: results_ready(app))  # the scan still finished

    run_ui(main())


def test_cancel_cancels_the_live_analyst(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("startup_sbom.pipeline.scan", fake_scan_factory(report, stage_seconds=0.4))
    monkeypatch.setattr(scan_mod, "make_live_analyst", lambda sink, s: FakeAnalyst(sink))
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            _push_scan(app, tmp_path, ai_live=True)
            await wait_until(pilot, lambda: _mounted(app))
            await wait_until(pilot, lambda: bool(FakeAnalyst.instances))
            screen = _scan_screen(app)
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, ScanScreen)
            assert screen.cancel_event.is_set()
            assert FakeAnalyst.instances[0].cancelled.is_set()

    run_ui(main())


def test_skip_stops_waiting_for_the_analyst(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("startup_sbom.pipeline.scan", fake_scan_factory(report))
    monkeypatch.setattr(
        scan_mod, "make_live_analyst", lambda sink, s: FakeAnalyst(sink, block_close=True)
    )
    app = make_app()

    async def main() -> None:
        from textual.widgets import Label

        async with app.run_test(size=(120, 40)) as pilot:
            _push_scan(app, tmp_path, ai_live=True)
            await wait_until(pilot, lambda: _mounted(app))
            screen = _scan_screen(app)
            await wait_until(
                pilot,
                lambda: (
                    "finishing its notes" in str(screen.query_one("#scan-stage", Label).content)
                ),
                message="never waited for the analyst",
            )
            await pilot.press("k")
            await wait_until(pilot, lambda: results_ready(app), timeout=5)
            assert FakeAnalyst.instances[0].cancelled.is_set()

    run_ui(main())


# ------------------------------------------------------------------- layout
def test_small_terminal_stacks_panes_and_toggles(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = threading.Event()
    monkeypatch.setattr("startup_sbom.pipeline.scan", fake_scan_factory(report, gate=gate))
    monkeypatch.setattr(scan_mod, "make_live_analyst", lambda sink, s: FakeAnalyst(sink))
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            _push_scan(app, tmp_path, ai_live=True)
            await wait_until(pilot, lambda: _mounted(app))
            screen = _scan_screen(app)
            await pilot.pause(0.2)
            assert screen.has_class("-narrow")
            assert screen.has_class("-short")
            ops = screen.query_one("#scan-ops")
            analyst = screen.query_one("#scan-analyst-box")
            assert ops.region.width > 70  # stacked: each pane spans the width
            assert analyst.region.width > 70
            assert not screen.query_one("#scan-log").display  # notes start hidden
            await pilot.press("o")
            await pilot.pause()
            assert not ops.display
            await pilot.press("n")
            await pilot.pause()
            assert screen.query_one("#scan-log").display
            await pilot.press("o")
            await pilot.pause()
            assert ops.display
            gate.set()
            await wait_until(pilot, lambda: results_ready(app))

    run_ui(main())


def test_wide_terminal_puts_panes_side_by_side(
    make_app: MakeApp, report: Report, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = threading.Event()
    monkeypatch.setattr("startup_sbom.pipeline.scan", fake_scan_factory(report, gate=gate))
    monkeypatch.setattr(scan_mod, "make_live_analyst", lambda sink, s: FakeAnalyst(sink))
    app = make_app()

    async def main() -> None:
        async with app.run_test(size=(120, 40)) as pilot:
            _push_scan(app, tmp_path, ai_live=True)
            await wait_until(pilot, lambda: _mounted(app))
            screen = _scan_screen(app)
            await pilot.pause(0.2)
            assert screen.has_class("-wide")
            ops = screen.query_one("#scan-ops").region
            analyst = screen.query_one("#scan-analyst-box").region
            assert ops.y == analyst.y
            assert ops.right <= analyst.x
            assert screen.query_one("#scan-log").display
            gate.set()
            await wait_until(pilot, lambda: results_ready(app))

    run_ui(main())


# ------------------------------------------------------------------- settings
def test_live_analyst_setting_maps_to_request_and_cli(make_app: MakeApp, tmp_path: Path) -> None:
    from startup_sbom.tui.screens.settings import SettingsScreen
    from startup_sbom.tui.state import equivalent_cli

    app = make_app()

    async def main() -> None:
        from textual.widgets import Checkbox

        async with app.run_test(size=(160, 60)) as pilot:
            app.push_screen(SettingsScreen(FormValues(target=f"dir:{tmp_path}")))
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, SettingsScreen)
            box = screen.query_one("#ai_live", Checkbox)
            assert box.value is False  # off by default
            box.value = True
            await pilot.pause(0.1)
            values, errors = screen.read_values()
            assert errors == []
            assert values.ai_live is True
            assert build_request(values, env={}).ai.live is True
            assert "--ai-live" in equivalent_cli(values)
            screen.query_one("#offline", Checkbox).value = True
            await pilot.pause(0.1)
            assert box.disabled
            values, _ = screen.read_values()
            assert build_request(values, env={}).ai.live is False

    run_ui(main())
