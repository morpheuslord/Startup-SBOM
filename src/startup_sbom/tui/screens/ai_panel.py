"""AI analyst panel: run ``ai.analyze`` in the background and stream its output."""

from __future__ import annotations

from typing import ClassVar, cast

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Label, Markdown, Select, Static
from textual.widgets.markdown import MarkdownStream

from startup_sbom.models import AIAssessment, Report
from startup_sbom.textsafe import safe_block
from startup_sbom.tui import integrations, render
from startup_sbom.tui.messages import AIChunk, TaskDone, run_background
from startup_sbom.tui.safe import md_escape, plain, txt
from startup_sbom.tui.state import AI_AUDIENCES, AI_PROFILES, AISettings
from startup_sbom.tui.widgets import SafeHeader

INTRO = (
    "The AI analyst reviews the deterministic findings; every statement must cite report "
    "ids and is machine-checked (grounding). Provider API keys come from the environment. "
    "Model output is untrusted and shown escaped."
)


class AIPanelScreen(Screen[None]):
    """Run, stream and store the grounded AI assessment."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("ctrl+r", "run", "Run analysis", priority=True),
        Binding("e", "export", "Export"),
    ]

    def __init__(self, report: Report, settings: AISettings | None = None) -> None:
        super().__init__()
        self.report = report
        self.settings = settings or AISettings()
        self.running = False
        self._stream: MarkdownStream | None = None

    def compose(self) -> ComposeResult:
        s = self.settings
        providers = integrations.ai_providers()
        opts: list[tuple[Text, str]] = [(Text("auto (default)"), "")]
        opts += [
            (txt(name + ("" if ok else " (no API key in env)")), name)
            for name, ok in sorted(providers.items())
        ]
        provider = s.provider if s.provider in providers else ""
        yield SafeHeader()
        with Horizontal(classes="row"):
            yield Label("Provider")
            yield Select(opts, value=provider, allow_blank=False, id="ai-provider")
            yield Label("Profile")
            yield Select(
                [(p, p) for p in AI_PROFILES], value=s.profile, allow_blank=False, id="ai-profile"
            )
            yield Label("Audience")
            yield Select(
                [(a, a) for a in AI_AUDIENCES],
                value=s.audience,
                allow_blank=False,
                id="ai-audience",
            )
            yield Label("Max cost (USD)")
            yield Input(f"{s.max_cost_usd:g}", type="number", id="ai-cost")
            yield Input(s.model or "", placeholder="model (default)", id="ai-model")
        with Horizontal(classes="buttons"):
            yield Button("Run analysis (ctrl+r)", id="ai-run", variant="primary")
            yield Button("Export report (e)", id="ai-export")
            yield Button("Back (esc)", id="ai-back")
        yield Static(Text(INTRO, style="dim"), id="ai-status")
        with VerticalScroll(classes="detail", id="ai-scroll"):
            yield Markdown("", id="ai-md", open_links=False)
        yield Footer()

    def on_mount(self) -> None:
        if self.report.ai is not None:
            self._show(self.report.ai)
        elif not integrations.ai_available():
            self.query_one("#ai-md", Markdown).update(
                "AI analysis is not installed. Install the extra: "
                "`pip install 'startup-sbom[ai]'` and set a provider API key in the environment."
            )

    def read_settings(self) -> AISettings:
        """Current panel values."""

        def sel(wid: str, default: str) -> str:
            value = self.query_one(wid, Select).value
            return value if isinstance(value, str) else default

        try:
            cost = float(self.query_one("#ai-cost", Input).value)
        except ValueError:
            cost = self.settings.max_cost_usd
        return AISettings(
            enabled=True,
            provider=sel("#ai-provider", "") or None,
            model=self.query_one("#ai-model", Input).value.strip() or None,
            profile=sel("#ai-profile", "cheap"),
            audience=sel("#ai-audience", "technical"),
            max_cost_usd=max(cost, 0.0),
        )

    @on(Button.Pressed, "#ai-run")
    def action_run(self) -> None:
        """Start the analysis in a daemon thread; chunks arrive as messages."""
        if self.running:
            return
        if not integrations.ai_available():
            self.notify(
                "AI analysis is not installed: pip install 'startup-sbom[ai]'",
                severity="error",
                markup=False,
            )
            return
        if self.report.metadata.coverage.offline:
            self.notify(
                "This report was produced offline; the AI call still needs network.",
                severity="warning",
                markup=False,
            )
        self.settings = self.read_settings()
        self.running = True
        md = self.query_one("#ai-md", Markdown)
        md.update("")
        self._stream = Markdown.get_stream(md)
        self.query_one("#ai-status", Static).update(Text("analysing…", style="bold"))
        report, settings = self.report, self.settings

        def chunk(data: object) -> None:
            self.post_message(AIChunk(str(data)))

        run_background(self, "ai", lambda: integrations.ai_analyze(report, settings, chunk))

    async def on_ai_chunk(self, message: AIChunk) -> None:
        if self._stream is not None:
            await self._stream.write(md_escape(safe_block(message.text, 20_000)))

    async def on_task_done(self, message: TaskDone) -> None:
        if message.name != "ai":
            return
        self.running = False
        if self._stream is not None:
            await self._stream.stop()
            self._stream = None
        if message.error is not None:
            text = plain(
                f"AI analysis failed: {type(message.error).__name__}: {message.error}", 800
            )
            self.query_one("#ai-status", Static).update(txt(text, "bold red", max_len=800))
            self.notify(text, severity="error", markup=False)
            return
        assessment = cast("AIAssessment", message.result)
        self.report.ai = assessment
        self._show(assessment)
        self.notify("AI assessment stored in the report (export to keep it)", markup=False)

    def _show(self, assessment: AIAssessment) -> None:
        self.query_one("#ai-status", Static).update(render.ai_status(assessment))
        self.query_one("#ai-md", Markdown).update(render.assessment_markdown(assessment))

    @on(Button.Pressed, "#ai-export")
    def action_export(self) -> None:
        """Export the report including the AI assessment."""
        from startup_sbom.tui.screens.export import ExportScreen

        self.app.push_screen(ExportScreen(self.report))

    @on(Button.Pressed, "#ai-back")
    def _back(self) -> None:
        self.app.pop_screen()
