"""Scan settings form: every ``startup-sbom scan`` option plus intel and AI toggles."""

from __future__ import annotations

import os
from typing import ClassVar

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.suggester import SuggestFromList
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    Footer,
    Input,
    Label,
    Select,
    SelectionList,
    Static,
)
from textual.widgets.selection_list import Selection

from startup_sbom.tui import integrations
from startup_sbom.tui.safe import txt, wrap_txt
from startup_sbom.tui.state import (
    AI_AUDIENCES,
    AI_PROFILES,
    CDX_SPECS,
    FAIL_ON,
    FormValues,
    available_formats,
    build_request,
    equivalent_cli,
    validate_values,
)
from startup_sbom.tui.widgets import SafeHeader

BOOL_FIELDS: tuple[tuple[str, str], ...] = (
    ("offline", "Offline (cached data only)"),
    ("epss", "EPSS"),
    ("kev", "CISA KEV"),
    ("eol", "End-of-life"),
    ("language_packages", "Language packages"),
    ("link_analysis", "Link analysis"),
    ("integrity", "Integrity check"),
    ("vex_unreachable", "VEX: unreachable → not_affected"),
    ("prefetch_intel", "Prefetch threat intel"),
    ("intel_articles", "Fetch articles"),
    ("ai_enabled", "Run AI analysis after the scan"),
)
SOURCE_LABELS = (("osv", "OSV.dev"), ("arch", "Arch security tracker"), ("nvd", "NVD (CPE)"))
PLATFORMS = ["linux/amd64", "linux/arm64", "linux/arm64/v8", "linux/arm/v7", "linux/386"]
ONLINE_ONLY = (
    "prefetch_intel",
    "intel_articles",
    "intel_max_cves",
    "intel_max_articles",
    "intel_budget",
    "ai_enabled",
    "ai_provider",
    "ai_model",
    "ai_profile",
    "ai_audience",
    "ai_max_cost",
)


def _str(select: Select[str]) -> str:
    value = select.value
    return value if isinstance(value, str) else ""


class SettingsScreen(Screen[None]):
    """The scan settings form."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("ctrl+r", "start", "Start scan", priority=True),
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, values: FormValues) -> None:
        super().__init__()
        self.values = values
        self.formats = available_formats()

    def compose(self) -> ComposeResult:
        v = self.values
        cb = {name: Checkbox(label, getattr(v, name), id=name) for name, label in BOOL_FIELDS}
        providers = integrations.ai_providers()
        provider_opts: list[tuple[Text, str]] = [(Text("auto (default)"), "")]
        provider_opts += [
            (txt(name + ("" if ok else " (no API key in env)")), name)
            for name, ok in sorted(providers.items())
        ]
        provider_value = v.ai_provider if v.ai_provider in {o[1] for o in provider_opts} else ""
        yield SafeHeader()
        with VerticalScroll(id="settings"):
            yield Static("", id="settings-target")
            yield Label("Data", classes="section")
            with Horizontal(classes="row"):
                yield cb["offline"]
                yield cb["epss"]
                yield cb["kev"]
                yield cb["eol"]
            yield Label("Vulnerability sources", classes="section")
            yield SelectionList[str](
                *[
                    Selection(Text(label), key, key in v.sources, id=key)
                    for key, label in SOURCE_LABELS
                ],
                id="sources",
            )
            yield Static("", id="nvd-hint")
            yield Label("Analysis", classes="section")
            with Horizontal(classes="row"):
                yield cb["language_packages"]
                yield cb["link_analysis"]
                yield cb["integrity"]
            with Collapsible(title="Advanced", collapsed=False, id="advanced"):
                with Horizontal(classes="row"):
                    yield Label("Platform")
                    yield Input(
                        v.platform,
                        placeholder="os/arch[/variant], e.g. linux/arm64",
                        suggester=SuggestFromList(PLATFORMS),
                        id="platform",
                    )
                    yield Label("Boot timing file")
                    yield Input(
                        v.boot_timing,
                        placeholder="systemd-analyze plot/blame output (optional)",
                        id="boot_timing",
                    )
                with Horizontal(classes="row"):
                    yield Label("CycloneDX spec")
                    yield Select(
                        [(s, s) for s in CDX_SPECS],
                        value=v.cdx_spec,
                        allow_blank=False,
                        id="cdx_spec",
                    )
                    yield cb["vex_unreachable"]
            yield Label("Output", classes="section")
            yield SelectionList[str](
                *[Selection(Text(f), f, f in v.formats, id=f) for f in self.formats],
                id="formats",
            )
            with Horizontal(classes="row"):
                yield Label("Output directory")
                yield Input(v.output_dir, placeholder="startup-sbom-out", id="output_dir")
                yield Label("Fail on")
                yield Select(
                    [(f, f) for f in FAIL_ON], value=v.fail_on, allow_blank=False, id="fail_on"
                )
            yield Label("Threat intel prefetch (online, opt-in)", classes="section")
            with Horizontal(classes="row"):
                yield cb["prefetch_intel"]
                yield cb["intel_articles"]
            with Horizontal(classes="row"):
                yield Label("Max CVEs")
                yield Input(str(v.intel_max_cves), type="integer", id="intel_max_cves")
                yield Label("Max articles")
                yield Input(str(v.intel_max_articles), type="integer", id="intel_max_articles")
                yield Label("Budget (s)")
                yield Input(f"{v.intel_budget:g}", type="number", id="intel_budget")
            yield Label("AI analyst (optional)", classes="section")
            with Horizontal(classes="row"):
                yield cb["ai_enabled"]
                yield Label("Provider")
                yield Select(
                    provider_opts, value=provider_value, allow_blank=False, id="ai_provider"
                )
            with Horizontal(classes="row"):
                yield Label("Profile")
                yield Select(
                    [(p, p) for p in AI_PROFILES],
                    value=v.ai_profile,
                    allow_blank=False,
                    id="ai_profile",
                )
                yield Label("Audience")
                yield Select(
                    [(a, a) for a in AI_AUDIENCES],
                    value=v.ai_audience,
                    allow_blank=False,
                    id="ai_audience",
                )
                yield Label("Max cost (USD)")
                yield Input(f"{v.ai_max_cost:g}", type="number", id="ai_max_cost")
                yield Label("Model")
                yield Input(v.ai_model, placeholder="provider default", id="ai_model")
            yield Static(
                Text(
                    "API keys are read from the environment only and are never typed or stored "
                    "here." + ("" if providers else " (AI module not installed)"),
                    style="dim",
                ),
                id="ai-hint",
            )
            yield Label("Equivalent CLI command", classes="section")
            yield Static("", id="cli-preview")
            yield Static("", id="form-errors")
            with Horizontal(classes="buttons"):
                yield Button("Start scan (ctrl+r)", id="start", variant="primary")
                yield Button("Back (esc)", id="settings-back")
        yield Footer()

    def on_mount(self) -> None:
        target = Text("Target: ", style="bold")
        target.append_text(txt(self.values.target, max_len=400))
        self.query_one("#settings-target", Static).update(target)
        self._refresh()

    # -- form <-> values -------------------------------------------------------
    def read_values(self) -> tuple[FormValues, list[str]]:
        """Current widget state as :class:`FormValues` plus conversion errors."""
        q = self.query_one
        errors: list[str] = []

        def number(wid: str, label: str, default: float, *, integer: bool = False) -> float:
            raw = q(f"#{wid}", Input).value.strip()
            try:
                return int(raw) if integer else float(raw)
            except ValueError:
                errors.append(f"{label}: not a number")
                return default

        flags = {name: q(f"#{name}", Checkbox).value for name, _ in BOOL_FIELDS}
        values = FormValues(
            target=self.values.target,
            sources=tuple(q("#sources", SelectionList).selected),
            platform=q("#platform", Input).value.strip(),
            boot_timing=q("#boot_timing", Input).value.strip(),
            cdx_spec=_str(q("#cdx_spec", Select)),
            formats=tuple(q("#formats", SelectionList).selected),
            output_dir=q("#output_dir", Input).value.strip(),
            fail_on=_str(q("#fail_on", Select)),
            intel_max_cves=int(number("intel_max_cves", "max CVEs", 25, integer=True)),
            intel_max_articles=int(number("intel_max_articles", "max articles", 4, integer=True)),
            intel_budget=number("intel_budget", "intel budget", 120.0),
            ai_provider=_str(q("#ai_provider", Select)),
            ai_model=q("#ai_model", Input).value.strip(),
            ai_profile=_str(q("#ai_profile", Select)),
            ai_audience=_str(q("#ai_audience", Select)),
            ai_max_cost=number("ai_max_cost", "AI max cost", 1.0),
            **flags,
        )
        return values, errors

    def _refresh(self) -> None:
        values, _ = self.read_values()
        offline = values.offline
        sources = self.query_one("#sources", SelectionList)
        if offline:
            if "nvd" in sources.selected:
                sources.deselect("nvd")
            sources.disable_option("nvd")
        else:
            sources.enable_option("nvd")
        for wid in ONLINE_ONLY:
            self.query_one(f"#{wid}").disabled = offline
        hint = ""
        if "nvd" in values.sources and not os.environ.get("NVD_API_KEY"):
            hint = "NVD without NVD_API_KEY in the environment is heavily rate-limited."
        self.query_one("#nvd-hint", Static).update(Text(hint, style="yellow"))
        self.query_one("#cli-preview", Static).update(wrap_txt(equivalent_cli(values), "bold"))

    @on(Checkbox.Changed)
    @on(Input.Changed)
    @on(Select.Changed)
    @on(SelectionList.SelectedChanged)
    def _changed(self) -> None:
        if self.is_mounted:
            self._refresh()

    # -- actions ---------------------------------------------------------------
    @on(Button.Pressed, "#settings-back")
    def _back(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#start")
    def action_start(self) -> None:
        """Validate and start the live scan."""
        from startup_sbom.tui.screens.scan import ScanScreen

        values, errors = self.read_values()
        errors += validate_values(values)
        box = self.query_one("#form-errors", Static)
        if errors:
            box.update(wrap_txt("\n".join(errors), "bold red", max_len=4000))
            self.notify(
                "Fix the settings first:\n" + "\n".join(errors), severity="error", markup=False
            )
            return
        box.update("")
        self.values = values
        self.app.push_screen(ScanScreen(build_request(values), values))

    def current_request_target(self) -> str:
        """The target this form scans."""
        return self.values.target
