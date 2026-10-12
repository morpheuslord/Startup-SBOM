"""Results browser: summary, threats, chains, supply chain, services, packages, vulns, warnings."""

from __future__ import annotations

import os
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Input,
    Label,
    Markdown,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)

from startup_sbom.models import (
    AttackChain,
    Explanations,
    IntelBundle,
    Package,
    Reachability,
    Report,
    Service,
    Severity,
    SSVCDecision,
    Vulnerability,
)
from startup_sbom.tui import integrations, render
from startup_sbom.tui.commands import ResultsCommands
from startup_sbom.tui.data import (
    ANY,
    PAGE_SIZE,
    ROW_CAP,
    THREAT_SORTS,
    ThreatIndex,
    ThreatRow,
    best_cvss,
    fmt_epss,
    intel_for,
    merge_intel,
    package_index,
    service_listeners,
    vuln_search_index,
)
from startup_sbom.tui.messages import TaskDone, run_background
from startup_sbom.tui.safe import plain, txt, wrap_txt
from startup_sbom.tui.state import AISettings
from startup_sbom.tui.widgets import SafeHeader

if TYPE_CHECKING:
    from startup_sbom.tui.app import StartupSbomApp

_MOUNT_RETRIES = 200  # refresh cycles to wait for nested panes before giving up

TABS: tuple[tuple[str, str], ...] = (
    ("tab-summary", "1 Summary"),
    ("tab-threats", "2 Threats"),
    ("tab-chains", "3 Chains"),
    ("tab-supply", "4 Supply chain"),
    ("tab-services", "5 Services"),
    ("tab-packages", "6 Packages"),
    ("tab-vulns", "7 Vulns"),
    ("tab-warnings", "8 Warnings"),
)
THREAT_COLUMNS: tuple[tuple[str, str, int | None], ...] = (
    ("risk", "Risk", 6),
    ("ssvc", "SSVC", 7),
    ("severity", "Severity", 9),
    ("epss", "EPSS", 7),
    ("kev", "KEV", 4),
    ("reach", "Reachability", 18),
    ("package", "Package", 20),
    ("title", "Title", None),
)
DEBOUNCE = 0.15
PaletteAction = tuple[str, str, Callable[[], object]]


class ResultsScreen(Screen[None]):
    """Browse one report."""

    COMMANDS: ClassVar = {ResultsCommands}
    BINDINGS: ClassVar[list[BindingType]] = [
        *[
            Binding(str(i), f"tab('{tab}')", label.split(" ", 1)[1], show=False)
            for i, (tab, label) in enumerate(TABS, 1)
        ],
        Binding("slash", "focus_search", "Search"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("e", "export", "Export"),
        Binding("a", "ai_panel", "AI analyst"),
        Binding("i", "intel", "Intel lookup"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(
        self,
        report: Report,
        *,
        source: Path | None = None,
        fail_on: str = "none",
        policy_violated: bool = False,
        ai_settings: AISettings | None = None,
    ) -> None:
        super().__init__()
        meta = report.metadata.target
        # Set before mounting: a change after the Header mounts can race its
        # title watcher (its HeaderTitle child may not be composed yet).
        self.sub_title = plain(f"{meta.kind}:{meta.reference}", 80)
        self.report = report
        self.source = source
        self.fail_on = fail_on
        self.policy_violated = policy_violated
        self.ai_settings = ai_settings or AISettings()
        self.index = ThreatIndex(report)
        self.threat_rows: list[ThreatRow] = []
        self.current_threat: ThreatRow | None = None
        self.sort_key = "risk"
        self.sort_reverse = True
        self._built: set[str] = set()
        self._debouncers: dict[str, Timer] = {}
        self._pkg_index = package_index(report)
        self._pkg_matches: list[Package] = []
        self._pkg_page = 0
        self._vuln_index = vuln_search_index(report)
        self._vuln_rows: list[Vulnerability] = []
        self._services = list(report.services)
        self._chains = list(report.attack_chains)

    @property
    def sbom_app(self) -> StartupSbomApp:
        return cast("StartupSbomApp", self.app)

    # ------------------------------------------------------------------ compose
    def compose(self) -> ComposeResult:
        yield SafeHeader()
        # No ``initial=``: the first pane activates by itself, while an explicit
        # initial tab races ContentTabs validation when the screen is pushed
        # during app startup (e.g. ``run(report_path=...)``).
        with TabbedContent(id="tabs"):
            with TabPane(TABS[0][1], id="tab-summary"), VerticalScroll(id="summary"):
                yield Static("", id="os-badge")
                yield Static("", id="policy")
                with Grid(id="kpi-grid"):
                    for label, _, _ in render.kpis(self.report):
                        yield Static("", classes="kpi", id=f"kpi-{_slug(label)}")
                with Horizontal(id="bars"):
                    yield Static("", id="sev-bars")
                    yield Static("", id="ssvc-bars")
                yield Static("", id="drivers")
                yield Static("", id="fixplan")
                yield Static("", id="quadrant")
                yield Static("", id="ai-summary")
                yield Label("Coverage", classes="section")
                yield Static("", id="coverage")
            with TabPane(TABS[1][1], id="tab-threats"):
                with Horizontal(classes="filters"):
                    yield Input(
                        placeholder="/ search CVE, title, package, service", id="threat-search"
                    )
                    yield Select(
                        [("Any SSVC", ANY)] + [(d.value, d.value) for d in reversed(SSVCDecision)],
                        value=ANY,
                        allow_blank=False,
                        id="f-ssvc",
                    )
                    yield Select(
                        [("Any reachability", ANY)] + [(r.value, r.value) for r in Reachability],
                        value=ANY,
                        allow_blank=False,
                        id="f-reach",
                    )
                    yield Select(
                        [("Any severity", ANY)] + [(s.value, s.value) for s in Severity],
                        value=ANY,
                        allow_blank=False,
                        id="f-sev",
                    )
                    yield Checkbox("KEV only", id="f-kev")
                yield Static("", id="threat-count")
                with Horizontal(classes="split"):
                    yield DataTable(cursor_type="row", zebra_stripes=True, id="threat-table")
                    with VerticalScroll(id="threat-detail", classes="detail"):
                        yield Markdown("Select a threat.", id="threat-md", open_links=False)
                        yield Static("", id="threat-visuals")
                        with Horizontal(classes="buttons"):
                            yield Button("Read articles", id="read-articles")
                            yield Button("Intel lookup (i)", id="intel-lookup")
            with TabPane(TABS[2][1], id="tab-chains"), Horizontal(classes="split"):
                yield Tree(Text("Attack chains"), id="chain-tree")
                with VerticalScroll(classes="detail"):
                    yield Static("", id="chain-diagram")
                    yield Markdown("", id="chain-md", open_links=False)
            with TabPane(TABS[3][1], id="tab-supply"), Horizontal(classes="split"):
                with Vertical(id="supply-left"):
                    yield Label("Vendors", classes="section")
                    yield DataTable(cursor_type="row", zebra_stripes=True, id="vendor-table")
                    yield Label("Blast radius", classes="section")
                    yield Tree(Text("Blast radius"), id="blast-tree")
                with VerticalScroll(classes="detail"):
                    yield Static("", id="blast-detail")
                    yield Label("Provenance findings", classes="section")
                    yield DataTable(cursor_type="row", zebra_stripes=True, id="finding-table")
                    yield Markdown("", id="finding-md", open_links=False)
            with TabPane(TABS[4][1], id="tab-services"), Horizontal(classes="split"):
                yield DataTable(cursor_type="row", zebra_stripes=True, id="service-table")
                with VerticalScroll(classes="detail"):
                    yield Markdown("Select a service.", id="service-md", open_links=False)
            with TabPane(TABS[5][1], id="tab-packages"):
                with Horizontal(classes="filters"):
                    yield Input(placeholder="/ search packages", id="pkg-search")
                    yield Button("◀ Prev", id="pkg-prev")
                    yield Button("Next ▶", id="pkg-next")
                yield Static("", id="pkg-count")
                yield DataTable(cursor_type="row", zebra_stripes=True, id="pkg-table")
            with TabPane(TABS[6][1], id="tab-vulns"):
                with Horizontal(classes="filters"):
                    yield Input(placeholder="/ search vulnerabilities", id="vuln-search")
                yield Static("", id="vuln-count")
                with Horizontal(classes="split"):
                    yield DataTable(cursor_type="row", zebra_stripes=True, id="vuln-table")
                    with VerticalScroll(classes="detail"):
                        yield Markdown("Select a vulnerability.", id="vuln-md", open_links=False)
            with TabPane(TABS[7][1], id="tab-warnings"):
                yield RichLog(markup=False, highlight=False, wrap=True, id="warnings-log")
        yield Footer()

    def on_mount(self) -> None:
        self._initial_build(_MOUNT_RETRIES)

    def _initial_build(self, retries: int) -> None:
        # Widgets nested inside TabbedContent panes mount in their own message
        # pumps, so on a slow host they can still be pending when this screen's
        # Mount runs; wait for them instead of crashing with NoMatches.
        if not self.query("#threat-table") or not self.query("#policy"):
            if retries:
                self.call_after_refresh(self._initial_build, retries - 1)
            return
        table = self.query_one("#threat-table", DataTable)
        for key, label, width in THREAT_COLUMNS:
            table.add_column(label, key=key, width=width)
        self.refresh_summary()
        self.refresh_threats()
        self._built.update({"tab-summary", "tab-threats"})
        if self.report.explanations is None and integrations.optional_module(
            integrations.EXPLAIN_MODULE
        ):
            report = self.report
            run_background(self, "explain", lambda: integrations.explain(report))

    def on_screen_resume(self) -> None:
        if "tab-summary" in self._built:
            self.refresh_summary()

    # ------------------------------------------------------------------ summary
    def refresh_summary(self) -> None:
        """(Re)render the summary dashboard."""
        r = self.report
        self.query_one("#os-badge", Static).update(render.os_badge(r))
        policy = self.query_one("#policy", Static)
        if self.fail_on != "none":
            text = (
                Text(f"Policy --fail-on {self.fail_on}: VIOLATED", style="bold white on red")
                if self.policy_violated
                else Text(f"Policy --fail-on {self.fail_on}: passed", style="bold green")
            )
            policy.update(text)
        policy.display = self.fail_on != "none"
        for label, value, cls in render.kpis(r):
            tile = self.query_one(f"#kpi-{_slug(label)}", Static)
            content = Text(f"{value:,}\n", style="bold")
            content.append(label, style="dim")
            tile.update(content)
            tile.set_class(cls == "bad", "kpi-bad")
            tile.set_class(cls == "warn", "kpi-warn")
        self.query_one("#sev-bars", Static).update(render.severity_bars(r))
        self.query_one("#ssvc-bars", Static).update(render.ssvc_bars(r))
        optional = (
            ("#drivers", render.risk_drivers(r)),
            ("#fixplan", render.fix_plan(r)),
            ("#quadrant", integrations.viz("epss_impact_quadrant", r)),
        )
        for wid, renderable in optional:
            widget = self.query_one(wid, Static)
            widget.display = renderable is not None
            if renderable is not None:
                widget.update(renderable)
        ai_box = self.query_one("#ai-summary", Static)
        ai_box.display = r.ai is not None
        if r.ai is not None:
            text = Text("AI analyst: ", style="bold")
            text.append_text(render.ai_status(r.ai))
            text.append("\n")
            text.append_text(wrap_txt(r.ai.executive_summary, max_len=2000))
            ai_box.update(text)
        self.query_one("#coverage", Static).update(render.coverage_text(r))

    # ------------------------------------------------------------------ threats
    def _select_value(self, wid: str) -> str:
        value = self.query_one(wid, Select).value
        return value if isinstance(value, str) else ANY

    def refresh_threats(self) -> None:
        """Re-filter, re-sort and rebuild the threat table (display capped)."""
        rows = self.index.filter(
            needle=self.query_one("#threat-search", Input).value,
            ssvc=self._select_value("#f-ssvc"),
            reach=self._select_value("#f-reach"),
            severity=self._select_value("#f-sev"),
            kev_only=self.query_one("#f-kev", Checkbox).value,
            sort=self.sort_key,
            reverse=self.sort_reverse,
        )
        self.threat_rows = rows[:ROW_CAP]
        table = self.query_one("#threat-table", DataTable)
        table.clear()
        for i, row in enumerate(self.threat_rows):
            t = row.threat
            ssvc_style = render.SSVC_STYLE.get(t.ssvc.decision, "") if t.ssvc else ""
            table.add_row(
                Text(f"{t.risk_score:5.1f}", justify="right"),
                Text(row.ssvc, style=ssvc_style),
                Text(row.severity.value, style=render.SEVERITY_STYLE[row.severity]),
                Text(fmt_epss(row.epss), justify="right"),
                Text("KEV", style="bold red") if row.kev else Text(""),
                Text(t.reachability.value),
                txt(row.package_name, max_len=60),
                txt(t.title, max_len=300),
                key=str(i),
            )
        total = len(self.index.rows)
        msg = f"{len(rows)} of {total} threats · sorted by {self.sort_key}"
        msg += " ↓" if self.sort_reverse else " ↑"
        if len(rows) > ROW_CAP:
            msg += f" · showing the first {ROW_CAP:,}; refine the search"
        self.query_one("#threat-count", Static).update(Text(msg))
        if self.threat_rows:
            self.show_threat(self.threat_rows[0])
        else:
            self.current_threat = None
            self.query_one("#threat-md", Markdown).update("No threats match the filters.")
            self.query_one("#threat-visuals", Static).update("")

    def show_threat(self, row: ThreatRow) -> None:
        """Render the detail pane for ``row``."""
        self.current_threat = row
        t = row.threat
        self.query_one("#threat-md", Markdown).update(
            render.threat_markdown(t, self.report, row.vuln)
        )
        self.query_one("#threat-visuals", Static).update(
            render.group(render.threat_visuals(t, self.report))
        )
        bundle = intel_for(self.report, t.vulnerability)
        self.query_one("#read-articles", Button).display = bool(
            bundle is not None and (bundle.articles or bundle.advisories)
        )

    def _debounce(self, name: str, fn: Callable[[], None]) -> None:
        timer = self._debouncers.pop(name, None)
        if timer is not None:
            timer.stop()
        self._debouncers[name] = self.set_timer(DEBOUNCE, fn)

    @on(Input.Changed, "#threat-search")
    def _threat_search(self) -> None:
        self._debounce("threats", self.refresh_threats)

    @on(Select.Changed, "#f-ssvc, #f-reach, #f-sev")
    @on(Checkbox.Changed, "#f-kev")
    def _threat_filter(self) -> None:
        if self.is_mounted:
            self.refresh_threats()

    @on(DataTable.RowHighlighted, "#threat-table")
    def _threat_highlighted(self, event: DataTable.RowHighlighted) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self.threat_rows):
            row = self.threat_rows[idx]
            if row is not self.current_threat:
                self.show_threat(row)

    @on(DataTable.HeaderSelected, "#threat-table")
    def _threat_header(self, event: DataTable.HeaderSelected) -> None:
        key = str(event.column_key.value)
        if key == self.sort_key:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_key = key
            self.sort_reverse = key not in ("package", "title", "reach")
        self.refresh_threats()

    def focus_threat(self, threat_id: str) -> None:
        """Show the Threats tab with ``threat_id`` selected (clearing filters if needed)."""
        self.query_one("#tabs", TabbedContent).active = "tab-threats"
        idx = self._row_of(threat_id)
        if idx is None:
            self.query_one("#threat-search", Input).value = ""
            self.query_one("#f-ssvc", Select).value = ANY
            self.query_one("#f-reach", Select).value = ANY
            self.query_one("#f-sev", Select).value = ANY
            self.query_one("#f-kev", Checkbox).value = False
            self.refresh_threats()
            idx = self._row_of(threat_id)
        if idx is None:
            return
        table = self.query_one("#threat-table", DataTable)
        table.move_cursor(row=idx)
        table.focus()
        self.show_threat(self.threat_rows[idx])

    def _row_of(self, threat_id: str) -> int | None:
        for i, row in enumerate(self.threat_rows):
            if row.threat.id == threat_id:
                return i
        return None

    @on(Button.Pressed, "#read-articles")
    def _read_articles(self) -> None:
        from startup_sbom.tui.screens.article import ArticleScreen

        if self.current_threat is None:
            return
        bundle = intel_for(self.report, self.current_threat.threat.vulnerability)
        if bundle is not None:
            self.app.push_screen(ArticleScreen(bundle))

    @on(Button.Pressed, "#intel-lookup")
    def _intel_button(self) -> None:
        self.action_intel()

    # ------------------------------------------------------------------ lazy tabs
    @on(TabbedContent.TabActivated, "#tabs")
    def _tab_activated(self, event: TabbedContent.TabActivated) -> None:
        tab = event.tabbed_content.active
        if tab in self._built:
            return
        self._built.add(tab)
        builder = {
            "tab-chains": self._build_chains,
            "tab-supply": self._build_supply,
            "tab-services": self._build_services,
            "tab-packages": self._build_packages,
            "tab-vulns": self._build_vulns,
            "tab-warnings": self._build_warnings,
        }.get(tab)
        if builder is not None:
            builder()

    def ensure_built(self, tab: str) -> None:
        """Build ``tab`` now (used by tests and palette jumps)."""
        if tab not in self._built:
            self.query_one("#tabs", TabbedContent).active = tab
            self._built.add(tab)
            {
                "tab-chains": self._build_chains,
                "tab-supply": self._build_supply,
                "tab-services": self._build_services,
                "tab-packages": self._build_packages,
                "tab-vulns": self._build_vulns,
                "tab-warnings": self._build_warnings,
            }.get(tab, lambda: None)()

    # chains -------------------------------------------------------------------
    def _build_chains(self) -> None:
        tree: Tree[tuple[str, int, int]] = self.query_one("#chain-tree", Tree)
        tree.root.set_label(Text(f"Attack chains ({len(self._chains)})", style="bold"))
        tree.root.data = ("root", -1, -1)
        tree.root.expand()
        for ci, chain in enumerate(self._chains[:500]):
            label = Text(f"{chain.score:5.1f} ", style="bold")
            label.append(chain.ssvc_decision.value, style=render.SSVC_STYLE[chain.ssvc_decision])
            label.append_text(txt(f"  {chain.id}  {chain.entry} → {chain.goal}"))
            if chain.mitigated:
                label.append("  mitigated", style="green")
            node = tree.root.add(label, data=("chain", ci, -1), expand=ci < 3)
            for si, step in enumerate(chain.steps):
                slabel = txt(f"{step.from_state} → {step.to_state}: {step.title}")
                if step.threat:
                    slabel.append("  ⏎ threat", style="cyan")
                snode = node.add(slabel, data=("step", ci, si))
                for ev in step.evidence[:10]:
                    snode.add_leaf(txt(f"evidence: {ev}", "dim"), data=("step", ci, si))
                for mit in step.mitigated_by[:10]:
                    snode.add_leaf(txt(f"mitigated by: {mit}", "green"), data=("step", ci, si))
        self._show_chain(None)

    def _show_chain(self, chain: AttackChain | None) -> None:
        diagram = self.query_one("#chain-diagram", Static)
        md = self.query_one("#chain-md", Markdown)
        if chain is None:
            graph = integrations.viz("privilege_graph", self.report)
            diagram.update(graph if graph is not None else Text("Select a chain."))
            md.update("")
            return
        diagram.update(render.chain_visual(chain))
        md.update(render.chain_markdown(chain))

    @on(Tree.NodeHighlighted, "#chain-tree")
    def _chain_highlighted(self, event: Tree.NodeHighlighted[tuple[str, int, int]]) -> None:
        data = event.node.data
        if data is None or data[0] == "root":
            self._show_chain(None)
        elif 0 <= data[1] < len(self._chains):
            self._show_chain(self._chains[data[1]])

    @on(Tree.NodeSelected, "#chain-tree")
    def _chain_selected(self, event: Tree.NodeSelected[tuple[str, int, int]]) -> None:
        data = event.node.data
        if data is None or data[0] != "step":
            return
        step = self._chains[data[1]].steps[data[2]]
        if step.threat:
            self.focus_threat(step.threat)

    # supply chain ---------------------------------------------------------------
    def _build_supply(self) -> None:
        sc = self.report.supply_chain
        vendors = self.query_one("#vendor-table", DataTable)
        for key, label, width in (
            ("vendor", "Vendor", 28),
            ("packages", "Pkgs", 6),
            ("boot", "Boot", 6),
            ("services", "Svcs", 6),
            ("vulns", "Vulns", 6),
            ("critical", "Crit", 5),
            ("high", "High", 5),
            ("kev", "KEV", 4),
        ):
            vendors.add_column(label, key=key, width=width)
        for i, v in enumerate(sc.vendors[:ROW_CAP]):
            vendors.add_row(
                txt(v.vendor, max_len=60),
                *(Text(str(n)) for n in (v.packages, v.boot_packages, v.services)),
                *(Text(str(n)) for n in (v.vulnerabilities, v.critical, v.high, v.kev)),
                key=str(i),
            )
        tree: Tree[int] = self.query_one("#blast-tree", Tree)
        tree.root.set_label(Text(f"Blast radius ({len(sc.blast_radius)})", style="bold"))
        tree.root.expand()
        for i, blast in enumerate(sc.blast_radius[:500]):
            node = tree.root.add(txt(f"{blast.score:5.1f}  {blast.package}"), data=i)
            for svc in blast.services[:50]:
                node.add_leaf(txt(f"service {svc}"), data=i)
            for path in blast.example_paths[:10]:
                node.add_leaf(txt(" → ".join(path), "dim", max_len=400), data=i)
        if sc.blast_radius:
            self.query_one("#blast-detail", Static).update(
                render.blast_visual(sc.blast_radius[0], self.report)
            )
        findings = self.query_one("#finding-table", DataTable)
        findings.add_column("Severity", key="severity", width=9)
        findings.add_column("Kind", key="kind", width=20)
        findings.add_column("Title", key="title")
        for i, f in enumerate(sc.findings[:ROW_CAP]):
            findings.add_row(
                Text(f.severity.value, style=render.SEVERITY_STYLE[f.severity]),
                txt(f.kind),
                txt(f.title, max_len=200),
                key=str(i),
            )
        if sc.findings:
            self.query_one("#finding-md", Markdown).update(render.finding_markdown(sc.findings[0]))

    @on(Tree.NodeHighlighted, "#blast-tree")
    def _blast_highlighted(self, event: Tree.NodeHighlighted[int]) -> None:
        idx = event.node.data
        blasts = self.report.supply_chain.blast_radius
        if idx is not None and 0 <= idx < len(blasts):
            self.query_one("#blast-detail", Static).update(
                render.blast_visual(blasts[idx], self.report)
            )

    @on(DataTable.RowHighlighted, "#finding-table")
    def _finding_highlighted(self, event: DataTable.RowHighlighted) -> None:
        findings = self.report.supply_chain.findings
        if 0 <= event.cursor_row < len(findings):
            self.query_one("#finding-md", Markdown).update(
                render.finding_markdown(findings[event.cursor_row])
            )

    # services -------------------------------------------------------------------
    def _build_services(self) -> None:
        table = self.query_one("#service-table", DataTable)
        for key, label, width in (
            ("name", "Service", 28),
            ("init", "Init", 9),
            ("enabled", "On", 3),
            ("activation", "Activation", 14),
            ("user", "User", 10),
            ("exposure", "Expo", 5),
            ("rating", "Rating", 8),
            ("listens", "Listeners", 18),
            ("packages", "Pkgs", 4),
        ):
            table.add_column(label, key=key, width=width)
        for i, s in enumerate(self._services[:ROW_CAP]):
            h = s.hardening
            table.add_row(
                txt(s.name, max_len=60),
                Text(s.init_system.value),
                Text("✓" if s.enabled else "-"),
                txt(",".join(a.value for a in s.activation)),
                txt(h.user),
                Text("-" if h.exposure is None else f"{h.exposure:.1f}"),
                txt(h.exposure_rating or "-"),
                txt(service_listeners(s), "bold" if s.network_exposed else ""),
                Text(str(len(s.packages))),
                key=str(i),
            )
        if self._services:
            self._show_service(self._services[0])

    def _show_service(self, service: Service) -> None:
        self.query_one("#service-md", Markdown).update(render.service_markdown(service))

    @on(DataTable.RowHighlighted, "#service-table")
    def _service_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if 0 <= event.cursor_row < len(self._services):
            self._show_service(self._services[event.cursor_row])

    # packages -------------------------------------------------------------------
    def _build_packages(self) -> None:
        table = self.query_one("#pkg-table", DataTable)
        for key, label, width in (
            ("name", "Name", 28),
            ("version", "Version", 22),
            ("type", "Type", 6),
            ("arch", "Arch", 7),
            ("vendor", "Vendor", 18),
            ("repo", "Repository", 24),
            ("signed", "Signed", 6),
            ("flags", "Flags", None),
        ):
            table.add_column(label, key=key, width=width)
        self.refresh_packages()

    def refresh_packages(self, *, reset_page: bool = True) -> None:
        """Filter packages and render the current page."""
        if reset_page:
            self._pkg_matches = self._pkg_index.filter(self.query_one("#pkg-search", Input).value)
            self._pkg_page = 0
        pages = max(1, -(-len(self._pkg_matches) // PAGE_SIZE))
        self._pkg_page = min(max(self._pkg_page, 0), pages - 1)
        start = self._pkg_page * PAGE_SIZE
        chunk = self._pkg_matches[start : start + PAGE_SIZE]
        table = self.query_one("#pkg-table", DataTable)
        table.clear()
        for i, p in enumerate(chunk):
            signed = "-" if p.signed is None else ("yes" if p.signed else "NO")
            table.add_row(
                txt(p.name, max_len=60),
                txt(p.version, max_len=60),
                Text(p.type.value),
                txt(p.arch or "-"),
                txt(p.vendor or "-"),
                txt(p.repository or "-"),
                Text(signed, style="red" if p.signed is False else ""),
                txt(", ".join(p.provenance_flags), "yellow"),
                key=str(i),
            )
        total = len(self.report.packages)
        end = start + len(chunk)
        self.query_one("#pkg-count", Static).update(
            Text(
                f"rows {start + 1 if chunk else 0}–{end} of {len(self._pkg_matches):,} matching "
                f"({total:,} packages) · page {self._pkg_page + 1}/{pages}"
            )
        )

    @on(Input.Changed, "#pkg-search")
    def _pkg_search(self) -> None:
        self._debounce("packages", self.refresh_packages)

    @on(Button.Pressed, "#pkg-prev")
    def _pkg_prev(self) -> None:
        self._pkg_page -= 1
        self.refresh_packages(reset_page=False)

    @on(Button.Pressed, "#pkg-next")
    def _pkg_next(self) -> None:
        self._pkg_page += 1
        self.refresh_packages(reset_page=False)

    # vulnerabilities ---------------------------------------------------------------
    def _build_vulns(self) -> None:
        table = self.query_one("#vuln-table", DataTable)
        for key, label, width in (
            ("id", "ID", 18),
            ("package", "Package", 18),
            ("installed", "Installed", 16),
            ("fixed", "Fixed", 16),
            ("status", "Status", 12),
            ("severity", "Severity", 9),
            ("cvss", "CVSS", 5),
            ("epss", "EPSS", 7),
            ("kev", "KEV", 4),
        ):
            table.add_column(label, key=key, width=width)
        self.refresh_vulns()

    def refresh_vulns(self) -> None:
        """Filter vulnerabilities (display capped)."""
        matches = self._vuln_index.filter(self.query_one("#vuln-search", Input).value)
        self._vuln_rows = matches[:ROW_CAP]
        table = self.query_one("#vuln-table", DataTable)
        table.clear()
        for i, v in enumerate(self._vuln_rows):
            table.add_row(
                txt(v.id),
                txt(v.package_name),
                txt(v.installed_version),
                txt(", ".join(v.fixed_versions) or "-"),
                Text(v.status.value),
                Text(v.severity.value, style=render.SEVERITY_STYLE[v.severity]),
                Text(best_cvss(v)),
                Text(fmt_epss(v.epss)),
                Text("KEV", style="bold red") if v.kev else Text(""),
                key=str(i),
            )
        msg = f"{len(matches):,} of {len(self.report.vulnerabilities):,} vulnerabilities"
        if len(matches) > ROW_CAP:
            msg += f" · showing the first {ROW_CAP:,}; refine the search"
        self.query_one("#vuln-count", Static).update(Text(msg))
        if self._vuln_rows:
            self.query_one("#vuln-md", Markdown).update(render.vuln_markdown(self._vuln_rows[0]))

    @on(Input.Changed, "#vuln-search")
    def _vuln_search(self) -> None:
        self._debounce("vulns", self.refresh_vulns)

    @on(DataTable.RowHighlighted, "#vuln-table")
    def _vuln_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if 0 <= event.cursor_row < len(self._vuln_rows):
            self.query_one("#vuln-md", Markdown).update(
                render.vuln_markdown(self._vuln_rows[event.cursor_row])
            )

    # warnings -------------------------------------------------------------------
    def _build_warnings(self) -> None:
        log = self.query_one("#warnings-log", RichLog)
        log.write(Text("Coverage limitations", style="bold yellow"))
        for lim in self.report.metadata.coverage.limitations or ["none recorded"]:
            log.write(txt(f"• {lim}", max_len=1000))
        log.write(Text(""))
        log.write(Text("Warnings", style="bold yellow"))
        for warning in self.report.warnings[:5000] or ["none recorded"]:
            log.write(txt(f"• {warning}", max_len=1000))

    # ------------------------------------------------------------------ actions
    def action_tab(self, tab: str) -> None:
        """Switch to ``tab``."""
        self.query_one("#tabs", TabbedContent).active = tab

    def action_focus_search(self) -> None:
        """Focus the search box of the current tab (threats otherwise)."""
        tabs = self.query_one("#tabs", TabbedContent)
        target = {"tab-packages": "#pkg-search", "tab-vulns": "#vuln-search"}.get(tabs.active)
        if target is None:
            tabs.active = "tab-threats"
            target = "#threat-search"
        self.query_one(target, Input).focus()

    def action_cycle_sort(self) -> None:
        """Cycle the threat sort: risk → EPSS → severity."""
        self.query_one("#tabs", TabbedContent).active = "tab-threats"
        idx = THREAT_SORTS.index(self.sort_key) if self.sort_key in THREAT_SORTS else -1
        self.sort_key = THREAT_SORTS[(idx + 1) % len(THREAT_SORTS)]
        self.sort_reverse = True
        self.refresh_threats()
        self.notify(f"Threats sorted by {self.sort_key}", markup=False, timeout=2)

    def action_export(self) -> None:
        """Open the export dialog."""
        from startup_sbom.tui.screens.export import ExportScreen

        self.app.push_screen(ExportScreen(self.report))

    def action_ai_panel(self) -> None:
        """Open the AI analyst panel."""
        from startup_sbom.tui.screens.ai_panel import AIPanelScreen

        self.app.push_screen(AIPanelScreen(self.report, self.ai_settings))

    def selected_cve(self) -> str | None:
        """CVE of the highlighted vulnerability (Vulns tab) or threat."""
        tabs = self.query_one("#tabs", TabbedContent)
        if tabs.active == "tab-vulns":
            idx = self.query_one("#vuln-table", DataTable).cursor_row
            if 0 <= idx < len(self._vuln_rows):
                return self._vuln_rows[idx].id
        if self.current_threat is not None:
            return self.current_threat.threat.vulnerability
        return None

    def action_intel(self) -> None:
        """Look up intel for the selected CVE in the background."""
        cve = self.selected_cve()
        if cve is None:
            self.notify("Select a threat or vulnerability first", severity="warning", markup=False)
            return
        if not integrations.intel_available():
            self.notify("Intel lookup is not available in this installation", markup=False)
            return
        cache = os.environ.get("STARTUP_SBOM_CACHE_DIR")
        offline = self.report.metadata.coverage.offline
        self.notify(f"Looking up intel for {plain(cve)}…", markup=False, timeout=3)
        run_background(
            self,
            "intel",
            partial(
                integrations.intel_lookup,
                cve,
                offline=offline,
                cache_dir=Path(cache) if cache else None,
            ),
        )

    def action_back(self) -> None:
        """Leave a search box, else go back."""
        if isinstance(self.focused, Input):
            tabs = self.query_one("#tabs", TabbedContent)
            table_id = {
                "tab-packages": "#pkg-table",
                "tab-vulns": "#vuln-table",
            }.get(tabs.active, "#threat-table")
            self.query_one(table_id, DataTable).focus()
            return
        self.app.pop_screen()

    def palette_actions(self) -> list[PaletteAction]:
        """Screen-specific command palette entries."""
        actions: list[PaletteAction] = [
            ("Export report", "Write report files (json, sbom, sarif, pdf…)", self.action_export),
            ("AI analyst", "Run or view the grounded AI assessment", self.action_ai_panel),
            (
                "Intel lookup",
                "Fetch exploit/PoC/advisory intel for the selected CVE",
                self.action_intel,
            ),
            ("Cycle threat sort", "risk → EPSS → severity", self.action_cycle_sort),
        ]
        actions += [
            (f"Go to {label.split(' ', 1)[1]}", "Switch tab", partial(self.action_tab, tab))
            for tab, label in TABS
        ]
        return actions

    # ------------------------------------------------------------------ background results
    def on_task_done(self, message: TaskDone) -> None:
        if message.name == "explain":
            if message.error is None and isinstance(message.result, Explanations):
                self.report.explanations = message.result
            self.refresh_summary()
            if self.current_threat is not None:
                self.show_threat(self.current_threat)
        elif message.name == "intel":
            if message.error is not None:
                self.notify(
                    plain(f"Intel lookup failed: {message.error}", 500),
                    severity="error",
                    markup=False,
                )
                return
            bundle = cast("IntelBundle", message.result)
            merge_intel(self.report, bundle)
            self.notify(f"Intel updated for {plain(bundle.cve)}", markup=False)
            if self.current_threat is not None:
                self.show_threat(self.current_threat)


def _slug(label: str) -> str:
    return label.lower().replace(" ", "-").replace("/", "-")
