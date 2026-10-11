"""Target picker: scheme, file browser or container list, validated with ``parse_target``."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    ContentSwitcher,
    DataTable,
    DirectoryTree,
    Footer,
    Input,
    Label,
    Select,
    Static,
)

from startup_sbom.errors import TargetError
from startup_sbom.tui.messages import TaskDone, run_background
from startup_sbom.tui.safe import plain, txt
from startup_sbom.tui.state import (
    DIR_SCHEMES,
    ENGINE_SCHEMES,
    SCHEMES,
    ContainerRow,
    FormValues,
    check_target,
    compose_target,
    split_target,
)
from startup_sbom.tui.widgets import SafeHeader

if TYPE_CHECKING:
    from startup_sbom.tui.app import StartupSbomApp

SCHEME_LABELS = {
    "auto": "auto (detect path)",
    "dir": "dir (root filesystem directory)",
    "host": "host (this machine)",
    "tar": "tar (rootfs tarball)",
    "docker-archive": "docker-archive (docker save)",
    "oci-dir": "oci-dir (OCI layout dir)",
    "oci-archive": "oci-archive (OCI tarball)",
    "docker": "docker (container/image)",
    "podman": "podman (container/image)",
    "nerdctl": "nerdctl (container/image)",
}
HOST_WARNING = (
    "host: reads this machine's root filesystem '/' (read-only; nothing is executed). "
    "Results describe the running host, and unreadable files are reported as warnings. "
    "Linux only."
)


class PathTree(DirectoryTree):
    """File browser filtered by scheme: directories only, or directories and files."""

    dirs_only = True

    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        out: list[Path] = []
        for p in paths:
            if p.name.startswith("."):
                continue
            try:
                is_dir = p.is_dir()
            except OSError:
                continue
            if is_dir or not self.dirs_only:
                out.append(p)
        return out


class TargetScreen(Screen[None]):
    """Choose what to scan."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("ctrl+n", "next", "Next", priority=True),
        Binding("ctrl+l", "refresh_containers", "Refresh containers", show=False),
    ]

    def __init__(self, values: FormValues | None = None, start_dir: Path | None = None) -> None:
        super().__init__()
        self.values = values or FormValues()
        self.start_dir = (start_dir or Path.cwd()).resolve()
        scheme, ref = split_target(self.values.target)
        self.initial_scheme = scheme
        self.initial_ref = ref
        self.containers: list[ContainerRow] = []

    @property
    def sbom_app(self) -> StartupSbomApp:
        return cast("StartupSbomApp", self.app)

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Vertical(id="target"):
            yield Label("Scheme")
            yield Select(
                [(Text(SCHEME_LABELS[s]), s) for s in ("auto", *SCHEMES)],
                value=self.initial_scheme,
                allow_blank=False,
                id="scheme",
            )
            with ContentSwitcher(initial="pane-path", id="target-switch"):
                with Vertical(id="pane-path"):
                    with Horizontal(classes="toolbar"):
                        yield Button("Up", id="path-up")
                        yield Button("Home", id="path-home")
                        yield Static(txt(str(self.start_dir), max_len=300), id="path-root")
                    yield PathTree(self.start_dir, id="path-tree")
                with Vertical(id="pane-engine"):
                    with Horizontal(classes="toolbar"):
                        yield Button("Refresh list", id="engine-refresh")
                        yield Static("", id="engine-status")
                    yield DataTable(cursor_type="row", zebra_stripes=True, id="container-table")
                with Vertical(id="pane-host"):
                    yield Static(Text(HOST_WARNING, style="bold yellow"), id="host-warning")
            yield Input(
                value=self.initial_ref, placeholder="path or container/image name", id="ref"
            )
            yield Static("", id="resolved")
            yield Static("", id="target-error")
            with Horizontal(classes="buttons"):
                yield Button("Next: settings (enter)", id="target-next", variant="primary")
                yield Button("Back (esc)", id="target-back")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#container-table", DataTable)
        table.add_column("Name", width=28, key="name")
        table.add_column("Image", width=36, key="image")
        table.add_column("State", width=12, key="state")
        table.add_column("ID", key="id")
        self._apply_scheme(self.initial_scheme, initial=True)
        self._update_resolved()

    # -- helpers ---------------------------------------------------------------
    @property
    def scheme(self) -> str:
        value = self.query_one("#scheme", Select).value
        return value if isinstance(value, str) else "dir"

    def resolved_target(self) -> str:
        """The target string the current widgets describe."""
        return compose_target(self.scheme, self.query_one("#ref", Input).value)

    def _apply_scheme(self, scheme: str, *, initial: bool = False) -> None:
        switch = self.query_one("#target-switch", ContentSwitcher)
        ref = self.query_one("#ref", Input)
        ref.disabled = scheme == "host"
        if scheme == "host":
            switch.current = "pane-host"
        elif scheme in ENGINE_SCHEMES:
            switch.current = "pane-engine"
            if not initial:
                ref.value = ""
            self.action_refresh_containers()
        else:
            switch.current = "pane-path"
            tree = self.query_one("#path-tree", PathTree)
            dirs_only = scheme in DIR_SCHEMES
            if tree.dirs_only != dirs_only:
                tree.dirs_only = dirs_only
                tree.reload()

    def _update_resolved(self) -> None:
        resolved = Text("Resolved target: ", style="bold")
        resolved.append_text(txt(self.resolved_target(), max_len=400))
        self.query_one("#resolved", Static).update(resolved)
        self.query_one("#target-error", Static).update("")

    def _set_root(self, path: Path) -> None:
        tree = self.query_one("#path-tree", PathTree)
        tree.path = path
        self.query_one("#path-root", Static).update(txt(str(path), max_len=300))

    # -- events ----------------------------------------------------------------
    @on(Select.Changed, "#scheme")
    def _scheme_changed(self) -> None:
        self._apply_scheme(self.scheme)
        self._update_resolved()

    @on(Input.Changed, "#ref")
    def _ref_changed(self) -> None:
        self._update_resolved()

    @on(Input.Submitted, "#ref")
    def _ref_submitted(self) -> None:
        self.action_next()

    @on(DirectoryTree.DirectorySelected, "#path-tree")
    def _dir_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        if self.scheme in DIR_SCHEMES or self.scheme == "auto":
            self.query_one("#ref", Input).value = plain(str(event.path), 4096)

    @on(DirectoryTree.FileSelected, "#path-tree")
    def _file_selected(self, event: DirectoryTree.FileSelected) -> None:
        if self.scheme not in DIR_SCHEMES:
            self.query_one("#ref", Input).value = plain(str(event.path), 4096)

    @on(Button.Pressed, "#path-up")
    def _up(self) -> None:
        tree = self.query_one("#path-tree", PathTree)
        self._set_root(Path(tree.path).resolve().parent)

    @on(Button.Pressed, "#path-home")
    def _home(self) -> None:
        self._set_root(Path.home())

    @on(Button.Pressed, "#engine-refresh")
    def action_refresh_containers(self) -> None:
        scheme = self.scheme
        if scheme not in ENGINE_SCHEMES:
            return
        self.query_one("#engine-status", Static).update(txt(f"listing {scheme} containers…"))
        lister = self.sbom_app.container_lister
        run_background(self, f"containers:{scheme}", lambda: lister(scheme))

    def on_task_done(self, message: TaskDone) -> None:
        if not message.name.startswith("containers:"):
            return
        status = self.query_one("#engine-status", Static)
        table = self.query_one("#container-table", DataTable)
        table.clear()
        self.containers = []
        if message.error is not None:
            status.update(txt(f"{message.error} — you can still type a name", "yellow"))
            return
        rows = cast("list[ContainerRow]", message.result or [])
        self.containers = rows
        for i, row in enumerate(rows):
            table.add_row(txt(row.name), txt(row.image), txt(row.state), txt(row.id), key=str(i))
        status.update(txt(f"{len(rows)} container(s); enter selects"))

    @on(DataTable.RowSelected, "#container-table")
    def _container_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self.containers):
            row = self.containers[idx]
            self.query_one("#ref", Input).value = plain(row.name.split(",")[0] or row.id)

    @on(Button.Pressed, "#target-back")
    def _back(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#target-next")
    def action_next(self) -> None:
        """Validate and continue to the settings form."""
        from startup_sbom.tui.screens.settings import SettingsScreen

        target = self.resolved_target()
        try:
            target = check_target(target)
        except TargetError as exc:
            msg = f"Invalid target: {exc}"
            self.query_one("#target-error", Static).update(txt(msg, "bold red", max_len=600))
            self.notify(plain(msg, 600), severity="error", markup=False)
            return
        if self.scheme == "host":
            self.notify(HOST_WARNING, severity="warning", markup=False)
        self.values = dataclasses.replace(self.values, target=target)
        self.app.push_screen(SettingsScreen(self.values))
