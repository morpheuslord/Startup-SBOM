"""Open-report dialog: browse to (or type) a ``report.json``."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import ClassVar

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Input, Label, Static

from startup_sbom.tui.safe import txt


class ReportTree(DirectoryTree):
    """Directories and ``*.json`` files only (dotfiles hidden)."""

    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        out: list[Path] = []
        for p in paths:
            if p.name.startswith("."):
                continue
            try:
                if p.is_dir() or p.suffix.lower() == ".json":
                    out.append(p)
            except OSError:
                continue
        return out


class OpenReportScreen(ModalScreen[Path | None]):
    """Pick a report file; dismisses with its path or ``None``."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "dismiss(None)", "Close")]

    def __init__(self, start: Path) -> None:
        super().__init__()
        self.start = start.resolve()

    def compose(self) -> ComposeResult:
        with Vertical(id="open-dialog", classes="dialog"):
            yield Label("Open report.json", classes="section")
            with Horizontal(classes="toolbar"):
                yield Button("Up", id="open-up")
                yield Static(txt(str(self.start), max_len=300), id="open-root")
            yield ReportTree(self.start, id="open-tree")
            yield Input(placeholder="…or type a path and press enter", id="open-path")
            with Horizontal(classes="buttons"):
                yield Button("Open", id="open-ok", variant="primary")
                yield Button("Cancel (esc)", id="open-cancel")

    @on(DirectoryTree.FileSelected, "#open-tree")
    def _picked(self, event: DirectoryTree.FileSelected) -> None:
        self.dismiss(Path(event.path))

    @on(Button.Pressed, "#open-up")
    def _up(self) -> None:
        tree = self.query_one("#open-tree", ReportTree)
        parent = Path(tree.path).resolve().parent
        tree.path = parent
        self.query_one("#open-root", Static).update(txt(str(parent), max_len=300))

    @on(Input.Submitted, "#open-path")
    @on(Button.Pressed, "#open-ok")
    def _typed(self) -> None:
        value = self.query_one("#open-path", Input).value.strip()
        if not value:
            self.notify("Type a path or pick a file", severity="warning", markup=False)
            return
        self.dismiss(Path(value).expanduser())

    @on(Button.Pressed, "#open-cancel")
    def _cancel(self) -> None:
        self.dismiss(None)

    def on_mount(self) -> None:
        self.query_one("#open-tree", ReportTree).focus()
        self.query_one("#open-root", Static).update(
            Text.assemble(("in ", "dim"), txt(str(self.start), max_len=300))
        )
