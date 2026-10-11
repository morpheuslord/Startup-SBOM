"""Article reader: cached, cleaned third-party text shown as plain (untrusted) text."""

from __future__ import annotations

from typing import ClassVar

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, OptionList, Static
from textual.widgets.option_list import Option

from startup_sbom.models import IntelBundle, IntelRecord
from startup_sbom.tui import integrations
from startup_sbom.tui.messages import TaskDone, run_background
from startup_sbom.tui.safe import txt, wrap_txt

BANNER = (
    "Third-party content — fetched from the web, untrusted and unverified. Shown as plain "
    "text; links are never opened. Do not run any commands it contains."
)


def _load(record: IntelRecord) -> str:
    text = integrations.article_text(record)
    if text:
        return text
    return record.snippet or "(no cached text for this article)"


class ArticleScreen(ModalScreen[None]):
    """List the bundle's articles and advisories; read one."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "dismiss(None)", "Close")]

    def __init__(self, bundle: IntelBundle) -> None:
        super().__init__()
        self.bundle = bundle
        self.records = [*bundle.advisories, *bundle.articles][:100]

    def compose(self) -> ComposeResult:
        with Vertical(id="article-dialog", classes="dialog"):
            yield Static(Text(BANNER, style="bold yellow"), id="article-banner")
            with Horizontal(classes="split"):
                yield OptionList(
                    *[
                        Option(txt(f"{r.kind}: {r.title or r.url}", max_len=80), id=str(i))
                        for i, r in enumerate(self.records)
                    ],
                    id="article-list",
                )
                with VerticalScroll(classes="detail"):
                    yield Static("", id="article-meta")
                    yield Static(Text("Select an article."), id="article-body")
            yield Button("Close (esc)", id="article-close")

    def on_mount(self) -> None:
        if self.records:
            self.show(0)

    @on(OptionList.OptionHighlighted, "#article-list")
    def _highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_index is not None:
            self.show(event.option_index)

    def show(self, idx: int) -> None:
        """Show metadata at once and load the text in the background."""
        if not 0 <= idx < len(self.records):
            return
        rec = self.records[idx]
        meta = Text()
        meta.append_text(txt(rec.title or rec.url, "bold", max_len=300))
        meta.append("\n")
        meta.append_text(txt(f"{rec.site or rec.source} · {rec.published or 'undated'}", "dim"))
        meta.append("\n")
        meta.append_text(txt(rec.final_url or rec.url, "dim", max_len=500))
        if rec.truncated:
            meta.append("\n(truncated)", style="dim")
        self.query_one("#article-meta", Static).update(meta)
        self.query_one("#article-body", Static).update(Text("loading…", style="dim"))
        run_background(self, f"article:{idx}", lambda: _load(rec))

    def on_task_done(self, message: TaskDone) -> None:
        if not message.name.startswith("article:"):
            return
        body = self.query_one("#article-body", Static)
        if message.error is not None:
            body.update(txt(f"cannot load article: {message.error}", "red"))
        else:
            body.update(wrap_txt(message.result, max_len=200_000))

    @on(Button.Pressed, "#article-close")
    def _close(self) -> None:
        self.dismiss(None)
