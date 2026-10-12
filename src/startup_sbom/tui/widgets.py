"""Shared widgets and fixes for Textual mount races.

Textual 8.2 widgets update their own children from watchers and Mount handlers
without checking that those children are composed yet.  On a loaded host (CI
runners, coverage tracing, a fast screen switch) the child can be missing and
the app crashes with ``NoMatches``:

* ``Header`` registers ``title``/``sub_title`` watchers that do
  ``query_one(HeaderTitle)`` guarded only against ``NoScreen``.
* ``Select`` sets its initial value in ``_on_mount``; the value watcher calls
  ``SelectCurrent.update``, which does ``query_one("#label")``.

Subclassing cannot help: Textual dispatches ``_on_mount`` for every class in
the MRO, so the unguarded base handler would still run.  The handlers are
therefore patched on the Textual classes themselves (textual is pinned
``>=8.2,<9``).  Importing this module applies the patches; the TUI app does so
at start-up, and :class:`SafeHeader` lets screens import the patched widget
from here explicitly.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from rich.console import RenderableType
from textual.css.query import NoMatches
from textual.dom import NoScreen
from textual.widgets import Header, Select, Static
from textual.widgets._header import HeaderTitle
from textual.widgets._select import NoSelection, SelectCurrent

if TYPE_CHECKING:
    from textual.events import Mount


def _header_on_mount(self: Header, _: Mount) -> None:
    async def set_title() -> None:
        with contextlib.suppress(NoScreen, NoMatches):
            self.query_one(HeaderTitle).update(self.format_title())

    self.watch(self.app, "title", set_title)
    self.watch(self.app, "sub_title", set_title)
    self.watch(self.screen, "title", set_title)
    self.watch(self.screen, "sub_title", set_title)


def _select_current_update(self: SelectCurrent, label: RenderableType | NoSelection) -> None:
    self.label = label
    self.has_value = label is not Select.NULL
    try:
        static = self.query_one("#label", Static)
    except NoMatches:
        # Label not composed yet: show the value once it is, instead of crashing.
        if self.is_attached:
            self.call_after_refresh(self.update, label)
        return
    static.update(self.placeholder if isinstance(label, NoSelection) else label)


Header._on_mount = _header_on_mount  # type: ignore[method-assign]
SelectCurrent.update = _select_current_update  # type: ignore[method-assign]


class SafeHeader(Header):
    """``Header`` that tolerates its title child being unmounted mid-update."""
