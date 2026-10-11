"""Shared widgets: a Header whose title watcher survives screen switches.

Textual 8.2's ``Header`` registers ``title``/``sub_title`` watchers whose
callback does ``query_one(HeaderTitle)`` guarded only against ``NoScreen``.
The callback runs from the message queue, so during a screen switch (or a
slow traced start-up) it can fire while the ``HeaderTitle`` child is not
composed yet or already torn down, crashing the app with ``NoMatches``.

Subclassing cannot help: Textual dispatches ``_on_mount`` for every class in
the MRO, so the unguarded base handler would still run.  The handler is
therefore replaced on ``Header`` itself (textual is pinned ``>=8.2,<9``),
and :class:`SafeHeader` exists so screens import the patched widget from
here instead of relying on the import-time side effect.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from textual.css.query import NoMatches
from textual.dom import NoScreen
from textual.widgets import Header
from textual.widgets._header import HeaderTitle

if TYPE_CHECKING:
    from textual.events import Mount


def _on_mount(self: Header, _: Mount) -> None:
    async def set_title() -> None:
        with contextlib.suppress(NoScreen, NoMatches):
            self.query_one(HeaderTitle).update(self.format_title())

    self.watch(self.app, "title", set_title)
    self.watch(self.app, "sub_title", set_title)
    self.watch(self.screen, "title", set_title)
    self.watch(self.screen, "sub_title", set_title)


Header._on_mount = _on_mount  # type: ignore[method-assign]


class SafeHeader(Header):
    """``Header`` that tolerates its title child being unmounted mid-update."""
