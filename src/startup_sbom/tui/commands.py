"""Command-palette provider for the results screen (actions + jump to threat).

Labels are built with ``Content(...)`` (never markup) because ``Matcher.highlight``
parses its argument as markup.
"""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.content import Content

from startup_sbom.textsafe import safe

if TYPE_CHECKING:
    from startup_sbom.tui.screens.results import ResultsScreen

MAX_THREAT_HITS = 5000


class ResultsCommands(Provider):
    """Results actions and threats by CVE id, title or package."""

    def _results(self) -> ResultsScreen | None:
        from startup_sbom.tui.screens.results import ResultsScreen

        screen = self.screen
        return screen if isinstance(screen, ResultsScreen) else None

    async def discover(self) -> Hits:
        screen = self._results()
        if screen is None:
            return
        for title, help_text, callback in screen.palette_actions():
            yield DiscoveryHit(Content(title), callback, help=help_text)

    async def search(self, query: str) -> Hits:
        screen = self._results()
        if screen is None:
            return
        matcher = self.matcher(query)
        for title, help_text, callback in screen.palette_actions():
            score = matcher.match(title)
            if score > 0:
                yield Hit(score, Content(title), callback, help=help_text)
        for row in screen.index.rows[:MAX_THREAT_HITS]:
            t = row.threat
            label = safe(f"{t.vulnerability}  {t.title}  ({row.package_name})", 160)
            score = matcher.match(label)
            if score > 0:
                yield Hit(
                    score,
                    Content(label),
                    partial(screen.focus_threat, t.id),
                    text=label,
                    help=f"threat · risk {t.risk_score:.1f}",
                )
