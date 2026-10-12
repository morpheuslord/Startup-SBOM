"""Regression tests for the Textual mount-race fixes in startup_sbom.tui.widgets."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.widgets import Select, Static
from textual.widgets._select import SelectCurrent
from tuihelpers import run_ui, wait_until

import startup_sbom.tui.widgets  # noqa: F401  (applies the patches)


def test_select_label_update_before_compose_does_not_crash() -> None:
    current = SelectCurrent("placeholder")
    current.update("Any SSVC")  # raised NoMatches('#label') before the fix
    assert current.label == "Any SSVC"
    assert current.has_value


def test_mounted_select_still_shows_its_initial_value() -> None:
    class Demo(App[None]):
        def compose(self) -> ComposeResult:
            yield Select([("Any SSVC", "any"), ("Act", "act")], value="act", id="s")

    app = Demo()

    async def main() -> None:
        async with app.run_test() as pilot:
            label = app.query_one("#s SelectCurrent #label", Static)
            await wait_until(pilot, lambda: str(label.content) == "Act")

    run_ui(main())
