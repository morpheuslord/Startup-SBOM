"""Async helpers for the TUI tests (no pytest-asyncio: tests call ``run_ui``)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from typing import Any

from textual.app import App
from textual.pilot import Pilot


def run_ui(coro: Coroutine[object, object, None], timeout: float = 90.0) -> None:
    """Run one headless UI scenario with an overall timeout."""
    asyncio.run(asyncio.wait_for(coro, timeout=timeout))


async def wait_until(
    pilot: Pilot[object],
    condition: Callable[[], bool],
    *,
    timeout: float = 10.0,
    message: str = "condition not met in time",
) -> None:
    """Poll ``condition`` while letting the app process messages."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        await pilot.pause(0.05)
    raise AssertionError(message)


def results_ready(app: App[Any]) -> bool:
    """The results browser is on screen *and* finished building.

    ``app.screen`` switches before the new screen mounts; ending a test then
    tears the screen down mid-mount, so tests wait for this instead.
    """
    from startup_sbom.tui.screens.results import ResultsScreen

    screen = app.screen
    return isinstance(screen, ResultsScreen) and screen.ready
