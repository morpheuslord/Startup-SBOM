"""Logging setup: human-friendly on a TTY, never mixing log lines into report output."""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler


def configure_logging(*, verbose: bool = False, debug: bool = False, quiet: bool = False) -> None:
    """Route ``startup_sbom`` logs to stderr with an appropriate level."""
    level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    if quiet and not debug:
        level = logging.ERROR
    handler = RichHandler(
        console=Console(stderr=True),
        show_time=debug,
        show_path=debug,
        markup=False,
        rich_tracebacks=debug,
    )
    root = logging.getLogger("startup_sbom")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False
    logging.getLogger("httpx").setLevel(logging.DEBUG if debug else logging.WARNING)
