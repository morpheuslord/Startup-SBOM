"""Logging setup: human-friendly on a TTY, never mixing log lines into report output."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager

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


#: Raw operation log: one line per concrete thing a stage does ("dpkg: 1,024
#: packages from /var/lib/dpkg/status", "ld.so --list /usr/sbin/sshd → 23 libs").
#: Live displays capture it through :func:`capture_ops`; otherwise it behaves like
#: any ``startup_sbom`` logger (shown with ``--verbose``).
ops = logging.getLogger("startup_sbom.ops")


class _Forward(logging.Handler):
    def __init__(self, sink: Callable[[logging.LogRecord], None]) -> None:
        super().__init__(logging.DEBUG)
        self.sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.sink(record)
        except Exception:  # noqa: BLE001 - a display failure never breaks a scan
            self.handleError(record)


@contextmanager
def capture_ops(
    sink: Callable[[logging.LogRecord], None], *, level: int = logging.INFO
) -> Iterator[None]:
    """Send :data:`ops` records to ``sink`` (and only there) for the duration.

    The ops logger stops propagating while captured so operation lines never
    interleave with a live display drawn on the same terminal.
    """
    handler = _Forward(sink)
    old = (ops.level, ops.propagate)
    ops.addHandler(handler)
    ops.setLevel(level)
    ops.propagate = False
    try:
        yield
    finally:
        ops.removeHandler(handler)
        ops.setLevel(old[0])
        ops.propagate = old[1]
