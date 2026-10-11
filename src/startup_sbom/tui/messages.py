"""Thread-safe messages and the daemon-thread runner used for blocking work.

``post_message`` is thread-safe and non-blocking, so background threads report
through these messages instead of ``call_from_thread``.  Blocking work (scans,
network lookups, AI calls) runs in *daemon* threads so quitting never waits for a
slow stage; a message posted to a screen that has gone away is dropped.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from textual.message import Message
from textual.message_pump import MessagePump

log = logging.getLogger("startup_sbom.tui")


class TaskDone(Message):
    """A background task finished with ``result`` or ``error``."""

    bubble = False

    def __init__(self, name: str, result: object, error: BaseException | None) -> None:
        super().__init__()
        self.name = name
        self.result = result
        self.error = error


class ScanProgress(Message):
    """A pipeline stage started."""

    bubble = False

    def __init__(self, stage: str, index: int, total: int) -> None:
        super().__init__()
        self.stage = stage
        self.index = index
        self.total = total


class ScanLog(Message):
    """A log record emitted during the scan."""

    bubble = False

    def __init__(self, level: str, text: str) -> None:
        super().__init__()
        self.level = level
        self.text = text


class AIChunk(Message):
    """A streamed chunk of AI analyst output."""

    bubble = False

    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text


def run_background(target: MessagePump, name: str, fn: Callable[[], object]) -> threading.Thread:
    """Run ``fn`` in a daemon thread and post :class:`TaskDone` to ``target``."""

    def runner() -> None:
        result: object = None
        error: BaseException | None = None
        try:
            result = fn()
        except Exception as exc:  # reported to the UI, never raised into the void
            log.debug("background task %s failed", name, exc_info=True)
            error = exc
        target.post_message(TaskDone(name, result, error))

    thread = threading.Thread(target=runner, name=f"sbom-tui-{name}", daemon=True)
    thread.start()
    return thread


class UILogHandler(logging.Handler):
    """Forward ``startup_sbom`` log records to a widget from any thread."""

    def __init__(self, target: MessagePump, level: int = logging.INFO) -> None:
        super().__init__(level)
        self.target = target

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.target.post_message(ScanLog(record.levelname, record.getMessage()))
        except Exception:  # noqa: BLE001 - logging must never raise
            self.handleError(record)
