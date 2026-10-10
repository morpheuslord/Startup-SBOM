"""Boot timing from ``systemd-analyze plot`` (SVG) or ``systemd-analyze blame`` output.

The input is user-supplied and may be hostile: it is size-capped and parsed as
*text* with regular expressions (no XML parser ever touches the SVG).  Results
map unit names to start-up durations in milliseconds.
"""

from __future__ import annotations

import html
import re
from pathlib import Path

from startup_sbom.errors import ParseError

MAX_INPUT_BYTES = 32 * 1024 * 1024

_UNIT_MS = {
    "y": 365.25 * 86_400_000,
    "month": 30.44 * 86_400_000,
    "w": 7 * 86_400_000,
    "d": 86_400_000,
    "h": 3_600_000,
    "min": 60_000,
    "s": 1000,
    "ms": 1,
    "us": 0.001,
    "µs": 0.001,
}
_SPAN_PART = r"\d+(?:\.\d+)?\s?(?:month|min|ms|us|µs|y|w|d|h|s)"
_TOKEN_RE = re.compile(r"(\d+(?:\.\d+)?)\s?(month|min|ms|us|µs|y|w|d|h|s)")
_SPAN_RE = re.compile(rf"^\s*({_SPAN_PART}(?:\s+{_SPAN_PART})*)\s*$")
_BLAME_RE = re.compile(rf"^\s*(?P<span>{_SPAN_PART}(?:\s+{_SPAN_PART})*)\s+(?P<unit>\S+)\s*$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9:_.\\@-]{1,256}$")
_SVG_TEXT_RE = re.compile(r"<text\b[^>]{0,512}>([^<]{1,1024})</text>", re.IGNORECASE)
_SVG_ENTRY_RE = re.compile(r"^\s*(?P<unit>\S+)\s+\((?P<span>[^()]{1,64})\)\s*$")


def parse_timespan(text: str) -> float | None:
    """Convert a systemd timespan (``1min 2.345s``, ``123ms``) to milliseconds."""
    if not _SPAN_RE.match(text):
        return None
    return sum(float(n) * _UNIT_MS[u] for n, u in _TOKEN_RE.findall(text))


def _store(out: dict[str, float], unit: str, ms: float | None) -> None:
    if ms is None or not _UNIT_RE.match(unit):
        return
    out[unit] = max(out.get(unit, 0.0), round(ms, 3))


def parse_blame(text: str) -> dict[str, float]:
    """Parse ``systemd-analyze blame`` output into ``{unit: milliseconds}``."""
    out: dict[str, float] = {}
    for line in text.splitlines():
        m = _BLAME_RE.match(line)
        if m:
            _store(out, m.group("unit"), parse_timespan(m.group("span")))
    return out


def parse_plot_svg(text: str) -> dict[str, float]:
    """Parse ``systemd-analyze plot`` SVG text labels ``unit (1.234s)`` into milliseconds."""
    out: dict[str, float] = {}
    for raw in _SVG_TEXT_RE.findall(text):
        m = _SVG_ENTRY_RE.match(html.unescape(raw))
        if not m:
            continue
        # newer systemd may show "activating / active" pairs: take the first span
        span = m.group("span").split("/")[0].strip()
        _store(out, m.group("unit"), parse_timespan(span))
    return out


def _looks_like_svg(text: str) -> bool:
    head = text[:4096].lstrip().lower()
    return head.startswith(("<?xml", "<svg", "<!doctype svg")) or "<svg" in head


def load_boot_timing(path: Path) -> dict[str, float]:
    """Load a ``systemd-analyze plot`` SVG or ``blame`` text file (format auto-detected)."""
    try:
        with path.open("rb") as f:
            data = f.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise ParseError(f"cannot read boot timing file {path}: {exc}") from exc
    if len(data) > MAX_INPUT_BYTES:
        raise ParseError(f"boot timing file {path} exceeds {MAX_INPUT_BYTES} bytes")
    text = data.decode("utf-8", "replace")
    return parse_plot_svg(text) if _looks_like_svg(text) else parse_blame(text)
