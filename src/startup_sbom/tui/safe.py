"""The only way untrusted strings reach TUI widgets.

Textual parses plain ``str`` in DataTable cells, Tree labels, Select prompts and
``notify()`` as markup, and ``rich.text.Text`` passes ``ESC`` straight through, so
every value from a report, a scanned system, an advisory or a model goes through
:mod:`startup_sbom.textsafe` here first.
"""

from __future__ import annotations

import re

from rich.style import Style
from rich.text import Text

from startup_sbom.textsafe import safe, safe_block

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~=&:])")


def txt(value: object, style: str | Style = "", *, max_len: int = 200) -> Text:
    """Single-line, sanitised, never-markup rich ``Text``."""
    return Text(safe(value, max_len), style=style, no_wrap=True, overflow="ellipsis")


def wrap_txt(value: object, style: str | Style = "", *, max_len: int = 20_000) -> Text:
    """Multi-line, sanitised, never-markup rich ``Text`` that wraps."""
    return Text(safe_block(value, max_len), style=style, overflow="fold")


def md_escape(text: str) -> str:
    """Backslash-escape every Markdown metacharacter (input must already be sanitised)."""
    return _MD_SPECIAL.sub(r"\\\1", text)


def md(value: object, max_len: int = 300) -> str:
    """Sanitised, single-line, Markdown-escaped text for interpolation."""
    return md_escape(safe(value, max_len))


def md_block(value: object, max_len: int = 20_000) -> str:
    """Sanitised multi-line text as escaped Markdown paragraphs (newlines kept)."""
    lines = safe_block(value, max_len).split("\n")
    return "\n".join(md_escape(line.strip()) for line in lines)


def plain(value: object, max_len: int = 300) -> str:
    """Sanitised single-line ``str`` for widgets that never parse markup (Input, Log)."""
    return safe(value, max_len)
