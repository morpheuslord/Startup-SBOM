"""Sanitising untrusted text before it reaches a terminal, a TUI, a document or an LLM.

Strings from scanned systems, advisories and fetched articles may carry terminal
escape sequences (OSC title changes, screen clears), bidi overrides that reorder
displayed text, zero-width characters and private-use code points.  Escaping rich
markup is not enough: ``rich.text.Text`` passes ``ESC`` straight through.
"""

from __future__ import annotations

import re
import unicodedata

from rich.style import Style
from rich.text import Text

_INVISIBLE = dict.fromkeys(
    [
        0x200B, 0x200C, 0x200D, 0x200E, 0x200F,  # zero-width, LRM/RLM
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi embeddings / overrides
        0x2060, 0x2066, 0x2067, 0x2068, 0x2069,  # word joiner, bidi isolates
        0xFEFF,  # BOM / zero-width no-break space
    ],
    None,
)  # fmt: skip
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")  # invisible Unicode "tag" characters
REPLACEMENT = "�"


def clean(text: object, *, max_len: int | None = None, keep_newlines: bool = False) -> str:
    """Remove control, bidi, zero-width, tag and private-use characters; bound length."""
    s = str(text)
    if keep_newlines:
        s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ")
        s = "\n".join(_CONTROL.sub(REPLACEMENT, line) for line in s.split("\n"))
    else:
        s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        s = _CONTROL.sub(REPLACEMENT, s)
    s = _TAG_CHARS.sub("", s.translate(_INVISIBLE))
    if any(unicodedata.category(ch) == "Co" for ch in s):
        s = "".join(REPLACEMENT if unicodedata.category(ch) == "Co" else ch for ch in s)
    if max_len is not None and len(s) > max_len:
        s = s[: max(0, max_len - 1)] + "…"
    return s


def safe(text: object, max_len: int = 200) -> str:
    """Single-line, length-bounded, terminal-safe string."""
    return clean(text, max_len=max_len)


def safe_text(
    text: object, style: str | Style = "", *, max_len: int = 200, wrap: bool = False
) -> Text:
    """A rich ``Text`` (never parsed as markup) built from sanitised content."""
    return Text(
        safe(text, max_len),
        style=style,
        no_wrap=not wrap,
        overflow="fold" if wrap else "ellipsis",
    )


def safe_block(text: object, max_len: int = 20_000) -> str:
    """Multi-line variant for narratives and article text (newlines preserved)."""
    return clean(text, max_len=max_len, keep_newlines=True)
