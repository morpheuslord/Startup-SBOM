"""Terminal-injection defences."""

from __future__ import annotations

import io

from rich.console import Console

from startup_sbom.textsafe import clean, safe, safe_block, safe_text


def test_escape_sequences_removed():
    hostile = "pkg\x1b]0;pwned\x07\x1b[2J\x1b[31mred"
    out = safe(hostile)
    assert "\x1b" not in out
    assert "\x07" not in out


def test_rendered_text_has_no_escape():
    buf = io.StringIO()
    Console(file=buf, force_terminal=False, color_system=None).print(
        safe_text("a\x1b]0;title\x07b")
    )
    assert "\x1b" not in buf.getvalue()


def test_bidi_and_zero_width_and_tags():
    s = "ad\u202emin\u200b\u2066x\U000e0041"
    assert clean(s) == "adminx"


def test_private_use_replaced_and_length_bounded():
    assert "" not in clean("ab")
    assert len(safe("x" * 500, max_len=10)) == 10


def test_markup_is_not_interpreted():
    buf = io.StringIO()
    Console(file=buf, color_system=None).print(safe_text("[bold red]boom[/]"))
    assert "[bold red]boom[/]" in buf.getvalue()


def test_block_keeps_newlines():
    assert safe_block("a\r\nb\x1bc") == "a\nb�c"
