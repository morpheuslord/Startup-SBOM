"""Markdown, HTML, DOT, Mermaid and console output: content and escaping of hostile strings."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re

from reportdata import build_report
from rich.console import Console

from startup_sbom.models import Report
from startup_sbom.report import print_console, render
from startup_sbom.report.graphs import mermaid_text
from startup_sbom.report.html import JS


# --------------------------------------------------------------------------- Markdown
def test_markdown_content(report: Report) -> None:
    text = render(report, "markdown")
    for heading in (
        "## Executive summary",
        "## Top threats",
        "## Attack chains",
        "## Supply chain",
        "## Boot services",
        "## Coverage and limitations",
    ):
        assert heading in text
    assert text.count("```mermaid") == len(report.attack_chains)
    assert "END OF LIFE" in text
    assert "CVE-2024-6387" in text
    assert "ssh.service" in text


def test_markdown_escapes_hostile(hostile_report: Report) -> None:
    text = render(hostile_report, "markdown")
    assert "<script>" not in text
    assert "</script>" not in text
    assert "<b>" not in text
    assert "&lt;/script&gt;" in text
    assert "\\[bold red\\]" in text
    lines = text.splitlines()
    assert not any(line.startswith("next") for line in lines)  # newline did not split
    in_fence = False
    for line in lines:  # nothing inside a mermaid fence can close it early
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            assert "`" not in line


def test_markdown_tables_have_consistent_columns(hostile_report: Report) -> None:
    lines = render(hostile_report, "markdown").splitlines()
    for i, line in enumerate(lines):
        if line.startswith("|---"):
            width = len(re.findall(r"(?<!\\)\|", lines[i - 1]))
            j = i + 1
            while j < len(lines) and lines[j].startswith("| "):
                assert len(re.findall(r"(?<!\\)\|", lines[j])) == width, lines[j]
                j += 1


# --------------------------------------------------------------------------- HTML
def _json_block(text: str) -> str:
    m = re.search(r'<script type="application/json" id="ssbom-data">(.*?)</script>', text, re.S)
    assert m is not None
    return m.group(1)


def test_html_self_contained(report: Report) -> None:
    text = render(report, "html")
    assert text.startswith("<!DOCTYPE html>")
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', text)
    assert csp is not None
    assert "default-src &#x27;none&#x27;" in csp.group(1)
    assert "unsafe" not in csp.group(1)
    assert "prefers-color-scheme" in text
    assert not re.search(r"""(?:src|href)\s*=\s*["']?(?:https?:)?//""", text)  # no external loads
    assert "@import" not in text
    assert "</" not in JS
    data = json.loads(_json_block(text))
    assert {n["kind"] for n in data["graph"]["nodes"]} >= {"entry", "goal", "package", "service"}
    assert 'class="sortable"' in text


def test_html_escapes_hostile(hostile_report: Report) -> None:
    text = render(hostile_report, "html")
    assert text.count("<script") == 2  # the data block and our own script, nothing injected
    assert "<script>alert" not in text
    assert "<b>" not in text
    assert "&lt;/script&gt;&lt;script&gt;alert(1)" in text
    block = _json_block(text)
    assert "</" not in block
    assert "<" not in block
    labels = [n["label"] for n in json.loads(block)["graph"]["nodes"]]
    assert any("</script><script>alert(1)</script>" in label for label in labels)


def test_html_csp_hashes_match(report: Report) -> None:
    text = render(report, "html")
    style = re.search(r"<style>(.*?)</style>", text, re.S)
    script = re.search(r"<script>(.*?)</script>", text, re.S)
    assert style is not None
    assert script is not None
    for block in (style.group(1), script.group(1)):
        digest = base64.b64encode(hashlib.sha256(block.encode()).digest()).decode()
        assert f"sha256-{digest}" in text


# --------------------------------------------------------------------------- DOT / Mermaid
_DOT_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')


def test_dot_structure(report: Report) -> None:
    text = render(report, "dot")
    assert text.startswith("digraph startup_sbom {")
    assert "cluster_attack" in text
    assert "cluster_supply" in text
    assert re.search(r"^\s+n\d+ -> n\d+ \[label=", text, re.M)


def test_dot_escapes_hostile(hostile_report: Report) -> None:
    text = render(hostile_report, "dot")
    skeleton = _DOT_STRING.sub('""', text)  # remove every well-formed quoted string
    for marker in ("script", "<b>", "bold red", "next", "tick"):
        assert marker not in skeleton
    assert '\\"q\\"' in text
    for line in text.splitlines():
        assert len(_DOT_STRING.sub("", line).split('"')) == 1  # no dangling quote


def test_mermaid_escapes_hostile(hostile_report: Report) -> None:
    text = render(hostile_report, "mermaid")
    assert text.startswith("flowchart LR")
    labels = re.findall(r'"([^"]*)"', text)
    assert labels
    for label in labels:
        for ch in '<>`|[]{}"':
            assert ch not in label
    skeleton = re.sub(r'"[^"]*"', '""', text)
    for marker in ("script", "bold", "next", "tick"):
        assert marker not in skeleton
    for line in skeleton.splitlines()[1:]:  # every statement is a classDef, node or edge
        assert re.match(r'^\s+(classDef \w+ |n\d+[\[\(\{/]|n\d+ -\.?->\|""\| n\d+$)', line), line
    assert mermaid_text('a"b<c>#d') == "a#quot;b#lt;c#gt;#35;d"


def test_markdown_mermaid_chain_ids_are_surrogates(hostile_report: Report) -> None:
    text = render(hostile_report, "markdown")
    blocks = re.findall(r"```mermaid\n(.*?)```", text, re.S)
    assert len(blocks) == 2
    for block in blocks:
        for line in block.splitlines()[1:]:
            if line.strip().startswith("classDef"):
                continue
            assert re.match(r'^\s+n\d+(?:[\[\(\{/"]|\s+-)', line), line


# --------------------------------------------------------------------------- console
def _console_text(report: Report, *, verbose: bool = False) -> str:
    buf = io.StringIO()
    console = Console(file=buf, width=220, force_terminal=False, color_system=None, record=True)
    print_console(report, console, verbose=verbose)
    return console.export_text()


def test_console_sections(report: Report) -> None:
    text = _console_text(report)
    for needle in (
        "Boot services",
        "Top threats" if len(report.threats) > 15 else "Threats",
        "Attack chains",
        "Supply-chain blast radius",
        "Supply-chain findings",
        "Coverage",
        "END OF LIFE",
        "CVE-2024-6387",
        "regreSSHion",
        "T1190",
        "remote",
    ):
        assert needle in text, needle
    verbose = _console_text(report, verbose=True)
    assert "Packages" in verbose
    assert "SIGALRM" in verbose  # per-threat narratives


def test_console_escapes_hostile(hostile_report: Report) -> None:
    for verbose in (False, True):
        text = _console_text(hostile_report, verbose=verbose)
        assert "[bold red]X[/]" in text  # printed literally, never interpreted as markup
        assert "evil</script>" in text


def test_console_markup_not_interpreted() -> None:
    r = build_report()
    r.os.pretty_name = "[link=https://evil.example]click[/link] [blink]x"
    text = _console_text(r)
    assert "[link=https://evil.example]click[/link]" in text
