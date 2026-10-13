"""tools/docs_to_wiki.py: MkDocs Docs/ -> GitHub wiki conversion (offline)."""

from __future__ import annotations

import importlib.util
import re
import sys
import textwrap
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_tool() -> ModuleType:
    name = "docs_to_wiki"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, REPO / "tools" / "docs_to_wiki.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


d2w = _load_tool()

MKDOCS_YML = """\
site_name: Demo
site_url: https://example.invalid/demo/
repo_url: https://github.com/owner/demo
docs_dir: Docs

# planning notes stay out of the site
not_in_nav: |
  Refactor Plan.md

nav:
  - Home: index.md
  - Guide: guide.md   # trailing comment
  - "Deep Dive":
      - Package Databases: sub/pkg.md
      - Upstream: https://example.invalid/upstream
  - Tabs and Alerts: tabs.md

markdown_extensions:
  - pymdownx.emoji:
      emoji_index: !!python/name:material.extensions.emoji.twemoji
"""


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


@pytest.fixture
def site(tmp_path: Path) -> tuple[Path, Path]:
    docs = tmp_path / "Docs"
    _write(
        docs,
        "index.md",
        """\
        # Demo

        <img src="assets/logo.svg" alt="logo">

        See the [guide](guide.md), [its setup](guide.md#setup-step) and
        [databases](sub/pkg.md#dpkg-and-rpm). Also [the plan](Refactor%20Plan.md),
        [upstream](https://example.invalid/x.md) and [top](#demo).

        [Get started](guide.md){ .md-button .md-button--primary }

        <div class="grid cards" markdown>

        -   :material-bug-check:{ .lg .middle } **Card**

            ---

            Body. [:octicons-arrow-right-24: Go](tabs.md)

        </div>
        """,
    )
    _write(
        docs,
        "guide.md",
        """\
        # Guide

        ## Setup step

        ## Custom { #custom-id }

        ```python
        x = "[not a link](guide.md)"  # { .keep } !!! note
        ```

        Inline `[code](guide.md){ .x }` stays.
        """,
    )
    _write(
        docs,
        "sub/pkg.md",
        """\
        # Package Databases

        ## dpkg → and RPM

        Back to [home](../index.md), [guide](../guide.md#custom-id) and the
        [diagram](../assets/diagram.png).
        """,
    )
    _write(
        docs,
        "tabs.md",
        """\
        # Tabs and Alerts

        !!! warning "Mind the gap"
            Body line one.

            ```mermaid
            graph TD
                A --> B
            ```

        ??? example
            Collapsed **body**.

        !!! danger ""
            No title here.

        === "pip"

            ```bash
            pip install demo
            ```

        === "uv"
            uv tool install demo
        After.
        """,
    )
    _write(docs, "Refactor Plan.md", "# Plan\n")
    _write(docs, "assets/logo.svg", "<svg/>")
    _write(docs, "assets/diagram.png", "png")
    yml = tmp_path / "mkdocs.yml"
    yml.write_text(MKDOCS_YML, encoding="utf-8")
    return docs, yml


def _run(site: tuple[Path, Path], out: Path, **kwargs: Any) -> Any:
    docs, yml = site
    return d2w.convert(docs, yml, out, **kwargs)


def _page(out: Path, name: str) -> str:
    return (out / name).read_text(encoding="utf-8")


def test_config_and_nav_parsing(site: tuple[Path, Path]) -> None:
    config = d2w.load_mkdocs_config(site[1])
    assert config.site_name == "Demo"
    assert config.docs_dir == "Docs"
    assert config.not_in_nav == ("Refactor Plan.md",)
    nav = d2w.build_nav(config.nav, site[0])
    assert [type(n).__name__ for n in nav] == ["NavPage", "NavPage", "NavSection", "NavPage"]
    assert nav[0].name == "Home"
    section = nav[2]
    assert section.title == "Deep Dive"
    assert section.children[0].name == "Package-Databases"
    assert section.children[1].url == "https://example.invalid/upstream"


def test_wiki_page_names() -> None:
    assert d2w.wiki_page_name("Package Databases") == "Package-Databases"
    assert d2w.wiki_page_name("Data Accessing - RPM") == "Data-Accessing-\u2010-RPM"
    assert d2w.wiki_page_name("A/B: c?") == "AB-c"


def test_link_rewriting(site: tuple[Path, Path], tmp_path: Path) -> None:
    out = tmp_path / "wiki"
    result = _run(site, out)
    home = _page(out, "Home.md")
    assert "[guide](Guide)" in home
    assert "[its setup](Guide#setup-step)" in home
    # MkDocs drops the arrow and collapses; GitHub keeps one '-' per space.
    assert "[databases](Package-Databases#dpkg--and-rpm)" in home
    assert "[the plan](https://github.com/owner/demo/blob/main/Docs/Refactor%20Plan.md)" in home
    assert "[upstream](https://example.invalid/x.md)" in home
    assert "[top](#demo)" in home
    assert '<img src="assets/logo.svg" alt="logo">' in home
    pkg = _page(out, "Package-Databases.md")
    assert "[home](Home)" in pkg
    assert "[guide](Guide#custom-id)" in pkg
    assert "[diagram](assets/diagram.png)" in pkg
    assert (out / "assets/logo.svg").read_text() == "<svg/>"
    assert (out / "assets/diagram.png").is_file()
    assert result.warnings == []


def test_material_syntax_is_lowered(site: tuple[Path, Path], tmp_path: Path) -> None:
    out = tmp_path / "wiki"
    _run(site, out)
    home = _page(out, "Home.md")
    assert "[Get started](Guide)\n" in home
    assert "md-button" not in home
    assert "<div" not in home
    assert "</div>" not in home
    assert ":material-" not in home
    assert "-   **Card**" in home
    assert "    ---" not in home
    assert "[→ Go](Tabs-and-Alerts)" in home
    guide = _page(out, "Guide.md")
    assert '<a id="custom-id"></a>\n## Custom\n' in guide


def test_admonitions_and_tabs(site: tuple[Path, Path], tmp_path: Path) -> None:
    out = tmp_path / "wiki"
    _run(site, out)
    tabs = _page(out, "Tabs-and-Alerts.md")
    expected_warning = textwrap.dedent(
        """\
        > [!WARNING]
        > **Mind the gap**
        > Body line one.
        >
        > ```mermaid
        > graph TD
        >     A --> B
        > ```
        """
    )
    assert expected_warning in tabs
    assert "> [!NOTE]\n> **Example**\n> Collapsed **body**.\n" in tabs
    assert "> [!CAUTION]\n> No title here.\n" in tabs
    assert "**pip**\n\n```bash\npip install demo\n```\n" in tabs
    assert "**uv**\n\nuv tool install demo\n\nAfter.\n" in tabs
    assert "!!!" not in tabs
    assert "???" not in tabs
    assert "===" not in tabs


def test_fenced_code_and_inline_code_untouched(site: tuple[Path, Path], tmp_path: Path) -> None:
    out = tmp_path / "wiki"
    _run(site, out)
    guide = _page(out, "Guide.md")
    assert '```python\nx = "[not a link](guide.md)"  # { .keep } !!! note\n```' in guide
    assert "Inline `[code](guide.md){ .x }` stays." in guide


def test_convert_lines_leaves_fences_verbatim() -> None:
    lines = [
        "~~~~",
        "!!! note",
        '    === "tab"',
        "[x](a.md){ #y }",
        "~~~~",
    ]
    converter = d2w.WikiConverter.__new__(d2w.WikiConverter)
    assert converter.convert_lines(lines) == lines


def test_sidebar_and_footer(site: tuple[Path, Path], tmp_path: Path) -> None:
    out = tmp_path / "wiki"
    _run(site, out)
    assert _page(out, "_Sidebar.md") == textwrap.dedent(
        """\
        **[Demo](Home)**

        - [Home](Home)
        - [Guide](Guide)
        - **Deep Dive**
          - [Package Databases](Package-Databases)
          - [Upstream](https://example.invalid/upstream)
        - [Tabs and Alerts](Tabs-and-Alerts)
        """
    )
    footer = _page(out, "_Footer.md")
    assert "https://github.com/owner/demo/tree/main/Docs" in footer
    assert "https://example.invalid/demo/" in footer


def test_not_in_nav_pages_are_excluded(site: tuple[Path, Path], tmp_path: Path) -> None:
    out = tmp_path / "wiki"
    result = _run(site, out)
    produced = {p.name for p in out.glob("*.md")}
    assert produced == {
        "Home.md",
        "Guide.md",
        "Package-Databases.md",
        "Tabs-and-Alerts.md",
        "_Sidebar.md",
        "_Footer.md",
    }
    assert not any("Plan" in rel for rel in result.written)


def test_orphan_page_warns(site: tuple[Path, Path], tmp_path: Path) -> None:
    _write(site[0], "orphan.md", "# Orphan\n")
    result = _run(site, tmp_path / "wiki")
    assert any("orphan.md is neither in nav" in w for w in result.warnings)
    assert (
        d2w.main(
            [
                "--docs",
                str(site[0]),
                "--mkdocs",
                str(site[1]),
                "--out",
                str(tmp_path / "w2"),
                "--strict",
            ]
        )
        == 1
    )


def test_broken_links_warn(site: tuple[Path, Path], tmp_path: Path) -> None:
    _write(site[0], "guide.md", "# Guide\n\n[gone](missing.md) [bad](index.md#nope)\n")
    result = _run(site, tmp_path / "wiki")
    assert any("missing page missing.md" in w for w in result.warnings)
    assert any("anchor #nope not found in index.md" in w for w in result.warnings)


def test_prune_keeps_git_and_removes_stale_pages(site: tuple[Path, Path], tmp_path: Path) -> None:
    out = tmp_path / "wiki"
    (out / ".git" / "refs").mkdir(parents=True)
    (out / ".git" / "HEAD").write_text("ref: refs/heads/master\n")
    (out / ".git" / "notes.md").write_text("git internals\n")
    (out / "Chroot-Analysis.md").write_text("stale 1.x page\n")
    (out / "Home.md").write_text("old home\n")
    (out / "old").mkdir()
    (out / "old" / "Nested.markdown").write_text("stale\n")
    (out / "image.png").write_text("not a page\n")

    unpruned = _run(site, out)
    assert unpruned.removed == []
    assert (out / "Chroot-Analysis.md").exists()

    result = _run(site, out, do_prune=True)
    assert result.removed == ["Chroot-Analysis.md", "old/Nested.markdown"]
    assert not (out / "Chroot-Analysis.md").exists()
    assert (out / ".git" / "HEAD").read_text() == "ref: refs/heads/master\n"
    assert (out / ".git" / "notes.md").exists()
    assert (out / "image.png").exists()
    assert _page(out, "Home.md").startswith("<!-- Generated by tools/docs_to_wiki.py")


def test_symlinks_in_the_wiki_are_replaced_not_followed(
    site: tuple[Path, Path], tmp_path: Path
) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n")
    out = tmp_path / "wiki"
    out.mkdir()
    try:
        (out / "Home.md").symlink_to(victim)
    except OSError:
        pytest.skip("symlinks unavailable")
    _run(site, out)
    assert victim.read_text() == "keep me\n"
    assert not (out / "Home.md").is_symlink()


def test_output_is_deterministic(site: tuple[Path, Path], tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    _run(site, first)
    _run(site, second)
    files_a = sorted(p.relative_to(first) for p in first.rglob("*") if p.is_file())
    files_b = sorted(p.relative_to(second) for p in second.rglob("*") if p.is_file())
    assert files_a == files_b
    for rel in files_a:
        assert (first / rel).read_bytes() == (second / rel).read_bytes()


def test_missing_nav_file_is_an_error(site: tuple[Path, Path], tmp_path: Path) -> None:
    (site[0] / "guide.md").unlink()
    with pytest.raises(d2w.ConversionError, match=r"missing file Docs/guide\.md"):
        _run(site, tmp_path / "wiki")
    rc = d2w.main(["--docs", str(site[0]), "--mkdocs", str(site[1]), "--out", str(tmp_path / "w")])
    assert rc == 1


def test_output_inside_docs_is_refused(site: tuple[Path, Path]) -> None:
    with pytest.raises(d2w.ConversionError, match="inside the docs directory"):
        _run(site, site[0] / "wiki")


def test_slugs() -> None:
    assert d2w.mkdocs_slug("Vulnerability → threat reversal") == "vulnerability-threat-reversal"
    assert d2w.github_slug("Vulnerability → threat reversal") == "vulnerability--threat-reversal"
    assert d2w.github_slug("The `Report` model (v2.1)") == "the-report-model-v21"


def test_nav_parser_matches_pyyaml_on_the_real_config() -> None:
    yaml = pytest.importorskip("yaml")

    class TolerantLoader(yaml.SafeLoader):  # type: ignore[name-defined,misc]
        """SafeLoader that maps unknown tags (``!!python/name:``) to None."""

    TolerantLoader.add_multi_constructor("tag:yaml.org,2002:python/", lambda *_: None)
    TolerantLoader.add_multi_constructor("!", lambda *_: None)
    data = yaml.load((REPO / "mkdocs.yml").read_text(encoding="utf-8"), Loader=TolerantLoader)

    def as_yaml(entries: tuple[Any, ...]) -> list[Any]:
        result: list[Any] = []
        for entry in entries:
            if entry.target is None:
                result.append({entry.title: as_yaml(entry.children)})
            elif entry.title is None:
                result.append(entry.target)
            else:
                result.append({entry.title: entry.target})
        return result

    config = d2w.load_mkdocs_config(REPO / "mkdocs.yml")
    assert as_yaml(config.nav) == data["nav"]
    assert config.site_url == data["site_url"]
    assert config.repo_url == data["repo_url"].rstrip("/")
    assert config.docs_dir == data["docs_dir"]
    expected = tuple(ln.strip() for ln in data.get("not_in_nav", "").splitlines() if ln.strip())
    assert config.not_in_nav == expected


def test_real_docs_convert(tmp_path: Path) -> None:
    out = tmp_path / "wiki"
    result = d2w.convert(REPO / "Docs", REPO / "mkdocs.yml", out)
    config = d2w.load_mkdocs_config(REPO / "mkdocs.yml")
    pages = d2w.iter_pages(d2w.build_nav(config.nav, REPO / "Docs"))
    assert {f"{p.name}.md" for p in pages} | {"_Sidebar.md", "_Footer.md"} <= set(result.written)
    assert (out / "Home.md").is_file()
    published = {p.stem for p in out.glob("*.md")}
    for page in out.glob("*.md"):
        for dest in re.findall(r"\]\(<?([^)\s>]+)", page.read_text(encoding="utf-8")):
            if dest.startswith(("http://", "https://", "#", "mailto:")):
                continue
            target = dest.split("#")[0]
            assert target in published or (out / target).is_file(), (page.name, dest)
