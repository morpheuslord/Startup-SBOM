#!/usr/bin/env python3
"""Publish the MkDocs documentation in ``Docs/`` as the project's GitHub wiki.

Development/CI tool only (stdlib, no network access).  The MkDocs Material site
stays the canonical rendering; this converter turns the same sources into a
flat GitHub wiki checkout so https://github.com/<owner>/<repo>/wiki mirrors it:

* one wiki page per ``nav`` entry, named after its nav title (``Package
  Databases`` -> ``Package-Databases.md``; ``index.md`` -> ``Home.md``); pages
  outside the nav (``not_in_nav``) are not published;
* relative links to pages become wiki links (``foo.md#x`` -> ``Foo#x``, with the
  anchor translated from MkDocs' slug to GitHub's), links to unpublished
  sources point at the file on GitHub, and linked assets are copied;
* MkDocs-Material-only syntax is lowered to GitHub markdown: admonitions become
  GitHub alerts, content tabs become bold headings, attribute lists, icon
  shortcodes and ``markdown``-enabled ``<div>`` wrappers are dropped.  Fenced
  code (mermaid included) is never transformed;
* ``_Sidebar.md`` mirrors the nav and ``_Footer.md`` says where to edit.

``mkdocs.yml`` is read with a small parser for the handful of top-level keys
needed here, so YAML tags such as ``!!python/name:`` are never constructed.

Usage::

    python tools/docs_to_wiki.py --docs Docs --mkdocs mkdocs.yml --out wiki [--prune]
"""

from __future__ import annotations

import argparse
import fnmatch
import html
import os
import posixpath
import re
import shutil
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, unquote

GENERATOR = "tools/docs_to_wiki.py"
DEFAULT_BRANCH = "main"
HOME_PAGE = "Home"
SIDEBAR = "_Sidebar.md"
FOOTER = "_Footer.md"
#: Wiki files with these suffixes are pages; ``--prune`` only ever removes these.
PAGE_SUFFIXES = (".md", ".markdown")

# GitHub alert types, keyed by MkDocs Material admonition type (and aliases).
ALERT_TYPES: dict[str, str] = {
    "note": "NOTE",
    "abstract": "NOTE",
    "summary": "NOTE",
    "tldr": "NOTE",
    "info": "NOTE",
    "todo": "NOTE",
    "example": "NOTE",
    "quote": "NOTE",
    "cite": "NOTE",
    "seealso": "NOTE",
    "tip": "TIP",
    "hint": "TIP",
    "success": "TIP",
    "check": "TIP",
    "done": "TIP",
    "question": "TIP",
    "help": "TIP",
    "faq": "TIP",
    "important": "IMPORTANT",
    "warning": "WARNING",
    "attention": "WARNING",
    "caution": "CAUTION",
    "danger": "CAUTION",
    "error": "CAUTION",
    "failure": "CAUTION",
    "fail": "CAUTION",
    "missing": "CAUTION",
    "bug": "CAUTION",
}

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_FENCE_OPEN = re.compile(r"^(?P<prefix>[ \t>]*)(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
_ADMONITION = re.compile(
    r"^(?P<indent>[ ]*)(?:!!!|\?\?\?\+?)[ ]+(?P<type>[\w-]+)(?:[ ]+[\w-]+)*"
    r'(?:[ ]+"(?P<title>.*)")?[ ]*$'
)
_TAB = re.compile(r'^(?P<indent>[ ]*)===[!+]*[ ]+"(?P<title>.*)"[ ]*$')
_HEADING = re.compile(r"^(?P<hashes>[ ]{0,3}#{1,6})[ \t]+(?P<text>.*?)(?:[ \t]+#+)?[ \t]*$")
_ATTR_ITEM = r"(?:[.#][\w:-]+|[\w-]+=(?:\"[^\"]*\"|'[^']*'|[^\s}]+))"
_ATTR_LIST = re.compile(
    r"[ \t]*\{:?[ \t]*" + _ATTR_ITEM + r"(?:[ \t]+" + _ATTR_ITEM + r")*[ \t]*\}"
)
_ATTR_ID = re.compile(r"(?:^|[\s{])#([\w:-]+)")
_ICON = re.compile(
    r":(?P<set>material|octicons|fontawesome|simple)-(?P<name>[\w-]+):"
    r"(?:\{[^}\n]*\})?[ ]?"
)
_CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")
_INLINE_HILITE = re.compile(r"^#!\w[\w+-]*[ ]")
_LINK_DEST = re.compile(
    r"(?P<pre>\]\([ \t]*)(?P<url><[^>\n]*>|[^\s()<>]+(?:\([^\s()]*\)[^\s()]*)*)"
)
_REF_DEF = re.compile(r"^(?P<pre>[ ]{0,3}\[[^\]]+\]:[ \t]*)(?P<url><[^>\n]*>|\S+)")
_HTML_ATTR = re.compile(r"(?P<pre>\b(?:src|href)=)(?P<q>[\"'])(?P<url>[^\"'\n]*)(?P=q)")
_DIV_OPEN = re.compile(r"^[ ]*<div\b(?P<attrs>[^>]*)>[ ]*$")
_DIV_CLOSE = re.compile(r"^[ ]*</div>[ ]*$")
_MD_ATTR = re.compile(r"\bmarkdown(?:=[\"']?(?:1|block|span)[\"']?)?(?=[\s>]|$)")
_CARD_RULE = re.compile(r"^[ ]+(?:-{3,}|\*{3,}|_{3,})[ ]*$")
_WIKI_NAME_BAD = re.compile(r"[\\/:*?\"<>|#%\[\]]")


class ConversionError(Exception):
    """The documentation cannot be converted (bad config or missing nav file)."""


# --------------------------------------------------------------------------
# mkdocs.yml (the subset this tool needs)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RawNav:
    """One entry of the ``nav`` list as written in mkdocs.yml."""

    title: str | None
    target: str | None
    children: tuple[RawNav, ...] = ()


@dataclass(frozen=True)
class MkDocsConfig:
    site_name: str
    site_url: str
    repo_url: str
    docs_dir: str
    nav: tuple[RawNav, ...]
    not_in_nav: tuple[str, ...]


def _strip_comment(line: str) -> str:
    """Drop a YAML ``# comment`` that is not inside a quoted scalar."""
    in_single = in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double and (idx == 0 or line[idx - 1] in " \t"):
            return line[:idx].rstrip()
    return line.rstrip()


def _scalar(text: str) -> str:
    """Interpret a plain or quoted single-line YAML scalar."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if text[:1] in ("[", "{", "!", "&", "*", "|", ">"):
        raise ConversionError(f"unsupported YAML value in mkdocs.yml: {text!r}")
    return text


def _top_level_blocks(text: str) -> dict[str, tuple[str, list[str]]]:
    """Split mkdocs.yml into ``key -> (inline value, continuation lines)``."""
    lines = text.replace("\r\n", "\n").split("\n")
    blocks: dict[str, tuple[str, list[str]]] = {}
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        if not raw.strip() or raw[0] in " \t#-" or raw.startswith("..."):
            continue
        match = re.match(r"^([A-Za-z_][\w-]*)[ \t]*:(?:[ \t]+(.*))?$", raw)
        if match is None:
            continue
        cont: list[str] = []
        while i < len(lines):
            nxt = lines[i]
            if nxt.strip() and nxt[0] not in " \t#" and not nxt.startswith("- ") and nxt != "-":
                break
            cont.append(nxt)
            i += 1
        blocks[match.group(1)] = (match.group(2) or "", cont)
    return blocks


def _block_scalar(indicator: str, lines: list[str]) -> list[str]:
    """Content lines of a ``|``/``>`` block scalar (dedented, blank-trimmed)."""
    if not re.fullmatch(r"[|>][+-]?", indicator.strip()):
        raise ConversionError(f"expected a block scalar in mkdocs.yml, got {indicator!r}")
    content = [ln.expandtabs(8) for ln in lines]
    while content and not content[-1].strip():
        content.pop()
    widths = [len(ln) - len(ln.lstrip(" ")) for ln in content if ln.strip()]
    cut = min(widths, default=0)
    return [ln[cut:] for ln in content]


def _split_key(body: str) -> tuple[str | None, str]:
    """``Title: value`` -> (title, value); a bare scalar -> (None, scalar)."""
    if body[:1] in ('"', "'"):
        quote_char = body[0]
        end = 1
        while True:
            end = body.find(quote_char, end)
            if end < 0:
                raise ConversionError(f"unterminated quote in mkdocs.yml nav entry: {body!r}")
            if quote_char == "'" and body[end + 1 : end + 2] == "'":
                end += 2
                continue
            if quote_char == '"' and body[end - 1] == "\\":
                end += 1
                continue
            break
        rest = body[end + 1 :].strip()
        if not rest:
            return None, _scalar(body)
        if not rest.startswith(":"):
            raise ConversionError(f"cannot parse mkdocs.yml nav entry: {body!r}")
        return _scalar(body[: end + 1]), rest[1:].strip()
    if body.endswith(":"):
        return body[:-1].strip(), ""
    idx = body.find(": ")
    if idx < 0:
        return None, body
    return body[:idx].strip(), body[idx + 2 :].strip()


def _parse_nav_items(
    items: list[tuple[int, str]], pos: int, indent: int
) -> tuple[list[RawNav], int]:
    entries: list[RawNav] = []
    while pos < len(items):
        ind, text = items[pos]
        if ind < indent:
            break
        if ind > indent or not (text == "-" or text.startswith("- ")):
            raise ConversionError(f"cannot parse mkdocs.yml nav line: {text!r}")
        body = text[1:].strip()
        pos += 1
        if not body:
            raise ConversionError("multi-line nav entries are not supported in mkdocs.yml")
        title, value = _split_key(body)
        if title is None:
            entries.append(RawNav(None, _scalar(value)))
        elif value:
            entries.append(RawNav(title, _scalar(value)))
        else:
            if pos >= len(items) or items[pos][0] <= indent:
                raise ConversionError(f"nav section {title!r} has no entries")
            children, pos = _parse_nav_items(items, pos, items[pos][0])
            entries.append(RawNav(title, None, tuple(children)))
    return entries, pos


def parse_nav(lines: list[str]) -> tuple[RawNav, ...]:
    """Parse the block-style ``nav`` sequence of mkdocs.yml."""
    items: list[tuple[int, str]] = []
    for raw in lines:
        stripped = _strip_comment(raw.expandtabs(8))
        if stripped.strip():
            items.append((len(stripped) - len(stripped.lstrip(" ")), stripped.strip()))
    if not items:
        return ()
    entries, pos = _parse_nav_items(items, 0, items[0][0])
    if pos != len(items):
        raise ConversionError(f"cannot parse mkdocs.yml nav line: {items[pos][1]!r}")
    return tuple(entries)


def load_mkdocs_config(path: Path) -> MkDocsConfig:
    """Read ``site_name``, ``site_url``, ``repo_url``, ``docs_dir``, ``nav`` and
    ``not_in_nav`` from mkdocs.yml without constructing any YAML tags."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConversionError(f"cannot read {path}: {exc}") from exc
    blocks = _top_level_blocks(text)

    def scalar(key: str, default: str = "") -> str:
        if key not in blocks:
            return default
        return _scalar(_strip_comment(blocks[key][0])) or default

    nav_inline, nav_lines = blocks.get("nav", ("", []))
    if _strip_comment(nav_inline).strip():
        raise ConversionError("mkdocs.yml: only a block-style nav list is supported")
    not_in_nav: tuple[str, ...] = ()
    if "not_in_nav" in blocks:
        indicator, lines = blocks["not_in_nav"]
        patterns = _block_scalar(_strip_comment(indicator), lines)
        not_in_nav = tuple(
            p.strip() for p in patterns if p.strip() and not p.strip().startswith("#")
        )
    nav = parse_nav(nav_lines)
    if not nav:
        raise ConversionError("mkdocs.yml has no nav; page names come from nav titles")
    return MkDocsConfig(
        site_name=scalar("site_name", "Documentation"),
        site_url=scalar("site_url"),
        repo_url=scalar("repo_url").rstrip("/"),
        docs_dir=scalar("docs_dir", "docs").strip("/"),
        nav=nav,
        not_in_nav=not_in_nav,
    )


def matches_not_in_nav(rel: str, patterns: tuple[str, ...]) -> bool:
    """gitignore-style match of a docs-relative path (what ``not_in_nav`` uses)."""
    for pattern in patterns:
        pat = pattern.rstrip("/")
        if pat.startswith("/") or "/" in pat:
            if fnmatch.fnmatchcase(rel, pat.lstrip("/")):
                return True
        elif any(fnmatch.fnmatchcase(part, pat) for part in rel.split("/")):
            return True
    return False


# --------------------------------------------------------------------------
# Navigation model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class NavPage:
    title: str
    src: str  # docs-relative POSIX path
    name: str  # wiki page name (file name without ``.md``)


@dataclass(frozen=True)
class NavLink:
    title: str
    url: str


@dataclass(frozen=True)
class NavSection:
    title: str
    children: tuple[NavItem, ...]


NavItem = NavPage | NavLink | NavSection


def wiki_page_name(title: str) -> str:
    """GitHub wiki file name for a page title.

    GitHub stores a title's spaces as ``-`` and a literal ``-`` as U+2010 so the
    title round-trips (the 1.x wiki's ``Data-Accessing-‐-RPM-and-DPKG.md``)."""
    name = _WIKI_NAME_BAD.sub("", title.strip()).replace("-", "\u2010")
    name = re.sub(r"\s+", "-", name)
    if not name:
        raise ConversionError(f"nav title {title!r} gives an empty wiki page name")
    return name


def _first_heading(path: Path) -> str | None:
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#[ \t]+(.+?)[ \t#]*$", line)
        if match:
            return _ATTR_LIST.sub("", match.group(1)).strip()
    return None


def build_nav(raw: tuple[RawNav, ...], docs: Path) -> tuple[NavItem, ...]:
    """Resolve the raw nav against the docs directory (missing files are errors)."""
    seen_names: dict[str, str] = {}

    def resolve(entry: RawNav) -> NavItem:
        if entry.target is None:
            return NavSection(entry.title or "", tuple(resolve(c) for c in entry.children))
        target = entry.target
        if _SCHEME.match(target) or target.startswith("/"):
            return NavLink(entry.title or target, target)
        src = posixpath.normpath(target.replace("\\", "/"))
        path = docs / src
        if src.startswith("../") or src == ".." or not path.is_file():
            raise ConversionError(
                f"nav entry {entry.title or target!r} points at missing file {docs.name}/{src}"
            )
        title = entry.title or _first_heading(path) or Path(src).stem.replace("-", " ").title()
        name = HOME_PAGE if src == "index.md" else wiki_page_name(title)
        if name in seen_names and seen_names[name] != src:
            raise ConversionError(
                f"nav entries {seen_names[name]!r} and {src!r} map to the same wiki page {name!r}"
            )
        seen_names[name] = src
        return NavPage(title, src, name)

    return tuple(resolve(e) for e in raw)


def iter_pages(items: tuple[NavItem, ...]) -> list[NavPage]:
    """Nav pages in nav order, first occurrence of each source only."""
    pages: list[NavPage] = []
    seen: set[str] = set()

    def walk(nodes: tuple[NavItem, ...]) -> None:
        for node in nodes:
            if isinstance(node, NavPage):
                if node.src not in seen:
                    seen.add(node.src)
                    pages.append(node)
            elif isinstance(node, NavSection):
                walk(node.children)

    walk(items)
    return pages


# --------------------------------------------------------------------------
# Headings and anchors
# --------------------------------------------------------------------------


def _heading_plain_text(raw: str) -> str:
    text = _ICON.sub("", _ATTR_LIST.sub("", raw))
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("`", "").replace("**", "").replace("*", "")
    text = re.sub(r"\\(.)", r"\1", text)
    return html.unescape(text).strip()


def mkdocs_slug(text: str) -> str:
    """Python-Markdown's default ``toc`` slugify (what MkDocs anchors use)."""
    value = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^\w\s-]", "", value).strip().lower()
    return re.sub(r"[-\s]+", "-", value)


def github_slug(text: str) -> str:
    """GitHub's heading anchor (github-slugger): punctuation dropped, no collapsing."""
    return re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")


@dataclass
class Anchors:
    """Heading anchors of one page: MkDocs id -> GitHub id."""

    by_mkdocs: dict[str, str] = field(default_factory=dict)
    github: set[str] = field(default_factory=set)

    def translate(self, anchor: str) -> str | None:
        if anchor in self.by_mkdocs:
            return self.by_mkdocs[anchor]
        if anchor in self.github:
            return anchor
        return None


def _iter_outside_fences(lines: list[str]) -> list[str]:
    result: list[str] = []
    fence: tuple[str, int] | None = None
    for line in lines:
        if fence is not None:
            if _closes_fence(line, fence):
                fence = None
            continue
        match = _FENCE_OPEN.match(line)
        if match and _valid_fence(match):
            fence = (match.group("fence")[0], len(match.group("fence")))
            continue
        result.append(line)
    return result


def collect_anchors(lines: list[str]) -> Anchors:
    anchors = Anchors()
    mk_used: set[str] = set()
    gh_count: dict[str, int] = {}
    for line in _iter_outside_fences(lines):
        for match in re.finditer(r"<a\s[^>]*\b(?:id|name)=[\"']([^\"']+)[\"']", line):
            anchors.by_mkdocs.setdefault(match.group(1), match.group(1))
            anchors.github.add(match.group(1))
        heading = _HEADING.match(line)
        if heading is None:
            continue
        raw = heading.group("text")
        attr = _ATTR_LIST.search(raw)
        custom = _ATTR_ID.search(attr.group(0)) if attr else None
        text = _heading_plain_text(raw)
        base = github_slug(text)
        count = gh_count.get(base, 0)
        gh_count[base] = count + 1
        gh_id = base if count == 0 else f"{base}-{count}"
        anchors.github.add(gh_id)
        if custom is not None:
            mk_id = custom.group(1)
            gh_id = mk_id  # an explicit <a id> is emitted before the heading
            anchors.github.add(mk_id)
        else:
            mk_id = mkdocs_slug(text)
            while mk_id in mk_used or not mk_id:
                numbered = re.match(r"^(.*)_([0-9]+)$", mk_id)
                mk_id = (
                    f"{numbered.group(1)}_{int(numbered.group(2)) + 1}"
                    if numbered
                    else f"{mk_id}_1"
                )
        mk_used.add(mk_id)
        anchors.by_mkdocs.setdefault(mk_id, gh_id)
    return anchors


# --------------------------------------------------------------------------
# Conversion
# --------------------------------------------------------------------------


def _valid_fence(match: re.Match[str]) -> bool:
    return not (match.group("fence")[0] == "`" and "`" in match.group("info"))


def _closes_fence(line: str, fence: tuple[str, int]) -> bool:
    char, length = fence
    return re.fullmatch(rf"[ \t>]*{re.escape(char)}{{{length},}}[ \t]*", line) is not None


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _collect_body(lines: list[str], start: int, min_indent: int) -> tuple[list[str], int]:
    """Indented body of an admonition/tab; returns (dedented lines, next index)."""
    body: list[str] = []
    end = start
    j = start
    while j < len(lines):
        line = lines[j].expandtabs(4)
        if not line.strip():
            body.append("")
        elif _indent_width(line) >= min_indent:
            body.append(line[min_indent:])
            end = j + 1
        else:
            break
        j += 1
    # trailing blank lines belong to the surrounding document
    return body[: end - start], end


def _md_dest(url: str) -> str:
    return f"<{url}>" if re.search(r"[\s()<>]", url) else url


@dataclass
class Result:
    written: list[str]
    removed: list[str]
    warnings: list[str]


class WikiConverter:
    """Convert the nav pages of a MkDocs docs directory into wiki files."""

    def __init__(self, docs: Path, config: MkDocsConfig, *, branch: str = DEFAULT_BRANCH) -> None:
        self.docs = docs
        self.config = config
        self.branch = branch
        self.nav = build_nav(config.nav, docs)
        self.pages = iter_pages(self.nav)
        self.by_src = {page.src: page for page in self.pages}
        self.anchors = {
            page.src: collect_anchors(self._read(page.src).split("\n")) for page in self.pages
        }
        self.assets: set[str] = set()
        self.warnings: list[str] = []
        self._page: NavPage | None = None

    # -- helpers -----------------------------------------------------------

    def _read(self, src: str) -> str:
        return (self.docs / src).read_text(encoding="utf-8").replace("\r\n", "\n")

    def _warn(self, message: str) -> None:
        where = f"{self.config.docs_dir}/{self._page.src}: " if self._page else ""
        self.warnings.append(where + message)

    def repo_file_url(self, docs_rel: str) -> str:
        path = posixpath.join(self.config.docs_dir, docs_rel) if docs_rel else self.config.docs_dir
        return f"{self.config.repo_url}/blob/{self.branch}/{quote(path)}"

    def unpublished_sources(self) -> list[str]:
        """Markdown sources that get no wiki page, warning about true orphans."""
        skipped: list[str] = []
        for path in sorted(self.docs.rglob("*.md")):
            rel = path.relative_to(self.docs).as_posix()
            if rel in self.by_src:
                continue
            skipped.append(rel)
            if not matches_not_in_nav(rel, self.config.not_in_nav):
                self._warn(f"{rel} is neither in nav nor in not_in_nav; not published")
        return skipped

    # -- links -------------------------------------------------------------

    def rewrite_url(self, url: str) -> str:
        """Map one link destination from MkDocs to the wiki."""
        if self._page is None:
            raise RuntimeError("rewrite_url() is only valid while a page is converted")
        bracketed = url.startswith("<") and url.endswith(">")
        raw = url[1:-1] if bracketed else url
        if not raw or _SCHEME.match(raw) or raw.startswith("/"):
            return url
        path_part, _, fragment = raw.partition("#")
        path_part, _, query = path_part.partition("?")
        if not path_part:
            anchors = self.anchors[self._page.src]
            return "#" + self._anchor(anchors, fragment, self._page.src) if fragment else url
        base = posixpath.dirname(self._page.src)
        target = posixpath.normpath(posixpath.join(base, unquote(path_part)))
        if target == ".." or target.startswith("../"):
            repo_path = posixpath.normpath(posixpath.join(self.config.docs_dir, target))
            if repo_path.startswith("../"):
                self._warn(f"link {raw!r} leaves the repository; left unchanged")
                return url
            dest = f"{self.config.repo_url}/blob/{self.branch}/{quote(repo_path)}"
            return _md_dest(dest + (f"#{fragment}" if fragment else ""))
        target = "" if target == "." else target
        full = self.docs / target if target else self.docs
        if full.is_dir() or path_part.endswith("/"):
            target = posixpath.join(target, "index.md") if target else "index.md"
            full = self.docs / target
        suffix = f"?{query}" if query else ""
        if target.endswith(".md"):
            page = self.by_src.get(target)
            if page is not None:
                anchor = (
                    "#" + self._anchor(self.anchors[target], fragment, target) if fragment else ""
                )
                return _md_dest(page.name + anchor)
            if not full.is_file():
                self._warn(f"link {raw!r} points at missing page {target}")
            dest = self.repo_file_url(target) + suffix + (f"#{fragment}" if fragment else "")
            return _md_dest(dest)
        if not full.is_file():
            self._warn(f"link {raw!r} points at missing file {target}")
            return url
        try:
            inside = full.resolve().is_relative_to(self.docs.resolve())
        except OSError:
            inside = False
        if not inside:
            self._warn(f"link {raw!r} resolves outside {self.config.docs_dir}/; left unchanged")
            return url
        self.assets.add(target)
        dest = quote(target) + suffix + (f"#{fragment}" if fragment else "")
        return f"<{dest}>" if bracketed else _md_dest(dest)

    def _anchor(self, anchors: Anchors, fragment: str, target: str) -> str:
        translated = anchors.translate(fragment)
        if translated is None:
            self._warn(f"anchor #{fragment} not found in {target}")
            return fragment
        return translated

    # -- inline ------------------------------------------------------------

    def _inline_text(self, text: str) -> str:
        def icon(match: re.Match[str]) -> str:
            return "→ " if match.group("name").startswith("arrow-right") else ""

        text = _ICON.sub(icon, text)
        text = _ATTR_LIST.sub("", text)
        text = _LINK_DEST.sub(lambda m: m.group("pre") + self.rewrite_url(m.group("url")), text)
        return _HTML_ATTR.sub(
            lambda m: (
                m.group("pre") + m.group("q") + self.rewrite_url(m.group("url")) + m.group("q")
            ),
            text,
        )

    def convert_inline(self, line: str) -> str:
        """Rewrite one non-code line, leaving inline code spans alone."""
        ref = _REF_DEF.match(line)
        if ref:
            return ref.group("pre") + self.rewrite_url(ref.group("url")) + line[ref.end() :]
        out: list[str] = []
        pos = 0
        for span in _CODE_SPAN.finditer(line):
            out.append(self._inline_text(line[pos : span.start()]))
            ticks, code = span.group(1), span.group(2)
            out.append(ticks + _INLINE_HILITE.sub("", code) + ticks)
            pos = span.end()
        out.append(self._inline_text(line[pos:]))
        return "".join(out)

    # -- blocks ------------------------------------------------------------

    def convert_lines(self, lines: list[str], alert_depth: int = 0) -> list[str]:
        out: list[str] = []
        fence: tuple[str, int] | None = None
        divs: list[str] = []  # "md" for dropped markdown-enabled divs, "html" otherwise
        i = 0
        while i < len(lines):
            line = lines[i]
            if fence is not None:
                out.append(line)
                if _closes_fence(line, fence):
                    fence = None
                i += 1
                continue
            fence_match = _FENCE_OPEN.match(line)
            if fence_match and _valid_fence(fence_match):
                fence = (fence_match.group("fence")[0], len(fence_match.group("fence")))
                out.append(line)
                i += 1
                continue
            admonition = _ADMONITION.match(line)
            tab = None if admonition else _TAB.match(line)
            block = admonition or tab
            if block is not None:
                indent = block.group("indent")
                body, i = _collect_body(lines, i + 1, len(indent) + 4)
                while body and not body[0].strip():
                    body.pop(0)
                if admonition is not None:
                    rendered = self._alert(
                        admonition.group("type").lower(),
                        admonition.group("title"),
                        body,
                        alert_depth,
                    )
                elif tab is not None:
                    title = self.convert_inline(tab.group("title").replace('\\"', '"'))
                    rendered = [f"**{title}**", "", *self.convert_lines(body, alert_depth)]
                if out and out[-1].strip():
                    out.append("")
                out.extend(indent + ln if ln else ln for ln in rendered)
                if i < len(lines) and lines[i].strip():
                    out.append("")
                continue
            div_open = _DIV_OPEN.match(line)
            if div_open:
                attrs = div_open.group("attrs")
                if _MD_ATTR.search(attrs):
                    divs.append("cards" if re.search(r"\bcards\b", attrs) else "md")
                    i += 1
                    continue
                divs.append("html")
            elif _DIV_CLOSE.match(line) and divs:
                if divs.pop() != "html":
                    i += 1
                    continue
            elif divs and divs[-1] == "cards" and _CARD_RULE.match(line):
                # grid-card separators would render as rules inside list items
                i += 1
                if i < len(lines) and not lines[i].strip():
                    i += 1
                continue
            heading = _HEADING.match(line)
            if heading:
                attr = _ATTR_LIST.search(heading.group("text"))
                custom = _ATTR_ID.search(attr.group(0)) if attr else None
                if custom is not None:
                    out.append(f'<a id="{html.escape(custom.group(1))}"></a>')
            out.append(self.convert_inline(line))
            i += 1
        return out

    def _alert(self, kind: str, title: str | None, body: list[str], depth: int) -> list[str]:
        alert = ALERT_TYPES.get(kind, "NOTE")
        if title is None and kind != alert.lower():
            title = kind.capitalize()  # keep e.g. "Example" visible when mapped to NOTE
        label = self.convert_inline(title.replace('\\"', '"')) if title else ""
        if depth == 0:
            head = [f"> [!{alert}]"] + ([f"> **{label}**"] if label else [])
        else:  # GitHub alerts cannot nest; fall back to a titled blockquote
            head = [f"> **{label or alert.capitalize()}**"]
        inner = self.convert_lines(body, depth + 1)
        while inner and not inner[-1].strip():
            inner.pop()
        return head + [f"> {ln}" if ln.strip() else ">" for ln in inner]

    def convert_page(self, page: NavPage) -> str:
        self._page = page
        try:
            lines = self.convert_lines(self._read(page.src).split("\n"))
        finally:
            self._page = None
        lines = _collapse_blank_lines(lines)
        header = (
            f"<!-- Generated by {GENERATOR} from {self.config.docs_dir}/{page.src}"
            " - edit the source in the repository, not this page. -->"
        )
        return header + "\n\n" + "\n".join(lines).strip("\n") + "\n"

    # -- wiki chrome ---------------------------------------------------------

    def sidebar(self) -> str:
        lines = [f"**[{self.config.site_name}]({HOME_PAGE})**", ""]

        def walk(items: tuple[NavItem, ...], depth: int) -> None:
            pad = "  " * depth
            for item in items:
                if isinstance(item, NavPage):
                    lines.append(f"{pad}- [{item.title}]({_md_dest(item.name)})")
                elif isinstance(item, NavLink):
                    lines.append(f"{pad}- [{item.title}]({_md_dest(item.url)})")
                else:
                    lines.append(f"{pad}- **{item.title}**")
                    walk(item.children, depth + 1)

        walk(self.nav, 0)
        return "\n".join(lines) + "\n"

    def footer(self) -> str:
        repo = self.config.repo_url
        docs = self.config.docs_dir
        text = (
            f"This wiki is generated from [`{docs}/`]({repo}/tree/{self.branch}/{quote(docs)})"
            f" on `{self.branch}` by [`{GENERATOR}`]({repo}/blob/{self.branch}/{GENERATOR});"
            " edits made here are overwritten on the next sync, so please change the files"
            " in the repository instead."
        )
        if self.config.site_url:
            text += (
                f" The documentation is also published at [{self.config.site_url}]"
                f"({self.config.site_url})."
            )
        return text + "\n"

    def render(self) -> dict[str, str]:
        """Every generated wiki page (relative path -> text); collects assets."""
        files: dict[str, str] = {}
        for page in self.pages:
            files[f"{page.name}.md"] = self.convert_page(page)
        files[SIDEBAR] = self.sidebar()
        files[FOOTER] = self.footer()
        return files


def _collapse_blank_lines(lines: list[str]) -> list[str]:
    out: list[str] = []
    fence: tuple[str, int] | None = None
    for line in lines:
        if fence is not None:
            out.append(line)
            if _closes_fence(line, fence):
                fence = None
            continue
        match = _FENCE_OPEN.match(line)
        if match and _valid_fence(match):
            fence = (match.group("fence")[0], len(match.group("fence")))
        if not line.strip():
            if out and out[-1] == "":
                continue
            out.append("")
            continue
        out.append(line)
    return out


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def _prepare_destination(out: Path, rel: str) -> Path:
    """Destination path under ``out``; symlinks on the way are replaced, never followed."""
    dest = out
    parts = rel.split("/")
    for part in parts[:-1]:
        dest /= part
        if dest.is_symlink():
            dest.unlink()
        dest.mkdir(exist_ok=True)
    dest /= parts[-1]
    if dest.is_symlink():
        dest.unlink()
    return dest


def _is_git_path(rel: Path) -> bool:
    return ".git" in rel.parts


def prune(out: Path, keep: set[str]) -> list[str]:
    """Remove wiki pages under ``out`` that were not generated; never touches ``.git``."""
    removed: list[str] = []
    for root, dirs, names in os.walk(out):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for name in sorted(names):
            path = Path(root) / name
            rel = path.relative_to(out)
            if _is_git_path(rel) or not name.lower().endswith(PAGE_SUFFIXES):
                continue
            if rel.as_posix() not in keep:
                path.unlink()
                removed.append(rel.as_posix())
    return sorted(removed)


def convert(
    docs: Path,
    mkdocs_yml: Path,
    out: Path,
    *,
    do_prune: bool = False,
    branch: str = DEFAULT_BRANCH,
) -> Result:
    """Convert ``docs`` into the wiki checkout ``out`` and return what changed."""
    if not docs.is_dir():
        raise ConversionError(f"docs directory {docs} does not exist")
    docs_abs, out_abs = docs.resolve(), out.resolve()
    if out_abs == docs_abs or out_abs.is_relative_to(docs_abs):
        raise ConversionError("the wiki output directory must not be inside the docs directory")
    config = load_mkdocs_config(mkdocs_yml)
    converter = WikiConverter(docs, config, branch=branch)
    converter.unpublished_sources()
    files = converter.render()
    out.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for rel in sorted(files):
        dest = _prepare_destination(out, rel)
        dest.write_bytes(files[rel].encode("utf-8"))
        written.append(rel)
    for rel in sorted(converter.assets):
        dest = _prepare_destination(out, rel)
        shutil.copyfile(docs / rel, dest)
        written.append(rel)
    removed = prune(out, set(files)) if do_prune else []
    return Result(written=written, removed=removed, warnings=converter.warnings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    parser.add_argument("--docs", type=Path, default=Path("Docs"), help="MkDocs docs_dir")
    parser.add_argument("--mkdocs", type=Path, default=Path("mkdocs.yml"), help="mkdocs.yml")
    parser.add_argument("--out", type=Path, required=True, help="GitHub wiki checkout to write")
    parser.add_argument(
        "--prune", action="store_true", help="delete wiki pages that are no longer generated"
    )
    parser.add_argument(
        "--branch", default=DEFAULT_BRANCH, help="branch used for links back to the repository"
    )
    parser.add_argument("--strict", action="store_true", help="exit 1 on any warning")
    args = parser.parse_args(argv)
    try:
        result = convert(args.docs, args.mkdocs, args.out, do_prune=args.prune, branch=args.branch)
    except ConversionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for rel in result.written:
        print(f"wrote   {rel}")
    for rel in result.removed:
        print(f"removed {rel}")
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return 1 if args.strict and result.warnings else 0


if __name__ == "__main__":
    sys.exit(main())
