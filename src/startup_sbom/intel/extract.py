"""Stdlib-only HTML/plain-text to clean text extraction and untrusted-text sanitising.

Never executes JavaScript and never loads sub-resources.  Drops script/style/template
and navigation chrome, and *hidden* content (``hidden``, ``aria-hidden``, inline
``display:none`` / ``visibility:hidden`` / zero size / off-screen / transparent text,
screen-reader-only classes, comments), which is the usual carrier of prompt-injection
payloads aimed at an LLM reading the page.  External-stylesheet hiding cannot be
detected without a CSS engine; spotlighting (:func:`startup_sbom.intel.untrusted_block`)
is the backstop.
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser

from startup_sbom.textsafe import clean

MAX_TEXT = 20_000
MAX_SNIPPET = 600
MAX_TITLE = 300

SKIP_TAGS = frozenset(
    {
        "script", "style", "noscript", "template", "svg", "math", "iframe", "object",
        "embed", "canvas", "video", "audio", "picture", "select", "button", "form",
        "nav", "header", "footer", "aside", "dialog", "textarea", "frameset",
    }
)  # fmt: skip
VOID = frozenset(
    {
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
        "param", "source", "track", "wbr",
    }
)  # fmt: skip
BLOCK = frozenset(
    {
        "p", "div", "section", "article", "main", "li", "ul", "ol", "pre", "blockquote",
        "h1", "h2", "h3", "h4", "h5", "h6", "tr", "table", "dt", "dd", "br", "hr",
        "figcaption", "summary", "details",
    }
)  # fmt: skip
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse)"
    r"|font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?:\.0+)?(?![.\d])"
    r"|(?:^|;)\s*(?:width|height|max-height|line-height)\s*:\s*0(?:px)?\s*(?:!important\s*)?(?:;|$)"
    r"|(?:left|top|right|text-indent)\s*:\s*-\d{3,}"
    r"|clip\s*:\s*rect\(\s*0|clip-path\s*:\s*inset\(\s*50%|transform\s*:\s*scale\(\s*0[\s,)]"
    r"|(?<![-\w])color\s*:\s*transparent",
    re.IGNORECASE,
)
_HIDDEN_CLASS = frozenset(
    {
        "sr-only", "visually-hidden", "visuallyhidden", "screen-reader-text",
        "screen-reader-only", "d-none", "invisible", "hidden", "hide", "is-hidden",
        "u-hidden", "offscreen",
    }
)  # fmt: skip
_RESPONSIVE_SHOW = re.compile(r"^\w+:(?:block|flex|grid|inline|inline-block|table)$")
_CHROME_CLASS = re.compile(
    r"(^|[\s_-])(cookie|consent|banner|newsletter|subscribe|share|social|related|sidebar|"
    r"breadcrumb|menu|navbar|footer|header|comment|comments|advert|promo|modal|popup)"
    r"([\s_-]|$)",
    re.IGNORECASE,
)
_CHROME_ROLES = frozenset({"navigation", "banner", "contentinfo", "dialog", "alert", "search"})
_CONTAINERS = frozenset({"div", "section", "ul", "ol", "span", "p", "table", "aside"})


@dataclass(slots=True)
class Extracted:
    title: str | None = None
    site_name: str | None = None
    published: str | None = None
    description: str | None = None
    text: str = ""
    links: list[str] = field(default_factory=list)


def _is_hidden(tag: str, attrs: dict[str, str]) -> bool:
    if "hidden" in attrs or attrs.get("aria-hidden", "").strip().lower() == "true":
        return True
    if _HIDDEN_STYLE.search(attrs.get("style", "")):
        return True
    if attrs.get("type", "").lower() == "hidden":
        return True
    tokens = attrs.get("class", "").lower().split()
    if any(t in _HIDDEN_CLASS for t in tokens):
        only_hidden = [t for t in tokens if t in _HIDDEN_CLASS]
        responsive = any(_RESPONSIVE_SHOW.match(t) for t in tokens)
        if not (responsive and only_hidden == ["hidden"]):
            return True
    if tag in _CONTAINERS and _CHROME_CLASS.search(
        attrs.get("class", "") + " " + attrs.get("id", "")
    ):
        return True
    return attrs.get("role", "").lower() in _CHROME_ROLES


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.skip: str | None = None  # tag of the dropped subtree we are inside
        self.skip_depth = 0
        self.in_title = False
        self.title_parts: list[str] = []
        self.meta: dict[str, str] = {}
        self.ldjson: list[str] = []
        self.in_ld = False
        self.body: list[str] = []
        self.main: list[str] = []
        self.main_depth = 0
        self.links: list[str] = []
        self.pre = 0
        self.h1: list[str] = []
        self.in_h1 = False
        self.seen_h1 = False

    def _emit(self, s: str) -> None:
        self.body.append(s)
        if self.main_depth:
            self.main.append(s)

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {k.lower(): (v or "") for k, v in attrs_list}
        if self.skip is not None:
            if tag == self.skip and tag not in VOID:
                self.skip_depth += 1
            return
        if tag == "meta":
            key = (
                attrs.get("property") or attrs.get("name") or attrs.get("itemprop") or ""
            ).lower()
            if key and attrs.get("content"):
                self.meta.setdefault(key, attrs["content"])
            return
        if tag == "title":
            self.in_title = True
            return
        if tag == "script" and attrs.get("type", "").lower() == "application/ld+json":
            self.in_ld = True
            self.skip, self.skip_depth = tag, 1
            return
        if tag == "time" and attrs.get("datetime"):
            self.meta.setdefault("time", attrs["datetime"])
        if tag in VOID:
            if tag in {"br", "hr"}:
                self._emit("\n")
            return
        if tag in SKIP_TAGS or _is_hidden(tag, attrs):
            self.skip, self.skip_depth = tag, 1
            return
        if tag in {"main", "article"}:
            self.main_depth += 1
        if tag == "a" and attrs.get("href", "").startswith("https://"):
            self.links.append(attrs["href"])
        if tag == "pre":
            self.pre += 1
        if tag == "h1" and not self.seen_h1:
            self.in_h1 = True
        if tag in BLOCK:
            self._emit("\n")
        if tag == "li":
            self._emit("- ")
        if tag in {"td", "th"}:
            self._emit(" | ")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # ``<div hidden/>`` is not self-closing in HTML; browsers treat it as an open tag.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if self.skip is not None:
            if tag == self.skip:
                self.skip_depth -= 1
                if self.skip_depth <= 0:
                    self.skip = None
                    self.in_ld = False
            return
        if tag == "title":
            self.in_title = False
        if tag in {"main", "article"} and self.main_depth:
            self.main_depth -= 1
        if tag == "pre" and self.pre:
            self.pre -= 1
        if tag == "h1" and self.in_h1:
            self.in_h1 = False
            self.seen_h1 = True
        if tag in BLOCK:
            self._emit("\n")

    def handle_data(self, data: str) -> None:
        if self.in_ld:
            if sum(len(x) for x in self.ldjson) < 200_000:
                self.ldjson.append(data)
            return
        if self.skip is not None:
            return
        if self.in_title:
            self.title_parts.append(data)
            return
        if self.in_h1:
            self.h1.append(data)
        self._emit(data if self.pre else re.sub(r"\s+", " ", data))


# --------------------------------------------------------------------------- sanitising
_INVISIBLE = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e"
    "\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb]"
    "|[\U000e0000-\U000e007f]"  # Unicode tag characters ("ASCII smuggling")
    "|[\U000e0100-\U000e01ef]"  # variation selectors supplement
)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")  # keeps \t and \n
_ANSI = re.compile(
    r"(?:\x1b|\x9b)(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])"
    r"|\x9d[^\x07\x1b\x9c]*(?:\x07|\x9c)?"
)


def sanitize(text: str, limit: int = MAX_TEXT) -> str:
    """Make untrusted text safe to store, print or hand to an LLM (not *trustworthy*)."""
    text = _ANSI.sub("", text)
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub("", text)
    text = clean(text, keep_newlines=True)  # private-use and anything textsafe knows
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > limit:
        cut = text[: max(0, limit - 16)]
        head = cut.rsplit(" ", 1)[0] if " " in cut else cut
        text = head + " […truncated]"
    return text


def _ld_fields(blobs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for blob in blobs:
        try:
            data = json.loads(blob)
        except ValueError:
            continue
        stack: list[object] = [data]
        seen = 0
        while stack and seen < 2000:
            seen += 1
            node = stack.pop()
            if isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, dict):
                for key in ("datePublished", "headline", "dateModified"):
                    value = node.get(key)
                    if isinstance(value, str):
                        out.setdefault(key, value)
                pub = node.get("publisher")
                if isinstance(pub, dict) and isinstance(pub.get("name"), str):
                    out.setdefault("publisher", pub["name"])
                stack.extend(v for v in node.values() if isinstance(v, dict | list))
    return out


def extract_html(markup: str, *, limit: int = MAX_TEXT) -> Extracted:
    """Extract title/site/date/description and the clean main text from HTML."""
    parser = _Parser()
    try:
        parser.feed(markup)
        parser.close()
    except (AssertionError, ValueError):  # html.parser is lenient; stay defensive
        pass
    main = "".join(parser.main)
    body = main if len(main.strip()) > 400 else "".join(parser.body)
    ld = _ld_fields(parser.ldjson)
    meta = parser.meta
    doc_title = html.unescape("".join(parser.title_parts)).strip()
    h1 = " ".join("".join(parser.h1).split())
    if len(doc_title) < 12 and len(h1) > len(doc_title):  # generic <title> such as "Blog"
        doc_title = h1
    title = meta.get("og:title") or ld.get("headline") or doc_title or None
    published = (
        meta.get("article:published_time")
        or ld.get("datePublished")
        or meta.get("date")
        or meta.get("dc.date")
        or meta.get("datepublished")
        or meta.get("time")
    )
    site = sanitize(meta.get("og:site_name") or ld.get("publisher") or "", 100)
    desc = sanitize(meta.get("og:description") or meta.get("description") or "", 500)
    return Extracted(
        title=sanitize(title, MAX_TITLE) if title else None,
        site_name=site or None,
        published=sanitize(published, 40) if published else None,
        description=desc or None,
        text=sanitize(body, limit),
        links=list(dict.fromkeys(parser.links))[:200],
    )


def extract_text_plain(raw: str, *, limit: int = MAX_TEXT) -> Extracted:
    """Plain-text advisories: first non-empty line is the title."""
    text = sanitize(raw, limit)
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    return Extracted(title=sanitize(first, 200) or None, text=text)


# --------------------------------------------------------------------------- analysis
CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b")
EXPLOIT_HINTS = re.compile(
    r"\b(proof[- ]of[- ]concept|PoC|exploit(?:ed|ation|s)?|metasploit|nuclei template|"
    r"in the wild|actively exploited|weaponi[sz]ed|working exploit|remote code execution)\b",
    re.IGNORECASE,
)
PATCH_HINTS = re.compile(
    r"\b(fixed in|patch(?:ed|es)?|upgrade to|update to|commit [0-9a-f]{7,40}|"
    r"security update|mitigation|workaround)\b",
    re.IGNORECASE,
)
_CHROME_LINE = re.compile(
    r"(follow @|twitter|cookie|subscribe|sign in|log in|all rights reserved|"
    r"please check out the|open source software security wiki|powered by blists|"
    r"mailing list|unsubscribe|list archive|previous message|next message|"
    r"thread-next|thread-prev|date-next|date-prev|\bfrom:|\bsubject:|\bdate:|\bto:)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class Analysis:
    cves: list[str]
    ghsas: list[str]
    exploit_indicators: list[str]
    patch_indicators: list[str]
    snippet: str


def _paragraphs(text: str, *, reflow: bool) -> list[str]:
    if reflow:  # hard-wrapped text/plain advisories: join lines within a paragraph
        blocks = re.split(r"\n\s*\n", text)
        return [" ".join(b.split()) for b in blocks if b.strip()]
    return [p.strip() for p in text.split("\n") if p.strip()]


def analyse(text: str, cve: str | None = None, *, plain: bool = False) -> Analysis:
    """Indicators and a short sanitised snippet (prefers a paragraph naming ``cve``)."""
    cves = sorted({f"CVE-{a}-{b}" for a, b in CVE_RE.findall(text)})
    exploit = sorted({m.lower() for m in EXPLOIT_HINTS.findall(text)})
    patch = sorted({m.lower() for m in PATCH_HINTS.findall(text)})
    paras = [
        p
        for p in _paragraphs(text, reflow=plain)
        if len(p) > 80 and re.search(r"[.:;]\s|[.]$", p) and not _CHROME_LINE.search(p[:200])
    ]
    snippet = ""
    if cve:
        snippet = next((p for p in paras if cve.upper() in p.upper()), "")
    if not snippet and paras:
        snippet = paras[0]
    return Analysis(
        cves=cves[:50],
        ghsas=sorted(set(GHSA_RE.findall(text)))[:20],
        exploit_indicators=exploit[:10],
        patch_indicators=patch[:10],
        snippet=sanitize(snippet, MAX_SNIPPET),
    )
