"""On-disk intel cache (``<cache_dir>/intel``).  Writes are atomic; raw HTML is never stored.

Layout::

    index/exploits.json.gz     compact CVE -> Exploit-DB / Metasploit / nuclei index
    cve/<CVE>.json             IntelBundle (TTL 24 h; stale served offline)
    articles/<id>.json         IntelRecord (TTL 7 d), id = sha256(url)[:32]
    articles/<id>.txt          sanitised full text (<= 20 000 chars) for reader / agent
    robots/<sha256(host)>.json robots.txt cache (24 h)
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from startup_sbom.intel.extract import MAX_TEXT
from startup_sbom.models import IntelBundle, IntelRecord

log = logging.getLogger(__name__)

BUNDLE_TTL = 24 * 3600.0
ARTICLE_TTL = 7 * 86400.0
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
ARTICLE_ID = re.compile(r"^[0-9a-f]{32}$")


def article_id(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8", "replace")).hexdigest()[:32]


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        Path(tmp).replace(path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class IntelStore:
    """Cache of bundles, articles, robots.txt and the exploit index under ``root``."""

    def __init__(self, root: Path) -> None:
        self.root = root

    # -- helpers --------------------------------------------------------------
    def _read(self, path: Path, ttl: float | None) -> tuple[bytes, bool] | None:
        """``(content, stale)``; ``ttl=None`` accepts any age."""
        try:
            age = time.time() - path.stat().st_mtime
            data = path.read_bytes()
        except OSError:
            return None
        return data, ttl is not None and age > ttl

    def _write(self, path: Path, data: bytes) -> None:
        try:
            atomic_write(path, data)
        except OSError as exc:
            log.debug("intel cache write failed: %s", exc)

    # -- bundles --------------------------------------------------------------
    def bundle_path(self, cve: str) -> Path:
        if not CVE_ID.match(cve):
            raise ValueError(f"not a CVE id: {cve!r}")
        return self.root / "cve" / f"{cve}.json"

    def load_bundle(self, cve: str, ttl: float = BUNDLE_TTL) -> tuple[IntelBundle, bool] | None:
        hit = self._read(self.bundle_path(cve), ttl)
        if hit is None:
            return None
        try:
            return IntelBundle.model_validate_json(hit[0]), hit[1]
        except (ValidationError, ValueError):
            return None

    def save_bundle(self, bundle: IntelBundle) -> None:
        self._write(self.bundle_path(bundle.cve), bundle.model_dump_json(indent=1).encode())

    # -- articles -------------------------------------------------------------
    def load_article(self, url: str, ttl: float = ARTICLE_TTL) -> IntelRecord | None:
        hit = self._read(self.root / "articles" / f"{article_id(url)}.json", ttl)
        if hit is None or hit[1]:
            return None
        try:
            return IntelRecord.model_validate_json(hit[0])
        except (ValidationError, ValueError):
            return None

    def load_article_any_age(self, url: str) -> IntelRecord | None:
        hit = self._read(self.root / "articles" / f"{article_id(url)}.json", None)
        if hit is None:
            return None
        try:
            return IntelRecord.model_validate_json(hit[0])
        except (ValidationError, ValueError):
            return None

    def save_article(self, url: str, record: IntelRecord, text: str | None) -> None:
        aid = article_id(url)
        if text:
            self._write(self.root / "articles" / f"{aid}.txt", text[:MAX_TEXT].encode())
        self._write(self.root / "articles" / f"{aid}.json", record.model_dump_json().encode())

    def article_text(self, text_ref: str) -> str | None:
        if not ARTICLE_ID.match(text_ref):
            return None
        hit = self._read(self.root / "articles" / f"{text_ref}.txt", None)
        return hit[0].decode("utf-8", "replace")[:MAX_TEXT] if hit else None

    # -- robots ---------------------------------------------------------------
    def _robots_path(self, host: str) -> Path:
        return self.root / "robots" / f"{hashlib.sha256(host.encode()).hexdigest()[:32]}.json"

    def load_robots(self, host: str, ttl: float) -> tuple[str, str, float] | None:
        path = self._robots_path(host)
        hit = self._read(path, ttl)
        if hit is None or hit[1]:
            return None
        try:
            doc = json.loads(hit[0])
            if doc.get("host") != host:
                return None
            return str(doc["mode"]), str(doc.get("text", "")), float(doc["fetched"])
        except (ValueError, KeyError, TypeError, AttributeError):
            return None

    def save_robots(self, host: str, mode: str, text: str) -> None:
        doc = {"host": host, "mode": mode, "text": text, "fetched": time.time()}
        self._write(self._robots_path(host), json.dumps(doc).encode())

    # -- exploit index --------------------------------------------------------
    @property
    def index_path(self) -> Path:
        return self.root / "index" / "exploits.json.gz"

    def load_index(self) -> tuple[dict[str, Any], float] | None:
        """``(document, age_seconds)`` of the compact exploit index."""
        hit = self._read(self.index_path, None)
        if hit is None:
            return None
        try:
            doc = json.loads(gzip.decompress(hit[0]))
            age = time.time() - float(doc.get("built", 0))
        except (OSError, EOFError, ValueError, TypeError, AttributeError):
            return None
        return (doc, age) if isinstance(doc, dict) else None

    def save_index(self, doc: dict[str, Any]) -> None:
        raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        self._write(self.index_path, gzip.compress(raw, mtime=0))
