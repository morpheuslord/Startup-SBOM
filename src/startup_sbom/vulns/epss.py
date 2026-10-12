"""FIRST EPSS scores from the daily bulk CSV, with the JSON API as fallback.

The bulk file is preferred: one request covers every CVE and works offline from
the cache.  ``epss_scores-current.csv.gz`` is a 302 to a dated file and the shared
HTTP client never follows redirects, so the dated name is requested directly
(today, then the previous days until one exists).  The API's ``cve=`` parameter
silently returns nothing above 2000 characters, so API calls are chunked to at
most 100 CVEs and 2000 characters.
"""

from __future__ import annotations

import csv
import gzip
import io
import time
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from startup_sbom.errors import NetworkError
from startup_sbom.net import HttpClient

EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_TTL = 24 * 3600.0
DATED_TTL = 30 * 86400.0  # a dated score file never changes
API_TTL = 24 * 3600.0
LOOKBACK_DAYS = 4
API_MAX_CVES = 100
API_MAX_CHARS = 2000
_NS = "epss"


@dataclass(slots=True)
class EpssData:
    """``scores`` maps CVE id to ``(epss, percentile)``."""

    scores: dict[str, tuple[float, float]] = field(default_factory=dict)
    score_date: str | None = None
    model_version: str | None = None


def parse_epss_csv(data: bytes, wanted: Collection[str] | None = None) -> EpssData:
    """Parse the (optionally gzip-compressed) EPSS CSV, keeping only ``wanted`` CVEs."""
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError) as exc:
            raise NetworkError("epss: corrupt score file") from exc
    text = io.StringIO(data.decode("utf-8", errors="replace"))
    out = EpssData()
    first = text.readline()
    if first.startswith("#"):
        for part in first[1:].strip().split(","):
            key, _, value = part.partition(":")
            if key == "model_version":
                out.model_version = value
            elif key == "score_date":
                out.score_date = value[:10]
    else:
        text.seek(0)
    reader = csv.reader(text)
    header = next(reader, None)
    if not header or [h.strip().lower() for h in header[:3]] != ["cve", "epss", "percentile"]:
        raise NetworkError("epss: unexpected score file format")
    want = set(wanted) if wanted is not None else None
    for row in reader:
        if len(row) < 3 or (want is not None and row[0] not in want):
            continue
        try:
            out.scores[row[0]] = (float(row[1]), float(row[2]))
        except ValueError:
            continue
    return out


def _candidates(today: date) -> list[str]:
    return [(today - timedelta(days=n)).isoformat() for n in range(LOOKBACK_DAYS)]


def _dated_get(http: HttpClient, day: str) -> bytes:
    url = EPSS_CSV_URL.format(date=day)
    return http.get(url, ttl=DATED_TTL, cache_key=f"epss-csv:{day}").content


def fetch_epss_csv(
    http: HttpClient, *, today: date | None = None, force: bool = False
) -> tuple[bytes, str]:
    """Return ``(raw_file, score_date)`` from cache or ``epss.empiricalsecurity.com``."""
    pointer = http.cache_get_json(_NS, "latest", float("inf"))
    known = pointer.get("date") if isinstance(pointer, dict) else None
    if isinstance(known, str):
        fetched = float(pointer.get("fetched", 0)) if isinstance(pointer, dict) else 0.0
        if http.offline or (not force and time.time() - fetched <= EPSS_TTL):
            try:
                return _dated_get(http, known), known
            except NetworkError:
                if http.offline:
                    raise
    if http.offline:
        raise NetworkError("offline mode and no cached EPSS scores")
    day0 = today or datetime.now(UTC).date()
    last: NetworkError | None = None
    for day in _candidates(day0):
        try:
            data = _dated_get(http, day)
        except NetworkError as exc:
            last = exc
            continue
        http.cache_put_json(_NS, "latest", {"date": day, "fetched": time.time()})
        return data, day
    if isinstance(known, str):  # serve the last good file (stale) rather than nothing
        return _dated_get(http, known), known
    raise NetworkError(f"epss: no score file available: {last}")


def _chunks(cves: Iterable[str]) -> list[list[str]]:
    chunks: list[list[str]] = []
    cur: list[str] = []
    size = 0
    for cve in cves:
        add = len(cve) + (1 if cur else 0)
        if cur and (len(cur) >= API_MAX_CVES or size + add > API_MAX_CHARS):
            chunks.append(cur)
            cur, size, add = [], 0, len(cve)
        cur.append(cve)
        size += add
    if cur:
        chunks.append(cur)
    return chunks


def epss_from_api(http: HttpClient, cves: Iterable[str]) -> dict[str, tuple[float, float]]:
    """Scores via the FIRST API in safe chunks (fallback path)."""
    out: dict[str, tuple[float, float]] = {}
    for chunk in _chunks(sorted(set(cves))):
        params = {"cve": ",".join(chunk), "limit": str(API_MAX_CVES)}
        resp = http.get(EPSS_API_URL, params=params, ttl=API_TTL)
        try:
            doc = resp.json()
        except ValueError as exc:
            raise NetworkError("epss: malformed API response") from exc
        rows = doc.get("data") if isinstance(doc, dict) else None
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            try:
                out[str(row["cve"])] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
    return out


def load_epss(
    http: HttpClient, cves: Collection[str], *, today: date | None = None
) -> dict[str, tuple[float, float]]:
    """EPSS ``(score, percentile)`` for ``cves``: bulk CSV first, API if that fails online."""
    if not cves:
        return {}
    try:
        raw, _ = fetch_epss_csv(http, today=today)
        return parse_epss_csv(raw, cves).scores
    except NetworkError:
        if http.offline:
            raise
    return epss_from_api(http, cves)
