"""Distribution end-of-life lookup via the endoflife.date API v1.

``GET https://endoflife.date/api/v1/products/{product}/releases/{cycle}`` returns
``{"result": {"name", "isLts", "isEol", "eolFrom", ...}}``.  Responses are cached
for :data:`EOL_TTL` seconds through :class:`~startup_sbom.net.HttpClient`; in
offline mode only the (possibly stale) cache is consulted.  ``is_eol`` is
computed against today's UTC date from ``eolFrom`` when present.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, date, datetime
from typing import Any

from startup_sbom.errors import NetworkError
from startup_sbom.models import EOLInfo, OSInfo
from startup_sbom.net import HttpClient

log = logging.getLogger(__name__)

API = "https://endoflife.date/api/v1/products"
EOL_TTL = 7 * 24 * 3600
ROLLING = "rolling"

_SAFE = re.compile(r"[a-z0-9][a-z0-9.\-]{0,63}")
_ROLLING_IDS = frozenset(
    {"arch", "archarm", "opensuse-tumbleweed", "wolfi", "chainguard", "gentoo", "void", "manjaro"}
)


def _major(v: str) -> str:
    return v.split(".", 1)[0]


def _major_minor(v: str) -> str:
    return ".".join(v.split(".")[:2])


def _as_is(v: str) -> str:
    return v


#: os-release ``ID`` → (endoflife.date product, cycle derivation from ``VERSION_ID``).
_PRODUCTS = {
    "debian": ("debian", _major),
    "ubuntu": ("ubuntu", _major_minor),
    "alpine": ("alpine-linux", _major_minor),
    "rhel": ("rhel", _major),
    "centos": ("centos", _major),
    "rocky": ("rocky-linux", _major),
    "almalinux": ("almalinux", _major),
    "fedora": ("fedora", _major),
    "amzn": ("amazon-linux", _major),
    "opensuse-leap": ("opensuse", _major_minor),
    "sles": ("sles", _major_minor),
    "sles_sap": ("sles", _major_minor),
    "ol": ("oracle-linux", _major),
    "photon": ("photon", _major_minor),
    "linuxmint": ("linuxmint", _as_is),
}


def eol_key(os_info: OSInfo) -> tuple[str, str] | None:
    """``(product, cycle)`` for ``os_info``, ``(id, "rolling")`` or ``None`` if unknown."""
    for ident in (os_info.id, *os_info.id_like):
        oid = (ident or "").strip().lower()
        if oid in _ROLLING_IDS:
            return oid, ROLLING
        entry = _PRODUCTS.get(oid)
        if entry is None:
            continue
        if oid != os_info.id.strip().lower():
            # an ID_LIKE match only helps when the version scheme is shared
            return None
        product, derive = entry
        version = (os_info.version_id or "").strip()
        if not version:
            return None
        if oid == "centos" and "stream" in (os_info.name or os_info.pretty_name or "").lower():
            product = "centos-stream"
        cycle = derive(version)
        if not (_SAFE.fullmatch(product) and _SAFE.fullmatch(cycle)):
            return None
        return product, cycle
    return None


def _parse_date(value: Any) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def lookup_eol(os_info: OSInfo, http: HttpClient, *, today: date | None = None) -> EOLInfo | None:
    """End-of-life status of the analysed distribution release, or ``None`` if unknown.

    Never raises for network or data problems: unknown products/cycles (HTTP 404),
    offline mode without a cached copy and malformed responses all yield ``None``.
    """
    key = eol_key(os_info)
    if key is None:
        return None
    product, cycle = key
    if cycle == ROLLING:
        return EOLInfo(product=product, cycle=ROLLING, eol_date=None, is_eol=False)
    url = f"{API}/{product}/releases/{cycle}"
    try:
        data = http.get(url, ttl=EOL_TTL).json()
    except (NetworkError, ValueError) as exc:
        log.info("EOL lookup for %s %s unavailable: %s", product, cycle, exc)
        return None
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, dict):
        return None
    now = today or datetime.now(UTC).date()
    eol_from = _parse_date(result.get("eolFrom"))
    raw_is_eol = result.get("isEol")
    is_eol: bool | None
    if eol_from is not None:
        is_eol = now >= eol_from
    elif isinstance(raw_is_eol, bool):
        is_eol = raw_is_eol
    else:
        is_eol = None
    lts = result.get("isLts")
    name = result.get("name")
    return EOLInfo(
        product=product,
        cycle=str(name) if isinstance(name, str | int) and str(name) else cycle,
        eol_date=eol_from.isoformat() if eol_from else None,
        is_eol=is_eol,
        lts=lts if isinstance(lts, bool) else None,
    )
