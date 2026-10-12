"""CWE → consequence classes, from MITRE's *Common Consequences* (shipped as ``cwe.json``).

Impacts are read from the weakness itself, or inherited from its nearest
``ChildOf`` ancestors in the CWE-1000 research view when it lists none.
Memory-corruption weaknesses list both code execution and crashes; the CVSS
impact metrics decide between the two (see :func:`consequences`).
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib.resources import files
from typing import Any

from startup_sbom.models import Consequence
from startup_sbom.threat.cvss import VectorFacts

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

#: CWE impact vocabulary → consequence class.
IMPACT_CLASS: dict[str, Consequence] = {
    "Execute Unauthorized Code or Commands": Consequence.RCE,
    "Gain Privileges or Assume Identity": Consequence.PRIVESC,
    "Read Application Data": Consequence.INFO_DISCLOSURE,
    "Read Memory": Consequence.INFO_DISCLOSURE,
    "Read Files or Directories": Consequence.INFO_DISCLOSURE,
    "Modify Application Data": Consequence.TAMPERING,
    "Modify Memory": Consequence.TAMPERING,
    "Modify Files or Directories": Consequence.TAMPERING,
    "DoS: Crash, Exit, or Restart": Consequence.DOS,
    "DoS: Instability": Consequence.DOS,
    "DoS: Resource Consumption (CPU)": Consequence.DOS,
    "DoS: Resource Consumption (Memory)": Consequence.DOS,
    "DoS: Resource Consumption (Other)": Consequence.DOS,
    "DoS: Amplification": Consequence.DOS,
}

#: Embedded malicious code / hidden functionality / unverified code download.
SUPPLY_CHAIN_CWES = frozenset({494, 506, 507, 508, 509, 510, 511, 512, 912})
#: Authentication weaknesses (auth bypass rather than generic privilege gain).
AUTH_CWES = frozenset({287, 288, 290, 294, 302, 304, 306, 307, 384, 613, 620, 639, 862, 863, 1390})
#: Memory-safety weaknesses whose outcome (RCE vs crash) depends on the CVSS impact.
MEMORY_CWES = frozenset(
    {119, 120, 121, 122, 123, 124, 125, 126, 127, 131, 190, 191, 415, 416, 476, 680, 787, 788,
     805, 822, 823, 824, 825, 843, 1284}
)  # fmt: skip
#: Obsolete NVD categories that carry no members in the catalogue.
CATEGORY_FALLBACK: dict[int, tuple[str, ...]] = {
    16: (),
    17: (),
    19: (),
    21: ("Read Files or Directories", "Modify Files or Directories"),
    189: ("Modify Memory", "DoS: Crash, Exit, or Restart"),
    254: ("Bypass Protection Mechanism",),
    255: ("Gain Privileges or Assume Identity",),
    264: ("Gain Privileges or Assume Identity", "Bypass Protection Mechanism"),
    310: ("Read Application Data",),
    399: ("DoS: Resource Consumption (Other)",),
}


@lru_cache(maxsize=1)
def _data() -> dict[str, Any]:
    raw = files("startup_sbom").joinpath("data", "cwe.json").read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(raw)
    return data


def catalogue_version() -> str:
    """Version of the shipped CWE catalogue."""
    return str(_data()["meta"].get("version") or "unknown")


def cwe_number(cwe: str) -> int | None:
    """``"CWE-787"`` / ``"787"`` → 787; ``None`` for NVD-CWE-Other/noinfo and junk."""
    m = _CWE_RE.search(cwe)
    if m:
        return int(m.group(1))
    return int(cwe) if cwe.isdigit() else None


@lru_cache(maxsize=4096)
def name(cwe: int) -> str | None:
    """Weakness name, e.g. ``787`` → ``"Out-of-bounds Write"``."""
    entry = _data()["cwe"].get(str(cwe))
    return str(entry["n"]) if entry else None


@lru_cache(maxsize=4096)
def impacts(cwe: int) -> tuple[str, ...]:
    """CWE impact strings, inherited from the nearest ancestors when absent."""
    data = _data()
    names: list[str] = data["impacts"]
    seen: set[int] = set()
    frontier = [cwe]
    while frontier:
        found: set[str] = set()
        nxt: list[int] = []
        for c in frontier:
            if c in seen:
                continue
            seen.add(c)
            entry = data["cwe"].get(str(c))
            if entry is None:
                continue
            found.update(names[i] for i in entry["i"])
            if not entry["i"] and c in CATEGORY_FALLBACK:
                found.update(CATEGORY_FALLBACK[c])
            nxt.extend(entry.get("p", []))
        if found:
            return tuple(sorted(found))
        frontier = nxt
    return tuple(sorted(CATEGORY_FALLBACK.get(cwe, ())))


@lru_cache(maxsize=4096)
def capec_ids(cwe: int) -> tuple[int, ...]:
    """CAPEC attack patterns related to the weakness."""
    entry = _data()["cwe"].get(str(cwe))
    return tuple(entry.get("c", [])) if entry else ()


def consequences(cwes: list[str], facts: VectorFacts) -> tuple[set[Consequence], list[str]]:
    """Consequence classes implied by ``cwes`` and the evidence behind each."""
    out: set[Consequence] = set()
    evidence: list[str] = []
    for raw in sorted(set(cwes)):
        num = cwe_number(raw)
        if num is None:
            continue
        found: set[Consequence] = set()
        if num in SUPPLY_CHAIN_CWES:
            found |= {Consequence.SUPPLY_CHAIN, Consequence.RCE}
        imps = impacts(num)
        found |= {IMPACT_CLASS[i] for i in imps if i in IMPACT_CLASS}
        if num in AUTH_CWES or (
            "Bypass Protection Mechanism" in imps and Consequence.PRIVESC in found
        ):
            found.add(Consequence.AUTH_BYPASS)
            if num in AUTH_CWES:
                found.discard(Consequence.PRIVESC)
        if num in MEMORY_CWES or Consequence.RCE in found:
            found = _disambiguate_memory(found, facts)
        if found:
            label = name(num) or "unknown weakness"
            classes = ", ".join(sorted(c.value for c in found))
            evidence.append(f"CWE-{num} ({label}) → {classes}")
            out |= found
    return out, evidence


def _disambiguate_memory(found: set[Consequence], facts: VectorFacts) -> set[Consequence]:
    """Drop code execution when CVSS says integrity is untouched (crash or read only)."""
    if Consequence.SUPPLY_CHAIN in found or not facts.known:
        return found
    if Consequence.RCE in found and facts.integrity == "none":
        found = found - {Consequence.RCE, Consequence.TAMPERING}
        if facts.availability == "high":
            found.add(Consequence.DOS)
        if facts.confidentiality != "none":
            found.add(Consequence.INFO_DISCLOSURE)
    if facts.confidentiality == "none":
        found.discard(Consequence.INFO_DISCLOSURE)
    if facts.availability == "none":
        found.discard(Consequence.DOS)
    return found
