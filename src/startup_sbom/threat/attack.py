"""MITRE ATT&CK lookups and vulnerability → technique mapping.

Priority of sources (first that yields an exploitation technique wins for that
role; impacts are merged):

1. CTID per-CVE mappings (Mappings Explorer KEV set + ``attack_to_cve`` CSV).
2. CTID methodology vulnerability-type table, joined to CWE (:data:`CWE_TECHNIQUES`).
3. CWE → CAPEC → ATT&CK taxonomy links (supplementary, capped).
4. Context-derived generic exploitation technique (CTID tactic table: T1190,
   T1210, T1068, T1203, T1211, T1212).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from typing import Any

from startup_sbom.models import AttackTechnique

#: CTID methodology "vulnerability type" rows, keyed by the CWE(s) of that type:
#: (primary impact techniques, secondary impact techniques, exploitation techniques).
CWE_TECHNIQUES: dict[int, tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    # OS command injection
    77: (("T1059.004",), (), ()),
    78: (("T1059.004",), (), ()),
    88: (("T1059.004",), (), ()),
    # code injection / expression language / deserialisation
    94: (("T1059",), (), ()),
    95: (("T1059",), (), ()),
    917: (("T1059",), (), ()),
    1336: (("T1059",), (), ()),
    502: (("T1059",), (), ()),
    # SQL injection, XSS, XXE, XEE
    89: (("T1059",), ("T1005", "T1505.003"), ()),
    79: (("T1059.007",), ("T1557",), ()),
    611: (("T1059",), ("T1005", "T1046"), ()),
    776: (("T1499.004",), (), ()),
    # unrestricted upload, path traversal, symlink following
    434: (("T1505.003",), ("T1059",), ()),
    22: (("T1005",), ("T1003.008", "T1552.001"), ("T1202",)),
    23: (("T1005",), ("T1003.008", "T1552.001"), ("T1202",)),
    36: (("T1005",), ("T1003.008", "T1552.001"), ("T1202",)),
    59: (("T1222",), (), ("T1202",)),
    # untrusted search path
    426: (("T1574",), (), ()),
    427: (("T1574",), (), ()),
    428: (("T1574",), (), ()),
    # SSRF, open redirect, CSRF, session fixation
    918: (("T1090",), ("T1135", "T1005"), ()),
    601: ((), ("T1036",), ("T1566.002",)),
    352: (("T1068",), (), ("T1204.001",)),
    384: (("T1563",), (), ()),
    # credentials
    798: (("T1078.001",), (), ()),
    259: (("T1078.001",), (), ()),
    319: (("T1552",), ("T1078",), ("T1040",)),
    522: (("T1552",), ("T1078",), ()),
    307: (("T1078",), (), ("T1110.001",)),
    521: ((), ("T1078",), ("T1110",)),
    916: ((), ("T1078",), ("T1110",)),
    294: (("T1190",), (), ("T1040",)),
    # resource exhaustion / infinite loops
    400: (("T1499",), (), ()),
    770: (("T1499",), (), ()),
    835: (("T1499.004",), (), ()),
    674: (("T1499.004",), (), ()),
    # memory modification (CTID: hijack execution flow / application DoS)
    119: (("T1574", "T1499.004"), (), ()),
    120: (("T1574", "T1499.004"), (), ()),
    121: (("T1574", "T1499.004"), (), ()),
    122: (("T1574", "T1499.004"), (), ()),
    787: (("T1574", "T1499.004"), (), ()),
    416: (("T1574", "T1499.004"), (), ()),
    415: (("T1574", "T1499.004"), (), ()),
    190: (("T1574", "T1499.004"), (), ()),
    843: (("T1574", "T1499.004"), (), ()),
    476: (("T1499.004",), (), ()),
    # memory read
    125: (("T1005", "T1499.004"), ("T1211", "T1212"), ()),
    126: (("T1005", "T1499.004"), ("T1211", "T1212"), ()),
    127: (("T1005", "T1499.004"), ("T1211", "T1212"), ()),
    # information exposure
    200: (("T1005",), (), ()),
    532: (("T1552.001",), (), ()),
    # privilege management / permissions
    269: (("T1068",), (), ()),
    250: (("T1068",), (), ()),
    732: (("T1222",), ("T1574",), ()),
    276: (("T1222",), ("T1574",), ()),
    # supply chain
    506: (("T1195.002",), (), ()),
    912: (("T1195.002",), (), ()),
    494: (("T1195.002",), (), ()),
}

#: Generic exploitation techniques per tactic (CTID methodology).
GENERIC = {
    "initial-access": "T1190",
    "execution": "T1203",
    "privilege-escalation": "T1068",
    "defense-evasion": "T1211",
    "credential-access": "T1212",
    "lateral-movement": "T1210",
}

#: CAPEC-derived techniques kept per CWE (the join is broad; keep it short).
CAPEC_LIMIT = 2


def _load(name: str) -> dict[str, Any]:
    raw = files("startup_sbom").joinpath("data", name).read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(raw)
    return data


@lru_cache(maxsize=1)
def _techniques() -> dict[str, Any]:
    return _load("attack_techniques.json")


@lru_cache(maxsize=1)
def _cve_map() -> dict[str, Any]:
    return _load("kev_attack.json")


@lru_cache(maxsize=1)
def _capec_map() -> dict[str, Any]:
    return _load("capec_attack.json")


def attack_version() -> str:
    """ATT&CK release the shipped technique table was built from."""
    return str(_techniques()["meta"].get("version") or "unknown")


def tactic_name(short: str) -> str:
    """``"privilege-escalation"`` → ``"Privilege Escalation"``."""
    entry = _techniques()["tactics"].get(short)
    return str(entry[0]) if entry else short.replace("-", " ").title()


def tactics_of(technique_id: str) -> tuple[str, ...]:
    """Tactic short names of a technique, in matrix order."""
    entry = _techniques()["techniques"].get(technique_id)
    return tuple(entry[1]) if entry else ()


@lru_cache(maxsize=2048)
def technique(id: str, prefer: tuple[str, ...] = ()) -> AttackTechnique | None:  # noqa: A002
    """Technique by id (``"T1068"``) with its tactic, or ``None`` if unknown.

    ``prefer`` lists tactic short names to pick when the technique belongs to
    several tactics (the first match wins, otherwise the first in matrix order).
    """
    entry = _techniques()["techniques"].get(id.strip().upper())
    if entry is None:
        return None
    tactics: list[str] = entry[1]
    chosen = next((t for t in prefer if t in tactics), tactics[0] if tactics else None)
    return AttackTechnique(
        id=id.strip().upper(),
        name=str(entry[0]),
        tactic=tactic_name(chosen) if chosen else None,
    )


@dataclass(slots=True)
class CveMapping:
    """ATT&CK mapping of one vulnerability in the CTID three-role model."""

    exploitation: list[str] = field(default_factory=list)
    primary: list[str] = field(default_factory=list)
    secondary: list[str] = field(default_factory=list)
    group: str | None = None  # CTID capability group, e.g. "priv_escalation"
    sources: list[str] = field(default_factory=list)

    def all(self) -> list[str]:
        out: list[str] = []
        for t in (*self.exploitation, *self.primary, *self.secondary):
            if t not in out:
                out.append(t)
        return out


def cve_mapping(ids: list[str]) -> CveMapping | None:
    """CTID per-CVE mapping for the first of ``ids`` (id + aliases) that has one."""
    cves = _cve_map()["cves"]
    for vid in ids:
        entry = cves.get(vid.upper())
        if entry:
            src = "CTID KEV→ATT&CK" if entry.get("src") == "kev" else "CTID attack_to_cve"
            return CveMapping(
                exploitation=list(entry.get("e", [])),
                primary=list(entry.get("p", [])),
                secondary=list(entry.get("s", [])),
                group=entry.get("g"),
                sources=[f"{src} ({vid.upper()})"],
            )
    return None


def capability_group_name(group: str) -> str:
    """Human name of a CTID capability group."""
    return str(_cve_map()["groups"].get(group, group))


def cwe_mapping(cwe_numbers: list[int]) -> CveMapping:
    """Techniques implied by CWE vulnerability types, then CWE→CAPEC→ATT&CK."""
    out = CveMapping()
    capec = _capec_map()["cwe"]
    for num in sorted(set(cwe_numbers)):
        row = CWE_TECHNIQUES.get(num)
        if row:
            prim, sec, expl = row
            _extend(out.primary, prim)
            _extend(out.secondary, sec)
            _extend(out.exploitation, expl)
            out.sources.append(f"CTID methodology vulnerability type (CWE-{num})")
        elif str(num) in capec:
            techs = [t for t in capec[str(num)] if t in _techniques()["techniques"]]
            _extend(out.secondary, techs[:CAPEC_LIMIT])
            out.sources.append(f"CWE-{num} → CAPEC → ATT&CK")
    return out


def _extend(target: list[str], items: tuple[str, ...] | list[str]) -> None:
    for t in items:
        if t not in target:
            target.append(t)
