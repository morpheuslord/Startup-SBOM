"""SSVC decision support (CISA Coordinator tree v2.0.3, CERT/CC SSVC, Apache-2.0).

The CISA tree's fourth input, *Mission & Well-Being*, cannot be observed in a
root filesystem.  We substitute the deployer-tree *System Exposure* observed by
the scan as the situated proxy: ``small → low``, ``controlled → medium``,
``open → high``.  The full 36-row table is reproduced in :data:`TABLE`.
"""

from __future__ import annotations

import re

from startup_sbom.models import SSVC, Consequence, Reachability, SSVCDecision, Vulnerability
from startup_sbom.threat.cvss import VectorFacts

#: EPSS probability treated as evidence of a public exploit (proxy for *public PoC*).
EPSS_POC_THRESHOLD = 0.1
EXPLOIT_REF_RE = re.compile(
    r"exploit-db\.com|exploitdb|packetstormsecurity|packetstorm\.news|"
    r"rapid7\.com/db/modules|metasploit-framework/|/exploits?/|[-_/]poc\b|\bpoc[-_/]|"
    r"proof[-_]of[-_]concept",
    re.IGNORECASE,
)
EXPOSURE_TO_MISSION = {"small": "low", "controlled": "medium", "open": "high"}

_T, _TS, _AT, _AC = (
    SSVCDecision.TRACK,
    SSVCDecision.TRACK_STAR,
    SSVCDecision.ATTEND,
    SSVCDecision.ACT,
)
#: (exploitation, automatable, technical impact) → decision for mission low/medium/high.
TABLE: dict[tuple[str, str, str], tuple[SSVCDecision, SSVCDecision, SSVCDecision]] = {
    ("none", "no", "partial"): (_T, _T, _T),
    ("none", "no", "total"): (_T, _T, _TS),
    ("none", "yes", "partial"): (_T, _T, _AT),
    ("none", "yes", "total"): (_T, _T, _AT),
    ("public_poc", "no", "partial"): (_T, _T, _TS),
    ("public_poc", "no", "total"): (_T, _TS, _AT),
    ("public_poc", "yes", "partial"): (_T, _T, _AT),
    ("public_poc", "yes", "total"): (_T, _TS, _AT),
    ("active", "no", "partial"): (_T, _T, _AT),
    ("active", "no", "total"): (_T, _AT, _AC),
    ("active", "yes", "partial"): (_AT, _AT, _AC),
    ("active", "yes", "total"): (_AT, _AC, _AC),
}
_MISSION_INDEX = {"low": 0, "medium": 1, "high": 2}
RANK = {_T: 0, _TS: 1, _AT: 2, _AC: 3}


def decide(
    exploitation: str, automatable: str, technical_impact: str, exposure: str
) -> SSVCDecision:
    """Look up the CISA Coordinator decision with exposure as the mission proxy."""
    row = TABLE[(exploitation, automatable, technical_impact)]
    return row[_MISSION_INDEX[EXPOSURE_TO_MISSION[exposure]]]


def exploitation(vuln: Vulnerability) -> tuple[str, str]:
    """``(state, reason)``: ``active`` if KEV, ``public_poc`` on EPSS/exploit refs, else none."""
    if vuln.kev is not None:
        added = f" (added {vuln.kev.date_added})" if vuln.kev.date_added else ""
        return "active", f"listed in CISA KEV{added}"
    refs = sorted(r for r in vuln.references if EXPLOIT_REF_RE.search(r))
    if vuln.epss is not None and vuln.epss >= EPSS_POC_THRESHOLD:
        return "public_poc", f"EPSS {vuln.epss:.3f} ≥ {EPSS_POC_THRESHOLD}"
    if refs:
        return "public_poc", f"exploit reference {refs[0]}"
    return "none", "no KEV listing, EPSS below threshold and no exploit reference"


def technical_impact(consequences: set[Consequence], facts: VectorFacts) -> str:
    """``total`` for code execution / privilege gain with high C and I, else ``partial``."""
    gains = consequences & {Consequence.RCE, Consequence.PRIVESC, Consequence.SUPPLY_CHAIN}
    if not gains:
        return "partial"
    if not facts.known:
        return "total" if Consequence.SUPPLY_CHAIN in consequences else "partial"
    return "total" if facts.confidentiality == "high" and facts.integrity == "high" else "partial"


def exposure(level: Reachability, network_exposed: bool, facts: VectorFacts) -> str:
    """System exposure from reachability (open = reachable from the network)."""
    if level is Reachability.NETWORK_SERVICE:
        return "open"
    if (
        level is Reachability.LINKED_BY_SERVICE
        and network_exposed
        and facts.attack_vector == "network"
    ):
        return "open"
    if level in (
        Reachability.BOOT_SERVICE,
        Reachability.LINKED_BY_SERVICE,
        Reachability.ON_DEMAND_SERVICE,
    ):
        return "controlled"
    return "small"


def assess(
    vuln: Vulnerability,
    facts: VectorFacts,
    consequences: set[Consequence],
    level: Reachability,
    network_exposed: bool,
) -> tuple[SSVC, list[str]]:
    """SSVC record for one threat plus the reasons behind each decision point."""
    expl, why = exploitation(vuln)
    auto = "yes" if facts.automatable else "no"
    impact = technical_impact(consequences, facts)
    exp = exposure(level, network_exposed, facts)
    decision = decide(expl, auto, impact, exp)
    reasons = [
        f"exploitation={expl} ({why})",
        f"automatable={auto} ("
        + ("AV:N/AC:L/PR:N/UI:N" if auto == "yes" else _not_auto(facts))
        + ")",
        f"technical_impact={impact}",
        f"exposure={exp} (reachability {level.value}; mission proxy {EXPOSURE_TO_MISSION[exp]})",
    ]
    ssvc = SSVC(
        exploitation=expl,
        automatable=auto,
        technical_impact=impact,
        exposure=exp,
        decision=decision,
    )
    return ssvc, reasons


def _not_auto(facts: VectorFacts) -> str:
    if not facts.known:
        return "no CVSS vector"
    blockers = []
    if facts.attack_vector != "network":
        blockers.append(f"attack vector {facts.attack_vector}")
    if facts.attack_complexity != "low":
        blockers.append("high attack complexity")
    if facts.privileges_required != "none":
        blockers.append(f"privileges {facts.privileges_required}")
    if facts.user_interaction is not False:
        blockers.append("user interaction")
    return ", ".join(blockers)
