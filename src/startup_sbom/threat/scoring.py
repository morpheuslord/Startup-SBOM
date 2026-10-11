"""Transparent 0–100 risk score (formula ``risk/1``), exactly decomposable.

``risk = 100 × likelihood × reachability × impact × privilege_gain × Π mitigation``

* likelihood   = min(1, max(0.6·EPSS + 0.4·min(1, exploitability / 3.887), KEV floor 1.0,
                 exploit-maturity floor)); a missing EPSS counts as 0, a missing vector
                 as exploitability 0.5·max.
* reachability = weight of the observed execution path (:data:`REACH_WEIGHT`).
* impact       = strongest consequence class (:data:`IMPACT`).
* privilege    = 1.0 root/host, 0.6 a service account or unspecified local user,
                 0.3 no change of attacker state (disclosure / DoS only).
* mitigation   = one multiplier per hardening directive that applies to this threat.

The formula itself lives in :mod:`startup_sbom.explain.attribution`, which also
produces the exact per-factor breakdown stored in ``Threat.explanation``;
``Threat.score_factors`` mirrors it as ``{factor: contribution in points}``.
"""

from __future__ import annotations

from startup_sbom.explain.attribution import (
    EPSS_WEIGHT,
    EXPLOIT_WEIGHT,
    KEV_FLOOR,
    MATURITY_FLOOR,
    UNKNOWN_EXPLOITABILITY,
    ThreatInputs,
    explain_threat,
)
from startup_sbom.models import Confidence, Consequence, Explanation, Reachability
from startup_sbom.threat.cvss import VectorFacts

__all__ = [
    "CONTAINER_KERNEL_WEIGHT",
    "EPSS_WEIGHT",
    "EXPLOIT_WEIGHT",
    "IMPACT",
    "KEV_FLOOR",
    "LINK_CONFIDENCE",
    "MATURITY_FLOOR",
    "REACH_WEIGHT",
    "UNKNOWN_EXPLOITABILITY",
    "ThreatInputs",
    "explain",
    "impact",
    "impact_label",
    "privilege_gain",
    "reach_weight",
]

IMPACT = {
    Consequence.RCE: 1.0,
    Consequence.SUPPLY_CHAIN: 1.0,
    Consequence.PRIVESC: 0.9,
    Consequence.AUTH_BYPASS: 0.7,
    Consequence.TAMPERING: 0.6,
    Consequence.INFO_DISCLOSURE: 0.5,
    Consequence.DOS: 0.3,
    Consequence.OTHER: 0.3,
}
REACH_WEIGHT = {
    Reachability.NETWORK_SERVICE: 1.0,
    Reachability.BOOT_SERVICE: 0.5,
    Reachability.LINKED_BY_SERVICE: 0.45,
    Reachability.ON_DEMAND_SERVICE: 0.4,
    Reachability.SETUID: 0.4,
    Reachability.KERNEL: 0.4,
    Reachability.INSTALLED: 0.15,
}
LINK_CONFIDENCE = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.8, Confidence.LOW: 0.5}
#: Kernel packages inside a container image are not the running kernel.
CONTAINER_KERNEL_WEIGHT = 0.1


def reach_weight(
    level: Reachability,
    facts: VectorFacts,
    *,
    network_exposed: bool,
    link_confidence: Confidence | None,
    in_container: bool,
) -> float:
    """Weight of the execution path, adjusted for attack-vector fit and link confidence."""
    w = REACH_WEIGHT[level]
    network = facts.attack_vector == "network"
    if level is Reachability.NETWORK_SERVICE:
        if not network:
            w = REACH_WEIGHT[Reachability.BOOT_SERVICE]
        elif facts.privileges_required != "none":
            w = 0.8
    elif level is Reachability.LINKED_BY_SERVICE:
        if network_exposed and network:
            w = 0.8
        w *= LINK_CONFIDENCE[link_confidence or Confidence.HIGH]
    elif level is Reachability.KERNEL and in_container:
        w = CONTAINER_KERNEL_WEIGHT
    return round(w, 4)


def impact(consequences: set[Consequence]) -> float:
    """Strongest consequence class (0.3 when nothing is known)."""
    return max((IMPACT[c] for c in consequences), default=IMPACT[Consequence.OTHER])


def privilege_gain(precondition: str, postcondition: str) -> float:
    """Value of the attacker-state change."""
    if postcondition == precondition:
        return 0.3
    if postcondition in ("root", "container_escape"):
        return 1.0
    return 0.6


def impact_label(consequences: set[Consequence]) -> str:
    """Name of the strongest consequence class (``other`` when nothing is known)."""
    best = max(consequences or {Consequence.OTHER}, key=lambda c: (IMPACT[c], c.value))
    return best.value


def explain(inputs: ThreatInputs) -> tuple[float, Explanation]:
    """``(risk score rounded to 0.1, exact explanation)`` for one threat."""
    expl = explain_threat(inputs)
    return round(max(0.0, min(100.0, expl.total)), 1), expl


def privilege_label(precondition: str, postcondition: str) -> str:
    """Human value of the attacker-state change."""
    if postcondition == precondition:
        return f"{precondition} (no change)"
    return f"{precondition} -> {postcondition}"


def build_inputs(
    subject: str,
    *,
    epss: float | None,
    kev: bool,
    facts: VectorFacts,
    level: Reachability,
    network_exposed: bool,
    link_confidence: Confidence | None,
    in_container: bool,
    consequences: set[Consequence],
    precondition: str,
    postcondition: str,
    mitigations: list[tuple[str, float]],
) -> ThreatInputs:
    """All inputs of formula ``risk/1`` for one threat."""
    return ThreatInputs(
        subject=subject,
        epss=epss,
        exploitability=facts.exploitability,
        kev=kev,
        reachability=(
            level.value,
            reach_weight(
                level,
                facts,
                network_exposed=network_exposed,
                link_confidence=link_confidence,
                in_container=in_container,
            ),
        ),
        impact=(impact_label(consequences), impact(consequences)),
        privilege_gain=(
            privilege_label(precondition, postcondition),
            privilege_gain(precondition, postcondition),
        ),
        mitigations=list(mitigations),
    )
