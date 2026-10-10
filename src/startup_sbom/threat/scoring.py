"""Transparent 0–100 risk score; every factor is recorded in ``Threat.score_factors``.

``risk = 100 × likelihood × reachability × impact × privilege_gain × mitigation``

* likelihood   = 0.6·EPSS + 0.4·(exploitability / 3.887), floored to 1.0 when in KEV;
                 a missing EPSS counts as 0, a missing vector as exploitability 0.5·max.
* reachability = weight of the observed execution path (:data:`REACH_WEIGHT`).
* impact       = strongest consequence class (:data:`IMPACT`).
* privilege    = 1.0 root/host, 0.6 a service account or unspecified local user,
                 0.3 no change of attacker state (disclosure / DoS only).
* mitigation   = product of hardening discounts that apply to this threat.
"""

from __future__ import annotations

from startup_sbom.models import Confidence, Consequence, Reachability
from startup_sbom.threat.cvss import MAX_EXPLOITABILITY, VectorFacts

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
UNKNOWN_EXPLOITABILITY = 0.5


def likelihood(epss: float | None, kev: bool, facts: VectorFacts) -> dict[str, float]:
    """Likelihood factor and its inputs."""
    out: dict[str, float] = {}
    e = epss if epss is not None else 0.0
    out["epss"] = round(e, 5)
    if epss is None:
        out["epss_missing"] = 1.0
    if facts.exploitability is not None:
        x = min(1.0, facts.exploitability / MAX_EXPLOITABILITY)
    else:
        x = UNKNOWN_EXPLOITABILITY
        out["exploitability_unknown"] = 1.0
    out["exploitability"] = round(x, 4)
    lk = 0.6 * e + 0.4 * x
    if kev:
        out["kev_floor"] = 1.0
        lk = 1.0
    out["likelihood"] = round(min(1.0, lk), 4)
    return out


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


def combine(factors: dict[str, float]) -> float:
    """Final 0..100 score from the recorded factors."""
    score = (
        factors["likelihood"]
        * factors["reachability"]
        * factors["impact"]
        * factors["privilege_gain"]
        * factors["mitigation"]
    )
    return round(100.0 * max(0.0, min(1.0, score)), 1)
