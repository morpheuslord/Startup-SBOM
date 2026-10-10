"""Thin wrapper over the ``cvss`` library: attacker pre-conditions from a vector.

Only the base metrics are read; scores are never recomputed by hand.  A vector
that is missing or unparsable yields :data:`UNKNOWN` so callers stay
conservative instead of guessing.
"""

from __future__ import annotations

from dataclasses import dataclass

from startup_sbom.models import CVSSScore, Vulnerability

_AV = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
_PR = {"N": "none", "L": "low", "H": "high"}
# CVSS v3.1 exploitability weights (FIRST spec §7.4), reused for v2/v4 approximations.
_W_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_W_AC = {"L": 0.77, "H": 0.44}
_W_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_W_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_W_UI = {"N": 0.85, "R": 0.62}
#: Maximum CVSS v3 exploitability sub-score (8.22 × 0.85⁴).
MAX_EXPLOITABILITY = 3.887


@dataclass(frozen=True, slots=True)
class VectorFacts:
    """Base metrics normalised across CVSS v2, v3.x and v4.0."""

    version: str | None
    vector: str | None
    attack_vector: str = "unknown"  # network | adjacent | local | physical | unknown
    attack_complexity: str = "unknown"  # low | high | unknown (v4 AT:P counts as high)
    privileges_required: str = "unknown"  # none | low | high | unknown
    user_interaction: bool | None = None
    scope_changed: bool = False  # v3 S:C, v4 SC/SI/SA ≠ N
    confidentiality: str = "unknown"  # high | low | none | unknown
    integrity: str = "unknown"
    availability: str = "unknown"
    base_score: float | None = None
    exploitability: float | None = None  # v3-style sub-score, 0..3.887

    @property
    def known(self) -> bool:
        return self.attack_vector != "unknown"

    @property
    def automatable(self) -> bool:
        """SSVC *Automatable* proxy: AV:N/AC:L/PR:N/UI:N (and AT:N for v4)."""
        return (
            self.attack_vector == "network"
            and self.attack_complexity == "low"
            and self.privileges_required == "none"
            and self.user_interaction is False
        )


UNKNOWN = VectorFacts(version=None, vector=None)

_LEVEL = {"H": "high", "L": "low", "N": "none", "C": "high", "P": "low"}


def _exploitability(av: str, ac: str, pr: str, ui: str, changed: bool) -> float | None:
    try:
        w_pr = (_W_PR_C if changed else _W_PR_U)[pr]
        return round(8.22 * _W_AV[av] * _W_AC[ac] * w_pr * _W_UI[ui], 4)
    except KeyError:
        return None


def parse(score: CVSSScore | None) -> VectorFacts:
    """Normalise one CVSS score; never raises."""
    if score is None or not score.vector:
        return UNKNOWN
    try:
        return _parse(score)
    except Exception:  # noqa: BLE001 - malformed third-party vectors must not abort analysis
        return UNKNOWN


def _parse(score: CVSSScore) -> VectorFacts:
    from cvss import CVSS2, CVSS3, CVSS4

    vec = score.vector.strip()
    if vec.startswith("CVSS:4.0/"):
        c4 = CVSS4(vec)
        m = c4.metrics
        av, pr, ui = m["AV"], m["PR"], m["UI"]
        ac = "H" if m["AC"] == "H" or m.get("AT") == "P" else "L"
        changed = any(m.get(k, "N") != "N" for k in ("SC", "SI", "SA"))
        ui_req = ui != "N"  # v4: N | P | A
        return VectorFacts(
            version="4.0",
            vector=vec,
            attack_vector=_AV[av],
            attack_complexity="high" if ac == "H" else "low",
            privileges_required=_PR[pr],
            user_interaction=ui_req,
            scope_changed=changed,
            confidentiality=_LEVEL[m["VC"]],
            integrity=_LEVEL[m["VI"]],
            availability=_LEVEL[m["VA"]],
            base_score=float(c4.base_score),
            exploitability=_exploitability(av, ac, pr, "R" if ui_req else "N", changed),
        )
    if vec.startswith("CVSS:3"):
        c3 = CVSS3(vec)
        m = c3.metrics
        changed = m["S"] == "C"
        return VectorFacts(
            version=vec[5:8],
            vector=vec,
            attack_vector=_AV[m["AV"]],
            attack_complexity="high" if m["AC"] == "H" else "low",
            privileges_required=_PR[m["PR"]],
            user_interaction=m["UI"] == "R",
            scope_changed=changed,
            confidentiality=_LEVEL[m["C"]],
            integrity=_LEVEL[m["I"]],
            availability=_LEVEL[m["A"]],
            base_score=float(c3.base_score),
            exploitability=round(float(c3.esc), 4),
        )
    c2 = CVSS2(vec.removeprefix("(").removesuffix(")"))
    m = c2.metrics
    pr = {"N": "N", "S": "L", "M": "H"}[m["Au"]]
    ac = "L" if m["AC"] == "L" else "H"
    return VectorFacts(
        version="2.0",
        vector=vec,
        attack_vector=_AV[m["AV"]],
        attack_complexity="high" if ac == "H" else "low",
        privileges_required=_PR[pr],
        user_interaction=None,  # v2 has no UI metric
        scope_changed=False,
        confidentiality=_LEVEL[m["C"]],
        integrity=_LEVEL[m["I"]],
        availability=_LEVEL[m["A"]],
        base_score=float(c2.base_score),
        exploitability=_exploitability(m["AV"], ac, pr, "N", False),
    )


def best(vuln: Vulnerability) -> VectorFacts:
    """Facts from the preferred vector (v4 > v3.1 > v3.0 > v2), falling back on parse errors."""
    order = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}
    for score in sorted(vuln.cvss, key=lambda c: (order.get(c.version, 9), c.vector)):
        facts = parse(score)
        if facts.known:
            return facts
    return UNKNOWN
