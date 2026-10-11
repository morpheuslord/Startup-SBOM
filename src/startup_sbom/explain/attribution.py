"""Exact additive attribution of the transparent risk formula (glass-box XAI).

Formula ``risk/1`` (the single source of truth; :mod:`startup_sbom.threat.scoring`
re-exports these constants)::

    x    = min(1, exploitability / 3.887)          (0.5 when no CVSS vector)
    L    = min(1, max(0.6·EPSS + 0.4·x,  1.0 if KEV,  maturity floor))
    risk = 100 · L · R · I · P · Π_k m_k            (R reach, I impact, P privilege,
                                                     m_k hardening multipliers)

Decomposition (method ``sequential+lmdi``), always ``baseline + Σ contributions ==
total`` to machine precision:

1. *Additive stage* ``0 → 100·L``: ``+60·EPSS`` and ``+40·x``.  The ``max()`` is
   attributed to its **binding branch**: when the KEV (or exploit-maturity) floor
   binds, that factor carries the whole stage and EPSS/exploitability are shown with
   contribution 0 ("superseded"), because changing them would change nothing.
2. *Multiplicative stage* ``100·L → risk``: LMDI-I (Ang 2004/2005),
   ``c_i = Lmean(V1, V0) · ln m_i`` — exact, order-independent, zero-safe (Ang & Liu
   2007 ε-substitution with renormalisation).

:func:`shapley` is the exact Shapley oracle used by the tests and as an optional
alternative view.

NIST IR 8312 mapping: *Explanation* and *Explanation accuracy* — the explanation is
computed from the formula itself and validator-enforced to be exact; *Knowledge
limits* — missing inputs are recorded in :attr:`Explanation.limits`.
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from startup_sbom.models import Explanation, ExplanationMethod, Factor

FORMULA_VERSION = "risk/1"
THREAT_FORMULA = "100 * min(1, max(0.6*EPSS + 0.4*x, KEV, maturity)) * R * I * P * prod(m)"
CHAIN_FORMULA = "100 * prod(p_step) * goal_impact"
EPSS_WEIGHT = 0.6
EXPLOIT_WEIGHT = 0.4
MAX_EXPLOITABILITY = 3.887
UNKNOWN_EXPLOITABILITY = 0.5
KEV_FLOOR = 1.0
#: Likelihood floor implied by public exploit maturity (intel prefetch).
MATURITY_FLOOR = {"none": 0.0, "poc": 0.3, "functional": 0.6, "weaponized": 0.9}
EPS = 1e-12  # zero replacement for LMDI (Ang & Liu 2007)

#: ICD 203 estimative-language bands (upper bound, phrase, band text).
_ICD203 = (
    (0.05, "almost no chance", "1-5%"),
    (0.20, "very unlikely", "5-20%"),
    (0.45, "unlikely", "20-45%"),
    (0.55, "roughly even chance", "45-55%"),
    (0.80, "likely", "55-80%"),
    (0.95, "very likely", "80-95%"),
    (1.01, "almost certain", "95-99%"),
)


def estimative(p: float) -> str:
    """ICD 203 verbal probability, always paired with the number by callers."""
    for hi, phrase, band in _ICD203:
        if p < hi:
            return f"{phrase} ({band})"
    return "almost certain (95-99%)"  # pragma: no cover - p > 1.01


# --------------------------------------------------------------------------- core maths
def log_mean(a: float, b: float) -> float:
    """Logarithmic mean ``(a - b) / (ln a - ln b)`` (``a`` when equal); zero-safe."""
    a, b = max(a, EPS), max(b, EPS)
    if math.isclose(a, b, rel_tol=1e-12, abs_tol=0.0):
        return a
    return (a - b) / (math.log(a) - math.log(b))


def lmdi(v0: float, multipliers: Sequence[float]) -> list[float]:
    """LMDI-I contributions of each multiplier to ``v0·Π m − v0`` (sums exactly)."""
    if not multipliers:
        return []
    v1 = v0 * math.prod(multipliers)
    if v0 <= 0.0:
        return [0.0] * len(multipliers)
    w = log_mean(v1, v0)
    raw = [w * math.log(max(m, EPS)) for m in multipliers]
    resid = (v1 - v0) - math.fsum(raw)
    tot = math.fsum(abs(r) for r in raw)
    if tot == 0.0:
        return [resid / len(raw)] * len(raw)
    return [r + resid * abs(r) / tot for r in raw]


def shapley(value: Callable[[frozenset[int]], float], n: int) -> list[float]:
    """Exact Shapley values, ``O(2^n · n)`` — a test oracle for ``n <= 12``."""
    phi = [0.0] * n
    fact = math.factorial
    for i in range(n):
        others = [j for j in range(n) if j != i]
        for r in range(n):
            wgt = fact(r) * fact(n - r - 1) / fact(n)
            for s in itertools.combinations(others, r):
                coalition = frozenset(s)
                phi[i] += wgt * (value(coalition | {i}) - value(coalition))
    return phi


# --------------------------------------------------------------------------- threats
@dataclass(slots=True)
class ThreatInputs:
    """Every input of formula ``risk/1`` for one threat (raw values + multipliers)."""

    subject: str
    epss: float | None
    exploitability: float | None  # CVSS v3-style sub-score 0..3.887; None = no vector
    kev: bool
    reachability: tuple[str, float]  # (label value, multiplier)
    impact: tuple[str, float]
    privilege_gain: tuple[str, float]
    mitigations: list[tuple[str, float]] = field(default_factory=list)  # (directive, m)
    exploit_maturity: str | None = None  # none | poc | functional | weaponized
    evidence: dict[str, list[str]] = field(default_factory=dict)  # factor name -> ids
    limits: list[str] = field(default_factory=list)

    def exploit_term(self) -> float:
        """Normalised exploitability ``x`` in 0..1."""
        if self.exploitability is None:
            return UNKNOWN_EXPLOITABILITY
        return min(1.0, max(0.0, self.exploitability / MAX_EXPLOITABILITY))

    def maturity_floor(self) -> float:
        return MATURITY_FLOOR.get(self.exploit_maturity or "none", 0.0)

    def likelihood(self) -> float:
        raw = EPSS_WEIGHT * (self.epss or 0.0) + EXPLOIT_WEIGHT * self.exploit_term()
        return min(1.0, max(raw, KEV_FLOOR if self.kev else 0.0, self.maturity_floor()))

    def multipliers(self) -> list[tuple[str, str, object, float, str]]:
        """``(name, label, value, multiplier, description)`` for the product stage."""
        out: list[tuple[str, str, object, float, str]] = [
            (
                "reachability",
                "Reachability",
                self.reachability[0],
                self.reachability[1],
                f"execution path {self.reachability[0]} -> x{self.reachability[1]:g}",
            ),
            (
                "impact",
                "Impact",
                self.impact[0],
                self.impact[1],
                f"strongest consequence {self.impact[0]} -> x{self.impact[1]:g}",
            ),
            (
                "privilege_gain",
                "Privilege gain",
                self.privilege_gain[0],
                self.privilege_gain[1],
                f"attacker state {self.privilege_gain[0]} -> x{self.privilege_gain[1]:g}",
            ),
        ]
        for directive, m in self.mitigations:
            out.append(
                (
                    f"mitigation:{directive}",
                    f"Mitigation {directive}",
                    directive,
                    m,
                    f"hardening multiplier x{m:g} ({1 - m:.0%} discount)",
                )
            )
        return out

    def score(self) -> float:
        return 100.0 * self.likelihood() * math.prod(m[3] for m in self.multipliers())


def explain_threat(t: ThreatInputs) -> Explanation:
    """Exact ``sequential+lmdi`` decomposition of a threat's risk score."""
    epss = t.epss or 0.0
    x = t.exploit_term()
    raw = EPSS_WEIGHT * epss + EXPLOIT_WEIGHT * x
    floor_m = t.maturity_floor()
    lk = t.likelihood()
    ev = t.evidence
    kev_binds = t.kev and raw < KEV_FLOOR
    mat_binds = not kev_binds and floor_m > raw
    binds = kev_binds or mat_binds
    note = ""
    if kev_binds:
        note = " (superseded by the KEV floor)"
    elif mat_binds:
        note = " (superseded by the exploit-maturity floor)"
    epss_desc = (
        f"0.6 x EPSS {epss:.3f}, {estimative(epss)}{note}"
        if t.epss is not None
        else f"EPSS unavailable: term counted as 0{note}"
    )
    x_desc = (
        f"0.4 x exploitability {t.exploitability:.2f}/{MAX_EXPLOITABILITY}{note}"
        if t.exploitability is not None
        else f"no CVSS vector: exploitability assumed {UNKNOWN_EXPLOITABILITY:g} of max{note}"
    )
    factors = [
        Factor(
            name="epss",
            label="EPSS exploit probability",
            value=t.epss,
            kind="additive",
            contribution=0.0 if binds else 100.0 * EPSS_WEIGHT * epss,
            evidence=list(ev.get("epss", [])),
            description=epss_desc,
        ),
        Factor(
            name="exploitability",
            label="CVSS exploitability",
            value=t.exploitability,
            kind="additive",
            contribution=0.0 if binds else 100.0 * EXPLOIT_WEIGHT * x,
            evidence=list(ev.get("exploitability", [])),
            description=x_desc,
        ),
    ]
    if t.kev:
        factors.append(
            Factor(
                name="kev_floor",
                label="CISA KEV (floor 1.0)",
                value=True,
                kind="additive",
                contribution=100.0 * KEV_FLOOR if kev_binds else 0.0,
                evidence=list(ev.get("kev_floor", [])),
                description="known exploited: likelihood floored to 1.0"
                if kev_binds
                else "known exploited; computed likelihood already 1.0",
            )
        )
    if t.exploit_maturity is not None:
        factors.append(
            Factor(
                name="exploit_maturity",
                label=f"Exploit maturity (floor {floor_m:g})",
                value=t.exploit_maturity,
                kind="additive",
                contribution=100.0 * floor_m if mat_binds else 0.0,
                evidence=list(ev.get("exploit_maturity", [])),
                description=(
                    f"public exploit maturity '{t.exploit_maturity}' floors likelihood to "
                    f"{floor_m:g}"
                    + ("" if mat_binds else " (not binding: computed likelihood is higher)")
                ),
            )
        )
    if not binds and raw > 1.0:  # cannot happen with valid inputs; keeps the sum exact
        factors.append(
            Factor(
                name="likelihood_cap",
                label="Likelihood cap",
                value=1.0,
                kind="additive",
                contribution=100.0 * (1.0 - raw),
                description="likelihood clamped to 1.0",
            )
        )
    v0 = 100.0 * lk
    mults = t.multipliers()
    for (name, label, value, m, desc), c in zip(
        mults, lmdi(v0, [m[3] for m in mults]), strict=True
    ):
        factors.append(
            Factor(
                name=name,
                label=label,
                value=_factor_value(value),
                multiplier=m,
                kind="multiplicative",
                contribution=c,
                evidence=list(ev.get(name, [])),
                description=desc,
            )
        )
    total = v0 * math.prod(m[3] for m in mults)
    limits = list(t.limits)
    if t.epss is None:
        limits.append("EPSS unavailable (offline or not published): EPSS term counted as 0")
    if t.exploitability is None:
        limits.append("no CVSS vector: exploitability assumed half of the maximum")
    return Explanation(
        subject=t.subject,
        method=ExplanationMethod.SEQUENTIAL_LMDI,
        formula=THREAT_FORMULA,
        formula_version=FORMULA_VERSION,
        baseline=0.0,
        total=total,
        factors=factors,
        limits=sorted(set(limits)),
    )


def _factor_value(value: object) -> float | str | bool | None:
    if value is None or isinstance(value, (str, float, bool)):
        return value
    if isinstance(value, int):
        return float(value)
    return str(value)


def likelihood_of(expl: Explanation) -> float:
    """Likelihood ``L`` (0..1) recovered from a threat explanation's additive stage."""
    return math.fsum(f.contribution for f in expl.factors if f.kind == "additive") / 100.0


def inputs_from_explanation(expl: Explanation) -> ThreatInputs | None:
    """Rebuild :class:`ThreatInputs` from a ``risk/1`` explanation (lossless round trip)."""
    by = {f.name: f for f in expl.factors}
    need = ("epss", "exploitability", "reachability", "impact", "privilege_gain")
    if expl.formula_version != FORMULA_VERSION or any(n not in by for n in need):
        return None

    def mult(name: str) -> tuple[str, float]:
        f = by[name]
        return (str(f.value), f.multiplier if f.multiplier is not None else 1.0)

    def num(v: object) -> float | None:
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None

    mat = by.get("exploit_maturity")
    return ThreatInputs(
        subject=expl.subject,
        epss=num(by["epss"].value),
        exploitability=num(by["exploitability"].value),
        kev="kev_floor" in by,
        reachability=mult("reachability"),
        impact=mult("impact"),
        privilege_gain=mult("privilege_gain"),
        mitigations=[
            (f.name.removeprefix("mitigation:"), f.multiplier if f.multiplier is not None else 1.0)
            for f in expl.factors
            if f.name.startswith("mitigation:")
        ],
        exploit_maturity=str(mat.value) if mat is not None else None,
    )


def shapley_threat(t: ThreatInputs) -> dict[str, float]:
    """Exact Shapley attribution over the same inputs (absent = 0 / x1.0 / no floor)."""
    mults = t.multipliers()
    names = ["epss", "exploitability", "kev_floor", "exploit_maturity"] + [m[0] for m in mults]

    def v(s: frozenset[int]) -> float:
        epss = (t.epss or 0.0) if 0 in s else 0.0
        x = t.exploit_term() if 1 in s else 0.0
        kev = t.kev and 2 in s
        mat = t.maturity_floor() if 3 in s else 0.0
        lk = min(1.0, max(EPSS_WEIGHT * epss + EXPLOIT_WEIGHT * x, 1.0 if kev else 0.0, mat))
        prod = math.prod(m[3] if 4 + k in s else 1.0 for k, m in enumerate(mults))
        return 100.0 * lk * prod

    return dict(zip(names, shapley(v, len(names)), strict=True))


# --------------------------------------------------------------------------- chains
@dataclass(frozen=True, slots=True)
class ChainStepInput:
    """One chain step for :func:`explain_chain` (``likelihood`` before any downgrade)."""

    id: str
    label: str
    likelihood: float
    mitigation: str | None = None
    mitigation_multiplier: float = 1.0
    evidence: tuple[str, ...] = ()


def chain_total(steps: Sequence[ChainStepInput], impact: float) -> float:
    """Chain score (unrounded): ``100 · Π p_step · m_step · impact``."""
    return 100.0 * math.prod(s.likelihood * s.mitigation_multiplier for s in steps) * impact


def explain_chain(chain_id: str, steps: Sequence[ChainStepInput], impact: float) -> Explanation:
    """LMDI decomposition of a chain score from the baseline 100 (certain, maximal)."""
    rows: list[tuple[str, str, float, str, list[str]]] = []
    for i, s in enumerate(steps, 1):
        rows.append(
            (
                f"step:{s.id}",
                f"Step {i}: {s.label}",
                s.likelihood,
                f"step likelihood p={s.likelihood:.3f}",
                list(s.evidence),
            )
        )
        if s.mitigation is not None:
            rows.append(
                (
                    f"mitigation:{s.id}",
                    f"Mitigation {s.mitigation}",
                    s.mitigation_multiplier,
                    f"hardening downgrades step {i} x{s.mitigation_multiplier:g}",
                    [],
                )
            )
    rows.append(("impact", "Goal impact", impact, f"impact of the goal state x{impact:g}", []))
    cs = lmdi(100.0, [r[2] for r in rows])
    total = chain_total(steps, impact)
    return Explanation(
        subject=chain_id,
        method=ExplanationMethod.LMDI,
        formula=CHAIN_FORMULA,
        formula_version="chain/1",
        baseline=100.0,
        total=total,
        factors=[
            Factor(
                name=n,
                label=lab,
                value=m,
                multiplier=m,
                kind="multiplicative",
                contribution=c,
                evidence=evs,
                description=d,
            )
            for (n, lab, m, d, evs), c in zip(rows, cs, strict=True)
        ],
        limits=["steps treated as independent events (product of likelihoods)"],
    )
