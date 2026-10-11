"""Global (system-level) explanations: noisy-OR system risk and its exact drivers.

``S = 100 · (1 − Π(1 − s_i/100))`` over attack chains and un-chained threats — the
probability that at least one item succeeds, *assuming independence* (chains that
share a step are correlated; stated as a knowledge limit).  Attribution is exact in
log-survival space: ``c_i = S · ln(1 − s_i/100) / Σ_j ln(1 − s_j/100)``.  Roll-ups to
packages, services and vendors split an item's contribution equally over its
distinct members, so every roll-up still sums to ``S``.

NIST IR 8312 mapping: *Meaningful* (Pareto view: "N packages explain 80 % of
risk") and *Explanation accuracy* (drivers sum exactly to the system score).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Literal

from startup_sbom.models import (
    Driver,
    Explanation,
    ExplanationMethod,
    Factor,
    GlobalExplanation,
)

EPS = 1e-12
SYSTEM_FORMULA = (
    "100 * (1 - prod(1 - s_i/100)) over attack chains and un-chained threats (independence assumed)"
)
DriverKind = Literal["chain", "threat", "package", "service", "vendor"]
_ROLLUPS: tuple[DriverKind, ...] = ("package", "service", "vendor")


def noisy_or(scores: Sequence[float]) -> float:
    """System risk (0..100) of independent items with scores 0..100."""
    return 100.0 * (1.0 - math.prod(1.0 - min(100.0, max(0.0, s)) / 100.0 for s in scores))


def attribute(items: Mapping[str, float]) -> tuple[float, dict[str, float]]:
    """``(S, {item: contribution})`` with ``Σ contribution == S`` exactly (to 1e-9)."""
    surv = {k: max(1.0 - min(100.0, max(0.0, v)) / 100.0, EPS) for k, v in items.items()}
    total = noisy_or(list(items.values()))
    logs = {k: math.log(s) for k, s in surv.items()}
    denom = math.fsum(logs.values())
    if denom == 0.0:
        return total, dict.fromkeys(items, 0.0)
    return total, {k: total * (lg / denom) for k, lg in logs.items()}


def explain_noisy_or(subject: str, items: Mapping[str, float]) -> Explanation:
    """System risk as an exact :class:`Explanation` (one factor per item)."""
    total, contrib = attribute(items)
    factors = [
        Factor(
            name=k,
            label=k,
            value=float(items[k]),
            multiplier=max(1.0 - items[k] / 100.0, 0.0),
            kind="multiplicative",
            contribution=contrib[k],
            description=f"item score {items[k]:.1f}",
        )
        for k in sorted(items, key=lambda k: (-contrib[k], k))
    ]
    s = math.fsum(f.contribution for f in factors)
    return Explanation(
        subject=subject,
        method=ExplanationMethod.NOISY_OR_LOG,
        formula=SYSTEM_FORMULA,
        formula_version="system/1",
        baseline=0.0,
        total=s if math.isclose(s, total, abs_tol=1e-9) else total,
        factors=factors,
        limits=["items treated as independent (chains sharing a step are correlated)"],
    )


def _emit(
    kind: DriverKind,
    agg: Mapping[str, float],
    total: float,
    labels: Mapping[str, str],
    out: list[Driver],
) -> int:
    """Append sorted drivers of one kind; return the Pareto-80 count."""
    cum = 0.0
    n80 = 0
    ordered = sorted(agg.items(), key=lambda kv: (-kv[1], kv[0]))
    for k, (key, v) in enumerate(ordered, 1):
        cum += v
        share = v / total if total else 0.0
        out.append(
            Driver(
                kind=kind,
                id=key,
                label=labels.get(key, key),
                contribution=v,
                share=round(share, 4),
                cumulative=round(cum / total, 4) if total else 0.0,
            )
        )
        if not n80 and total and cum / total >= 0.8 - 1e-9:
            n80 = k
    return n80 or len(ordered)


def global_explanation(
    items: Mapping[str, float],
    item_kinds: Mapping[str, Literal["chain", "threat"]],
    members: Mapping[str, Mapping[str, Sequence[str]]],
    labels: Mapping[str, str] | None = None,
) -> GlobalExplanation:
    """Exact system-risk drivers, rolled up to packages / services / vendors.

    ``items``: item id -> score; ``item_kinds``: item id -> ``chain``/``threat``;
    ``members[kind][item]``: member ids of that item (an item without members is
    attributed to the pseudo-member ``"(none)"`` so roll-ups stay exact).
    """
    lab = dict(labels or {})
    total, contrib = attribute(items)
    drivers: list[Driver] = []
    pareto: dict[str, int] = {}
    chains = {k: v for k, v in contrib.items() if item_kinds.get(k) == "chain"}
    threats = {k: v for k, v in contrib.items() if item_kinds.get(k) != "chain"}
    _emit("chain", chains, total, lab, drivers)
    _emit("threat", threats, total, lab, drivers)
    combined: list[Driver] = []
    pareto["item"] = _emit("threat", contrib, total, lab, combined)
    for kind in _ROLLUPS:
        mapping = members.get(kind, {})
        agg: dict[str, float] = {}
        for item, c in contrib.items():
            ms = sorted(set(mapping.get(item, ()))) or ["(none)"]
            for m in ms:
                agg[m] = agg.get(m, 0.0) + c / len(ms)
        pareto[kind] = _emit(kind, agg, total, lab, drivers)
    return GlobalExplanation(
        system_risk=total,
        method=ExplanationMethod.NOISY_OR_LOG,
        formula=SYSTEM_FORMULA,
        drivers=drivers,
        pareto_80=pareto,
    )
