"""Exactness, order invariance and the Shapley oracle for the risk attribution."""

from __future__ import annotations

import math

from hypothesis import given, settings
from hypothesis import strategies as st

from startup_sbom.explain.attribution import (
    ChainStepInput,
    ThreatInputs,
    chain_total,
    estimative,
    explain_chain,
    explain_threat,
    inputs_from_explanation,
    likelihood_of,
    lmdi,
    log_mean,
    shapley,
    shapley_threat,
)

ABS_TOL = 1e-6

_mult = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
_directives = st.sampled_from(
    ["NoNewPrivileges=yes", "User=www-data (non-root)", "ProtectSystem=strict", "SystemCallFilter"]
)
_threat_inputs = st.builds(
    ThreatInputs,
    subject=st.just("threat:x"),
    epss=st.none() | st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    exploitability=st.none() | st.floats(min_value=0.0, max_value=3.887, allow_nan=False),
    kev=st.booleans(),
    reachability=st.tuples(st.just("network_service"), _mult),
    impact=st.tuples(st.just("code_execution"), _mult),
    privilege_gain=st.tuples(st.just("root"), _mult),
    mitigations=st.lists(
        st.tuples(_directives, st.floats(min_value=0.05, max_value=1.0, allow_nan=False)),
        max_size=4,
        unique_by=lambda m: m[0],
    ),
    exploit_maturity=st.sampled_from([None, "none", "poc", "functional", "weaponized"]),
)


@settings(max_examples=300, deadline=None)
@given(t=_threat_inputs)
def test_threat_explanation_is_exact_on_random_inputs(t: ThreatInputs) -> None:
    e = explain_threat(t)  # the model validator itself enforces exactness at 1e-6
    total = e.baseline + math.fsum(f.contribution for f in e.factors)
    assert math.isclose(total, e.total, abs_tol=ABS_TOL)
    assert math.isclose(e.total, t.score(), abs_tol=ABS_TOL)
    assert math.isclose(likelihood_of(e), t.likelihood(), abs_tol=ABS_TOL)


@settings(max_examples=100, deadline=None)
@given(t=_threat_inputs)
def test_mitigation_order_does_not_change_contributions(t: ThreatInputs) -> None:
    reordered = ThreatInputs(
        subject=t.subject,
        epss=t.epss,
        exploitability=t.exploitability,
        kev=t.kev,
        reachability=t.reachability,
        impact=t.impact,
        privilege_gain=t.privilege_gain,
        mitigations=list(reversed(t.mitigations)),
        exploit_maturity=t.exploit_maturity,
    )
    a = {f.name: f.contribution for f in explain_threat(t).factors}
    b = {f.name: f.contribution for f in explain_threat(reordered).factors}
    assert set(a) == set(b)
    for name, value in a.items():
        assert math.isclose(value, b[name], abs_tol=1e-9), name


@settings(max_examples=100, deadline=None)
@given(
    steps=st.lists(
        st.floats(min_value=0.0, max_value=1.0, allow_nan=False), min_size=1, max_size=5
    ),
    impact=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    downgrade=st.sampled_from([1.0, 0.3]),
)
def test_chain_explanation_is_exact(steps: list[float], impact: float, downgrade: float) -> None:
    inputs = [
        ChainStepInput(
            id=f"step:{i}",
            label=f"s{i}",
            likelihood=p,
            mitigation="NoNewPrivileges=yes" if downgrade != 1.0 and i == 0 else None,
            mitigation_multiplier=downgrade if downgrade != 1.0 and i == 0 else 1.0,
        )
        for i, p in enumerate(steps)
    ]
    e = explain_chain("chain:x", inputs, impact)
    total = e.baseline + math.fsum(f.contribution for f in e.factors)
    assert math.isclose(total, e.total, abs_tol=ABS_TOL)
    assert math.isclose(e.total, chain_total(inputs, impact), abs_tol=ABS_TOL)


def test_zero_factor_zeroes_the_score_exactly() -> None:
    t = ThreatInputs(
        subject="t",
        epss=0.5,
        exploitability=3.0,
        kev=False,
        reachability=("installed", 0.0),
        impact=("code_execution", 1.0),
        privilege_gain=("root", 1.0),
    )
    e = explain_threat(t)
    assert e.total == 0.0
    contributions = math.fsum(f.contribution for f in e.factors)
    assert math.isclose(e.baseline + contributions, 0.0, abs_tol=ABS_TOL)


def test_kev_floor_binds_and_supersedes_epss() -> None:
    t = ThreatInputs(
        subject="t",
        epss=0.3,
        exploitability=2.0,
        kev=True,
        reachability=("network_service", 1.0),
        impact=("code_execution", 1.0),
        privilege_gain=("root", 1.0),
    )
    by = {f.name: f for f in explain_threat(t).factors}
    assert by["kev_floor"].contribution == 100.0
    assert by["epss"].contribution == 0.0
    assert by["exploitability"].contribution == 0.0
    assert "superseded" in by["epss"].description


def test_maturity_floor_binds_when_higher_than_computed_likelihood() -> None:
    t = ThreatInputs(
        subject="t",
        epss=0.01,
        exploitability=1.0,
        kev=False,
        reachability=("network_service", 1.0),
        impact=("code_execution", 1.0),
        privilege_gain=("root", 1.0),
        exploit_maturity="functional",
    )
    by = {f.name: f for f in explain_threat(t).factors}
    assert by["exploit_maturity"].contribution == 60.0
    assert by["epss"].contribution == 0.0
    assert math.isclose(t.likelihood(), 0.6, abs_tol=1e-12)


def test_lmdi_matches_exact_shapley_on_small_factor_sets() -> None:
    """LMDI and product-Shapley sum identically and agree closely for small n."""
    for multipliers in ([0.5], [0.5, 0.8], [0.9, 0.7, 0.6], [0.4, 1.0, 0.85]):
        v0 = 100.0
        contribs = lmdi(v0, multipliers)

        def value(s: frozenset[int], ms: list[float] = multipliers, base: float = v0) -> float:
            return base * math.prod(m for i, m in enumerate(ms) if i in s)

        phi = shapley(value, len(multipliers))
        delta = v0 * math.prod(multipliers) - v0
        assert math.isclose(math.fsum(contribs), delta, abs_tol=1e-9)
        assert math.isclose(math.fsum(phi), delta, abs_tol=1e-9)
        for c, p in zip(contribs, phi, strict=True):
            if len(multipliers) == 1:
                assert math.isclose(c, p, abs_tol=1e-9)
            else:  # order-free views agree to a few percent of the explained change
                assert abs(c - p) <= 0.05 * max(1.0, abs(delta))
            assert (c <= 1e-9) == (p <= 1e-9)  # same sign


def test_shapley_threat_oracle_sums_to_the_score() -> None:
    t = ThreatInputs(
        subject="t",
        epss=0.85,
        exploitability=1.18,
        kev=True,
        reachability=("setuid", 0.5),
        impact=("privilege_escalation", 0.8),
        privilege_gain=("root", 1.0),
    )
    e = explain_threat(t)
    phi = shapley_threat(t)
    assert math.isclose(math.fsum(phi.values()), e.total, abs_tol=1e-6)
    assert math.isclose(phi["privilege_gain"], 0.0, abs_tol=1e-9)  # multiplier 1.0 contributes 0


def test_inputs_round_trip_through_the_explanation() -> None:
    t = ThreatInputs(
        subject="threat:rt",
        epss=0.42,
        exploitability=2.8,
        kev=False,
        reachability=("boot_service", 0.8),
        impact=("code_execution", 1.0),
        privilege_gain=("root -> root", 1.0),
        mitigations=[("NoNewPrivileges=yes", 0.5)],
        exploit_maturity="poc",
    )
    e = explain_threat(t)
    back = inputs_from_explanation(e)
    assert back is not None
    assert math.isclose(explain_threat(back).total, e.total, abs_tol=1e-9)
    assert back.kev == t.kev
    assert back.mitigations == t.mitigations
    assert back.exploit_maturity == t.exploit_maturity


def test_log_mean_and_estimative_edges() -> None:
    assert math.isclose(log_mean(5.0, 5.0), 5.0)
    assert log_mean(0.0, 0.0) > 0.0  # EPS-clamped, never a division by zero
    assert estimative(0.35).startswith("unlikely")
    assert "almost certain" in estimative(0.99)
