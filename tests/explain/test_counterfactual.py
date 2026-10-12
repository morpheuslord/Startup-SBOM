"""Hitting-set, min-cut and what-if mechanics on synthetic chains."""

from __future__ import annotations

import math

from startup_sbom.explain.counterfactual import (
    ChainItem,
    breakable,
    covers,
    exact_hitting_set,
    greedy_hitting_set,
    min_cut,
    system_risk,
    what_if,
)
from startup_sbom.explain.global_ import noisy_or
from startup_sbom.models import Fix


def _fix(fid: str, breaks: list[str], cost: float = 1.0) -> Fix:
    return Fix(id=fid, kind="upgrade", target=fid, action=f"apply {fid}", cost=cost, breaks=breaks)


CHAINS = [
    ChainItem("c1", 80.0, (("e1", "remote", "user"), ("e2", "user", "root"))),
    ChainItem("c2", 60.0, (("e3", "remote", "root"),)),
    ChainItem("c3", 40.0, (("e1", "remote", "user"), ("e4", "user", "root"))),
]
FIXES = [
    _fix("fix:a", ["e1"]),  # breaks c1 and c3
    _fix("fix:b", ["e2"]),  # breaks c1
    _fix("fix:c", ["e3"]),  # breaks c2
    _fix("fix:d", ["e4"]),  # breaks c3
    _fix("fix:e", ["e2", "e4"], cost=0.5),  # hardening: breaks c1 and c3
]


def test_covers_and_breakable() -> None:
    assert covers(FIXES[0], CHAINS) == {"c1", "c3"}
    assert covers(FIXES[2], CHAINS) == {"c2"}
    assert {c.id for c in breakable(CHAINS, FIXES)} == {"c1", "c2", "c3"}


def test_exact_hitting_set_is_minimum_cost_and_irredundant() -> None:
    plans = exact_hitting_set(CHAINS, FIXES)
    assert plans  # cheapest cover: either {a, c} (2.0) is beaten by {e, c} (1.5)
    assert plans == [["fix:c", "fix:e"]]
    greedy = greedy_hitting_set(CHAINS, FIXES)
    assert set(greedy) >= {"fix:c"}
    broken = {s for f in FIXES if f.id in greedy for s in f.breaks}
    assert all(c.step_ids & broken for c in CHAINS)


def test_exact_hitting_set_keeps_cost_ties() -> None:
    # fix:x alone covers c1 (e1), c2 (e3) and c3 (e1) -> the single-fix plan wins
    fixes = [_fix("fix:x", ["e1", "e3"]), _fix("fix:y", ["e2", "e3"]), _fix("fix:z", ["e4"])]
    assert exact_hitting_set(CHAINS, fixes) == [["fix:x"]]
    # two equal-cost full covers -> both minimum plans are kept, sorted
    tied = [_fix("fix:p", ["e1", "e3"]), _fix("fix:q", ["e2", "e3", "e4"])]
    assert exact_hitting_set(CHAINS, tied) == [["fix:p"], ["fix:q"]]


def test_unbreakable_chains_are_excluded_not_fatal() -> None:
    chains = [*CHAINS, ChainItem("c4", 90.0, (("e9", "remote", "host"),))]
    plans = exact_hitting_set(chains, FIXES)
    assert plans == [["fix:c", "fix:e"]]  # c4 has no fix and is left out of `need`
    assert {c.id for c in breakable(chains, FIXES)} == {"c1", "c2", "c3"}


def test_min_cut_value_and_upper_bound() -> None:
    cut = min_cut(CHAINS, FIXES)
    assert cut is not None
    value, steps = cut
    # cheapest separation: e3 (1.0) + e1 (1.0) or e3 + e2/e4 (0.5 each edge counted per edge)
    assert value <= sum(f.cost for f in FIXES)
    broken = set(steps)
    assert all(c.step_ids & broken for c in CHAINS), "the cut severs every chain"


def test_min_cut_none_when_no_finite_cut() -> None:
    chains = [ChainItem("c", 50.0, (("u1", "remote", "root"),))]
    assert min_cut(chains, []) is None


def test_system_risk_matches_noisy_or_and_what_if_rounds() -> None:
    standalone = {"t1": 30.0}
    before = system_risk(CHAINS, standalone)
    assert math.isclose(before, noisy_or([80.0, 60.0, 40.0, 30.0]), abs_tol=1e-9)
    fixes = {f.id: f for f in FIXES}
    w = what_if(CHAINS, standalone, fixes, ["fix:a"], "single", "note")
    assert w.chains_broken == ["c1", "c3"]
    assert math.isclose(w.risk_after, round(noisy_or([60.0, 30.0]), 1), abs_tol=1e-9)
    assert w.risk_before >= w.risk_after
    assert w.note == "note"
