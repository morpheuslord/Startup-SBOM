"""Attack-chain construction: fixpoint over the rules, then path enumeration.

:func:`build_attack_chains` turns a report and its threats into ranked
:class:`AttackChain` objects.  The rule engine (:mod:`startup_sbom.threat.rules`)
derives privilege-lattice edges; this module takes their reachability fixpoint
from each entry state, enumerates the simple paths to the strongest reachable
goal, scores and labels them, and writes a step-by-step narrative.  Pure Python
— no graph library.

Chain score = ``100 · Π p_step · goal impact`` (formula ``chain/1``), decomposed
exactly by LMDI into ``AttackChain.explanation``.  The former chain-length bonus
was dropped: it rewarded longer, less likely chains and pushed scores past 100.
"""

from __future__ import annotations

import hashlib

from startup_sbom.context import ScanContext
from startup_sbom.explain.attribution import ChainStepInput, explain_chain
from startup_sbom.models import (
    AttackChain,
    AttackStep,
    AttackTechnique,
    Report,
    SSVCDecision,
    Threat,
)
from startup_sbom.threat import attack
from startup_sbom.threat.facts import (
    GOAL_RANK,
    LOCAL_UNPRIV,
    REMOTE,
    build_facts,
    is_local,
)
from startup_sbom.threat.narrative import chain_narrative, step_line
from startup_sbom.threat.reachability import SystemIndex
from startup_sbom.threat.rules import MITIGATION_DOWNGRADE, Edge, derive

#: Longest chain the enumerator will build (keeps path search bounded).
MAX_DEPTH = 6
#: Hard cap on paths explored per entry before ranking.
MAX_PATHS_PER_ENTRY = 200
GOAL_IMPACT = {"persistence": 1.0, "host": 1.0, "container_escape": 1.0, "root": 0.9}
_DEFAULT_GOAL_SSVC = {
    "persistence": SSVCDecision.ATTEND,
    "host": SSVCDecision.ATTEND,
    "container_escape": SSVCDecision.ATTEND,
    "root": SSVCDecision.ATTEND,
}
from startup_sbom.threat.ssvc import RANK  # noqa: E402 - avoid duplicating the rank map


def build_attack_chains(
    report: Report,
    threats: list[Threat],
    ctx: ScanContext,
    extra_facts: list[object] | None = None,
) -> list[AttackChain]:
    """Build ranked attack chains for the system (capped at ``ctx.options.max_chains``).

    ``extra_facts`` injects facts the scanner could not observe (e.g.
    world-writable unit files) — see :mod:`startup_sbom.threat.facts`.
    """
    index = SystemIndex(report)
    fb = build_facts(report, threats, index, extra_facts)
    edges = derive(fb)
    if not edges:
        return []
    out_edges: dict[str, list[Edge]] = {}
    for e in edges:
        out_edges.setdefault(e.from_state, []).append(e)
    threats_by_id = {t.id: t for t in threats}

    chains: dict[str, AttackChain] = {}
    for entry in _entries(out_edges):
        reachable = _reachable(entry, out_edges)
        for goal in _goals(reachable):
            for path in _paths(entry, goal, out_edges):
                chain = _make_chain(entry, goal, path, threats_by_id)
                chains.setdefault(chain.id, chain)

    ranked = sorted(chains.values(), key=lambda c: (c.mitigated, -c.score, c.id))
    return ranked[: ctx.options.max_chains]


# --------------------------------------------------------------------------- graph
def _entries(out_edges: dict[str, list[Edge]]) -> list[str]:
    """Entry states: ``remote`` plus every local foothold that some rule starts from.

    Local entries model the "local-only" scenarios (a logged-in unprivileged user,
    a specific service account, or the writer of a world-writable unit).
    """
    entries: list[str] = []
    if REMOTE in out_edges:
        entries.append(REMOTE)
    entries.extend(sorted(s for s in out_edges if is_local(s)))
    if LOCAL_UNPRIV in out_edges and LOCAL_UNPRIV not in entries:
        entries.append(LOCAL_UNPRIV)
    return entries


def _goals(reachable: set[str]) -> list[str]:
    """Every reachable goal state, strongest first."""
    return sorted((s for s in reachable if s in GOAL_RANK), key=lambda g: -GOAL_RANK[g])


def _reachable(entry: str, out_edges: dict[str, list[Edge]]) -> set[str]:
    """Fixpoint of states reachable from ``entry``."""
    seen = {entry}
    frontier = [entry]
    while frontier:
        cur = frontier.pop()
        for e in out_edges.get(cur, []):
            if e.to_state not in seen:
                seen.add(e.to_state)
                frontier.append(e.to_state)
    return seen


def _paths(entry: str, goal: str, out_edges: dict[str, list[Edge]]) -> list[list[Edge]]:
    """All simple paths ``entry → goal`` (bounded by depth and count)."""
    results: list[list[Edge]] = []

    def dfs(state: str, visited: frozenset[str], acc: list[Edge]) -> None:
        if len(results) >= MAX_PATHS_PER_ENTRY or len(acc) >= MAX_DEPTH:
            return
        for e in out_edges.get(state, []):
            if e.to_state in visited:
                continue
            nxt = [*acc, e]
            if e.to_state == goal:
                results.append(nxt)
                if len(results) >= MAX_PATHS_PER_ENTRY:
                    return
                continue
            dfs(e.to_state, visited | {e.to_state}, nxt)

    dfs(entry, frozenset({entry}), [])
    # Prefer the shortest, highest-likelihood witness per distinct rule signature.
    results.sort(key=lambda p: (len(p), -_product(p)))
    return _dedupe_paths(results)


def _dedupe_paths(paths: list[list[Edge]]) -> list[list[Edge]]:
    seen: set[tuple[tuple[str, str, str], ...]] = set()
    out = []
    for p in paths:
        sig = tuple((e.rule, e.from_state, e.to_state) for e in p)
        if sig not in seen:
            seen.add(sig)
            out.append(p)
    return out


# --------------------------------------------------------------------------- chain build
def _make_chain(
    entry: str,
    goal: str,
    path: list[Edge],
    threats_by_id: dict[str, Threat],
) -> AttackChain:
    steps: list[AttackStep] = []
    worst_rank = -1
    worst_decision = _DEFAULT_GOAL_SSVC.get(goal, SSVCDecision.TRACK)
    mitigated = False

    for e in path:
        tech = attack.technique(e.technique_id) if e.technique_id else None
        steps.append(
            AttackStep(
                id=step_id(e.rule, e.from_state, e.to_state, e.threat_id or e.service or ""),
                rule=e.rule,
                title=e.title,
                from_state=e.from_state,
                to_state=e.to_state,
                technique=tech,
                threat=e.threat_id,
                vulnerability=e.vulnerability,
                service=e.service,
                evidence=list(e.evidence),
                mitigated_by=list(e.mitigated_by),
                likelihood=round(e.likelihood, 4),
            )
        )
        mitigated = mitigated or e.mitigated or bool(e.mitigated_by)
        decision = _step_decision(e, threats_by_id)
        if decision is not None and RANK[decision] > worst_rank:
            worst_rank, worst_decision = RANK[decision], decision

    impact = GOAL_IMPACT.get(goal, 0.6)
    cid = _chain_id(entry, path)
    inputs = [
        step_input(s, e.likelihood / MITIGATION_DOWNGRADE if e.mitigated_by else e.likelihood)
        for s, e in zip(steps, path, strict=True)
    ]
    explanation = explain_chain(cid, inputs, impact)
    likelihood = 1.0
    for s in inputs:
        likelihood *= s.likelihood * s.mitigation_multiplier
    chain = AttackChain(
        id=cid,
        entry=entry,
        goal=goal,
        steps=steps,
        likelihood=round(likelihood, 4),
        impact=impact,
        score=round(max(0.0, min(100.0, explanation.total)), 1),
        ssvc_decision=worst_decision,
        mitigated=mitigated,
        narrative="",
        explanation=explanation,
    )
    chain.narrative = narrate(chain)
    return chain


def step_id(rule: str, from_state: str, to_state: str, subject: str) -> str:
    """Canonical edge id shared by every chain that uses the same exploit step."""
    sig = "\x1f".join((rule, from_state, to_state, subject))
    return "step:" + hashlib.sha256(sig.encode("utf-8", "replace")).hexdigest()[:12]


def step_input(step: AttackStep, base_likelihood: float) -> ChainStepInput:
    """Explanation input for one step (hardening downgrade shown as its own factor)."""
    label = step.technique.id if step.technique else step.rule
    label = f"{label} {step.vulnerability or step.title}"
    return ChainStepInput(
        id=step.id or step.rule,
        label=f"{step.from_state} -> {step.to_state} ({label})",
        likelihood=base_likelihood,
        mitigation=step.mitigated_by[0] if step.mitigated_by else None,
        mitigation_multiplier=MITIGATION_DOWNGRADE if step.mitigated_by else 1.0,
        evidence=(step.derivation,) if step.derivation else (),
    )


def narrate(chain: AttackChain) -> str:
    """Step-by-step chain narrative (regenerated whenever the score changes)."""
    lines = [
        step_line(
            i,
            s.technique.tactic if s.technique else None,
            s.technique.id if s.technique else None,
            s.title,
            s.from_state,
            s.to_state,
            s.mitigated_by,
        )
        for i, s in enumerate(chain.steps, start=1)
    ]
    return chain_narrative(chain, lines)


def _step_decision(e: Edge, threats_by_id: dict[str, Threat]) -> SSVCDecision | None:
    if e.threat_id and (t := threats_by_id.get(e.threat_id)) and t.ssvc is not None:
        return t.ssvc.decision
    return None


def _product(path: list[Edge]) -> float:
    out = 1.0
    for e in path:
        out *= e.likelihood
    return out


def _chain_id(entry: str, path: list[Edge]) -> str:
    sig = entry + "|" + ";".join(f"{e.rule}:{e.from_state}>{e.to_state}:{e.key()[3]}" for e in path)
    return "chain-" + hashlib.sha256(sig.encode()).hexdigest()[:12]


def technique(id: str) -> AttackTechnique | None:  # noqa: A002 - public re-export
    """Public helper: ATT&CK technique by id (see :func:`startup_sbom.threat.attack.technique`)."""
    return attack.technique(id)
