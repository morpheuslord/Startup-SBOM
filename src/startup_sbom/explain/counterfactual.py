"""Counterfactual ("what-if") explanations and minimal fix plans.

A chain is broken when ANY of its steps is removed.  Choosing the cheapest set of
fixes that breaks every chain is a weighted hitting-set problem (the dual of set
cover, NP-hard — Jha, Sheyner & Wing 2002): we report the greedy
``H_n``-approximation, an exact minimum-cost search over plans of up to
:data:`K_MAX` fixes (ties kept), and an Edmonds–Karp min s-t cut on the
privilege-state graph.  The cut covers *all* paths, not only enumerated chains, and
is exact when every fix removes one edge; when one fix removes several edges it is
counted once per edge, so the cut value is an **upper bound** on plan cost.

Fixes are *model-based*: a hardening fix only breaks the steps whose rule the
engine knows it blocks.

NIST IR 8312 mapping: *Meaningful* (actionable "smallest change that flips the
outcome", Wachter et al. 2017) and *Knowledge limits* (bounds and residual chains
are reported, never hidden).
"""

from __future__ import annotations

import hashlib
import itertools
import math
import re
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from startup_sbom.explain.global_ import noisy_or
from startup_sbom.models import Fix, PackageType, Report, Threat, WhatIf

K_MAX = 4
#: Upper bound on subsets examined by the exact search before falling back to greedy.
EXACT_BUDGET = 250_000
SOURCE = "__S__"
SINK = "__T__"
FixKind = Literal["upgrade", "hardening", "config", "remove"]
COST = {"upgrade": 1.0, "hardening": 0.5, "config": 1.0, "remove": 3.0}
#: Rules whose setuid-based escalation ``NoNewPrivileges=yes`` blocks.
NNP_RULES = frozenset({"R4", "R5", "R8"})


@dataclass(frozen=True, slots=True)
class ChainItem:
    """A chain reduced to what counterfactuals need."""

    id: str
    score: float
    steps: tuple[tuple[str, str, str], ...]  # (step id, from_state, to_state)

    @property
    def step_ids(self) -> frozenset[str]:
        return frozenset(s[0] for s in self.steps)


# --------------------------------------------------------------------------- what-if
def system_risk(
    chains: Sequence[ChainItem],
    standalone: Mapping[str, float],
    broken: Iterable[str] = (),
    resolved: Iterable[str] = (),
) -> float:
    """Noisy-OR system risk after removing ``broken`` steps and ``resolved`` threats."""
    b, r = set(broken), set(resolved)
    scores = [c.score for c in chains if not (c.step_ids & b)]
    scores += [v for t, v in standalone.items() if t not in r]
    return noisy_or(scores)


def _apply(fixes: Mapping[str, Fix], ids: Iterable[str]) -> tuple[set[str], set[str]]:
    sel = [fixes[i] for i in ids if i in fixes]
    return {k for f in sel for k in f.breaks}, {t for f in sel for t in f.resolves}


def what_if(
    chains: Sequence[ChainItem],
    standalone: Mapping[str, float],
    fixes: Mapping[str, Fix],
    ids: Sequence[str],
    method: Literal["single", "greedy_set_cover", "exact_hitting_set", "min_cut"] = "single",
    note: str = "",
) -> WhatIf:
    """Re-score the system with the fixes ``ids`` applied together."""
    broken, resolved = _apply(fixes, ids)
    return WhatIf(
        fixes=sorted(ids),
        chains_broken=sorted(c.id for c in chains if c.step_ids & broken),
        threats_resolved=sorted(resolved),
        risk_before=round(system_risk(chains, standalone), 1),
        risk_after=round(system_risk(chains, standalone, broken, resolved), 1),
        method=method,
        note=note,
    )


# --------------------------------------------------------------------------- hitting set
def covers(fix: Fix, chains: Sequence[ChainItem]) -> frozenset[str]:
    """Chain ids that ``fix`` breaks."""
    br = set(fix.breaks)
    return frozenset(c.id for c in chains if c.step_ids & br)


def breakable(chains: Sequence[ChainItem], fixes: Sequence[Fix]) -> list[ChainItem]:
    """Chains that at least one fix can break."""
    every = {s for f in fixes for s in f.breaks}
    return [c for c in chains if c.step_ids & every]


def candidates(chains: Sequence[ChainItem], fixes: Sequence[Fix]) -> list[Fix]:
    """Fixes that break something, minus strictly dominated ones (deterministic order)."""
    cov = {f.id: covers(f, chains) for f in fixes}
    useful = [f for f in fixes if cov[f.id]]
    out: list[Fix] = []
    for f in useful:
        dominated = any(
            g.id != f.id
            and (
                (cov[f.id] < cov[g.id] and g.cost <= f.cost)
                or (cov[f.id] == cov[g.id] and g.cost < f.cost)
            )
            for g in useful
        )
        if not dominated:
            out.append(f)
    return sorted(out, key=lambda f: f.id)


def greedy_hitting_set(chains: Sequence[ChainItem], fixes: Sequence[Fix]) -> list[str]:
    """Repeatedly pick the best (risk-weighted chains broken) / cost fix."""
    todo = {c.id: max(c.score, 1e-6) for c in breakable(chains, fixes)}
    cov = {f.id: covers(f, chains) for f in fixes}
    plan: list[str] = []
    while todo:
        best = min(
            fixes,
            key=lambda f: (
                -math.fsum(todo.get(c, 0.0) for c in cov[f.id]) / max(f.cost, 1e-9),
                f.cost,
                f.id,
            ),
        )
        gain = cov[best.id] & todo.keys()
        if not gain:
            break
        plan.append(best.id)
        for c in gain:
            todo.pop(c)
    return sorted(plan)


def exact_hitting_set(
    chains: Sequence[ChainItem], fixes: Sequence[Fix], k_max: int = K_MAX
) -> list[list[str]]:
    """All minimum-cost plans of at most ``k_max`` fixes that break every breakable chain.

    Returns ``[]`` when no plan fits in ``k_max`` fixes or the search exceeds
    :data:`EXACT_BUDGET` subsets (callers then use the greedy plan).
    """
    need = frozenset(c.id for c in breakable(chains, fixes))
    if not need:
        return []
    cand = candidates(chains, fixes)
    n = len(cand)
    if sum(math.comb(n, k) for k in range(1, min(k_max, n) + 1)) > EXACT_BUDGET:
        return []
    cov = {f.id: covers(f, chains) for f in cand}
    best_cost = math.inf
    best: list[list[str]] = []
    for k in range(1, min(k_max, n) + 1):
        for combo in itertools.combinations(cand, k):
            got: frozenset[str] = frozenset().union(*(cov[f.id] for f in combo))
            if got != need:
                continue
            cost = math.fsum(f.cost for f in combo)
            ids = sorted(f.id for f in combo)
            if cost < best_cost - 1e-9:
                best_cost, best = cost, [ids]
            elif math.isclose(cost, best_cost, abs_tol=1e-9):
                best.append(ids)
    # keep only irredundant plans (no fix can be dropped)
    out = [p for p in best if not _redundant(p, cov, need)]
    return sorted(out)


def _redundant(plan: list[str], cov: Mapping[str, frozenset[str]], need: frozenset[str]) -> bool:
    for i in range(len(plan)):
        rest = plan[:i] + plan[i + 1 :]
        if rest and frozenset().union(*(cov[x] for x in rest)) >= need:
            return True
    return False


# --------------------------------------------------------------------------- min cut
def min_cut(chains: Sequence[ChainItem], fixes: Sequence[Fix]) -> tuple[float, list[str]] | None:
    """Edmonds–Karp min cut from every chain entry to every chain goal.

    Edge capacity = cost of the cheapest fix breaking that step (∞ if none).
    Returns ``(value, cut step ids)`` or ``None`` when no finite cut exists.
    """
    if not chains:
        return None
    cheapest: dict[str, float] = {}
    for f in fixes:
        for k in f.breaks:
            cheapest[k] = min(cheapest.get(k, math.inf), f.cost)
    cap: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    edge_steps: dict[tuple[str, str], set[str]] = defaultdict(set)
    for c in chains:
        if not c.steps:
            continue
        cap[SOURCE][c.steps[0][1]] = math.inf
        cap[c.steps[-1][2]][SINK] = math.inf
        for sid, a, b in c.steps:
            if sid not in edge_steps[(a, b)]:
                edge_steps[(a, b)].add(sid)
                cap[a][b] += cheapest.get(sid, math.inf)
    flow = 0.0
    while True:
        parent: dict[str, str | None] = {SOURCE: None}
        q: deque[str] = deque([SOURCE])
        while q and SINK not in parent:
            u = q.popleft()
            for v in sorted(cap[u]):
                if cap[u][v] > 1e-12 and v not in parent:
                    parent[v] = u
                    q.append(v)
        if SINK not in parent:
            break
        path: list[tuple[str, str]] = []
        node = SINK
        while (prev := parent[node]) is not None:
            path.append((prev, node))
            node = prev
        aug = min(cap[u][v] for u, v in path)
        if math.isinf(aug):
            return None
        for u, v in path:
            cap[u][v] -= aug
            cap[v][u] += aug
        flow += aug
    reach = set(parent)
    cut = sorted(
        sid for (a, b), sids in edge_steps.items() if a in reach and b not in reach for sid in sids
    )
    return flow, cut


# --------------------------------------------------------------------------- fixes
_SLUG = re.compile(r"[^A-Za-z0-9.+-]+")


def fix_id(kind: str, label: str, key: str) -> str:
    """Stable, shell- and markup-safe fix id: ``fix:<kind>:<slug>-<hash6>``."""
    slug = _SLUG.sub("-", label).strip("-")[:40] or "x"
    return f"fix:{kind}:{slug}-{hashlib.sha256(key.encode('utf-8', 'replace')).hexdigest()[:6]}"


def _sorted_versions(ptype: PackageType, versions: Iterable[str]) -> list[str]:
    from startup_sbom.vulns.versions import sort_versions

    vs = sorted({v for v in versions if v})
    try:
        return sort_versions(ptype, vs)
    except Exception:  # noqa: BLE001 - malformed third-party versions must not abort
        return vs


def generate_fixes(report: Report) -> list[Fix]:
    """Candidate fixes derived from the report (upgrade, hardening, config, remove)."""
    pkgs = report.package_by_id()
    svcs = report.service_by_id()
    vulns = {(v.id, v.package): v for v in report.vulnerabilities}
    steps_by_threat: dict[str, set[str]] = defaultdict(set)
    all_steps = [s for c in report.attack_chains for s in c.steps if s.id]
    for s in all_steps:
        if s.threat and s.id:
            steps_by_threat[s.threat].add(s.id)
    fixes: dict[str, Fix] = {}

    def add(fix: Fix) -> None:
        if fix.breaks or fix.resolves:
            fixes.setdefault(fix.id, fix)

    by_pkg: dict[str, list[Threat]] = defaultdict(list)
    for t in report.threats:
        by_pkg[t.package].append(t)
    for pid, threats in sorted(by_pkg.items()):
        pkg = pkgs.get(pid)
        name = pkg.name if pkg else pid
        ptype = pkg.type if pkg else PackageType.GENERIC
        fixable: list[Threat] = []
        mins: list[str] = []
        unfixable: list[Threat] = []
        for t in threats:
            v = vulns.get((t.vulnerability, t.package))
            ordered = _sorted_versions(ptype, v.fixed_versions) if v is not None else []
            if ordered:
                fixable.append(t)
                mins.append(ordered[0])  # smallest version fixing this vulnerability
            else:
                unfixable.append(t)
        if fixable:
            target_v = _sorted_versions(ptype, mins)[-1]
            resolves = sorted(t.id for t in fixable)
            add(
                Fix(
                    id=fix_id("upgrade", name, pid),
                    kind="upgrade",
                    target=pid,
                    action=f"upgrade {name} to >= {target_v}",
                    cost=COST["upgrade"],
                    breaks=sorted({s for t in resolves for s in steps_by_threat.get(t, ())}),
                    resolves=resolves,
                )
            )
        if unfixable:
            resolves = sorted(t.id for t in unfixable)
            cves = ", ".join(sorted({t.vulnerability for t in unfixable})[:3])
            add(
                Fix(
                    id=fix_id("remove", name, pid),
                    kind="remove",
                    target=pid,
                    action=f"remove or replace {name} (no fixed version for {cves})",
                    cost=COST["remove"],
                    breaks=sorted({s for t in resolves for s in steps_by_threat.get(t, ())}),
                    resolves=resolves,
                )
            )

    # NoNewPrivileges on every service of a local account blocks setuid escalation.
    nnp_steps: dict[str, set[str]] = defaultdict(set)
    for s in all_steps:
        if s.rule in NNP_RULES and not s.mitigated_by and s.from_state.startswith("local:"):
            user = s.from_state.split(":", 1)[1]
            nnp_steps[user].add(s.id or "")
    for user, sids in sorted(nnp_steps.items()):
        targets = sorted(
            sid
            for sid, svc in svcs.items()
            if svc.hardening.user == user and not svc.hardening.no_new_privileges
        )
        if not targets:
            continue
        names = ", ".join(svcs[t].name for t in targets[:3])
        add(
            Fix(
                id=fix_id("hardening", f"nnp-{user}", "|".join(targets)),
                kind="hardening",
                target=targets[0],
                action=f"set NoNewPrivileges=yes on {names} (blocks setuid escalation from {user})",
                cost=COST["hardening"],
                breaks=sorted(sids),
            )
        )

    # Misconfiguration steps (container posture, writable units, capabilities).
    groups: dict[tuple[FixKind, str, str], set[str]] = defaultdict(set)
    for s in all_steps:
        if s.threat:
            continue
        title = s.title.lower()
        target = s.service or "container"
        key: tuple[FixKind, str, str]
        if s.rule == "R9":
            if "docker socket" in title:
                key = ("config", target, f"remove the Docker socket mount from {target}")
            elif "privileged" in title:
                key = ("config", "container", "run the container without --privileged")
            elif "pid namespace" in title:
                key = ("config", "container", "do not share the host PID namespace")
            else:
                key = ("config", "container", "drop the added container capabilities")
        elif s.rule == "R6":
            key = ("config", target, f"make {target} writable by root only")
        elif s.rule == "R8":
            key = ("hardening", target, f"drop dangerous capabilities from {target}")
        else:
            continue
        groups[key].add(s.id or "")
    for (kind, target, action), sids in sorted(groups.items()):
        add(
            Fix(
                id=fix_id(kind, action.split(" ")[0] + "-" + target, action),
                kind=kind,
                target=target,
                action=action,
                cost=1.0,
                breaks=sorted(sids),
            )
        )
    return [fixes[k] for k in sorted(fixes)]
