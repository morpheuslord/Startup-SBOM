"""One-paragraph digests of what each pipeline stage found.

Digests feed live displays (CLI dashboard, TUI scan log) and the optional live
analyst model.  Each returns ``(message, data)``: a human sentence and the key
numbers behind it.  They only summarise the in-memory report, never read the
target, and every free-text value is bounded so a hostile image cannot flood
a display or a model prompt.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from startup_sbom.models import (
    Activation,
    Binary,
    EOLInfo,
    OSInfo,
    Package,
    Report,
    Service,
    Severity,
    Threat,
    Vulnerability,
)
from startup_sbom.textsafe import safe

Digest = tuple[str, dict[str, object]]
_TOP = 5


def _clip(value: str, limit: int = 80) -> str:
    return safe(value, limit)


def _counts(counter: Counter[str], limit: int = 6) -> str:
    return ", ".join(f"{k} {v:,}" for k, v in counter.most_common(limit))


def _names(items: Iterable[str], limit: int = _TOP) -> str:
    seen = list(dict.fromkeys(items))
    shown = ", ".join(_clip(x, 60) for x in seen[:limit])
    return shown + (f" (+{len(seen) - limit:,} more)" if len(seen) > limit else "")


def os_digest(info: OSInfo) -> Digest:
    name = _clip(info.pretty_name or info.name or info.id)
    like = f", like {', '.join(info.id_like)}" if info.id_like else ""
    eco = ", ".join(info.vuln_ecosystems) or "none (no advisory ecosystem)"
    return (
        f"{name} ({info.id}{like}); advisory ecosystems: {eco}",
        {"id": info.id, "version": info.version_id, "ecosystems": list(info.vuln_ecosystems)},
    )


def packages_digest(packages: list[Package], databases: Iterable[str]) -> Digest:
    by_type = Counter(p.type.value for p in packages)
    dbs = sorted(databases)
    return (
        f"{len(packages):,} OS packages from {', '.join(dbs) or 'no database'}",
        {"packages": len(packages), "databases": dbs, "by_type": dict(by_type)},
    )


def services_digest(services: list[Service]) -> Digest:
    auto = [s for s in services if s.starts_automatically]
    acts: Counter[str] = Counter(a.value for s in auto for a in s.activation)
    by_init = Counter(s.init_system.value for s in services)
    exposed = [s for s in auto if s.network_exposed]
    root = sum(1 for s in auto if s.hardening.runs_as_root)
    msg = (
        f"{len(services):,} services ({_counts(by_init)}); {len(auto):,} start automatically "
        f"({_counts(acts)}); {root:,} of them as root"
    )
    if exposed:
        msg += f"; network-exposed: {_names(s.name for s in exposed)}"
    return msg, {
        "services": len(services),
        "automatic": len(auto),
        "activation": dict(acts),
        "by_init": dict(by_init),
        "network_exposed": [s.id for s in exposed[:20]],
        "root": root,
    }


def binaries_digest(binaries: list[Binary], unmanaged: list[str]) -> Digest:
    links = sum(len(b.libraries) for b in binaries)
    priv = [b for b in binaries if b.setuid or b.setgid or b.capabilities]
    unresolved = sum(len(b.unresolved) for b in binaries)
    msg = (
        f"{len(binaries):,} executables analysed, {links:,} library links resolved"
        f"{f' ({unresolved:,} unresolved)' if unresolved else ''}; "
        f"{len(priv):,} setuid/setgid/capability binaries"
    )
    if priv:
        msg += f" ({_names(b.path.rsplit('/', 1)[-1] for b in priv)})"
    if unmanaged:
        msg += f"; {len(unmanaged):,} executables owned by no package"
    return msg, {
        "executables": len(binaries),
        "links": links,
        "unresolved": unresolved,
        "privileged": [b.path for b in priv[:40]],
        "unmanaged": unmanaged[:40],
    }


def language_digest(packages: list[Package]) -> Digest:
    by_type = Counter(p.type.value for p in packages)
    return (
        f"{len(packages):,} language packages ({_counts(by_type) or 'none'})",
        {"packages": len(packages), "by_type": dict(by_type)},
    )


def vulns_digest(vulns: list[Vulnerability]) -> Digest:
    sev = Counter(v.severity.value for v in vulns)
    kev = [v for v in vulns if v.kev is not None]
    ordered = [s.value for s in Severity if sev.get(s.value)]
    msg = f"{len(vulns):,} vulnerabilities (" + (
        ", ".join(f"{s} {sev[s]:,}" for s in ordered) or "none"
    )
    msg += ")"
    if kev:
        msg += f"; known exploited (CISA KEV): {_names(f'{v.id} in {v.package_name}' for v in kev)}"
    worst = sorted(vulns, key=lambda v: (-v.severity.rank, -(v.epss or 0.0), v.id))[:_TOP]
    return msg, {
        "vulnerabilities": len(vulns),
        "by_severity": {s: sev[s] for s in ordered},
        "kev": [v.id for v in kev[:20]],
        "worst": [f"{v.id} {v.package_name} {v.severity.value}" for v in worst],
    }


def threats_digest(threats: list[Threat]) -> Digest:
    if not threats:
        return "no actionable vulnerabilities to reverse into threats", {"threats": 0}
    reach = Counter(t.reachability.value for t in threats)
    fired = Counter(tr.fired_by for t in threats for tr in t.triggers[:1])
    untriggered = sum(1 for t in threats if not t.triggers)
    to_root = [t for t in threats if t.postcondition == "root"]
    decisions = Counter(t.ssvc.decision.value for t in threats if t.ssvc is not None)
    msg = (
        f"{len(threats):,} threats; reachability {_counts(reach)}; "
        f"{untriggered:,} have no trigger (installed code nothing runs); "
        f"{len(to_root):,} lead to root"
    )
    if fired:
        msg += f"; strongest trigger fired by {_counts(fired)}"
    if decisions:
        msg += f"; SSVC {_counts(decisions)}"
    top = threats[:_TOP]
    return msg, {
        "threats": len(threats),
        "reachability": dict(reach),
        "no_trigger": untriggered,
        "to_root": len(to_root),
        "fired_by": dict(fired),
        "ssvc": dict(decisions),
        "top": [_clip(t.title, 140) for t in top],
    }


def chains_digest(report: Report) -> Digest:
    chains = report.attack_chains
    if not chains:
        return "no attack chain reaches a privileged goal", {"chains": 0}
    best = chains[0]
    rules = Counter(s.rule for c in chains for s in c.steps)
    path = " → ".join([best.entry, *(s.to_state for s in best.steps)])
    return (
        f"{len(chains):,} attack chain(s); strongest: {path} (score {best.score:.0f}, "
        f"SSVC {best.ssvc_decision}); rules used {_counts(rules)}",
        {
            "chains": len(chains),
            "best": path,
            "best_score": best.score,
            "rules": dict(rules),
        },
    )


def supply_chain_digest(report: Report) -> Digest:
    sc = report.supply_chain
    kinds = Counter(f.kind for f in sc.findings)
    widest = sorted(sc.blast_radius, key=lambda b: (-len(b.services), b.package))[:3]
    msg = f"{len(sc.findings):,} supply-chain finding(s)"
    if kinds:
        msg += f" ({_counts(kinds)})"
    if widest and widest[0].services:
        msg += "; widest blast radius: " + "; ".join(
            f"{_clip(b.package, 60)} reaches {len(b.services):,} service(s)" for b in widest
        )
    return msg, {"findings": len(sc.findings), "kinds": dict(kinds)}


def activation_summary(services: list[Service]) -> dict[str, int]:
    """Automatically started services per activation kind (for compact displays)."""
    return dict(
        Counter(
            a.value
            for s in services
            if s.starts_automatically
            for a in s.activation
            if a is not Activation.MANUAL
        )
    )


def eol_digest(eol: EOLInfo | None) -> Digest:
    if eol is None:
        return "no end-of-life data for this release", {"is_eol": None}
    state = "END OF LIFE" if eol.is_eol else "supported"
    when = f" (EOL {eol.eol_date})" if eol.eol_date else ""
    return f"{_clip(eol.product)} {_clip(eol.cycle)}: {state}{when}", {"is_eol": eol.is_eol}
