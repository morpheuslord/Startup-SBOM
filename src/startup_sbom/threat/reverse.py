"""Reverse each vulnerability into a concrete :class:`Threat` for the scanned system.

The public entry point is :func:`reverse_vulnerabilities`.  Every conclusion is
backed by evidence drawn from the scan; where data is missing the analysis stays
conservative (unknown attack vector, no privilege gain, lower score) rather than
guessing.
"""

from __future__ import annotations

import hashlib

from startup_sbom.context import ScanContext
from startup_sbom.models import (
    AttackTechnique,
    Consequence,
    Hardening,
    Package,
    Reachability,
    Report,
    Service,
    Threat,
    Vulnerability,
    VulnStatus,
)
from startup_sbom.threat import attack, cwe, scoring, ssvc
from startup_sbom.threat.cvss import VectorFacts, best
from startup_sbom.threat.narrative import postcondition_phrase, threat_narrative
from startup_sbom.threat.reachability import (
    ReachInfo,
    SystemIndex,
    dangerous_caps,
    describe_listen,
    is_kernel_package,
    service_user,
    setuid_root,
)

SKIP_STATUS = {VulnStatus.FIXED, VulnStatus.NOT_AFFECTED}
#: CWE numbers whose local exploitation yields root (privilege escalation family).
PRIVESC_CWES = frozenset(
    {250, 266, 267, 268, 269, 271, 272, 273, 274, 276, 277, 278, 279, 426, 427, 428, 732, 15}
)
DESC_RCE = ("remote code execution", "arbitrary code", "command execution", "rce")
DESC_PRIVESC = ("privilege escalation", "escalate privilege", "gain root", "elevation of privilege")
DESC_DOS = ("denial of service", "denial-of-service", "crash", "infinite loop")
DESC_INFO = ("information disclosure", "information leak", "memory disclosure", "read memory")


def reverse_vulnerabilities(report: Report, ctx: ScanContext) -> list[Threat]:
    """One :class:`Threat` per actionable ``(vulnerability, package)`` pair.

    Vulnerabilities whose status is *fixed* or *not_affected* are skipped.
    Results are sorted by descending risk then id for deterministic output.
    """
    index = SystemIndex(report)
    reach_cache: dict[str, ReachInfo] = {}
    threats: list[Threat] = []
    no_cvss: list[str] = []
    unknown_pkg: list[str] = []
    total = 0
    for vuln in sorted(report.vulnerabilities, key=lambda v: (v.id, v.package)):
        if vuln.status in SKIP_STATUS:
            continue
        total += 1
        pkg = index.packages.get(vuln.package)
        if pkg is None:
            unknown_pkg.append(vuln.id)
            continue
        info = reach_cache.get(pkg.id)
        if info is None:
            from startup_sbom.threat.reachability import classify

            info = classify(index, pkg)
            reach_cache[pkg.id] = info
        facts = best(vuln)
        if not facts.known:
            no_cvss.append(vuln.id)
        threats.append(_build(report, index, vuln, pkg, info, facts))
    if unknown_pkg:
        ctx.warn(
            f"threat: {len(unknown_pkg):,} vulnerabilit{'y' if len(unknown_pkg) == 1 else 'ies'} "
            f"reference packages missing from the inventory and were skipped "
            f"({_examples(unknown_pkg)})"
        )
    if no_cvss:
        ctx.limit(
            f"{len(no_cvss):,} of {total:,} vulnerabilities have no CVSS vector; their attack "
            f"vector, privileges and automatability were assessed conservatively as unknown "
            f"({_examples(no_cvss)})"
        )
    threats.sort(key=lambda t: (-t.risk_score, t.id))
    return threats


def _examples(ids: list[str], n: int = 5) -> str:
    """The first ``n`` distinct ids, order preserved, plus an "and N more" tail."""
    seen = list(dict.fromkeys(ids))
    shown = ", ".join(seen[:n])
    rest = len(seen) - n
    return f"{shown} and {rest:,} more" if rest > 0 else shown


def _build(
    report: Report,
    index: SystemIndex,
    vuln: Vulnerability,
    pkg: Package,
    info: ReachInfo,
    facts: VectorFacts,
) -> Threat:
    consequences, cons_evidence = _consequences(vuln, facts)
    primary = index.services.get(info.primary_service or "")
    run_as = service_user(primary) if primary else None
    precondition = _precondition(facts, info)
    postcondition, post_reason = _postcondition(vuln, pkg, info, facts, consequences, run_as)

    techniques, tech_label, tech_sources = _techniques(vuln, facts, consequences, info)
    stride = _stride(consequences, facts)
    mit_factors = mitigation_factors(primary, info.level, consequences)
    mitigations = [m[0] for m in mit_factors]
    mit_evidence = [f"mitigation: {m[2]}" for m in mit_factors]
    ssvc_rec, ssvc_reasons = ssvc.assess(
        vuln, facts, consequences, info.level, info.network_exposed
    )
    threat_id = _threat_id(vuln, pkg)
    inputs = scoring.build_inputs(
        threat_id,
        epss=vuln.epss,
        kev=vuln.kev is not None,
        facts=facts,
        level=info.level,
        network_exposed=info.network_exposed,
        link_confidence=info.link.confidence if info.link else None,
        in_container=False,
        consequences=consequences,
        precondition=precondition,
        postcondition=postcondition,
        mitigations=[(m[0], m[1]) for m in mit_factors],
    )
    risk, explanation = scoring.explain(inputs)

    threat = Threat(
        id=threat_id,
        vulnerability=vuln.id,
        package=pkg.id,
        title=_title(vuln, pkg, info, postcondition),
        reachability=info.level,
        reachability_paths=[list(p) for p in info.paths],
        services=list(info.services),
        binaries=list(info.binaries),
        attack_vector=facts.attack_vector,
        privileges_required=facts.privileges_required,
        user_interaction=bool(facts.user_interaction),
        precondition=precondition,
        postcondition=postcondition,
        consequences=sorted(consequences, key=lambda c: c.value),
        run_as=run_as,
        network_exposed=info.network_exposed,
        listens=list(info.listens),
        mitigations=mitigations,
        attack_techniques=techniques,
        stride=stride,
        ssvc=ssvc_rec,
        risk_score=risk,
        score_factors={f.name: round(f.contribution, 3) for f in explanation.factors},
        narrative="",
        remediation=_remediation(vuln),
        explanation=explanation,
    )
    threat.narrative = threat_narrative(
        threat,
        package_label=_pkg_label(pkg),
        service_label=primary.id if primary else None,
        binary=info.binaries[0] if info.binaries else None,
        epss=vuln.epss,
        kev=vuln.kev is not None,
        techniques=tech_label,
    )
    evidence = [
        *info.evidence,
        *cons_evidence,
        *mit_evidence,
        f"attacker state: {precondition} → {postcondition} ({post_reason})",
        *(f"SSVC {r}" for r in ssvc_reasons),
        *(f"ATT&CK via {s}" for s in tech_sources),
    ]
    if not facts.known:
        evidence.insert(0, "no CVSS vector: attack vector and privileges treated as unknown")
    _record_evidence(threat, evidence)
    return threat


# --------------------------------------------------------------------------- consequences
def _consequences(vuln: Vulnerability, facts: VectorFacts) -> tuple[set[Consequence], list[str]]:
    consequences, evidence = cwe.consequences(vuln.cwes, facts)
    if not consequences:
        consequences, ev = _consequences_from_cvss(facts)
        evidence.extend(ev)
    if not consequences:
        consequences, ev = _consequences_from_description(vuln)
        evidence.extend(ev)
    if not consequences:
        consequences = {Consequence.OTHER}
        evidence.append("no CWE, CVSS impact or description signal: consequence recorded as other")
    return consequences, evidence


def _consequences_from_cvss(facts: VectorFacts) -> tuple[set[Consequence], list[str]]:
    if not facts.known:
        return set(), []
    out: set[Consequence] = set()
    if facts.integrity == "high" and (facts.availability == "high" or facts.scope_changed):
        out.add(Consequence.RCE)
    elif facts.integrity != "none":
        out.add(Consequence.TAMPERING)
    if facts.confidentiality != "none":
        out.add(Consequence.INFO_DISCLOSURE)
    if facts.availability == "high" and facts.integrity == "none":
        out.add(Consequence.DOS)
    reason = (
        f"no usable CWE; inferred from CVSS impact C:{facts.confidentiality[:1].upper()}/"
        f"I:{facts.integrity[:1].upper()}/A:{facts.availability[:1].upper()}"
    )
    return out, [reason] if out else []


def _consequences_from_description(vuln: Vulnerability) -> tuple[set[Consequence], list[str]]:
    text = (vuln.summary or "").lower()
    if not text:
        return set(), []
    out: set[Consequence] = set()
    if any(k in text for k in DESC_RCE):
        out.add(Consequence.RCE)
    if any(k in text for k in DESC_PRIVESC):
        out.add(Consequence.PRIVESC)
    if any(k in text for k in DESC_INFO):
        out.add(Consequence.INFO_DISCLOSURE)
    if any(k in text for k in DESC_DOS) and not out:
        out.add(Consequence.DOS)
    return out, ["consequence inferred from description keywords (last resort)"] if out else []


# --------------------------------------------------------------------------- pre/post
def _precondition(facts: VectorFacts, info: ReachInfo) -> str:
    av = facts.attack_vector
    if av == "network":
        return "remote" if facts.privileges_required == "none" else _local_state(info)
    if av == "adjacent":
        return "adjacent"
    if av == "physical":
        return "physical"
    if av == "local":
        return _local_state(info)
    # Unknown vector: use reachability as the conservative tie-breaker.
    if info.level is Reachability.NETWORK_SERVICE:
        return "remote"
    return _local_state(info)


def _local_state(info: ReachInfo) -> str:
    if info.level is Reachability.NETWORK_SERVICE and info.primary_service:
        return "remote"
    return "local"


def _postcondition(
    vuln: Vulnerability,
    pkg: Package,
    info: ReachInfo,
    facts: VectorFacts,
    consequences: set[Consequence],
    run_as: str | None,
) -> tuple[str, str]:
    cwe_nums = {n for c in vuln.cwes if (n := cwe.cwe_number(c)) is not None}
    gains_root = (
        is_kernel_package(pkg)
        or any(setuid_root(b) for b in info.setuid_binaries)
        or any(dangerous_caps(b) for b in info.setuid_binaries)
        or bool(cwe_nums & PRIVESC_CWES)
        or Consequence.PRIVESC in consequences
    )
    control = consequences & {Consequence.RCE, Consequence.SUPPLY_CHAIN, Consequence.AUTH_BYPASS}
    if not control and not gains_root:
        # Disclosure / DoS / tampering only: attacker state does not advance.
        state = _as_precondition(info, run_as)
        return state, "information/availability impact only; no change of attacker state"
    if gains_root and info.level in (
        Reachability.KERNEL,
        Reachability.SETUID,
    ):
        return "root", "privilege-escalation weakness on a kernel/setuid-root component"
    if gains_root and info.level in (Reachability.BOOT_SERVICE, Reachability.ON_DEMAND_SERVICE):
        if run_as in ("root", None):
            return "root", "privilege escalation in a service running as root"
        return "root", "privilege-escalation weakness reachable from the service account"
    if run_as and run_as not in ("root",):
        return f"local:{run_as}", f"code execution as the service account {run_as}"
    if info.primary_service:
        return "root", "code execution in a service running as root"
    if gains_root:
        return "root", "privilege-escalation weakness"
    return "local", "code execution as a local user"


def _as_precondition(info: ReachInfo, run_as: str | None) -> str:
    if info.level is Reachability.NETWORK_SERVICE:
        return "remote"
    if run_as and run_as != "root":
        return f"local:{run_as}"
    return "local"


# --------------------------------------------------------------------------- att&ck
def _techniques(
    vuln: Vulnerability,
    facts: VectorFacts,
    consequences: set[Consequence],
    info: ReachInfo,
) -> tuple[list[AttackTechnique], str, list[str]]:
    ids = [vuln.id, *vuln.aliases]
    mapping = attack.cve_mapping(ids)
    sources: list[str] = []
    if mapping is not None:
        sources.extend(mapping.sources)
    cwe_nums = sorted({n for c in vuln.cwes if (n := cwe.cwe_number(c)) is not None})
    cwe_map = attack.cwe_mapping(cwe_nums)
    exploitation: list[str] = []
    primary: list[str] = []
    secondary: list[str] = []
    if mapping is not None:
        exploitation, primary, secondary = (
            list(mapping.exploitation),
            list(mapping.primary),
            list(mapping.secondary),
        )
    if not exploitation:
        exploitation = list(cwe_map.exploitation)
    if not primary:
        primary = list(cwe_map.primary)
    if not secondary:
        secondary = list(cwe_map.secondary)
    if cwe_map.sources and (mapping is None or not mapping.exploitation):
        sources.extend(cwe_map.sources)
    if not exploitation:
        generic, why = _generic_exploitation(consequences, info)
        exploitation = [generic]
        sources.append(why)

    prefer = _preferred_tactics(info, consequences)
    seen: dict[str, AttackTechnique] = {}
    label_ids: list[str] = []
    for tid in [*exploitation, *primary, *secondary]:
        if tid in seen:
            continue
        tech = attack.technique(tid, prefer)
        if tech is not None:
            seen[tid] = tech
            label_ids.append(f"{tech.id} ({tech.tactic})" if tech.tactic else tech.id)
    techniques = [seen[k] for k in sorted(seen)]
    return techniques, ", ".join(label_ids[:4]), sorted(set(sources))


def _generic_exploitation(consequences: set[Consequence], info: ReachInfo) -> tuple[str, str]:
    if info.level is Reachability.NETWORK_SERVICE:
        return attack.GENERIC["initial-access"], "generic tactic: network-exposed service (T1190)"
    if consequences & {Consequence.PRIVESC}:
        return attack.GENERIC["privilege-escalation"], "generic tactic: privilege escalation"
    if consequences & {Consequence.RCE}:
        return attack.GENERIC["execution"], "generic tactic: code execution (T1203)"
    if info.level is Reachability.LINKED_BY_SERVICE:
        return attack.GENERIC["lateral-movement"], "generic tactic: linked-library exploit (T1210)"
    return attack.GENERIC["privilege-escalation"], "generic tactic fallback (T1068)"


def _preferred_tactics(info: ReachInfo, consequences: set[Consequence]) -> tuple[str, ...]:
    if info.level is Reachability.NETWORK_SERVICE:
        return ("initial-access", "execution", "privilege-escalation")
    if info.level in (Reachability.SETUID, Reachability.KERNEL):
        return ("privilege-escalation", "execution")
    if Consequence.PRIVESC in consequences:
        return ("privilege-escalation", "execution")
    return ("execution", "privilege-escalation", "initial-access")


# --------------------------------------------------------------------------- stride
def _stride(consequences: set[Consequence], facts: VectorFacts) -> list[str]:
    out: set[str] = set()
    mapping = {
        Consequence.AUTH_BYPASS: "Spoofing",
        Consequence.TAMPERING: "Tampering",
        Consequence.INFO_DISCLOSURE: "Information Disclosure",
        Consequence.DOS: "Denial of Service",
        Consequence.PRIVESC: "Elevation of Privilege",
        Consequence.RCE: "Elevation of Privilege",
        Consequence.SUPPLY_CHAIN: "Tampering",
    }
    for c in consequences:
        if c in mapping:
            out.add(mapping[c])
    if facts.known:
        if facts.confidentiality != "none":
            out.add("Information Disclosure")
        if facts.integrity != "none":
            out.add("Tampering")
        if facts.availability == "high":
            out.add("Denial of Service")
    return sorted(out)


# --------------------------------------------------------------------------- mitigations
def mitigation_factors(
    service: Service | None,
    level: Reachability,
    consequences: set[Consequence],
) -> list[tuple[str, float, str]]:
    """``(directive label, score multiplier, why)`` for each mitigation on ``service``."""
    if service is None:
        return []
    h = service.hardening
    out: list[tuple[str, float, str]] = []
    privesc = bool(consequences & {Consequence.PRIVESC, Consequence.RCE})
    if h.no_new_privileges and privesc:
        out.append(("NoNewPrivileges=yes", 0.5, "NoNewPrivileges=yes blocks setuid/privilege gain"))
    if not h.runs_as_root:
        out.append(
            (
                f"User={h.user} (non-root)" if not h.dynamic_user else "DynamicUser=yes",
                0.7,
                "service runs as a non-root account, so compromise lands unprivileged",
            )
        )
    if _caps_dropped(h) and privesc:
        out.append(
            (
                "CapabilityBoundingSet drops dangerous capabilities",
                0.7,
                "capability bounding set drops CAP_SYS_ADMIN/DAC/MODULE/PTRACE",
            )
        )
    if h.restrict_suid_sgid:
        out.append(
            ("RestrictSUIDSGID=yes", 0.85, "RestrictSUIDSGID=yes prevents new setuid binaries")
        )
    if h.system_call_filter and level in (Reachability.KERNEL, Reachability.SETUID):
        out.append(
            ("SystemCallFilter set", 0.8, "system-call filter reduces kernel-exploit reliability")
        )
    if h.protect_system == "strict":
        out.append(("ProtectSystem=strict", 0.9, "read-only system paths hinder persistence"))
    return out


def service_mitigations(
    service: Service | None,
    level: Reachability,
    consequences: set[Consequence],
) -> tuple[list[str], float, list[str]]:
    """Mitigating directives on ``service`` and the multiplicative score discount."""
    factors = mitigation_factors(service, level, consequences)
    discount = 1.0
    for _, m, _ in factors:
        discount *= m
    return [f[0] for f in factors], round(discount, 4), [f"mitigation: {f[2]}" for f in factors]


def _caps_dropped(h: Hardening) -> bool:
    from startup_sbom.rootfs.caps import DANGEROUS_CAPS

    if h.capability_bounding_set is None:
        return False
    if not h.capability_bounding_set:
        return True
    kept = {c.lower().removeprefix("cap_") for c in h.capability_bounding_set}
    return not (kept & DANGEROUS_CAPS)


# --------------------------------------------------------------------------- labels
def _pkg_label(pkg: Package) -> str:
    return f"{pkg.name} {pkg.version}"


def _title(vuln: Vulnerability, pkg: Package, info: ReachInfo, postcondition: str) -> str:
    outcome = postcondition_phrase(postcondition, None)
    where = {
        Reachability.NETWORK_SERVICE: "network-exposed",
        Reachability.BOOT_SERVICE: "boot-started",
        Reachability.LINKED_BY_SERVICE: "service-linked",
        Reachability.ON_DEMAND_SERVICE: "on-demand",
        Reachability.SETUID: "setuid/privileged",
        Reachability.KERNEL: "kernel",
        Reachability.INSTALLED: "installed",
    }[info.level]
    return f"{vuln.id} in {pkg.name} ({where}) → {outcome}"


def _remediation(vuln: Vulnerability) -> str:
    fixes = sorted(set(vuln.fixed_versions))
    if fixes:
        return f"upgrade {vuln.package_name} to ≥ {fixes[0]}"
    if vuln.status is VulnStatus.WILL_NOT_FIX:
        return (
            f"no fix planned for {vuln.package_name} — mitigate by removing the package or "
            "restricting its reachability (hardening, network policy)"
        )
    return (
        f"no fixed version published for {vuln.package_name} — mitigate by restricting "
        "reachability (service hardening, drop capabilities, network policy) or removing it"
    )


def _threat_id(vuln: Vulnerability, pkg: Package) -> str:
    digest = hashlib.sha256(f"{vuln.id}|{pkg.id}".encode()).hexdigest()[:12]
    return f"threat-{digest}"


def _record_evidence(threat: Threat, evidence: list[str]) -> None:
    # The Threat model has no free-form evidence field, so the audit trail is folded
    # into the narrative tail as a machine-parseable "Evidence:" block (one item/line).
    seen: list[str] = []
    for e in evidence:
        if e and e not in seen:
            seen.append(e)
    seen.extend(
        "reachability path: " + " → ".join(path) for path in threat.reachability_paths[:3] if path
    )
    if seen:
        threat.narrative = threat.narrative + "\n\nEvidence:\n- " + "\n- ".join(seen)


def listen_summary(info: ReachInfo) -> str:
    """Comma-separated listener summary (used by reporters)."""
    return ", ".join(describe_listen(li) for li in info.listens)
