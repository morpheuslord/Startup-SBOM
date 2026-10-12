"""Forward-chaining rule set R1–R12 over a :class:`FactBase` (research §4).

Each rule is a pure function that reads facts and yields :class:`Edge` objects
in the privilege lattice ``remote → local:<user> → root →
container_escape/host → persistence``.  Every edge keeps its rule id, evidence,
driving threat, ATT&CK technique and any hardening that prunes or downgrades it
(R12).  The engine (``chains.py``) takes the fixpoint of these edges.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from startup_sbom.models import Consequence, Reachability
from startup_sbom.threat.facts import (
    CONTAINER_ESCAPE,
    HOST,
    LOCAL_UNPRIV,
    PERSISTENCE,
    REMOTE,
    ROOT,
    FactBase,
    ThreatFact,
    is_local,
)

#: Likelihood of a non-vulnerability (misconfiguration) edge.
MISCONFIG_LIKELIHOOD = 0.9
#: Multiplicative downgrade applied to an edge a hardening directive weakens (R12).
MITIGATION_DOWNGRADE = 0.3


@dataclass(slots=True)
class Edge:
    """A derived attacker-state transition with full provenance."""

    rule: str
    title: str
    from_state: str
    to_state: str
    likelihood: float
    technique_id: str | None = None
    threat_id: str | None = None
    vulnerability: str | None = None
    service: str | None = None
    evidence: list[str] = field(default_factory=list)
    mitigated_by: list[str] = field(default_factory=list)
    mitigated: bool = False

    def key(self) -> tuple[str, str, str, str]:
        return (self.rule, self.from_state, self.to_state, self.threat_id or self.service or "")


def all_rules() -> list[Callable[[FactBase], Iterator[Edge]]]:
    """Every rule, in id order."""
    return [
        r1_remote_service_rce,
        r3_local_privesc,
        r6_writable_unit,
        r8_dangerous_capability,
        r9_container_escape,
        r10_supply_chain,
        r11_persistence,
    ]


def derive(fb: FactBase) -> list[Edge]:
    """All edges from all rules, de-duplicated and deterministically ordered."""
    edges: dict[tuple[str, str, str, str], Edge] = {}
    for rule in all_rules():
        for edge in rule(fb):
            edges.setdefault(edge.key(), edge)
    return sorted(edges.values(), key=lambda e: (e.rule, e.from_state, e.to_state, e.key()[3]))


# --------------------------------------------------------------------------- R1 / R2
def r1_remote_service_rce(fb: FactBase) -> Iterator[Edge]:
    """Remote exploit of a network-reachable service → foothold as its run-as user."""
    for t in fb.threats:
        if not _remote_reachable(t) or not t.gains_control:
            continue
        rule = "R1" if t.privileges_required in ("none", "unknown") else "R2"
        auth = "" if rule == "R1" else f" (requires {t.privileges_required}-privilege account)"
        to_state = t.postcondition if t.postcondition != t.precondition else _foothold(t)
        yield Edge(
            rule=rule,
            title=f"Remote exploit of {t.vulnerability} in a network service{auth}",
            from_state=REMOTE,
            to_state=to_state,
            likelihood=t.likelihood,
            technique_id=t.technique_id,
            threat_id=t.threat_id,
            vulnerability=t.vulnerability,
            service=t.service,
            evidence=[
                f"{t.vulnerability} is reachable over the network via {t.service or t.package}",
                f"gains {to_state}",
            ],
        )


# --------------------------------------------------------------------------- R3 / R4 / R5 / R7
def r3_local_privesc(fb: FactBase) -> Iterator[Edge]:
    """Local privilege escalation to root (setuid R4, glibc+setuid R5, kernel R7, else R3)."""
    local_states = fb.local_states()
    for t in fb.threats:
        if t.postcondition != ROOT or _remote_reachable_as_root(t):
            continue
        if not (t.is_privesc or t.gains_control):
            continue
        if t.attack_vector not in ("local", "unknown"):
            continue
        rule, why = _privesc_rule(t, fb)
        for src in local_states:
            mitigated_by = _nnp_for_user(fb, src)
            yield Edge(
                rule=rule,
                title=f"Local privilege escalation via {t.vulnerability} ({why})",
                from_state=src,
                to_state=ROOT,
                likelihood=t.likelihood * (MITIGATION_DOWNGRADE if mitigated_by else 1.0),
                technique_id=t.technique_id,
                threat_id=t.threat_id,
                vulnerability=t.vulnerability,
                service=t.service,
                evidence=[f"{t.vulnerability}: {why}", f"exploitable from {src}"],
                mitigated_by=mitigated_by,
                mitigated=bool(mitigated_by),
            )


def _privesc_rule(t: ThreatFact, fb: FactBase) -> tuple[str, str]:
    if t.reachability is Reachability.KERNEL:
        return "R7", "kernel vulnerability exploitable by a local user"
    if t.reachability is Reachability.SETUID:
        return "R4", "setuid/privileged binary with a local privilege-escalation flaw"
    if fb.setuid and t.reachability in (Reachability.LINKED_BY_SERVICE, Reachability.INSTALLED):
        return "R5", "library/loader flaw abused through a present setuid binary"
    return "R3", "local privilege-escalation weakness"


# --------------------------------------------------------------------------- R6
def r6_writable_unit(fb: FactBase) -> Iterator[Edge]:
    """A boot-reachable unit/executable writable by a non-root user → root."""
    for w in fb.writable_units:
        if w.runs_as not in ("root", "0"):
            continue
        anon = w.writable_by in ("world", "", None)
        src = LOCAL_UNPRIV if anon else f"local:{w.writable_by}"
        yield Edge(
            rule="R6",
            title=f"Hijack root-run unit writable by {w.writable_by}",
            from_state=src if is_local(src) else LOCAL_UNPRIV,
            to_state=ROOT,
            likelihood=MISCONFIG_LIKELIHOOD,
            technique_id="T1574.010",
            service=w.path,
            evidence=[f"{w.path} runs as {w.runs_as} and is writable by {w.writable_by}"],
        )


# --------------------------------------------------------------------------- R8
def r8_dangerous_capability(fb: FactBase) -> Iterator[Edge]:
    """A compromised service holding a root-equivalent capability escalates to root/escape."""
    container = fb.container is not None
    for svc in fb.services.values():
        if not svc.dangerous_caps:
            continue
        src = f"local:{svc.user}" if svc.user not in ("root", "0") else None
        if src is None:
            continue  # already root; capabilities add nothing
        to_state = CONTAINER_ESCAPE if container else ROOT
        mitigated = ["NoNewPrivileges=yes"] if svc.no_new_privileges else []
        yield Edge(
            rule="R8",
            title=f"Abuse {', '.join('cap_' + c for c in svc.dangerous_caps)} held by {svc.id}",
            from_state=src,
            to_state=to_state,
            likelihood=0.8 * (MITIGATION_DOWNGRADE if mitigated else 1.0),
            technique_id="T1548",
            service=svc.id,
            evidence=[
                f"{svc.id} runs with dangerous capabilities: "
                + ", ".join("cap_" + c for c in svc.dangerous_caps)
            ],
            mitigated_by=mitigated,
            mitigated=bool(mitigated),
        )


# --------------------------------------------------------------------------- R9
def r9_container_escape(fb: FactBase) -> Iterator[Edge]:
    """docker.sock mounts and privileged/host-namespace containers enable host takeover."""
    for svc in fb.services.values():
        if not svc.docker_socket:
            continue
        src = f"local:{svc.user}" if svc.user not in ("root", "0") else ROOT
        yield Edge(
            rule="R9",
            title=f"Mount of the Docker socket in {svc.id} grants host control",
            from_state=src,
            to_state=CONTAINER_ESCAPE,
            likelihood=0.95,
            technique_id="T1610",
            service=svc.id,
            evidence=[f"{svc.id} can reach /var/run/docker.sock"],
        )
    c = fb.container
    if c is None:
        return
    if c.privileged:
        yield Edge(
            "R9",
            "Privileged container escapes to the host",
            ROOT,
            CONTAINER_ESCAPE,
            0.95,
            technique_id="T1611",
            evidence=["container runs with --privileged"],
        )
    if c.docker_socket:
        yield Edge(
            "R9",
            "Mounted Docker socket grants host control",
            ROOT,
            CONTAINER_ESCAPE,
            0.95,
            technique_id="T1610",
            evidence=["/var/run/docker.sock is mounted into the container"],
        )
    if c.host_pid:
        yield Edge(
            "R9",
            "Host PID namespace exposes host processes",
            ROOT,
            HOST,
            0.8,
            technique_id="T1611",
            evidence=["container shares the host PID namespace (pid_mode=host)"],
        )
    if c.cap_add:
        dangerous = sorted({x.upper().removeprefix("CAP_") for x in c.cap_add} & _DANGEROUS_SHORT)
        if dangerous:
            yield Edge(
                "R9",
                f"Added container capabilities {', '.join('cap_' + d.lower() for d in dangerous)}",
                ROOT,
                CONTAINER_ESCAPE,
                0.8,
                technique_id="T1611",
                evidence=["container adds dangerous capabilities: " + ", ".join(dangerous)],
            )


_DANGEROUS_SHORT = frozenset(
    {"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "DAC_OVERRIDE", "DAC_READ_SEARCH", "SYS_RAWIO",
     "NET_ADMIN", "SYS_BOOT", "SETUID", "SETGID"}
)  # fmt: skip


# --------------------------------------------------------------------------- R10
def r10_supply_chain(fb: FactBase) -> Iterator[Edge]:
    """Supply-chain backdoor in a library linked by a network service → pre-auth root."""
    for e in fb.blast_edges:
        if not e.network_exposed:
            continue
        threat = next((t for t in fb.threats if t.threat_id == e.threat_id), None)
        if threat is not None and Consequence.SUPPLY_CHAIN not in threat.consequences:
            continue
        yield Edge(
            rule="R10",
            title=f"Supply-chain backdoor in {e.package} reached through {e.service}",
            from_state=REMOTE,
            to_state=ROOT,
            likelihood=threat.likelihood if threat else 0.9,
            technique_id=threat.technique_id if threat else "T1195.002",
            threat_id=e.threat_id,
            vulnerability=threat.vulnerability if threat else None,
            service=e.service,
            evidence=[
                f"{e.package} is loaded by the network-facing service {e.service}; "
                "a planted backdoor executes pre-authentication"
            ],
        )


# --------------------------------------------------------------------------- R11
def r11_persistence(fb: FactBase) -> Iterator[Edge]:
    """Once root, persist through an enabled service or a writable boot unit."""
    enabled = [s for s in fb.services.values() if s.enabled_at_boot or s.is_entrypoint]
    if not enabled and not fb.writable_units:
        return
    if fb.writable_units:
        detail = f"modify a writable boot unit ({fb.writable_units[0].path})"
    else:
        detail = f"install or modify an enabled service (e.g. {enabled[0].id})"
    yield Edge(
        rule="R11",
        title="Establish persistence across reboot",
        from_state=ROOT,
        to_state=PERSISTENCE,
        likelihood=MISCONFIG_LIKELIHOOD,
        technique_id="T1543.002",
        evidence=[f"with root, the attacker can {detail}"],
    )


# --------------------------------------------------------------------------- helpers
def _remote_reachable(t: ThreatFact) -> bool:
    if t.reachability is Reachability.NETWORK_SERVICE:
        return True
    return (
        t.reachability is Reachability.LINKED_BY_SERVICE
        and t.network_exposed
        and t.attack_vector == "network"
    )


def _remote_reachable_as_root(t: ThreatFact) -> bool:
    return _remote_reachable(t) and t.postcondition == ROOT and t.precondition == REMOTE


def _foothold(t: ThreatFact) -> str:
    if t.run_as and t.run_as not in ("root", "0"):
        return f"local:{t.run_as}"
    return ROOT if t.run_as in ("root", "0", None) else LOCAL_UNPRIV


def _nnp_for_user(fb: FactBase, state: str) -> list[str]:
    """``NoNewPrivileges=yes`` evidence when every service for ``state``'s user sets it."""
    if not is_local(state) or state == LOCAL_UNPRIV:
        return []
    user = state.split(":", 1)[1]
    svcs = [s for s in fb.services.values() if s.user == user]
    if svcs and all(s.no_new_privileges for s in svcs):
        return [f"NoNewPrivileges=yes on {', '.join(sorted(s.id for s in svcs))}"]
    return []
