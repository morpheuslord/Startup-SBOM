"""Facts extracted from a report for the attack-chain rule engine.

A :class:`FactBase` is the static ground truth the rules reason over: the
reversed threats, the services that run them, privileged binaries, the kernel,
container posture, writable units and supply-chain blast-radius edges.  Callers
may add facts the scanner could not see (e.g. world-writable unit files) through
``extra_facts``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from startup_sbom.explain.attribution import FORMULA_VERSION, likelihood_of
from startup_sbom.models import (
    Activation,
    Consequence,
    Reachability,
    Report,
    Service,
    Threat,
)
from startup_sbom.threat.reachability import (
    SystemIndex,
    dangerous_caps,
    service_user,
    setuid_root,
)

#: Canonical attacker states (the privilege lattice).
REMOTE = "remote"
LOCAL_UNPRIV = "local:unprivileged"
ROOT = "root"
CONTAINER_ESCAPE = "container_escape"
HOST = "host"
PERSISTENCE = "persistence"
GOAL_RANK = {
    PERSISTENCE: 5,
    HOST: 4,
    CONTAINER_ESCAPE: 3,
    ROOT: 2,
}


def is_local(state: str) -> bool:
    """True for any ``local:*`` foothold state."""
    return state.startswith("local:")


@dataclass(frozen=True, slots=True)
class ThreatFact:
    """A reversed threat, flattened to the fields rules consult."""

    threat_id: str
    vulnerability: str
    package: str
    reachability: Reachability
    precondition: str
    postcondition: str
    consequences: frozenset[Consequence]
    service: str | None
    run_as: str | None
    network_exposed: bool
    attack_vector: str
    privileges_required: str
    likelihood: float
    technique_id: str | None
    mitigations: tuple[str, ...]
    title: str

    @property
    def gains_control(self) -> bool:
        return bool(
            self.consequences & {Consequence.RCE, Consequence.SUPPLY_CHAIN, Consequence.AUTH_BYPASS}
        )

    @property
    def is_privesc(self) -> bool:
        return self.postcondition in (ROOT, CONTAINER_ESCAPE, HOST) or bool(
            self.consequences & {Consequence.PRIVESC}
        )


@dataclass(frozen=True, slots=True)
class ServiceFact:
    """Autostarted service context for capability / socket / persistence rules."""

    id: str
    user: str
    network_exposed: bool
    enabled_at_boot: bool
    on_demand: bool
    is_entrypoint: bool
    dangerous_caps: tuple[str, ...]
    docker_socket: bool
    no_new_privileges: bool
    mitigations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SetuidFact:
    """A setuid/setgid or file-capability binary found in the rootfs."""

    path: str
    package: str | None
    owner_root: bool
    caps: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class KernelFact:
    package: str
    threat_ids: tuple[str, ...]
    in_container: bool


@dataclass(frozen=True, slots=True)
class ContainerFact:
    privileged: bool
    cap_add: tuple[str, ...]
    docker_socket: bool
    host_pid: bool
    host_network: bool
    readonly_rootfs: bool
    run_as_root: bool


@dataclass(frozen=True, slots=True)
class WritableUnitFact:
    """A unit file or boot-reachable executable writable by a non-owner."""

    path: str
    writable_by: str  # user/group label, or "world"
    runs_as: str = "root"


@dataclass(frozen=True, slots=True)
class BlastEdgeFact:
    """Supply-chain blast-radius edge: a backdoored package reaches a service (R10)."""

    package: str
    service: str
    network_exposed: bool
    threat_id: str | None


@dataclass(slots=True)
class FactBase:
    """All facts for one host, indexed for the rule engine."""

    threats: list[ThreatFact] = field(default_factory=list)
    services: dict[str, ServiceFact] = field(default_factory=dict)
    setuid: list[SetuidFact] = field(default_factory=list)
    kernel: list[KernelFact] = field(default_factory=list)
    container: ContainerFact | None = None
    writable_units: list[WritableUnitFact] = field(default_factory=list)
    blast_edges: list[BlastEdgeFact] = field(default_factory=list)

    def local_states(self) -> list[str]:
        """Candidate local footholds: the unprivileged default plus every service account."""
        states = {LOCAL_UNPRIV}
        for svc in self.services.values():
            if svc.user not in ("root", "0"):
                states.add(f"local:{svc.user}")
        for t in self.threats:
            if is_local(t.precondition):
                states.add(t.precondition)
        return sorted(states)


DOCKER_SOCK_PATHS = ("/var/run/docker.sock", "/run/docker.sock")


def build_facts(
    report: Report,
    threats: list[Threat],
    index: SystemIndex,
    extra_facts: Iterable[object] | None = None,
) -> FactBase:
    """Assemble the :class:`FactBase` from the report, threats and any extra facts."""
    fb = FactBase()
    in_container = report.container is not None

    for svc in index.services.values():
        if svc.masked or not svc.starts_automatically:
            continue
        svc_bins = index.service_binaries.get(svc.id, [])
        caps = sorted({c for b in svc_bins for c in dangerous_caps(b)})
        amb = sorted(set(svc.hardening.ambient_capabilities) & _DANGEROUS)
        fb.services[svc.id] = ServiceFact(
            id=svc.id,
            user=service_user(svc),
            network_exposed=index.exposure[svc.id].exposed,
            enabled_at_boot=_enabled_at_boot(svc),
            on_demand=_on_demand(svc),
            is_entrypoint=index.is_entrypoint(svc),
            dangerous_caps=tuple(sorted(set(caps) | set(amb))),
            docker_socket=_mounts_docker_sock(svc),
            no_new_privileges=svc.hardening.no_new_privileges,
            mitigations=(("NoNewPrivileges=yes",) if svc.hardening.no_new_privileges else ()),
        )

    for t in threats:
        fb.threats.append(_threat_fact(t))

    seen_setuid: set[str] = set()
    for b in sorted(report.binaries, key=lambda b: b.path):
        if (b.setuid or b.setgid or b.capabilities) and b.path not in seen_setuid:
            seen_setuid.add(b.path)
            fb.setuid.append(
                SetuidFact(
                    path=b.path,
                    package=b.package,
                    owner_root=setuid_root(b) or bool(dangerous_caps(b)),
                    caps=tuple(dangerous_caps(b)),
                )
            )

    kernel_threats: dict[str, list[str]] = {}
    for t in threats:
        if t.reachability is Reachability.KERNEL:
            kernel_threats.setdefault(t.package, []).append(t.id)
    for pkg_id, tids in sorted(kernel_threats.items()):
        fb.kernel.append(KernelFact(pkg_id, tuple(sorted(tids)), in_container))

    if report.container is not None:
        c = report.container
        fb.container = ContainerFact(
            privileged=bool(c.privileged),
            cap_add=tuple(sorted(c.cap_add)),
            docker_socket=any(
                m.destination in DOCKER_SOCK_PATHS or (m.source or "") in DOCKER_SOCK_PATHS
                for m in c.mounts
            ),
            host_pid=(c.pid_mode == "host"),
            host_network=(c.network_mode == "host"),
            readonly_rootfs=bool(c.readonly_rootfs),
            run_as_root=c.user in (None, "", "root", "0"),
        )

    for br in report.supply_chain.blast_radius:
        for sid in br.services:
            exposed = sid in index.exposure and index.exposure[sid].exposed
            tid = next(
                (
                    t.id
                    for t in threats
                    if t.package == br.package and Consequence.SUPPLY_CHAIN in t.consequences
                ),
                None,
            )
            fb.blast_edges.append(BlastEdgeFact(br.package, sid, exposed, tid))

    if extra_facts:
        for fact in extra_facts:
            _add_extra(fb, fact)
    return fb


_DANGEROUS = frozenset(
    {"CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
     "CAP_SYS_RAWIO", "CAP_SETUID", "CAP_SETGID", "CAP_NET_ADMIN", "CAP_SYS_BOOT"}
)  # fmt: skip


def _threat_fact(t: Threat) -> ThreatFact:
    technique = t.attack_techniques[0].id if t.attack_techniques else None
    if t.explanation is not None and t.explanation.formula_version == FORMULA_VERSION:
        like = likelihood_of(t.explanation)
    else:  # legacy (pre-2.1) factor map
        like = t.score_factors.get("likelihood", 0.0)
    return ThreatFact(
        threat_id=t.id,
        vulnerability=t.vulnerability,
        package=t.package,
        reachability=t.reachability,
        precondition=t.precondition,
        postcondition=t.postcondition,
        consequences=frozenset(t.consequences),
        service=t.services[0] if t.services else None,
        run_as=t.run_as,
        network_exposed=t.network_exposed,
        attack_vector=t.attack_vector,
        privileges_required=t.privileges_required,
        likelihood=like,
        technique_id=technique,
        mitigations=tuple(t.mitigations),
        title=t.title,
    )


def _enabled_at_boot(svc: Service) -> bool:
    return Activation.BOOT in svc.activation or Activation.ENTRYPOINT in svc.activation


def _on_demand(svc: Service) -> bool:
    return bool(set(svc.activation) & {Activation.SOCKET, Activation.TIMER, Activation.DBUS})


def _mounts_docker_sock(svc: Service) -> bool:
    blob = " ".join(svc.evidence) + " " + " ".join(c.raw for c in svc.commands)
    return any(p in blob for p in DOCKER_SOCK_PATHS)


def _add_extra(fb: FactBase, fact: object) -> None:
    if isinstance(fact, WritableUnitFact):
        fb.writable_units.append(fact)
    elif isinstance(fact, SetuidFact):
        fb.setuid.append(fact)
    elif isinstance(fact, BlastEdgeFact):
        fb.blast_edges.append(fact)
    elif isinstance(fact, KernelFact):
        fb.kernel.append(fact)
