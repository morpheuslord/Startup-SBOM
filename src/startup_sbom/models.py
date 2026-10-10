"""Pydantic models for the native startup-sbom report.

These models are the contract between every analysis stage and every output
format.  The JSON Schema of :class:`Report` is published (``startup-sbom schema``)
and versioned through :data:`SCHEMA_VERSION`.
"""

from __future__ import annotations

import math
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "2.1"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=False)


# --------------------------------------------------------------------------- enums
class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_score(cls, score: float | None) -> Severity:
        if score is None:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.NONE

    @classmethod
    def parse(cls, value: str | None) -> Severity:
        if not value:
            return cls.UNKNOWN
        v = value.strip().lower()
        aliases = {
            "important": "high",
            "moderate": "medium",
            "negligible": "low",
            "unimportant": "low",
            "untriaged": "unknown",
            "not yet assigned": "unknown",
        }
        v = aliases.get(v, v)
        try:
            return cls(v)
        except ValueError:
            return cls.UNKNOWN


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.NONE: 1,
    Severity.UNKNOWN: 0,
}


class PackageType(StrEnum):
    DEB = "deb"
    RPM = "rpm"
    APK = "apk"
    ALPM = "alpm"
    PYPI = "pypi"
    NPM = "npm"
    GOLANG = "golang"
    MAVEN = "maven"
    CARGO = "cargo"
    GENERIC = "generic"


class InitSystem(StrEnum):
    SYSTEMD = "systemd"
    SYSV = "sysv"
    OPENRC = "openrc"
    RUNIT = "runit"
    S6 = "s6"
    SUPERVISORD = "supervisord"
    INITTAB = "inittab"
    CONTAINER = "container"


class Activation(StrEnum):
    BOOT = "boot"  # pulled in by the default target / runlevel
    SOCKET = "socket"
    TIMER = "timer"
    PATH = "path"
    DBUS = "dbus"
    ENTRYPOINT = "entrypoint"
    MANUAL = "manual"  # installed but not started automatically


class VulnStatus(StrEnum):
    AFFECTED = "affected"
    FIXED = "fixed"
    NOT_AFFECTED = "not_affected"
    UNDER_INVESTIGATION = "under_investigation"
    WILL_NOT_FIX = "will_not_fix"
    NO_FIX_AVAILABLE = "no_fix_available"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Reachability(StrEnum):
    """How a vulnerable package is reachable on the analysed system (strongest first)."""

    NETWORK_SERVICE = "network_service"  # executable of a network-listening service
    BOOT_SERVICE = "boot_service"  # executable of a service started at boot
    LINKED_BY_SERVICE = "linked_by_service"  # library loaded by a boot service
    ON_DEMAND_SERVICE = "on_demand_service"  # socket/timer/dbus activated
    SETUID = "setuid"  # ships a setuid/setgid or capability binary
    KERNEL = "kernel"  # installed kernel package
    INSTALLED = "installed"  # installed but not observed in any execution path


class Consequence(StrEnum):
    RCE = "code_execution"
    PRIVESC = "privilege_escalation"
    AUTH_BYPASS = "authentication_bypass"
    INFO_DISCLOSURE = "information_disclosure"
    TAMPERING = "tampering"
    DOS = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain_compromise"
    OTHER = "other"


class SSVCDecision(StrEnum):
    TRACK = "Track"
    TRACK_STAR = "Track*"
    ATTEND = "Attend"
    ACT = "Act"


# --------------------------------------------------------------------------- system
class EOLInfo(_Model):
    product: str
    cycle: str
    eol_date: str | None = None
    is_eol: bool | None = None
    lts: bool | None = None
    source: str = "endoflife.date"


class OSInfo(_Model):
    id: str = "unknown"
    id_like: list[str] = Field(default_factory=list)
    name: str | None = None
    pretty_name: str | None = None
    version_id: str | None = None
    version_codename: str | None = None
    variant_id: str | None = None
    build_id: str | None = None
    family: str | None = None  # debian | rhel | suse | alpine | arch | ...
    vuln_ecosystems: list[str] = Field(default_factory=list)  # e.g. ["Debian:12"]
    eol: EOLInfo | None = None
    evidence: list[str] = Field(default_factory=list)


class ContainerMount(_Model):
    source: str | None = None
    destination: str
    read_write: bool = True
    kind: str | None = None
    engine_socket: bool = False  # docker/podman/containerd API socket mounted inside


class ContainerInfo(_Model):
    kind: str = "container"  # container | image
    engine: str | None = None  # docker | podman | nerdctl | archive
    id: str | None = None
    name: str | None = None
    image: str | None = None
    image_digest: str | None = None
    platform: str | None = None
    entrypoint: list[str] = Field(default_factory=list)
    cmd: list[str] = Field(default_factory=list)
    working_dir: str | None = None
    user: str | None = None
    exposed_ports: list[str] = Field(default_factory=list)
    env_keys: list[str] = Field(default_factory=list)  # values never recorded
    path: list[str] = Field(default_factory=list)  # PATH directories (not a secret)
    redacted_env_keys: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    privileged: bool | None = None
    cap_add: list[str] = Field(default_factory=list)
    cap_drop: list[str] = Field(default_factory=list)
    security_opt: list[str] = Field(default_factory=list)
    mounts: list[ContainerMount] = Field(default_factory=list)
    network_mode: str | None = None
    pid_mode: str | None = None
    ipc_mode: str | None = None
    port_bindings: list[str] = Field(default_factory=list)
    readonly_rootfs: bool | None = None


# --------------------------------------------------------------------------- packages
class Package(_Model):
    """An installed package (OS or language ecosystem)."""

    id: str  # stable bom-ref (normally the purl)
    type: PackageType
    name: str
    version: str  # full distro version, epoch included where the distro uses one
    epoch: int | None = None
    arch: str | None = None
    source_name: str | None = None
    source_version: str | None = None
    purl: str | None = None
    cpes: list[str] = Field(default_factory=list)
    summary: str | None = None
    maintainer: str | None = None
    vendor: str | None = None
    packager: str | None = None
    license: str | None = None
    homepage: str | None = None
    installed_size: int | None = None
    depends: list[str] = Field(default_factory=list)
    provides: list[str] = Field(default_factory=list)
    file_count: int = 0
    repository: str | None = None
    signing_key: str | None = None
    signed: bool | None = None
    install_time: str | None = None
    location: str | None = None  # database or manifest that recorded it
    provenance_flags: list[str] = Field(default_factory=list)
    properties: dict[str, str] = Field(default_factory=dict)


# --------------------------------------------------------------------------- services
class ListenAddress(_Model):
    protocol: str  # tcp | udp | sctp | unix | netlink | fifo | vsock | unknown
    address: str | None = None
    port: int | None = None
    path: str | None = None
    scope: str = "network"  # network | loopback | local
    source: str  # where it was declared (unit, config file, image config)


class Hardening(_Model):
    user: str = "root"
    group: str | None = None
    dynamic_user: bool = False
    no_new_privileges: bool = False
    capability_bounding_set: list[str] | None = None  # None = all (default)
    ambient_capabilities: list[str] = Field(default_factory=list)
    private_network: bool = False
    private_tmp: bool = False
    private_devices: bool = False
    private_users: bool = False
    protect_system: str | None = None
    protect_home: str | None = None
    restrict_suid_sgid: bool = False
    system_call_filter: bool = False
    restrict_address_families: list[str] | None = None
    root_directory: str | None = None
    exposure: float | None = None  # 0.0 (safe) .. 10.0 (unsafe), systemd-analyze style
    exposure_rating: str | None = None
    weaknesses: list[str] = Field(default_factory=list)

    @property
    def runs_as_root(self) -> bool:
        return self.user in ("root", "0") and not self.dynamic_user


class Command(_Model):
    directive: str  # ExecStart, command, run, Entrypoint, ...
    argv: list[str] = Field(default_factory=list)
    raw: str
    executable: str | None = None  # resolved, canonical in-image path
    full_privileges: bool = False  # systemd '+' prefix
    wrapped_by: list[str] = Field(default_factory=list)  # e.g. ["/usr/bin/tini", "/bin/sh"]


class Service(_Model):
    id: str  # "<init>:<name>"
    name: str
    init_system: InitSystem
    description: str | None = None
    unit_path: str | None = None
    enabled: bool = False
    masked: bool = False
    activation: list[Activation] = Field(default_factory=list)
    boot_path: list[str] = Field(default_factory=list)  # e.g. default.target -> x.service
    commands: list[Command] = Field(default_factory=list)
    executables: list[str] = Field(default_factory=list)
    hardening: Hardening = Field(default_factory=Hardening)
    listens: list[ListenAddress] = Field(default_factory=list)
    packages: list[str] = Field(default_factory=list)  # Package.id owning executables
    start_time_ms: float | None = None
    evidence: list[str] = Field(default_factory=list)

    @property
    def starts_automatically(self) -> bool:
        return bool(set(self.activation) - {Activation.MANUAL}) and not self.masked

    @property
    def network_exposed(self) -> bool:
        return any(listen.scope == "network" for listen in self.listens)


# --------------------------------------------------------------------------- binaries
class LibraryLink(_Model):
    soname: str
    path: str | None = None
    package: str | None = None
    via: str = "needed"  # needed | dlopen | preload | interpreter | config
    confidence: Confidence = Confidence.HIGH
    depth: int = 1
    parent: str | None = None  # canonical path of the object that loads this one


class Binary(_Model):
    path: str
    package: str | None = None
    kind: str = "unknown"  # elf | script | unknown
    arch: str | None = None
    interpreter: str | None = None
    needed: list[str] = Field(default_factory=list)
    libraries: list[LibraryLink] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)
    setuid: bool = False
    setgid: bool = False
    owner_uid: int | None = None
    capabilities: list[str] = Field(default_factory=list)
    embedded_package: str | None = None  # from ELF .note.package
    used_by: list[str] = Field(default_factory=list)  # Service.id


# --------------------------------------------------------------------------- vulnerabilities
class CVSSScore(_Model):
    version: str  # "3.1" | "3.0" | "4.0" | "2.0"
    vector: str
    base_score: float | None = None
    severity: Severity = Severity.UNKNOWN
    source: str | None = None


class KEVInfo(_Model):
    date_added: str | None = None
    due_date: str | None = None
    ransomware: bool = False
    required_action: str | None = None
    vendor_project: str | None = None
    product: str | None = None
    forensic_triage: str | None = None


class Vulnerability(_Model):
    """A vulnerability matched against one installed package."""

    id: str  # canonical id (CVE when known)
    aliases: list[str] = Field(default_factory=list)
    advisories: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)  # osv | arch | nvd
    package: str  # Package.id
    package_name: str
    installed_version: str
    fixed_versions: list[str] = Field(default_factory=list)
    status: VulnStatus = VulnStatus.AFFECTED
    summary: str | None = None
    published: str | None = None
    modified: str | None = None
    severity: Severity = Severity.UNKNOWN
    cvss: list[CVSSScore] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    epss: float | None = None
    epss_percentile: float | None = None
    kev: KEVInfo | None = None
    references: list[str] = Field(default_factory=list)
    match_confidence: Confidence = Confidence.HIGH
    match_reason: str | None = None

    @property
    def best_cvss(self) -> CVSSScore | None:
        order = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}
        scored = [c for c in self.cvss if c.vector]
        return min(scored, key=lambda c: order.get(c.version, 9)) if scored else None


# --------------------------------------------------------------------------- threats
class AttackTechnique(_Model):
    id: str  # ATT&CK id, e.g. T1190
    name: str
    tactic: str | None = None


class SSVC(_Model):
    exploitation: str  # none | public_poc | active
    automatable: str  # yes | no
    technical_impact: str  # partial | total
    exposure: str  # small | controlled | open
    decision: SSVCDecision
    trace: SSVCTrace | None = None  # coordinator tree decision path
    bod_26_04: SSVCTrace | None = None  # deployer timeline tree decision path


class Threat(_Model):
    """One vulnerability reversed into the context of the analysed system."""

    id: str
    vulnerability: str  # Vulnerability.id
    package: str  # Package.id
    title: str
    reachability: Reachability
    reachability_paths: list[list[str]] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)  # Service.id
    binaries: list[str] = Field(default_factory=list)
    attack_vector: str = "unknown"  # network | adjacent | local | physical | unknown
    privileges_required: str = "unknown"  # none | low | high | unknown
    user_interaction: bool = False
    precondition: str  # attacker state required, e.g. "remote" | "local:www-data"
    postcondition: str  # attacker state gained, e.g. "root" | "local:www-data"
    consequences: list[Consequence] = Field(default_factory=list)
    run_as: str | None = None
    network_exposed: bool = False
    listens: list[ListenAddress] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
    stride: list[str] = Field(default_factory=list)
    ssvc: SSVC | None = None
    risk_score: float = 0.0  # 0..100
    score_factors: dict[str, float] = Field(default_factory=dict)
    narrative: str
    remediation: str | None = None
    evidence: list[str] = Field(default_factory=list)  # Evidence / Derivation ids
    intel_summary: str | None = None
    confidence: Confidence = Confidence.HIGH  # weakest link over the evidence
    explanation: Explanation | None = None  # exact additive breakdown of risk_score


class AttackStep(_Model):
    id: str | None = None  # canonical edge id, shared by chains using the same step
    rule: str
    title: str
    from_state: str
    to_state: str
    technique: AttackTechnique | None = None
    threat: str | None = None  # Threat.id when vulnerability driven
    vulnerability: str | None = None
    service: str | None = None
    evidence: list[str] = Field(default_factory=list)
    mitigated_by: list[str] = Field(default_factory=list)
    likelihood: float = 0.0
    derivation: str | None = None  # Derivation.id that fired this step


class AttackChain(_Model):
    id: str
    entry: str
    goal: str
    steps: list[AttackStep]
    likelihood: float
    impact: float
    score: float  # 0..100
    ssvc_decision: SSVCDecision
    mitigated: bool = False
    narrative: str
    explanation: Explanation | None = None


# --------------------------------------------------------------------------- supply chain
class SupplyChainFinding(_Model):
    id: str
    kind: str  # third_party_repo | unsigned_package | local_build | unmanaged_binary | ...
    severity: Severity
    subject: str  # package id, file path, or "system"
    title: str
    detail: str | None = None
    evidence: list[str] = Field(default_factory=list)


class BlastRadius(_Model):
    package: str  # Package.id
    vendor: str | None = None
    services: list[str] = Field(default_factory=list)
    binaries: list[str] = Field(default_factory=list)
    example_paths: list[list[str]] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    score: float = 0.0


class VendorSummary(_Model):
    vendor: str
    packages: int = 0
    boot_packages: int = 0
    services: int = 0
    vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    kev: int = 0


class GraphNode(_Model):
    id: str
    kind: str
    label: str


class GraphEdge(_Model):
    source: str
    target: str
    kind: str
    confidence: Confidence = Confidence.HIGH


class SupplyChain(_Model):
    vendors: list[VendorSummary] = Field(default_factory=list)
    findings: list[SupplyChainFinding] = Field(default_factory=list)
    blast_radius: list[BlastRadius] = Field(default_factory=list)
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


# --------------------------------------------------------------------------- intel
class ExploitRef(_Model):
    source: str  # exploitdb | metasploit | nuclei
    id: str
    title: str | None = None
    url: str | None = None
    kind: str | None = None  # exploit | auxiliary | template | ...
    verified: bool | None = None
    published: str | None = None


class PocRepo(_Model):
    """Metadata of a public proof-of-concept repository (never cloned or executed)."""

    full_name: str
    url: str
    description: str | None = None
    stars: int = 0
    created_at: str | None = None
    pushed_at: str | None = None
    untrusted: bool = True


class VendorStatus(_Model):
    vendor: str  # ubuntu | redhat | debian | ...
    severity: str | None = None
    status: str | None = None
    statement: str | None = None
    mitigation: str | None = None
    advisories: list[str] = Field(default_factory=list)
    url: str | None = None


class IntelRecord(_Model):
    """One advisory or article fetched for a CVE.  Unstructured text is untrusted."""

    id: str
    source: str
    url: str
    final_url: str | None = None
    kind: str  # advisory | exploit | poc | writeup | patch | vendor | scanner | mailing-list
    title: str | None = None
    site: str | None = None
    published: str | None = None
    snippet: str | None = None
    cves: list[str] = Field(default_factory=list)
    fetched_at: datetime
    trust: str = "unstructured"  # structured | unstructured
    exploit_maturity: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    sha256: str | None = None
    truncated: bool = False
    text_ref: str | None = None  # key of the cleaned full text in the intel store


class IntelBundle(_Model):
    """Everything prefetched about one CVE."""

    cve: str
    exploit_maturity: str = "none"  # none | poc | functional | weaponized
    exploitation: str = "none"  # SSVC semantics: none | public_poc | active
    exploit_available: bool = False
    exploit_sources: list[str] = Field(default_factory=list)
    metasploit: list[ExploitRef] = Field(default_factory=list)
    exploitdb: list[ExploitRef] = Field(default_factory=list)
    nuclei: list[ExploitRef] = Field(default_factory=list)
    poc_repos_count: int = 0
    poc_repos_top: list[PocRepo] = Field(default_factory=list)
    cisa_ssvc: dict[str, str] = Field(default_factory=dict)
    kev: KEVInfo | None = None
    epss_trend: list[tuple[str, float]] = Field(default_factory=list)
    vendor_status: list[VendorStatus] = Field(default_factory=list)
    advisories: list[IntelRecord] = Field(default_factory=list)
    articles: list[IntelRecord] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    fetched_at: datetime


# --------------------------------------------------------------------------- explainability
class EvidenceKind(StrEnum):
    FILE = "file"  # a file read inside the target root
    PACKAGE_DB = "package_db"
    ADVISORY = "advisory"
    FEED = "feed"  # EPSS / KEV / CISA ADP snapshot
    CONTAINER_CONFIG = "container_config"
    USER_INPUT = "user_input"
    DEFAULT = "default"  # an assumption the tool made (always surfaced)


class Evidence(_Model):
    """An atomic, citable fact with its source.  Ids are content-addressed."""

    id: str  # "ev:" + sha256(kind|source|locator|statement)[:12]
    kind: EvidenceKind
    statement: str
    source: str  # in-image POSIX path, "osv:DSA-5724-1", "epss:2026-10-09", ...
    locator: str | None = None
    digest: str | None = None
    retrieved: str | None = None
    confidence: Confidence = Confidence.HIGH


class Derivation(_Model):
    """One rule firing: premises (evidence or other derivations) -> conclusion."""

    id: str  # "dv:<rule>:<hash>"
    conclusion: str
    rule: str
    premises: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.HIGH


class ExplanationMethod(StrEnum):
    SEQUENTIAL_LMDI = "sequential+lmdi"
    LMDI = "lmdi"
    SHAPLEY = "shapley_exact"
    NOISY_OR_LOG = "noisy_or_log"
    RULE_TRACE = "rule_trace"


class Factor(_Model):
    name: str
    label: str
    value: float | str | bool | None = None
    multiplier: float | None = None
    kind: Literal["additive", "multiplicative"]
    contribution: float  # signed points on the score scale
    evidence: list[str] = Field(default_factory=list)
    description: str = ""


class Explanation(_Model):
    """Exact additive decomposition: ``baseline + sum(contributions) == total``."""

    subject: str
    method: ExplanationMethod
    formula: str
    formula_version: str = "risk/1"
    baseline: float
    total: float
    factors: list[Factor]
    confidence: Confidence = Confidence.HIGH
    limits: list[str] = Field(default_factory=list)  # knowledge limits (NIST IR 8312)

    @model_validator(mode="after")
    def _exact(self) -> Explanation:
        s = self.baseline + sum(f.contribution for f in self.factors)
        if not math.isclose(s, self.total, abs_tol=1e-6):
            raise ValueError(f"explanation not exact: {s} != {self.total}")
        return self


class DecisionNode(_Model):
    decision_point: str
    value: str
    alternatives: list[str]
    rationale: str
    evidence: list[str] = Field(default_factory=list)
    source: Literal["cisa_adp", "computed", "user", "default"] = "computed"


class SSVCTrace(_Model):
    tree: str
    path: list[DecisionNode]
    row: int
    outcome: str
    flips: list[str] = Field(default_factory=list)


class Fix(_Model):
    id: str
    kind: Literal["upgrade", "hardening", "config", "remove"]
    target: str
    action: str
    cost: float = 1.0
    breaks: list[str] = Field(default_factory=list)  # AttackStep ids
    resolves: list[str] = Field(default_factory=list)  # Threat ids


class WhatIf(_Model):
    fixes: list[str]
    chains_broken: list[str] = Field(default_factory=list)
    threats_resolved: list[str] = Field(default_factory=list)
    risk_before: float
    risk_after: float
    method: Literal["single", "greedy_set_cover", "exact_hitting_set", "min_cut"]
    note: str = ""


class Driver(_Model):
    kind: Literal["chain", "threat", "package", "service", "vendor"]
    id: str
    label: str
    contribution: float
    share: float
    cumulative: float


class GlobalExplanation(_Model):
    system_risk: float
    method: ExplanationMethod = ExplanationMethod.NOISY_OR_LOG
    formula: str
    drivers: list[Driver] = Field(default_factory=list)
    pareto_80: dict[str, int] = Field(default_factory=dict)


class NumericClaim(_Model):
    ref: str
    field: str
    value: float


class Claim(_Model):
    text: str
    cites: list[str] = Field(default_factory=list)
    numbers: list[NumericClaim] = Field(default_factory=list)
    kind: Literal["finding", "recommendation", "context"] = "finding"


class GroundingIssue(_Model):
    claim: int  # index into claims (-1 = summary)
    code: Literal["unknown_id", "uncited", "numeric_mismatch", "unknown_number_ref"]
    detail: str


class GroundingResult(_Model):
    passed: bool
    grounded_ratio: float
    issues: list[GroundingIssue] = Field(default_factory=list)


class Explanations(_Model):
    system: GlobalExplanation | None = None
    fix_plan: list[WhatIf] = Field(default_factory=list)  # minimal fix set(s)
    what_if: list[WhatIf] = Field(default_factory=list)  # per single fix
    fixes: list[Fix] = Field(default_factory=list)


# --------------------------------------------------------------------------- AI assessment
class AIEvidenceRef(_Model):
    ref: str  # threat id, CVE id, package purl, service id, chain id or finding id
    kind: str
    note: str | None = None


class AICounterfactual(_Model):
    condition: str
    effect: str


class AIFinding(_Model):
    threat_id: str | None = None
    title: str
    priority: str  # P1 | P2 | P3 | P4
    agrees_with_scanner: bool = True
    evidence: list[AIEvidenceRef] = Field(default_factory=list)
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
    counterfactuals: list[AICounterfactual] = Field(default_factory=list)


class AIRemediationStep(_Model):
    title: str
    commands: list[str] = Field(default_factory=list)  # suggestions only, never executed
    fixes: list[str] = Field(default_factory=list)  # Threat ids
    evidence: list[AIEvidenceRef] = Field(default_factory=list)
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)


class AIAssessment(_Model):
    """Grounded, machine-checked AI analysis attached to a report."""

    provider: str
    model: str
    agents: list[str] = Field(default_factory=list)
    generated: datetime
    input_sha256: str  # hash of the canonical report the agents saw
    audience: Literal["executive", "technical"] = "technical"
    executive_summary: str
    findings: list[AIFinding] = Field(default_factory=list)
    remediation_plan: list[AIRemediationStep] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)
    grounding: GroundingResult
    usage: dict[str, float] = Field(default_factory=dict)  # requests, tokens, est_cost_usd
    disclaimer: str = (
        "AI-generated analysis over the deterministic findings; every statement cites "
        "report ids and was machine-checked against them."
    )


# --------------------------------------------------------------------------- report
class TargetInfo(_Model):
    kind: str  # dir | host | tar | docker-archive | oci-dir | oci-archive | container
    reference: str
    digest: str | None = None
    platform: str | None = None


class Coverage(_Model):
    package_databases: list[str] = Field(default_factory=list)
    init_systems: list[str] = Field(default_factory=list)
    vulnerability_sources: list[str] = Field(default_factory=list)
    vulnerability_ecosystems: list[str] = Field(default_factory=list)
    offline: bool = False
    limitations: list[str] = Field(default_factory=list)


class Summary(_Model):
    packages: int = 0
    boot_packages: int = 0
    services: int = 0
    boot_services: int = 0
    network_services: int = 0
    vulnerabilities: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    kev: int = 0
    threats: int = 0
    act: int = 0
    attend: int = 0
    attack_chains: int = 0
    supply_chain_findings: int = 0


class ScanMetadata(_Model):
    tool: str = "startup-sbom"
    tool_version: str
    schema_version: str = SCHEMA_VERSION
    scan_id: str
    started: datetime
    finished: datetime | None = None
    target: TargetInfo
    coverage: Coverage = Field(default_factory=Coverage)


class Report(_Model):
    metadata: ScanMetadata
    os: OSInfo = Field(default_factory=OSInfo)
    container: ContainerInfo | None = None
    summary: Summary = Field(default_factory=Summary)
    packages: list[Package] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    binaries: list[Binary] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    threats: list[Threat] = Field(default_factory=list)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    supply_chain: SupplyChain = Field(default_factory=SupplyChain)
    intel: list[IntelBundle] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    derivations: list[Derivation] = Field(default_factory=list)
    explanations: Explanations | None = None
    ai: AIAssessment | None = None
    warnings: list[str] = Field(default_factory=list)

    def package_by_id(self) -> dict[str, Package]:
        return {p.id: p for p in self.packages}

    def service_by_id(self) -> dict[str, Service]:
        return {s.id: s for s in self.services}
