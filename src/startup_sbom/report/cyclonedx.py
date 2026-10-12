"""CycloneDX SBOM (1.5 / 1.6 / 1.7) built with cyclonedx-python-lib.

Layout follows what Trivy, Syft/Grype and Dependency-Track consume: exactly one
``operating-system`` component (name = os-release ``ID``, version = ``VERSION_ID``)
with dependency edges to every package; package bom-refs are the purls; services
are CycloneDX services with endpoints; vulnerabilities carry CVSS ratings, CWEs,
EPSS/KEV properties.  Threats and attack chains live in the native report, linked
through a ``threat-model`` external reference.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from urllib.parse import quote

from cyclonedx.contrib.license.factories import LicenseFactory
from cyclonedx.exception.model import InvalidUriException
from cyclonedx.model import (
    DataClassification,
    DataFlow,
    ExternalReference,
    ExternalReferenceType,
    Property,
    XsUri,
)
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.model.dependency import Dependable, Dependency
from cyclonedx.model.impact_analysis import (
    ImpactAnalysisAffectedStatus,
    ImpactAnalysisResponse,
    ImpactAnalysisState,
)
from cyclonedx.model.license import License, LicenseAcknowledgement
from cyclonedx.model.service import Service as CdxService
from cyclonedx.model.tool import ToolRepository
from cyclonedx.model.vulnerability import (
    BomTarget,
    BomTargetVersionRange,
    VulnerabilityAnalysis,
    VulnerabilityRating,
    VulnerabilityReference,
    VulnerabilityScoreSource,
    VulnerabilitySeverity,
    VulnerabilitySource,
)
from cyclonedx.model.vulnerability import Vulnerability as CdxVulnerability
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL

from startup_sbom.models import (
    CVSSScore,
    ListenAddress,
    Package,
    Reachability,
    Report,
    Service,
    Severity,
    Threat,
    Vulnerability,
    VulnStatus,
)
from startup_sbom.report.native import (
    PROJECT_URL,
    RenderOptions,
    listen_text,
    package_reachability,
    parse_time,
    scan_uuid,
    short_hash,
    threats_by_vuln,
    timestamp,
    vuln_reachability,
)

NS = "startup-sbom"
REPORT_FILENAME = "report.json"
VEX_FILENAME = "vex.cdx.json"

SPEC = {"1.5": SchemaVersion.V1_5, "1.6": SchemaVersion.V1_6, "1.7": SchemaVersion.V1_7}

#: Supplier organisation of a distribution's own packages, by os-release ID.
DISTRO_SUPPLIERS = {
    "debian": "Debian Project",
    "ubuntu": "Canonical Ltd.",
    "alpine": "Alpine Linux",
    "fedora": "Fedora Project",
    "rhel": "Red Hat, Inc.",
    "centos": "CentOS Project",
    "rocky": "Rocky Enterprise Software Foundation",
    "almalinux": "AlmaLinux OS Foundation",
    "amzn": "Amazon Web Services",
    "ol": "Oracle Corporation",
    "arch": "Arch Linux",
    "opensuse-leap": "openSUSE Project",
    "opensuse-tumbleweed": "openSUSE Project",
    "sles": "SUSE LLC",
    "wolfi": "Chainguard, Inc.",
    "chainguard": "Chainguard, Inc.",
}

_SEVERITY = {
    Severity.CRITICAL: VulnerabilitySeverity.CRITICAL,
    Severity.HIGH: VulnerabilitySeverity.HIGH,
    Severity.MEDIUM: VulnerabilitySeverity.MEDIUM,
    Severity.LOW: VulnerabilitySeverity.LOW,
    Severity.NONE: VulnerabilitySeverity.NONE,
    Severity.UNKNOWN: VulnerabilitySeverity.UNKNOWN,
}
_METHOD = {
    "2.0": VulnerabilityScoreSource.CVSS_V2,
    "3.0": VulnerabilityScoreSource.CVSS_V3,
    "3.1": VulnerabilityScoreSource.CVSS_V3_1,
    "4.0": VulnerabilityScoreSource.CVSS_V4,
}
_SAFE_URL = re.compile(r"^https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")
_CWE = re.compile(r"(?:CWE-)?(\d+)$", re.IGNORECASE)
_DEP_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9+._@/-]*)")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_licenses = LicenseFactory()


def prop(name: str, value: object) -> Property:
    """A ``startup-sbom:``-namespaced property (control characters stripped)."""
    return Property(name=f"{NS}:{name}", value=clean(str(value)))


def clean(text: str) -> str:
    """Remove control characters that JSON allows but XML/consumers choke on."""
    return _CTRL.sub("", text)


def safe_url(url: str | None) -> XsUri | None:
    """``XsUri`` for a plain http(s) URL, ``None`` for anything else."""
    if url and _SAFE_URL.match(url.strip()):
        try:
            return XsUri(url.strip())
        except InvalidUriException:
            return None
    return None


def parse_purl(value: str | None) -> PackageURL | None:
    """Parse a purl string; ``None`` when absent or invalid."""
    if not value:
        return None
    try:
        return PackageURL.from_string(value)
    except ValueError:
        return None


def make_license(text: str | None) -> list[License]:
    """SPDX id / expression when valid, else a named license (DECLARED)."""
    if not text or not text.strip():
        return []
    try:
        lic = _licenses.make_from_string(
            clean(text.strip()), license_acknowledgement=LicenseAcknowledgement.DECLARED
        )
    except Exception:  # noqa: BLE001 - malformed metadata must not abort the SBOM
        return []
    return [lic]


def package_instances(report: Report) -> list[tuple[Package, str]]:
    """Every package with a unique bom-ref, in canonical order.

    The bom-ref is ``Package.id``; a (defective) duplicate id gets a deterministic
    ``~dupN`` suffix so the BOM stays schema-valid.
    """
    out: list[tuple[Package, str]] = []
    used: set[str] = set()
    ordered = sorted(
        report.packages,
        key=lambda p: (p.id, p.name, p.version, p.arch or "", p.model_dump_json()),
    )
    for pkg in ordered:
        base = pkg.id or f"pkg:generic/{quote(pkg.name)}"
        ref, n = base, 1
        while ref in used:
            n += 1
            ref = f"{base}~dup{n}"
        used.add(ref)
        out.append((pkg, ref))
    return out


def package_refs(report: Report) -> dict[str, str]:
    """Map ``Package.id`` → bom-ref of its first instance."""
    refs: dict[str, str] = {}
    for pkg, ref in package_instances(report):
        refs.setdefault(pkg.id, ref)
    return refs


def os_ref(report: Report) -> str:
    """bom-ref of the operating-system component (Syft convention)."""
    return f"os:{report.os.id}@{report.os.version_id or 'unknown'}"


def vuln_ref(v: Vulnerability) -> str:
    """bom-ref of a vulnerability entry (unique per vulnerability x package)."""
    return f"vuln:{v.id}:{short_hash(v.package, length=12)}"


def service_ref(s: Service) -> str:
    """bom-ref of a service."""
    return f"svc:{s.id}"


def split_epoch(version: str) -> tuple[str | None, str]:
    """``'1:2.3-4'`` → ``('1', '2.3-4')``."""
    head, sep, tail = version.partition(":")
    if sep and head.isdigit():
        return head, tail
    return None, version


# --------------------------------------------------------------------------- components
def _supplier(report: Report, pkg: Package) -> OrganizationalEntity | None:
    name = pkg.vendor
    if not name and pkg.type.value in ("deb", "rpm", "apk", "alpm"):
        name = DISTRO_SUPPLIERS.get(report.os.id)
    return OrganizationalEntity(name=clean(name)) if name else None


def _trivy_props(pkg: Package) -> list[Property]:
    if not pkg.source_name:
        return []
    out = [Property(name="aquasecurity:trivy:SrcName", value=clean(pkg.source_name))]
    epoch, version = split_epoch(pkg.source_version or pkg.version)
    if pkg.type.value == "rpm" and "-" in version:
        version, release = version.rsplit("-", 1)
        out.append(Property(name="aquasecurity:trivy:SrcRelease", value=clean(release)))
    out.append(Property(name="aquasecurity:trivy:SrcVersion", value=clean(version)))
    if epoch and epoch != "0":
        out.append(Property(name="aquasecurity:trivy:SrcEpoch", value=epoch))
    return out


def package_component(
    report: Report,
    pkg: Package,
    ref: str,
    reach: Reachability,
    options: RenderOptions,
) -> Component:
    """CycloneDX component of one installed package."""
    props = [prop("package:type", pkg.type.value), prop("reachability", reach.value)]
    optional = {
        "package:arch": pkg.arch,
        "package:epoch": pkg.epoch,
        "package:sourceName": pkg.source_name,
        "package:sourceVersion": pkg.source_version,
        "package:repository": pkg.repository,
        "package:packager": pkg.packager,
        "package:signingKey": pkg.signing_key,
        "package:signed": None if pkg.signed is None else str(pkg.signed).lower(),
        "package:installTime": pkg.install_time,
        "package:location": pkg.location,
        "package:fileCount": pkg.file_count or None,
        "package:installedSize": pkg.installed_size,
    }
    props += [prop(k, v) for k, v in optional.items() if v not in (None, "")]
    props += [prop("package:provenanceFlag", f) for f in pkg.provenance_flags]
    props += [prop(f"package:{k}", v) for k, v in sorted(pkg.properties.items())]
    if pkg.id != ref:
        props.append(prop("package:id", pkg.id))
    if options.trivy_compat:
        props += _trivy_props(pkg)
    ext = []
    if url := safe_url(pkg.homepage):
        ext.append(ExternalReference(type=ExternalReferenceType.WEBSITE, url=url))
    return Component(
        type=ComponentType.LIBRARY,
        bom_ref=ref,
        name=clean(pkg.name) or "unknown",
        version=clean(pkg.version),
        purl=parse_purl(pkg.purl or pkg.id),
        cpe=pkg.cpes[0] if pkg.cpes else None,
        description=clean(pkg.summary) if pkg.summary else None,
        supplier=_supplier(report, pkg),
        publisher=clean(pkg.maintainer) if pkg.maintainer else None,
        licenses=make_license(pkg.license),
        external_references=ext,
        properties=props,
    )


def os_component(report: Report) -> Component:
    """The single ``operating-system`` component."""
    o = report.os
    props = [prop("os:family", o.family)] if o.family else []
    for key, val in (
        ("os:versionCodename", o.version_codename),
        ("os:variantId", o.variant_id),
        ("os:buildId", o.build_id),
    ):
        if val:
            props.append(prop(key, val))
    props += [prop("os:idLike", x) for x in o.id_like]
    props += [prop("os:vulnEcosystem", x) for x in o.vuln_ecosystems]
    if o.eol is not None:
        props.append(prop("eol:cycle", o.eol.cycle))
        if o.eol.eol_date:
            props.append(prop("eol:date", o.eol.eol_date))
        if o.eol.is_eol is not None:
            props.append(prop("eol:isEol", str(o.eol.is_eol).lower()))
    supplier = DISTRO_SUPPLIERS.get(o.id)
    return Component(
        type=ComponentType.OPERATING_SYSTEM,
        bom_ref=os_ref(report),
        name=clean(o.id) or "unknown",
        version=clean(o.version_id) if o.version_id else None,
        description=clean(o.pretty_name) if o.pretty_name else None,
        supplier=OrganizationalEntity(name=supplier) if supplier else None,
        properties=props,
    )


def container_component(report: Report) -> Component:
    """``type: container`` root component for container / image targets."""
    c = report.container
    assert c is not None  # noqa: S101 - only called when present
    name = c.image or c.name or report.metadata.target.reference or "container"
    repo, _, _tag = name.partition("@")
    repo_no_tag = re.sub(r":[^/:]+$", "", repo)
    purl = None
    if c.image_digest and repo_no_tag:
        last = repo_no_tag.rsplit("/", 1)[-1].lower()
        try:
            purl = PackageURL(
                "oci", None, last, c.image_digest, {"repository_url": repo_no_tag.lower()}
            )
        except ValueError:
            purl = None
    props = [prop("container:kind", c.kind)]
    for key, val in (
        ("container:engine", c.engine),
        ("container:platform", c.platform),
        ("container:user", c.user),
        ("container:privileged", None if c.privileged is None else str(c.privileged).lower()),
        (
            "container:readonlyRootfs",
            None if c.readonly_rootfs is None else str(c.readonly_rootfs).lower(),
        ),
        ("container:networkMode", c.network_mode),
    ):
        if val:
            props.append(prop(key, val))
    props += [prop("container:exposedPort", p) for p in c.exposed_ports]
    props += [prop("container:capAdd", p) for p in c.cap_add]
    props += [prop("container:redactedEnvKey", k) for k in c.redacted_env_keys]
    return Component(
        type=ComponentType.CONTAINER,
        bom_ref=f"target:{name}",
        name=clean(name),
        version=clean(c.image_digest) if c.image_digest else None,
        purl=purl,
        properties=props,
    )


# --------------------------------------------------------------------------- services
def endpoint(listen: ListenAddress) -> XsUri | None:
    """URI form of a listener: ``tcp://0.0.0.0:22``, ``unix:///run/x.sock``.

    IPv6 literals cannot be expressed (the library percent-encodes ``[``/``]``,
    which breaks ``iri-reference``), so they are only recorded as properties.
    """
    proto = re.sub(r"[^a-z0-9+.-]", "", listen.protocol.lower()) or "unknown"
    if not proto[0].isalpha():
        proto = f"x-{proto}"
    if listen.path:
        uri = f"{proto}://{quote(listen.path, safe='/@')}"
    else:
        host = listen.address or "0.0.0.0"  # noqa: S104 - descriptive, not a bind
        if ":" in host:
            return None
        host = quote(host, safe=".-")
        uri = f"{proto}://{host}" if listen.port is None else f"{proto}://{host}:{listen.port}"
    try:
        return XsUri(uri)
    except InvalidUriException:
        return None


def service_entry(s: Service) -> CdxService:
    """CycloneDX service of one init-system service."""
    h = s.hardening
    props = [
        prop("service:id", s.id),
        prop("service:initSystem", s.init_system.value),
        prop("service:enabled", str(s.enabled).lower()),
        prop("service:user", h.user),
    ]
    props += [prop("service:activation", a.value) for a in s.activation]
    for key, val in (
        ("service:unitPath", s.unit_path),
        ("service:masked", "true" if s.masked else None),
        ("service:exposure", None if h.exposure is None else f"{h.exposure:.1f}"),
        ("service:exposureRating", h.exposure_rating),
        ("service:dynamicUser", "true" if h.dynamic_user else None),
        ("service:noNewPrivileges", "true" if h.no_new_privileges else None),
    ):
        if val:
            props.append(prop(key, val))
    props += [prop("service:executable", e) for e in s.executables]
    props += [
        prop("service:listen", f"{listen_text(x.protocol, x.address, x.port, x.path)} ({x.scope})")
        for x in s.listens
    ]
    if s.boot_path:
        props.append(prop("service:bootPath", " -> ".join(s.boot_path)))
    endpoints = [e for e in (endpoint(x) for x in s.listens) if e is not None]
    return CdxService(
        name=clean(s.name) or s.id,
        bom_ref=service_ref(s),
        group=s.init_system.value,
        description=clean(s.description) if s.description else None,
        endpoints=endpoints or None,
        x_trust_boundary=True if s.network_exposed else None,
        data=(
            [DataClassification(flow=DataFlow.BI_DIRECTIONAL, classification="network")]
            if s.listens
            else None
        ),
        properties=props,
    )


# --------------------------------------------------------------------------- vulnerabilities
def vuln_source(v: Vulnerability) -> VulnerabilitySource:
    """Primary database the vulnerability came from."""
    sources = {s.lower() for s in v.sources}
    if "osv" in sources or not sources:
        return VulnerabilitySource(
            name="OSV", url=XsUri(f"https://osv.dev/vulnerability/{quote(v.id, safe='')}")
        )
    if "arch" in sources:
        return VulnerabilitySource(
            name="Arch Linux Security Tracker",
            url=XsUri(f"https://security.archlinux.org/{quote(v.id, safe='')}"),
        )
    if v.id.upper().startswith("CVE-"):
        return _nvd(v.id)
    return VulnerabilitySource(name=clean(sorted(sources)[0]))


def _nvd(cve: str) -> VulnerabilitySource:
    return VulnerabilitySource(
        name="NVD", url=XsUri(f"https://nvd.nist.gov/vuln/detail/{quote(cve, safe='')}")
    )


def _reference(alias: str) -> VulnerabilityReference:
    a = alias.upper()
    if a.startswith("CVE-"):
        src = _nvd(alias)
    elif a.startswith("GHSA-"):
        src = VulnerabilitySource(
            name="GitHub",
            url=XsUri(f"https://github.com/advisories/{quote(alias, safe='')}"),
        )
    else:
        src = VulnerabilitySource(
            name="OSV", url=XsUri(f"https://osv.dev/vulnerability/{quote(alias, safe='')}")
        )
    return VulnerabilityReference(id=clean(alias), source=src)


def rating(c: CVSSScore, default_source: VulnerabilitySource) -> VulnerabilityRating:
    """CycloneDX rating of one CVSS score (vector prefix stripped by the library)."""
    score = None
    if c.base_score is not None:
        try:
            score = Decimal(str(c.base_score))
        except InvalidOperation:
            score = None
    sev = c.severity if c.severity is not Severity.UNKNOWN else Severity.from_score(c.base_score)
    src = VulnerabilitySource(name=clean(c.source)) if c.source else default_source
    return VulnerabilityRating(
        source=src,
        score=score,
        severity=_SEVERITY[sev],
        method=_METHOD.get(c.version, VulnerabilityScoreSource.OTHER),
        vector=clean(c.vector) if c.vector else None,
    )


def cwe_ids(cwes: Iterable[str]) -> list[int]:
    """``['CWE-787', 'NVD-CWE-Other']`` → ``[787]``."""
    out = set()
    for c in cwes:
        m = _CWE.search(c.strip())
        if m:
            out.add(int(m.group(1)))
    return sorted(out)


def upstream_analysis(v: Vulnerability) -> VulnerabilityAnalysis | None:
    """Analysis block reflecting a non-``affected`` upstream status, else ``None``."""
    st = v.status
    if st is VulnStatus.AFFECTED:
        return None
    if st is VulnStatus.NOT_AFFECTED:
        return VulnerabilityAnalysis(
            state=ImpactAnalysisState.NOT_AFFECTED,
            detail="The distribution advisory marks the installed version as not affected.",
        )
    if st is VulnStatus.FIXED:
        return VulnerabilityAnalysis(
            state=ImpactAnalysisState.RESOLVED,
            detail="The distribution advisory marks the installed version as fixed.",
        )
    if st is VulnStatus.WILL_NOT_FIX:
        return VulnerabilityAnalysis(
            state=ImpactAnalysisState.IN_TRIAGE,
            responses=[ImpactAnalysisResponse.WILL_NOT_FIX],
            detail="The distribution has decided not to fix this vulnerability.",
        )
    if st is VulnStatus.NO_FIX_AVAILABLE:
        return VulnerabilityAnalysis(
            state=ImpactAnalysisState.IN_TRIAGE,
            responses=[ImpactAnalysisResponse.CAN_NOT_FIX],
            detail="No fixed version is available from the distribution yet.",
        )
    return VulnerabilityAnalysis(
        state=ImpactAnalysisState.IN_TRIAGE,
        detail="The distribution is still investigating this vulnerability.",
    )


def vulnerability_entry(
    v: Vulnerability,
    target_ref: str,
    *,
    reach: Reachability,
    threats: list[Threat],
    analysis: VulnerabilityAnalysis | None,
) -> CdxVulnerability:
    """CycloneDX vulnerability for one vulnerability x package match."""
    src = vuln_source(v)
    refs = {a: _reference(a) for a in [*v.aliases, *v.advisories] if a and a != v.id}
    if v.kev is not None:
        refs["kev"] = VulnerabilityReference(
            id=clean(v.id),
            source=VulnerabilitySource(
                name="CISA KEV",
                url=XsUri("https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
            ),
        )
    props = [prop("reachability", reach.value), prop("matchConfidence", v.match_confidence)]
    props.append(prop("status", v.status.value))
    if v.epss is not None:
        props.append(prop("epss:score", f"{v.epss:.5f}"))
    if v.epss_percentile is not None:
        props.append(prop("epss:percentile", f"{v.epss_percentile:.5f}"))
    if v.kev is not None:
        props.append(prop("kev:listed", "true"))
        if v.kev.date_added:
            props.append(prop("kev:dateAdded", v.kev.date_added))
        if v.kev.due_date:
            props.append(prop("kev:dueDate", v.kev.due_date))
        props.append(prop("kev:knownRansomwareCampaignUse", str(v.kev.ransomware).lower()))
    for t in threats:
        props.append(prop("threat:id", t.id))
        props.append(prop("threat:riskScore", f"{t.risk_score:.1f}"))
        if t.ssvc is not None:
            props.append(prop("threat:ssvcDecision", t.ssvc.decision.value))
    if v.match_reason:
        props.append(prop("matchReason", v.match_reason))
    recommendation = None
    if v.fixed_versions:
        recommendation = clean(
            f"Upgrade {v.package_name} to {' or '.join(v.fixed_versions)} or later."
        )
    unaffected = v.status in (VulnStatus.FIXED, VulnStatus.NOT_AFFECTED)
    return CdxVulnerability(
        bom_ref=vuln_ref(v),
        id=clean(v.id),
        source=src,
        references=list(refs.values()),
        ratings=[rating(c, src) for c in v.cvss if c.vector or c.base_score is not None],
        cwes=cwe_ids(v.cwes),
        description=clean(v.summary) if v.summary else None,
        recommendation=recommendation,
        published=parse_time(v.published),
        updated=parse_time(v.modified),
        affects=[
            BomTarget(
                ref=target_ref,
                versions=[
                    BomTargetVersionRange(
                        version=clean(v.installed_version) or None,
                        status=(
                            ImpactAnalysisAffectedStatus.UNAFFECTED
                            if unaffected
                            else ImpactAnalysisAffectedStatus.AFFECTED
                        ),
                    )
                ],
            )
        ],
        analysis=analysis,
        properties=props,
    )


# --------------------------------------------------------------------------- dependencies
def dependency_index(report: Report, refs: dict[str, str]) -> dict[str, list[str]]:
    """Map package / provided names → package ids (sorted, for resolution)."""
    idx: dict[str, set[str]] = {}
    for p in report.packages:
        idx.setdefault(p.name, set()).add(p.id)
        for prov in p.provides:
            m = _DEP_NAME.match(prov)
            if m:
                idx.setdefault(m.group(1), set()).add(p.id)
    return {k: sorted(i for i in v if i in refs) for k, v in idx.items()}


def resolve_depends(
    pkg: Package, index: dict[str, list[str]], by_id: dict[str, Package]
) -> set[str]:
    """Resolve ``Depends:``-style entries of ``pkg`` to package ids (same arch preferred)."""
    out: set[str] = set()
    for entry in pkg.depends:
        for alt in entry.replace(",", "|").split("|"):
            m = _DEP_NAME.match(alt)
            if not m:
                continue
            name = m.group(1).split(":", 1)[0]
            cands = [c for c in index.get(name, []) if c != pkg.id]
            if not cands:
                continue
            same = [c for c in cands if by_id[c].arch in (pkg.arch, "all", "noarch", None)]
            out.update(same or cands)
            break  # first satisfiable alternative wins
    return out


# --------------------------------------------------------------------------- BOM
class DependencyGraph:
    """Collects ``dependencies`` edges in linear time.

    ``Bom.register_dependency`` scans every existing entry per call (quadratic for
    thousands of packages, and ``Bom.validate`` calls it once per component), so
    edges are gathered here and installed in one step, and the instance's
    ``register_dependency`` is given an O(1) fast path for refs already present.
    """

    def __init__(self) -> None:
        self._edges: dict[str, tuple[BomRef, set[str]]] = {}

    def add(
        self, target: Component | CdxService, depends_on: Iterable[Component | CdxService] = ()
    ) -> None:
        """Record ``target → depends_on`` (every node gets an entry)."""
        entry = self._edges.setdefault(str(target.bom_ref), (target.bom_ref, set()))
        for dep in depends_on:
            self._edges.setdefault(str(dep.bom_ref), (dep.bom_ref, set()))
            entry[1].add(str(dep.bom_ref))

    def install(self, bom: Bom) -> None:
        """Replace ``bom.dependencies`` with the collected graph."""
        bom.dependencies = [
            Dependency(
                ref=ref, dependencies=[Dependency(ref=self._edges[c][0]) for c in sorted(kids)]
            )
            for _key, (ref, kids) in sorted(self._edges.items())
        ]
        known = {str(d.ref) for d in bom.dependencies}
        original = bom.register_dependency

        def register(target: Dependable, depends_on: Iterable[Dependable] | None = None) -> None:
            extra = list(depends_on or ())
            if not extra and str(target.bom_ref) in known:
                return
            original(target, extra or None)
            known.update(str(d.ref) for d in bom.dependencies)

        bom.register_dependency = register  # type: ignore[method-assign]


def build_bom(report: Report, options: RenderOptions) -> Bom:
    """Build the CycloneDX SBOM object model for ``report``."""
    md = report.metadata
    tool = Component(
        type=ComponentType.APPLICATION,
        name="startup-sbom",
        group="morpheuslord",
        version=md.tool_version,
        bom_ref="tool:startup-sbom",
        external_references=[
            ExternalReference(type=ExternalReferenceType.VCS, url=XsUri(PROJECT_URL))
        ],
    )
    osc = os_component(report)
    root = container_component(report) if report.container is not None else osc
    root.properties.update(
        [
            prop("target:kind", md.target.kind),
            prop("target:reference", md.target.reference),
        ]
    )
    if md.target.digest:
        root.properties.add(prop("target:digest", md.target.digest))
    if md.target.platform:
        root.properties.add(prop("target:platform", md.target.platform))
    meta_props = [
        prop("schemaVersion", md.schema_version),
        prop("scanId", md.scan_id),
    ]
    meta_props += [prop("coverage:limitation", x) for x in md.coverage.limitations]
    meta_props += [
        prop("coverage:vulnerabilitySource", x) for x in md.coverage.vulnerability_sources
    ]
    bom = Bom(
        serial_number=scan_uuid(report),
        version=1,
        metadata=BomMetaData(
            timestamp=timestamp(report),
            tools=ToolRepository(components=[tool]),
            component=root,
            properties=meta_props,
        ),
    )
    graph = DependencyGraph()
    graph.add(osc)
    if root is not osc:
        bom.components.add(osc)
        graph.add(root, [osc])

    instances = package_instances(report)
    refs = package_refs(report)
    reach = package_reachability(report)
    by_id = {pkg.id: pkg for pkg, _ in reversed(instances)}  # first instance wins
    comps: dict[str, Component] = {}
    for pkg, ref in instances:
        c = package_component(report, pkg, ref, reach.get(pkg.id, Reachability.INSTALLED), options)
        comps[ref] = c
        bom.components.add(c)
    if comps:
        graph.add(osc, [comps[r] for r in sorted(comps)])
    index = dependency_index(report, refs)
    for pkg, ref in instances:
        deps = resolve_depends(pkg, index, by_id)
        graph.add(comps[ref], [comps[refs[d]] for d in sorted(deps)])

    linked: dict[str, set[str]] = {}
    for b in report.binaries:
        pkgs = {b.package} if b.package else set()
        pkgs |= {lib.package for lib in b.libraries if lib.package}
        for user in b.used_by:
            linked.setdefault(user, set()).update(p for p in pkgs if p)
    for s in report.services:
        svc = service_entry(s)
        bom.services.add(svc)
        dep_ids = set(s.packages) | linked.get(s.id, set())
        targets = [comps[refs[d]] for d in sorted(dep_ids) if refs.get(d) in comps]
        graph.add(svc, targets)

    threats = threats_by_vuln(report)
    for v in report.vulnerabilities:
        target = refs.get(v.package)
        if target is None:  # vulnerability on an unknown package: keep it, reference the OS
            target = osc.bom_ref.value or os_ref(report)
        bom.vulnerabilities.add(
            vulnerability_entry(
                v,
                target,
                reach=vuln_reachability(report, v, threats=threats, pkg_reach=reach),
                threats=threats.get((v.id, v.package), []),
                analysis=upstream_analysis(v),
            )
        )
    graph.install(bom)

    bom.external_references.add(
        ExternalReference(
            type=ExternalReferenceType.THREAT_MODEL,
            url=XsUri(REPORT_FILENAME),
            comment="Startup-SBOM native report: threats, attack chains, supply-chain analysis",
        )
    )
    bom.external_references.add(
        ExternalReference(
            type=ExternalReferenceType.EXPLOITABILITY_STATEMENT,
            url=XsUri(VEX_FILENAME),
            comment="CycloneDX VEX with reachability-based analysis",
        )
    )
    return bom


def serialize(bom: Bom, spec: str) -> str:
    """Serialise ``bom`` as JSON for CycloneDX ``spec``."""
    out = make_outputter(bom, OutputFormat.JSON, SPEC[spec]).output_as_string(indent=2)
    return out if out.endswith("\n") else out + "\n"


def render_cyclonedx(report: Report, options: RenderOptions) -> str:
    """Render the CycloneDX SBOM (spec ``options.cdx_spec``)."""
    return serialize(build_bom(report, options), options.cdx_spec)


def sbom_serial(report: Report) -> uuid.UUID:
    """Serial number of the SBOM (deterministic from the scan id)."""
    return scan_uuid(report)
