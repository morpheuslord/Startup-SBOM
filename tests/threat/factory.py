"""Builders for hand-crafted :class:`Report` objects used by the threat tests.

They reproduce the research worked examples (regreSSHion, xz, pkexec, DirtyPipe,
docker.sock) as compact, deterministic in-memory reports.
"""

from __future__ import annotations

from datetime import UTC, datetime

from startup_sbom.models import (
    Activation,
    Binary,
    Command,
    ContainerInfo,
    ContainerMount,
    CVSSScore,
    Hardening,
    InitSystem,
    KEVInfo,
    LibraryLink,
    ListenAddress,
    Package,
    PackageType,
    Report,
    ScanMetadata,
    Service,
    Severity,
    SupplyChain,
    TargetInfo,
    Vulnerability,
)

EPOCH = datetime(2026, 10, 10, 0, 0, 0, tzinfo=UTC)


def make_report(
    *,
    packages: list[Package] | None = None,
    services: list[Service] | None = None,
    binaries: list[Binary] | None = None,
    vulnerabilities: list[Vulnerability] | None = None,
    container: ContainerInfo | None = None,
    supply_chain: SupplyChain | None = None,
) -> Report:
    """Assemble a minimal but valid report."""
    return Report(
        metadata=ScanMetadata(
            tool_version="2.0.0",
            scan_id="test-scan",
            started=EPOCH,
            target=TargetInfo(kind="dir", reference="/test"),
        ),
        container=container,
        packages=packages or [],
        services=services or [],
        binaries=binaries or [],
        vulnerabilities=vulnerabilities or [],
        supply_chain=supply_chain or SupplyChain(),
    )


def pkg(name: str, version: str, *, ptype: PackageType = PackageType.DEB) -> Package:
    pid = f"pkg:{ptype.value}/debian/{name}@{version}"
    return Package(id=pid, type=ptype, name=name, version=version, source_name=name)


def binary(
    path: str,
    *,
    package: str | None = None,
    libraries: list[LibraryLink] | None = None,
    setuid: bool = False,
    owner_uid: int | None = None,
    capabilities: list[str] | None = None,
    used_by: list[str] | None = None,
) -> Binary:
    return Binary(
        path=path,
        package=package,
        kind="elf",
        libraries=libraries or [],
        setuid=setuid,
        owner_uid=owner_uid if owner_uid is not None else (0 if setuid else None),
        capabilities=capabilities or [],
        used_by=used_by or [],
    )


def service(
    name: str,
    *,
    executables: list[str],
    packages: list[str] | None = None,
    user: str = "root",
    enabled: bool = True,
    activation: list[Activation] | None = None,
    listens: list[ListenAddress] | None = None,
    hardening: Hardening | None = None,
    init: InitSystem = InitSystem.SYSTEMD,
    masked: bool = False,
) -> Service:
    h = hardening or Hardening(user=user)
    return Service(
        id=f"{init.value}:{name}",
        name=name,
        init_system=init,
        enabled=enabled,
        masked=masked,
        activation=activation or [Activation.BOOT],
        commands=[Command(directive="ExecStart", raw=executables[0], executable=executables[0])],
        executables=executables,
        hardening=h,
        listens=listens or [],
        packages=packages or [],
    )


def tcp(port: int, *, scope: str = "network", source: str = "unit") -> ListenAddress:
    return ListenAddress(protocol="tcp", port=port, scope=scope, source=source)


def cvss(vector: str, score: float, version: str = "3.1") -> CVSSScore:
    return CVSSScore(
        version=version,
        vector=vector,
        base_score=score,
        severity=Severity.from_score(score),
        source="NVD",
    )


def vuln(
    cve: str,
    package: Package,
    *,
    fixed: list[str] | None = None,
    cvss_scores: list[CVSSScore] | None = None,
    cwes: list[str] | None = None,
    epss: float | None = None,
    kev: bool = False,
    summary: str | None = None,
    references: list[str] | None = None,
    aliases: list[str] | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=cve,
        aliases=aliases or [],
        package=package.id,
        package_name=package.name,
        installed_version=package.version,
        fixed_versions=fixed or [],
        summary=summary,
        severity=cvss_scores[0].severity if cvss_scores else Severity.UNKNOWN,
        cvss=cvss_scores or [],
        cwes=cwes or [],
        epss=epss,
        kev=KEVInfo(date_added="2024-01-01") if kev else None,
        references=references or [],
    )


def lib(
    soname: str, path: str, package: str, *, via: str = "needed", depth: int = 1
) -> LibraryLink:
    from startup_sbom.models import Confidence

    return LibraryLink(
        soname=soname,
        path=path,
        package=package,
        via=via,
        depth=depth,
        confidence=Confidence.HIGH if via == "needed" else Confidence.MEDIUM,
    )


def docker_mount() -> ContainerMount:
    return ContainerMount(source="/var/run/docker.sock", destination="/var/run/docker.sock")
