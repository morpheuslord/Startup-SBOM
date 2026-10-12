"""Vendor attribution and per-vendor summaries.

The vendor of a package is derived from the most authoritative field its
package manager records — rpm ``VENDOR``, deb ``Maintainer``, apk ``m:``, pacman
``%PACKAGER%`` — normalised so that distribution teams group together: e-mail
addresses are stripped, ``Debian * Maintainers`` / ``@debian.org`` become
``Debian``, ``Unknown Packager`` becomes ``local build``, and individual distro
maintainers of packages from an official repository are attributed to the
distribution itself.
"""

from __future__ import annotations

import re
from collections import defaultdict

from startup_sbom.models import Package, PackageType, Report, Severity, VendorSummary, VulnStatus
from startup_sbom.supplychain.graph import RunningSet, is_language_package
from startup_sbom.supplychain.repos import THIRD_PARTY, DistroTrust, email_domain, host_matches

LOCAL_BUILD_VENDOR = "local build"
UNKNOWN_VENDOR = "unknown"

#: e-mail domain suffix → organisation.
_DOMAIN_ORGS: tuple[tuple[str, str], ...] = (
    ("debian.org", "Debian"),
    ("ubuntu.com", "Ubuntu"),
    ("canonical.com", "Ubuntu"),
    ("alpinelinux.org", "Alpine Linux"),
    ("archlinux.org", "Arch Linux"),
    ("fedoraproject.org", "Fedora Project"),
    ("redhat.com", "Red Hat"),
    ("centos.org", "CentOS"),
    ("rockylinux.org", "Rocky Linux"),
    ("almalinux.org", "AlmaLinux"),
    ("oracle.com", "Oracle"),
    ("amazon.com", "Amazon Linux"),
    ("suse.com", "SUSE"),
    ("suse.de", "SUSE"),
    ("opensuse.org", "openSUSE"),
    ("kali.org", "Kali"),
    ("wolfi.dev", "Wolfi"),
    ("chainguard.dev", "Chainguard"),
)
#: leading words of team names → organisation.
_NAME_ORGS = re.compile(
    r"^(?P<org>Debian|Ubuntu|Alpine|Arch Linux|Fedora|Red Hat|CentOS|openSUSE|SUSE|Kali)\b",
    re.IGNORECASE,
)
_CANONICAL_NAMES = {
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "alpine": "Alpine Linux",
    "arch linux": "Arch Linux",
    "fedora": "Fedora Project",
    "red hat": "Red Hat",
    "centos": "CentOS",
    "opensuse": "openSUSE",
    "suse": "SUSE",
    "kali": "Kali",
}


def person_name(raw: str | None) -> str | None:
    """``"Jane Doe <jane@example.org>"`` → ``"Jane Doe"`` (e-mail only → the address)."""
    if not raw:
        return None
    text = re.sub(r"\s+", " ", raw).strip()
    name = re.sub(r"\s*<[^>]*>\s*", " ", text).strip().strip('"').strip()
    if not name:
        m = re.search(r"<([^>]+)>", text)
        name = m.group(1) if m else text
    return name[:120] or None


def _org_from_text(raw: str) -> str | None:
    dom = email_domain(raw)
    if dom:
        for suffix, org in _DOMAIN_ORGS:
            if host_matches(dom, (suffix,)):
                return org
    m = _NAME_ORGS.match(person_name(raw) or "")
    if m:
        return _CANONICAL_NAMES.get(m.group("org").lower(), m.group("org"))
    return None


def maintainer_of(pkg: Package) -> str | None:
    """The raw responsible party recorded for ``pkg`` (team or person)."""
    if pkg.type is PackageType.RPM:
        return pkg.packager or pkg.vendor or pkg.maintainer
    if pkg.type is PackageType.ALPM:
        return pkg.packager or pkg.maintainer
    return pkg.maintainer or pkg.packager or pkg.vendor


def vendor_of(pkg: Package, trust: DistroTrust | None = None) -> str:
    """Normalised vendor name of ``pkg``.

    Order: ``Unknown Packager`` → ``local build``; rpm ``VENDOR`` verbatim;
    organisation recognised from the e-mail domain
    or team name; the distribution itself for distro-repo packages maintained by
    individuals; otherwise the maintainer's name (or organisation-looking domain).
    """
    raw_packager = (pkg.packager or "").strip()
    if raw_packager.lower() == "unknown packager":
        return LOCAL_BUILD_VENDOR
    if pkg.type is PackageType.RPM and pkg.vendor and pkg.vendor.strip():
        v = re.sub(r"\s*<[^>]*>\s*", " ", pkg.vendor).strip()
        return v[:120] or UNKNOWN_VENDOR
    raw = maintainer_of(pkg)
    if raw:
        org = _org_from_text(raw)
        if org:
            return org
    third_party = THIRD_PARTY in pkg.provenance_flags
    if trust is not None and not third_party and not is_language_package(pkg):
        return trust.name
    if raw:
        return person_name(raw) or email_domain(raw) or UNKNOWN_VENDOR
    if is_language_package(pkg):
        return f"{pkg.type.value} (unattributed)"
    return UNKNOWN_VENDOR


def vendor_map(packages: list[Package], trust: DistroTrust | None) -> dict[str, str]:
    """``package id → vendor`` for every package."""
    return {p.id: vendor_of(p, trust) for p in packages}


_OPEN = frozenset(
    {
        VulnStatus.AFFECTED,
        VulnStatus.UNDER_INVESTIGATION,
        VulnStatus.NO_FIX_AVAILABLE,
        VulnStatus.WILL_NOT_FIX,
    }
)


def open_vulnerabilities(report: Report) -> list[tuple[str, str, Severity, bool]]:
    """``(package id, vuln id, severity, kev)`` of every unresolved vulnerability."""
    return [
        (v.package, v.id, v.severity, v.kev is not None)
        for v in report.vulnerabilities
        if v.status in _OPEN
    ]


def summarize_vendors(
    report: Report, running: RunningSet, vendors: dict[str, str]
) -> list[VendorSummary]:
    """One :class:`VendorSummary` per vendor, sorted by exposure then name."""
    boot = running.boot_packages
    pkgs_by_vendor: dict[str, set[str]] = defaultdict(set)
    for p in report.packages:
        pkgs_by_vendor[vendors.get(p.id, UNKNOWN_VENDOR)].add(p.id)
    vulns: dict[str, dict[str, tuple[Severity, bool]]] = defaultdict(dict)
    for pid, vid, sev, kev in open_vulnerabilities(report):
        prev = vulns[pid].get(vid)
        if prev is None or sev.rank > prev[0].rank or (kev and not prev[1]):
            vulns[pid][vid] = (sev, kev or (prev[1] if prev else False))
    out: list[VendorSummary] = []
    for vendor, pids in pkgs_by_vendor.items():
        services: set[str] = set()
        for pid in pids:
            services |= running.package_services.get(pid, set())
        per_vuln: dict[str, tuple[Severity, bool]] = {}
        for pid in pids:
            for vid, (sev, kev) in vulns.get(pid, {}).items():
                key = f"{pid}|{vid}"
                per_vuln[key] = (sev, kev)
        out.append(
            VendorSummary(
                vendor=vendor,
                packages=len(pids),
                boot_packages=len(pids & boot),
                services=len(services),
                vulnerabilities=len(per_vuln),
                critical=sum(1 for s, _ in per_vuln.values() if s is Severity.CRITICAL),
                high=sum(1 for s, _ in per_vuln.values() if s is Severity.HIGH),
                kev=sum(1 for _, k in per_vuln.values() if k),
            )
        )
    out.sort(key=lambda v: (-v.boot_packages, -v.critical, -v.high, -v.packages, v.vendor))
    return out
