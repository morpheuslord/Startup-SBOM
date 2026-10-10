"""Arch Linux security tracker (security.archlinux.org) matching for ``alpm`` packages.

Arch is not in OSV.  The tracker's ``/issues/all.json`` lists AVG groups keyed by
*binary* pkgname with an ``affected`` and an optional ``fixed`` version; a package
is vulnerable iff ``affected <= installed < fixed`` under pacman's ``vercmp``.
The tracker has been effectively unmaintained since mid-2025, so every Arch scan
records that as a coverage limitation and results carry medium confidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from startup_sbom.context import ScanContext
from startup_sbom.errors import NetworkError
from startup_sbom.models import (
    Confidence,
    Package,
    PackageType,
    Severity,
    Vulnerability,
    VulnStatus,
)
from startup_sbom.net import HttpClient
from startup_sbom.vulns.base import VulnerabilitySource
from startup_sbom.vulns.normalize import Fragment, merge_vulnerabilities
from startup_sbom.vulns.osv import full_version
from startup_sbom.vulns.versions import compare

ARCH_URL = "https://security.archlinux.org/issues/all.json"
ARCH_TTL = 24 * 3600.0
STALE_NOTE = (
    "arch: security.archlinux.org is best-effort and has received few updates since"
    " mid-2025; recent Arch vulnerabilities may be missing"
)


def load_arch_groups(http: HttpClient, *, force: bool = False) -> list[dict[str, Any]]:
    """Fetch (or read from cache) the tracker's AVG groups."""
    resp = http.get(ARCH_URL, ttl=0.0 if force else ARCH_TTL)
    try:
        data = resp.json()
    except ValueError as exc:
        raise NetworkError("arch: malformed tracker response") from exc
    if not isinstance(data, list):
        raise NetworkError("arch: unexpected tracker response")
    return [g for g in data if isinstance(g, dict) and isinstance(g.get("name"), str)]


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def evaluate_group(group: Mapping[str, Any], installed: str) -> VulnStatus | None:
    """Status of ``installed`` against one AVG group, ``None`` when it does not apply."""
    status = str(group.get("status", ""))
    affected, fixed = _str(group.get("affected")), _str(group.get("fixed"))
    if affected and compare(PackageType.ALPM, installed, affected) < 0:
        return None
    if fixed and compare(PackageType.ALPM, installed, fixed) >= 0:
        return None
    if status == "Not affected":
        return VulnStatus.NOT_AFFECTED
    if status == "Unknown" and not fixed:
        return VulnStatus.UNDER_INVESTIGATION
    if status in ("Vulnerable", "Fixed", "Unknown"):
        return VulnStatus.AFFECTED if fixed else VulnStatus.NO_FIX_AVAILABLE
    return None


class ArchTrackerSource(VulnerabilitySource):
    """Matches pacman packages against the Arch Linux security tracker."""

    name = "arch"

    def __init__(self, http: HttpClient) -> None:
        self.http = http

    def applicable(self, ctx: ScanContext, packages: list[Package]) -> list[Package]:
        return [p for p in packages if p.type == PackageType.ALPM]

    def match(self, ctx: ScanContext, packages: list[Package]) -> list[Vulnerability]:
        pkgs = self.applicable(ctx, packages)
        if not pkgs:
            return []
        ctx.limit(STALE_NOTE)
        groups = load_arch_groups(self.http)
        index: dict[str, list[dict[str, Any]]] = {}
        for group in groups:
            for name in group.get("packages") or []:
                if isinstance(name, str):
                    index.setdefault(name, []).append(group)
        fragments: list[Fragment] = []
        for pkg in pkgs:
            installed = full_version(pkg)
            seen: set[str] = set()
            for name in dict.fromkeys(n for n in (pkg.name, pkg.source_name) if n):
                for group in index.get(name, []):
                    if group["name"] in seen:
                        continue
                    seen.add(group["name"])
                    status = evaluate_group(group, installed)
                    if status is not None:
                        fragments.extend(_fragments(pkg, name, installed, group, status))
        return merge_vulnerabilities(fragments, {p.id: p.type for p in pkgs})


def _fragments(
    pkg: Package, name: str, installed: str, group: Mapping[str, Any], status: VulnStatus
) -> list[Fragment]:
    avg = str(group["name"])
    issues = sorted({i for i in group.get("issues") or [] if isinstance(i, str) and i})
    ids = issues or [avg]
    advisories = sorted({avg} | {a for a in group.get("advisories") or [] if isinstance(a, str)})
    fixed = _str(group.get("fixed"))
    kind = _str(group.get("type"))
    summary = f"{kind} in {name}" if kind and kind != "unknown" else None
    refs = [f"https://security.archlinux.org/{avg}"]
    refs += [f"https://security.archlinux.org/{a}" for a in advisories if a.startswith("ASA-")]
    reason = (
        f"arch:{avg} package={name} affected={_str(group.get('affected')) or '?'}"
        f" fixed={fixed or 'none'} version={installed}"
    )
    return [
        Fragment(
            Vulnerability(
                id=vid,
                advisories=[a for a in advisories if a != vid],
                sources=["arch"],
                package=pkg.id,
                package_name=pkg.name,
                installed_version=pkg.version,
                fixed_versions=[fixed] if fixed and status is VulnStatus.AFFECTED else [],
                status=status,
                summary=summary,
                severity=Severity.parse(_str(group.get("severity"))),
                references=refs,
                match_confidence=Confidence.MEDIUM,
                match_reason=reason,
            ),
            2 if len(ids) == 1 else 1,
        )
        for vid in ids
    ]
