"""Provenance findings: turn repository, integrity and inventory signals into findings.

Findings concerning packages that matter at boot (they own an executable of an
automatic service or a library such a service loads) are reported one per
package; the same signal on other packages is aggregated into a single
``system`` finding per kind so the list stays bounded on large systems.

Finding kinds: ``third_party_repo``, ``insecure_repository``, ``third_party_key``,
``unsigned_package``, ``local_build``, ``not_in_repository``,
``repo_version_mismatch``, ``repo_checksum_mismatch``, ``unknown_signing_key``,
``modified_file``, ``unmanaged_binary``, ``suspicious_version``, ``eol_distro``,
``embedded_language_packages`` and ``vendor_concentration``.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from startup_sbom.models import Package, Report, Severity, SupplyChainFinding
from startup_sbom.rootfs import RootFS
from startup_sbom.supplychain.graph import RunningSet, is_language_package
from startup_sbom.supplychain.integrity import IntegrityResult
from startup_sbom.supplychain.repos import (
    CHECKSUM_MISMATCH,
    LOCAL_BUILD,
    NOT_IN_REPO,
    THIRD_PARTY,
    UNKNOWN_KEY,
    UNSIGNED,
    VERSION_MISMATCH,
    RepoAnalysis,
)
from startup_sbom.supplychain.vendors import maintainer_of, person_name

MODIFIED = "modified_file"
SUSPICIOUS = "suspicious_version"
MAX_EVIDENCE = 25
MAX_INDIVIDUAL_UNMANAGED = 200
_TMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")  # noqa: S108 - path prefixes


def finding_id(kind: str, subject: str) -> str:
    """Stable, content-derived finding id."""
    digest = hashlib.sha256(f"{kind}\0{subject}".encode()).hexdigest()[:12]
    return f"SC-{digest.upper()}"


def _finding(
    kind: str,
    severity: Severity,
    subject: str,
    title: str,
    detail: str | None = None,
    evidence: Iterable[str] = (),
) -> SupplyChainFinding:
    ev = list(dict.fromkeys(evidence))
    if len(ev) > MAX_EVIDENCE:
        ev = [*ev[:MAX_EVIDENCE], f"... and {len(ev) - MAX_EVIDENCE} more"]
    return SupplyChainFinding(
        id=finding_id(kind, subject),
        kind=kind,
        severity=severity,
        subject=subject,
        title=title,
        detail=detail,
        evidence=ev,
    )


# --------------------------------------------------------------------------- compromised releases
@dataclass(frozen=True, slots=True)
class CompromisedRelease:
    """An upstream release known to contain malicious code."""

    names: tuple[str, ...]  # binary or source package names
    versions: tuple[str, ...]  # upstream versions
    advisories: tuple[str, ...]
    summary: str
    sources: tuple[str, ...]


#: Tiny curated table of supply-chain-compromised upstream releases.
KNOWN_COMPROMISED: tuple[CompromisedRelease, ...] = (
    CompromisedRelease(
        names=(
            "xz",
            "xz-utils",
            "xz-libs",
            "xz-devel",
            "xz-static",
            "xz-lzma-compat",
            "liblzma",
            "liblzma5",
            "liblzma-dev",
            "liblzma-devel",
            "lib32-xz",
        ),
        versions=("5.6.0", "5.6.1"),
        advisories=("CVE-2024-3094",),
        summary="xz/liblzma release tarballs carrying the sshd backdoor",
        sources=(
            "https://www.openwall.com/lists/oss-security/2024/03/29/4",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
        ),
    ),
)


def upstream_version(version: str) -> str:
    """Upstream part of a distro version.

    Strips the epoch and the distro revision (``-1``, ``-r0``, ``-1.fc40``); a
    ``+really`` marker means the package really contains the version after it
    (``5.6.1+really5.4.5-1`` → ``5.4.5``).
    """
    v = version.strip()
    if ":" in v and v.split(":", 1)[0].isdigit():
        v = v.split(":", 1)[1]
    if "+really" in v:
        v = v.split("+really", 1)[1]
    return v.split("-", 1)[0]


def compromised_release(pkg: Package) -> CompromisedRelease | None:
    """The :class:`CompromisedRelease` entry matching ``pkg``, if any."""
    names = {pkg.name.lower(), (pkg.source_name or "").lower()}
    versions = [pkg.version]
    if pkg.source_version:
        versions.append(pkg.source_version)
    for entry in KNOWN_COMPROMISED:
        if not names & set(entry.names):
            continue
        for ver in versions:
            up = upstream_version(ver)
            for bad in entry.versions:
                if up == bad or re.match(re.escape(bad) + r"(?:[~+_]|\.(?!\d))", up):
                    return entry
    return None


# --------------------------------------------------------------------------- builder
_PKG_FLAG_KINDS: tuple[tuple[str, str, Severity, Severity, str], ...] = (
    # flag, finding kind, boot severity, aggregated severity, title
    (UNSIGNED, "unsigned_package", Severity.HIGH, Severity.MEDIUM, "Unsigned package"),
    (LOCAL_BUILD, "local_build", Severity.HIGH, Severity.MEDIUM, "Locally built package"),
    (
        NOT_IN_REPO,
        "not_in_repository",
        Severity.MEDIUM,
        Severity.LOW,
        "Package not available from any configured repository",
    ),
    (
        UNKNOWN_KEY,
        "unknown_signing_key",
        Severity.MEDIUM,
        Severity.LOW,
        "Package signed by a key that is not trusted on this system",
    ),
)


def build_findings(
    report: Report,
    repos: RepoAnalysis,
    running: RunningSet,
    *,
    integrity: IntegrityResult | None = None,
    unmanaged_executables: Iterable[str] = (),
    fs: RootFS | None = None,
    ownership_known: bool = True,
) -> list[SupplyChainFinding]:
    """All provenance findings for ``report``, sorted by severity, kind and subject.

    ``ownership_known`` enables flagging running files without an owner as
    unmanaged (disable it when the package databases record no file lists).
    Adds ``modified_file`` / ``suspicious_version`` to the affected packages'
    ``provenance_flags`` in place.
    """
    pkgs = report.package_by_id()
    boot = running.boot_packages
    findings: list[SupplyChainFinding] = []

    def label(pid: str) -> str:
        p = pkgs.get(pid)
        return f"{p.name} {p.version}" if p else pid

    # repositories
    by_origin: dict[str, list[str]] = defaultdict(list)
    for pid, prov in sorted(repos.packages.items()):
        if THIRD_PARTY in prov.flags:
            for origin in sorted(prov.third_party):
                by_origin[origin].append(pid)
    for rid, repo in sorted(repos.repositories.items()):
        if repo.enabled and repo.third_party and rid not in by_origin:
            by_origin[rid] = []
        if repo.enabled and repo.signed is False:
            findings.append(
                _finding(
                    "insecure_repository",
                    Severity.HIGH,
                    f"repo:{rid}",
                    f"Signature verification disabled for repository {rid}",
                    "Packages from this repository are accepted without a valid signature "
                    "(trusted=yes / gpgcheck=0 / SigLevel Never).",
                    [*repo.evidence, *([f"file {repo.source_file}"] if repo.source_file else [])],
                )
            )
    for origin, pids in sorted(by_origin.items()):
        boot_pids = [p for p in pids if p in boot]
        sev = Severity.MEDIUM if boot_pids else Severity.LOW
        origin_repo = repos.repositories.get(origin)
        detail = (
            f"{len(pids)} installed package(s) come from a third-party source"
            + (f", {len(boot_pids)} of them run at boot" if boot_pids else "")
            + "; its publisher is an additional trusted party in the supply chain."
        )
        findings.append(
            _finding(
                "third_party_repo",
                sev,
                f"repo:{origin}" if origin_repo else origin,
                f"Third-party package source: {origin}",
                detail,
                [*(f"boot package {label(p)}" for p in boot_pids)]
                + [label(p) for p in pids if p not in boot_pids]
                + (origin_repo.evidence if origin_repo else []),
            )
        )
    findings.extend(
        _finding(
            "third_party_key",
            Severity.LOW,
            f"key:{key.key_id}",
            f"Third-party signing key trusted: {key.uid or key.key_id}",
            "Packages signed by this key are accepted by the package manager.",
            [f"source {key.source}"]
            + ([f"fingerprint {key.fingerprint}"] if key.fingerprint else []),
        )
        for key in repos.third_party_keys
    )

    # per-package repository flags
    for flag, kind, boot_sev, agg_sev, title in _PKG_FLAG_KINDS:
        flagged = sorted(pid for pid, prov in repos.packages.items() if flag in prov.flags)
        rest: list[str] = []
        for pid in flagged:
            if pid in boot:
                findings.append(
                    _finding(
                        kind,
                        boot_sev,
                        pid,
                        f"{title}: {label(pid)}",
                        "The package provides code that runs at boot.",
                        repos.packages[pid].evidence,
                    )
                )
            else:
                rest.append(pid)
        if rest:
            findings.append(
                _finding(
                    kind,
                    agg_sev,
                    "system",
                    f"{title}: {len(rest)} package(s)",
                    None,
                    [label(p) for p in rest],
                )
            )
    mism = sorted(pid for pid, p in repos.packages.items() if VERSION_MISMATCH in p.flags)
    if mism:
        findings.append(
            _finding(
                "repo_version_mismatch",
                Severity.LOW,
                "system",
                f"{len(mism)} installed package version(s) differ from the configured repositories",
                "Usually superseded versions (pending updates) or packages pinned/installed "
                "from elsewhere; these are not orphans.",
                [f"boot package {label(p)}" for p in mism if p in boot]
                + [label(p) for p in mism if p not in boot],
            )
        )
    checksum = sorted(p for p, prov in repos.packages.items() if CHECKSUM_MISMATCH in prov.flags)
    findings.extend(
        _finding(
            "repo_checksum_mismatch",
            Severity.HIGH,
            pid,
            f"Installed package differs from the repository build: {label(pid)}",
            "Same name and version are published with a different identity checksum.",
            repos.packages[pid].evidence,
        )
        for pid in checksum
    )

    # integrity
    if integrity is not None:
        per_pkg: dict[str, list[str]] = defaultdict(list)
        code_pkgs: set[str] = set()
        for m in integrity.modified:
            per_pkg[m.package].append(
                f"{m.path}: {m.algorithm} expected {m.expected} actual {m.actual}"
            )
            if m.code:
                code_pkgs.add(m.package)
        for pid, ev in sorted(per_pkg.items()):
            if pid in pkgs:
                p = pkgs[pid]
                p.provenance_flags = sorted({*p.provenance_flags, MODIFIED})
            findings.append(
                _finding(
                    "modified_file",
                    Severity.HIGH if pid in code_pkgs else Severity.MEDIUM,
                    pid,
                    f"Packaged file(s) modified on disk: {label(pid)}",
                    "File content does not match the digest recorded by the package manager."
                    + (" Executable code was changed." if pid in code_pkgs else ""),
                    ev,
                )
            )

    # unmanaged code
    findings.extend(_unmanaged_findings(running, unmanaged_executables, fs, infer=ownership_known))

    # known-compromised releases
    for p in sorted(report.packages, key=lambda x: x.id):
        entry = compromised_release(p)
        if entry is None:
            continue
        p.provenance_flags = sorted({*p.provenance_flags, SUSPICIOUS})
        findings.append(
            _finding(
                "suspicious_version",
                Severity.CRITICAL,
                p.id,
                f"Known-compromised upstream release: {p.name} {p.version} "
                f"({', '.join(entry.advisories)})",
                entry.summary + ".",
                [*(f"advisory {a}" for a in entry.advisories), *entry.sources],
            )
        )

    # distribution EOL
    eol = report.os.eol
    if eol is not None and eol.is_eol:
        findings.append(
            _finding(
                "eol_distro",
                Severity.HIGH,
                "system",
                f"Distribution release is end-of-life: {eol.product} {eol.cycle}",
                "No further security updates are published for this release.",
                [f"eol date {eol.eol_date}" if eol.eol_date else "eol", f"source {eol.source}"],
            )
        )

    findings.extend(_language_summary(report))
    findings.extend(_vendor_concentration(report, running))
    findings.sort(key=lambda f: (-f.severity.rank, f.kind, f.subject, f.id))
    return findings


def _unmanaged_findings(
    running: RunningSet, paths: Iterable[str], fs: RootFS | None, *, infer: bool
) -> list[SupplyChainFinding]:
    canon = running.canon
    candidates = {canon(p) for p in paths if p}
    if infer:  # running executables/libraries without an owning package
        candidates.update(
            p
            for p in set(running.executables) | set(running.libraries)
            if p not in running.file_owner
        )
    bins = running.binaries
    out: list[SupplyChainFinding] = []
    low: list[str] = []
    for path in sorted(candidates):
        if path in running.file_owner:
            continue
        svcs = sorted(running.services_of_file(path))
        b = bins.get(path)
        st = fs.try_stat(path) if fs is not None else None
        if b is None and st is None and not svcs:
            # reported unmanaged by the caller but unknown to us: still note it
            low.append(path)
            continue
        setuid = bool(b and (b.setuid or b.setgid or b.capabilities)) or bool(
            st and (st.is_setuid or st.is_setgid)
        )
        in_tmp = path.startswith(_TMP_DIRS)
        if svcs:
            sev = Severity.HIGH
            why = "executed or loaded by " + ", ".join(svcs[:5])
        elif setuid:
            sev, why = Severity.HIGH, "setuid/setgid or file capabilities"
        elif in_tmp:
            sev, why = Severity.MEDIUM, "located in a world-writable temporary directory"
        else:
            low.append(path)
            continue
        if len(out) >= MAX_INDIVIDUAL_UNMANAGED:
            low.append(path)
            continue
        kind_word = "library" if path in running.libraries else "executable"
        ev = [why]
        if b is not None and b.embedded_package:
            ev.append(f"ELF package note: {b.embedded_package}")
        out.append(
            _finding(
                "unmanaged_binary",
                sev,
                path,
                f"Unmanaged {kind_word} {posixpath.basename(path)} not owned by any package",
                "Code outside package management receives no updates or vulnerability "
                "matching and cannot be verified.",
                ev,
            )
        )
    if low:
        out.append(
            _finding(
                "unmanaged_binary",
                Severity.LOW,
                "system",
                f"{len(low)} executable(s) not owned by any package",
                None,
                low,
            )
        )
    return out


def _language_summary(report: Report) -> list[SupplyChainFinding]:
    by_type: dict[str, list[Package]] = defaultdict(list)
    for p in report.packages:
        if is_language_package(p):
            by_type[p.type.value].append(p)
    if not by_type:
        return []
    ev = [f"{t}: {len(ps)} package(s)" for t, ps in sorted(by_type.items())]
    locations = sorted({p.location for ps in by_type.values() for p in ps if p.location})
    ev += [f"location {loc}" for loc in locations[:10]]
    total = sum(len(ps) for ps in by_type.values())
    return [
        _finding(
            "embedded_language_packages",
            Severity.NONE,
            "system",
            f"{total} embedded language-ecosystem package(s) outside the OS package manager",
            "These are updated by application rebuilds, not by distribution updates.",
            ev,
        )
    ]


def _vendor_concentration(report: Report, running: RunningSet) -> list[SupplyChainFinding]:
    boot = running.boot_packages
    if len(boot) < 10:
        return []
    by_maint: dict[str, list[str]] = defaultdict(list)
    pkgs = report.package_by_id()
    for pid in sorted(boot):
        p = pkgs.get(pid)
        name = person_name(maintainer_of(p)) if p else None
        if name:
            by_maint[name].append(pid)
    out: list[SupplyChainFinding] = []
    threshold = max(5, int(len(boot) * 0.15))
    ranked = sorted(by_maint.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for name, pids in ranked[:5]:
        if len(pids) < threshold:
            break
        services = set().union(*(running.package_services.get(p, set()) for p in pids))
        out.append(
            _finding(
                "vendor_concentration",
                Severity.NONE,
                f"maintainer:{name}",
                f"{name} maintains {len(pids)} of {len(boot)} boot-critical packages",
                f"A single party controls code used by {len(services)} service(s); a "
                "compromise of this maintainer (cf. xz/CVE-2024-3094) would have a wide "
                "blast radius.",
                [pkgs[p].name for p in pids if p in pkgs],
            )
        )
    return out
