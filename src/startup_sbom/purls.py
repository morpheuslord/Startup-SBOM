"""Package URL (purl) construction for OS and language packages.

Follows purl-spec / ECMA-427 type definitions plus the de-facto conventions of
Syft, Grype and Trivy for OS packages:

* ``deb`` and ``alpm`` keep the epoch *inside* the version (``1:2.4.47-2``).
* ``rpm`` puts the epoch in the ``epoch`` qualifier and the purl version is
  ``version-release`` only; ``upstream`` is the source RPM file name.
* ``distro=<ID>-<VERSION_ID>`` (Syft form; ``<ID>`` alone for rolling distros).
* ``upstream=<source>[@<source version>]`` when the source package differs.

Qualifiers are sorted and percent-encoded by ``packageurl-python``.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from packageurl import PackageURL

from startup_sbom.models import OSInfo, PackageType

_OS_TYPES = frozenset({PackageType.DEB, PackageType.RPM, PackageType.APK, PackageType.ALPM})
_EPOCH_RE = re.compile(r"^(\d+):(.*)$")
_UNKNOWN_IDS = frozenset({"", "unknown", "linux"})
_SLASH = "\ue000"
_SLASH_ENC = quote(_SLASH)

#: os-release ``ID`` → rpm purl namespace (Syft convention, ``rhel`` → ``redhat``).
RPM_NAMESPACES: dict[str, str] = {
    "rhel": "redhat",
    "redhat": "redhat",
    "centos": "centos",
    "rocky": "rocky",
    "almalinux": "almalinux",
    "fedora": "fedora",
    "amzn": "amzn",
    "ol": "ol",
    "opensuse": "opensuse",
    "opensuse-leap": "opensuse",
    "opensuse-tumbleweed": "opensuse",
    "opensuse-leap-micro": "opensuse",
    "opensuse-slowroll": "opensuse",
    "sles": "sles",
    "sles_sap": "sles",
    "sle-micro": "sles",
    "sl-micro": "sles",
    "mariner": "mariner",
    "azurelinux": "azurelinux",
    "photon": "photon",
    "openeuler": "openeuler",
    "mageia": "mageia",
    "scientific": "scientific",
    "amazon": "amzn",
}
_APK_NAMESPACES = frozenset({"alpine", "wolfi", "chainguard", "postmarketos", "openwrt"})
_ALPM_NAMESPACES = frozenset({"arch", "arch32", "archarm", "manjaro", "msys"})


def split_epoch(version: str) -> tuple[int | None, str]:
    """Split ``"1:2.3-4"`` into ``(1, "2.3-4")``; no epoch gives ``(None, version)``."""
    m = _EPOCH_RE.match(version)
    if not m:
        return None, version
    try:
        return int(m.group(1)), m.group(2)
    except ValueError:  # pragma: no cover - regex guarantees digits
        return None, version


def distro_qualifier(os_info: OSInfo | None) -> str | None:
    """``<ID>-<VERSION_ID>`` (or ``<ID>`` for rolling releases); ``None`` if unknown."""
    if os_info is None or os_info.id in _UNKNOWN_IDS:
        return None
    if os_info.version_id:
        return f"{os_info.id}-{os_info.version_id}"
    return os_info.id


def purl_namespace(ptype: PackageType, os_info: OSInfo | None) -> str | None:
    """Return the vendor namespace for an OS package type, derived from ``os_info``."""
    os_id = os_info.id if os_info is not None else ""
    like = list(os_info.id_like) if os_info is not None else []
    if ptype is PackageType.DEB:
        for cand in (os_id, *like):
            if cand in ("debian", "ubuntu"):
                return cand
        return "debian"
    if ptype is PackageType.RPM:
        for cand in (os_id, *like):
            if cand in RPM_NAMESPACES:
                return RPM_NAMESPACES[cand]
        return None if os_id in _UNKNOWN_IDS else os_id
    if ptype is PackageType.APK:
        for cand in (os_id, *like):
            if cand in _APK_NAMESPACES:
                return cand
        return "alpine"
    if ptype is PackageType.ALPM:
        for cand in (os_id, *like):
            if cand in _ALPM_NAMESPACES:
                return cand
        return "arch"
    return None


def _rpm_upstream(source_name: str, source_version: str | None) -> str:
    if not source_version:
        return source_name
    _epoch, vr = split_epoch(source_version)
    return f"{source_name}-{vr}.src.rpm"


def package_purl(
    ptype: PackageType,
    name: str,
    version: str,
    *,
    os_info: OSInfo | None = None,
    arch: str | None = None,
    epoch: int | None = None,
    source_name: str | None = None,
    source_version: str | None = None,
    namespace: str | None = None,
) -> str:
    """Build a canonical purl string for a package.

    ``version`` is the full distro version; for rpm a leading ``epoch:`` is
    moved to the ``epoch`` qualifier.  OS package types get ``arch``,
    ``distro`` and ``upstream`` qualifiers; other types only name/version.
    """
    ptype = PackageType(ptype)
    qualifiers: dict[str, str] = {}
    pversion: str | None = version or None
    if ptype in _OS_TYPES:
        if namespace is None:
            namespace = purl_namespace(ptype, os_info)
        if arch:
            qualifiers["arch"] = arch
        distro = distro_qualifier(os_info)
        if distro:
            qualifiers["distro"] = distro
        v_epoch, bare = split_epoch(version)
        eff_epoch = epoch if epoch is not None else v_epoch
        if ptype is PackageType.RPM:
            pversion = bare or None
            if eff_epoch:
                qualifiers["epoch"] = str(eff_epoch)
            if source_name:
                qualifiers["upstream"] = _rpm_upstream(source_name, source_version)
        else:
            if eff_epoch and v_epoch is None and version:
                pversion = f"{eff_epoch}:{version}"
            src_differs = bool(source_version) and source_version != version
            if source_name and (source_name != name or src_differs):
                if ptype is PackageType.DEB and src_differs:
                    qualifiers["upstream"] = f"{source_name}@{source_version}"
                else:
                    qualifiers["upstream"] = source_name
    elif namespace is None:
        if ptype is PackageType.MAVEN and ":" in name:
            namespace, name = name.split(":", 1)
        elif ptype in (PackageType.GOLANG, PackageType.NPM) and "/" in name:
            namespace, name = name.rsplit("/", 1)
    # packageurl-python leaves "/" in names unencoded, which would turn part of a
    # (hostile) name into namespace; route it through a private-use placeholder.
    slash = "/" in name
    out = PackageURL(
        type=ptype.value,
        namespace=namespace or None,
        name=name.replace("/", _SLASH) if slash else name,
        version=pversion,
        qualifiers=qualifiers or None,
    ).to_string()
    return out.replace(_SLASH_ENC, "%2F") if slash else out


def with_qualifiers(purl: str, **qualifiers: str) -> str:
    """Return ``purl`` with ``qualifiers`` added or replaced (canonical form)."""
    parsed = PackageURL.from_string(purl)
    current = parsed.qualifiers
    merged: dict[str, str] = dict(current) if isinstance(current, dict) else {}
    merged.update(qualifiers)
    return PackageURL(
        type=parsed.type,
        namespace=parsed.namespace,
        name=parsed.name,
        version=parsed.version,
        qualifiers=merged or None,
        subpath=parsed.subpath,
    ).to_string()
