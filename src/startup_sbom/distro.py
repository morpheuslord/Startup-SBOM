"""Identify the *target's* operating system and map it to OSV ecosystems.

The analysed image's ``/etc/os-release`` (falling back to ``/usr/lib/os-release``)
is read through :class:`~startup_sbom.rootfs.RootFS`, so symlinks such as
``/etc/os-release -> ../usr/lib/os-release`` resolve inside the image.  When no
os-release exists, legacy release files are consulted.  The host OS is never
looked at.

OSV ecosystem strings follow the live OSV data (October 2026): ``Debian:12``,
``Ubuntu:22.04:LTS``, ``Alpine:v3.20``, ``Rocky Linux:9``, ``AlmaLinux:9``,
``Red Hat``, ``SUSE``, ``openSUSE:Leap 15.6`` ...  Distros OSV does not cover
(Fedora, CentOS, Oracle, Amazon, Arch, Gentoo, Photon, ...) get an empty list.
"""

from __future__ import annotations

import re

from startup_sbom.models import OSInfo
from startup_sbom.rootfs import RootFS

OS_RELEASE_PATHS = ("/etc/os-release", "/usr/lib/os-release")
_RELEASE_READ_LIMIT = 64 * 1024
_FIELD_LIMIT = 256

#: Debian codename → release number (distro-info-data ``debian.csv``).
DEBIAN_CODENAMES: dict[str, str] = {
    "woody": "3.0",
    "sarge": "3.1",
    "etch": "4.0",
    "lenny": "5.0",
    "squeeze": "6.0",
    "wheezy": "7",
    "jessie": "8",
    "stretch": "9",
    "buster": "10",
    "bullseye": "11",
    "bookworm": "12",
    "trixie": "13",
    "forky": "14",
    "duke": "15",
}

#: Codename of the current Debian *testing* suite (distro-info-data ``debian.csv``:
#: the first codename without a release date).  Rolling Debian derivatives are
#: matched against it (see :func:`derivative_fallback_ecosystem`).  Bump it when
#: forky is released and the next suite becomes testing.
DEBIAN_TESTING_CODENAME = "forky"

#: Debian derivatives that only ship a rolling release built from Debian testing.
#: Kali's os-release says ``VERSION_CODENAME=kali-rolling`` (``VERSION_ID`` is a
#: snapshot date such as ``2025.3``), so it is listed explicitly as well.
_ROLLING_DEBIAN_DERIVATIVES = frozenset({"kali"})
_ROLLING_MARKER = re.compile(r"(?:^|[-_.\s])(?:rolling|testing|sid|unstable)(?:$|[-_.\s])")

#: ``ID`` values that :func:`_ecosystems` maps to an OSV ecosystem of their own (or
#: deliberately leaves unmapped); everything else may use the derivative fallback.
_NATIVE_IDS = frozenset(
    {
        "debian",
        "raspbian",
        "ubuntu",
        "alpine",
        "rhel",
        "rocky",
        "almalinux",
        "sles",
        "sles_sap",
        "sle-micro",
        "sl-micro",
        "opensuse",
        "opensuse-leap",
        "opensuse-leap-micro",
        "opensuse-tumbleweed",
        "azurelinux",
        "mariner",
        "openeuler",
        "mageia",
        "wolfi",
        "chainguard",
        "minimos",
        "alpaquita",
    }
)

#: Ubuntu codename → release (distro-info-data ``ubuntu.csv``).
UBUNTU_CODENAMES: dict[str, str] = {
    "trusty": "14.04",
    "xenial": "16.04",
    "bionic": "18.04",
    "focal": "20.04",
    "jammy": "22.04",
    "kinetic": "22.10",
    "lunar": "23.04",
    "mantic": "23.10",
    "noble": "24.04",
    "oracular": "24.10",
    "plucky": "25.04",
    "questing": "25.10",
    "resolute": "26.04",
    "stonking": "26.10",
}

_FAMILY_BY_ID: dict[str, str] = {
    "debian": "debian",
    "ubuntu": "debian",
    "raspbian": "debian",
    "kali": "debian",
    "linuxmint": "debian",
    "pop": "debian",
    "elementary": "debian",
    "devuan": "debian",
    "rhel": "rhel",
    "centos": "rhel",
    "rocky": "rhel",
    "almalinux": "rhel",
    "ol": "rhel",
    "amzn": "rhel",
    "scientific": "rhel",
    "mariner": "rhel",
    "azurelinux": "rhel",
    "photon": "rhel",
    "openeuler": "rhel",
    "mageia": "rhel",
    "fedora": "fedora",
    "sles": "suse",
    "sles_sap": "suse",
    "sle-micro": "suse",
    "sl-micro": "suse",
    "opensuse": "suse",
    "opensuse-leap": "suse",
    "opensuse-tumbleweed": "suse",
    "opensuse-leap-micro": "suse",
    "opensuse-slowroll": "suse",
    "alpine": "alpine",
    "postmarketos": "alpine",
    "wolfi": "wolfi",
    "chainguard": "wolfi",
    "arch": "arch",
    "archarm": "arch",
    "manjaro": "arch",
    "endeavouros": "arch",
    "steamos": "arch",
    "artix": "arch",
    "gentoo": "gentoo",
    "void": "void",
}
# Priority when walking ID_LIKE: more specific families first.
_LIKE_FAMILY: tuple[tuple[str, str], ...] = (
    ("debian", "debian"),
    ("ubuntu", "debian"),
    ("rhel", "rhel"),
    ("centos", "rhel"),
    ("suse", "suse"),
    ("opensuse", "suse"),
    ("fedora", "fedora"),
    ("alpine", "alpine"),
    ("wolfi", "wolfi"),
    ("arch", "arch"),
    ("gentoo", "gentoo"),
    ("void", "void"),
)

_ID_SAFE = re.compile(r"[^a-z0-9._-]")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_RH_RELEASE = re.compile(r"^(?P<name>.*?)\s+release\s+(?P<version>\d+(?:\.\d+)*)", re.IGNORECASE)
_VERSION_NUM = re.compile(r"(\d+(?:\.\d+)*)")


# --------------------------------------------------------------------------- parsing
def _unquote(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        quote, value = value[0], value[1:-1]
        if quote == '"':
            value = re.sub(r"\\(.)", r"\1", value)
    elif value and value[0] in "\"'":
        value = value[1:]  # unbalanced quote: keep the rest verbatim
    return value


def _clean(value: str) -> str:
    return _CTRL.sub("", value)[:_FIELD_LIMIT].strip()


def parse_os_release(text: str) -> dict[str, str]:
    """Parse shell-style ``KEY=value`` lines (quotes, escapes, comments)."""
    out: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        key = key.strip()
        if not key.replace("_", "").isalnum():
            continue
        out[key.upper()] = _clean(_unquote(raw))
    return out


def _safe_id(value: str) -> str:
    return _ID_SAFE.sub("", value.strip().lower())[:64]


def _major(version: str | None) -> str | None:
    if not version:
        return None
    head = version.split(".", 1)[0]
    return head if head.isdigit() else None


def _major_minor(version: str | None) -> str | None:
    if not version:
        return None
    parts = version.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    return f"{parts[0]}.{parts[1]}"


def os_family(os_id: str, id_like: list[str]) -> str:
    """Map an os-release ``ID``/``ID_LIKE`` to a family name (``unknown`` if none).

    ``rhel`` covers Red Hat–like rpm distributions (including Amazon, Azure Linux,
    Photon, openEuler and Mageia); ``fedora`` is used for Fedora and derivatives
    that do not also claim RHEL compatibility.
    """
    if os_id in _FAMILY_BY_ID:
        return _FAMILY_BY_ID[os_id]
    likes = set(id_like)
    for like, family in _LIKE_FAMILY:
        if like in likes:
            return family
    for like in id_like:
        if like.startswith("opensuse") or like == "sles":
            return "suse"
    return "unknown"


# --------------------------------------------------------------------------- OSV mapping
def _debian_release(info: OSInfo) -> str | None:
    if info.version_id:
        major = _major(info.version_id)
        if major is None:
            return None
        if int(major) >= 7:
            return major
        return _major_minor(info.version_id) or major
    codename = (info.version_codename or "").lower()
    return DEBIAN_CODENAMES.get(codename)


def _ubuntu_ecosystem(version: str, pretty: str | None) -> str | None:
    mm = _major_minor(version)
    if mm is None:
        return None
    yy, mon = mm.split(".")
    lts = (mon == "04" and int(yy) % 2 == 0) or "LTS" in (pretty or "")
    return f"Ubuntu:{mm}:LTS" if lts else f"Ubuntu:{mm}"


def _ecosystems(info: OSInfo, hints: dict[str, str] | None = None) -> list[str]:
    hints = hints or {}
    os_id = info.id
    ver = info.version_id
    out: list[str] = []
    if os_id in ("debian", "raspbian"):
        rel = _debian_release(info)
        if rel:
            out.append(f"Debian:{rel}")
    elif os_id == "ubuntu":
        version = ver or UBUNTU_CODENAMES.get((info.version_codename or "").lower(), "")
        eco = _ubuntu_ecosystem(version, info.pretty_name)
        if eco:
            out.append(eco)
    elif os_id == "alpine":
        mm = _major_minor(ver)
        if mm and ver and "_" not in ver:
            out.append(f"Alpine:v{mm}")
    elif os_id == "rhel":
        out.append("Red Hat")
    elif os_id == "rocky":
        if major := _major(ver):
            out.append(f"Rocky Linux:{major}")
    elif os_id == "almalinux":
        if major := _major(ver):
            out.append(f"AlmaLinux:{major}")
    elif os_id in ("sles", "sles_sap", "sle-micro", "sl-micro"):
        out.append("SUSE")
    elif os_id == "opensuse-tumbleweed":
        out.append("openSUSE:Tumbleweed")
    elif os_id in ("opensuse-leap", "opensuse"):
        if _major_minor(ver):
            out.append(f"openSUSE:Leap {ver}")
    elif os_id == "opensuse-leap-micro":
        if _major_minor(ver):
            out.append(f"openSUSE:Leap Micro {ver}")
    elif os_id in ("azurelinux", "mariner"):
        if major := _major(ver):
            out.append(f"Azure Linux:{major}")
    elif os_id == "openeuler":
        m = re.search(r"\(([^)]*LTS[^)]*)\)", info.pretty_name or "")
        mm = _major_minor(ver)
        if mm:
            out.append(f"openEuler:{mm}-{m.group(1)}" if m else f"openEuler:{mm}")
    elif os_id == "mageia":
        if major := _major(ver):
            out.append(f"Mageia:{major}")
    elif os_id == "wolfi":
        out.append("Wolfi")
    elif os_id == "chainguard":
        out.append("Chainguard")
    elif os_id == "minimos":
        out.append("MinimOS")
    elif os_id == "alpaquita":
        if ver:
            out.append(f"Alpaquita:{_major(ver) or ver}")
    else:
        # Derivatives: approximate through the parent distribution.
        likes = info.id_like
        if "ubuntu" in likes:
            codename = hints.get("UBUNTU_CODENAME", "").lower()
            version = UBUNTU_CODENAMES.get(codename, "")
            eco = _ubuntu_ecosystem(version, None) if version else None
            if eco:
                out.append(eco)
        elif "debian" in likes:
            codename = (info.version_codename or "").lower()
            if codename in DEBIAN_CODENAMES:
                out.append(f"Debian:{DEBIAN_CODENAMES[codename]}")
            elif fallback := derivative_fallback_ecosystem(info):
                out.append(fallback)
    return out


def derivative_fallback_ecosystem(info: OSInfo) -> str | None:
    """Parent OSV ecosystem used for a rolling Debian derivative, else ``None``.

    OSV.dev has no ecosystem for Kali, Parrot (rolling) and similar distributions,
    but their archives are rebuilt continuously from Debian *testing*.  Such a
    system is therefore matched against the advisories of the Debian testing
    release, ``Debian:<n>`` with ``n`` the release number testing will get
    (``forky`` -> ``Debian:14``) -- the same string a plain ``forky/sid`` Debian
    install maps to here.  An unversioned ``Debian`` query is not used: it would
    accept affected ranges of *every* Debian release (old-stable entries without a
    fix included), and a stable release's ranges are pinned to ``+debNuM`` security
    builds a rolling system never installs.

    Only derivatives that are evidently rolling qualify (a known rolling ``ID`` or
    a ``rolling``/``testing``/``sid`` codename); a derivative pinned to a stable
    Debian release under its own codename (Parrot ``lory``, Devuan ``daedalus``)
    is not guessed at.  Ubuntu derivatives are mapped exactly through
    ``UBUNTU_CODENAME`` and never take this path.  Matches made this way carry
    reduced confidence (see :mod:`startup_sbom.vulns.osv`).
    """
    if info.id in _NATIVE_IDS or "debian" not in info.id_like or "ubuntu" in info.id_like:
        return None
    codename = (info.version_codename or "").lower()
    if codename in DEBIAN_CODENAMES:
        return None  # the exact parent release is known: not a fallback
    if info.id in _ROLLING_DEBIAN_DERIVATIVES or _ROLLING_MARKER.search(codename):
        return f"Debian:{DEBIAN_CODENAMES[DEBIAN_TESTING_CODENAME]}"
    return None


def osv_ecosystems(os: OSInfo) -> list[str]:
    """OSV ecosystem strings (priority order) for ``os``; empty if OSV lacks coverage."""
    return _ecosystems(os)


# --------------------------------------------------------------------------- fallbacks
def _read(fs: RootFS, path: str) -> tuple[str, str] | None:
    """Return ``(canonical_path, text)`` for a readable file inside the image."""
    text = fs.try_read_text(path, _RELEASE_READ_LIMIT)
    if text is None:
        return None
    return fs.try_resolve(path) or path, text


def _from_rh_release(text: str) -> dict[str, str] | None:
    line = text.strip().splitlines()[0] if text.strip() else ""
    m = _RH_RELEASE.match(line)
    if not m:
        return None
    name, version = m.group("name").strip(), m.group("version")
    lname = name.lower()
    os_id, like = "rhel", "fedora"
    if "red hat" in lname:
        os_id = "rhel"
    elif "centos" in lname:
        os_id, version = "centos", _major(version) or version
    elif "rocky" in lname:
        os_id = "rocky"
    elif "alma" in lname:
        os_id = "almalinux"
    elif "oracle" in lname:
        os_id = "ol"
    elif "scientific" in lname:
        os_id = "scientific"
    elif "fedora" in lname:
        os_id, like = "fedora", ""
    elif "amazon" in lname:
        os_id = "amzn"
    else:
        return None
    rel = {"ID": os_id, "NAME": name, "VERSION_ID": version, "PRETTY_NAME": _clean(line)}
    if os_id not in ("rhel", "fedora"):
        rel["ID_LIKE"] = "rhel fedora"
    elif like:
        rel["ID_LIKE"] = like
    return rel


def _fallback(fs: RootFS) -> tuple[dict[str, str], list[str]] | None:
    got = _read(fs, "/etc/lsb-release")
    if got:
        lsb = parse_os_release(got[1])
        if lsb.get("DISTRIB_ID"):
            rel = {
                "ID": lsb["DISTRIB_ID"],
                "NAME": lsb["DISTRIB_ID"],
                "VERSION_ID": lsb.get("DISTRIB_RELEASE", ""),
                "VERSION_CODENAME": lsb.get("DISTRIB_CODENAME", ""),
                "PRETTY_NAME": lsb.get("DISTRIB_DESCRIPTION", ""),
            }
            return rel, [got[0]]
    got = _read(fs, "/etc/alpine-release")
    if got and got[1].strip():
        version = _clean(got[1].strip().splitlines()[0])
        return {"ID": "alpine", "NAME": "Alpine Linux", "VERSION_ID": version}, [got[0]]
    for path in (
        "/etc/redhat-release",
        "/etc/centos-release",
        "/etc/rocky-release",
        "/etc/almalinux-release",
        "/etc/oracle-release",
        "/etc/fedora-release",
        "/etc/system-release",
    ):
        got = _read(fs, path)
        if got:
            parsed = _from_rh_release(got[1])
            if parsed:
                return parsed, [got[0]]
    got = _read(fs, "/etc/SuSE-release")
    if got:
        first = got[1].strip().splitlines()[0] if got[1].strip() else ""
        kv = parse_os_release(got[1].replace(" = ", "="))
        version = kv.get("VERSION", "")
        if kv.get("PATCHLEVEL", "").isdigit() and version:
            version = f"{version}.{kv['PATCHLEVEL']}"
        os_id = "opensuse" if "opensuse" in first.lower() else "sles"
        return {"ID": os_id, "NAME": _clean(first), "VERSION_ID": version}, [got[0]]
    got = _read(fs, "/etc/debian_version")
    if got and got[1].strip():
        value = _clean(got[1].strip().splitlines()[0])
        rel = {"ID": "debian", "NAME": "Debian GNU/Linux"}
        major = _major(value)
        if major:
            rel["VERSION_ID"] = major if int(major) >= 7 else (_major_minor(value) or major)
        else:
            rel["VERSION_CODENAME"] = value.split("/", 1)[0]
        return rel, [got[0]]
    for path, os_id, name in (
        ("/etc/arch-release", "arch", "Arch Linux"),
        ("/etc/gentoo-release", "gentoo", "Gentoo"),
        ("/etc/photon-release", "photon", "VMware Photon OS"),
        ("/etc/mariner-release", "mariner", "CBL-Mariner"),
    ):
        got = _read(fs, path)
        if got is not None:
            m = _VERSION_NUM.search(got[1])
            rel = {"ID": os_id, "NAME": name}
            if m and os_id != "arch":
                rel["VERSION_ID"] = _major_minor(m.group(1)) or m.group(1)
            return rel, [got[0]]
    return None


# --------------------------------------------------------------------------- entry point
def identify(fs: RootFS) -> OSInfo:
    """Identify the analysed root filesystem's OS (never the host's)."""
    rel: dict[str, str] | None = None
    evidence: list[str] = []
    for path in OS_RELEASE_PATHS:
        got = _read(fs, path)
        if got is None:
            continue
        parsed = parse_os_release(got[1])
        if parsed.get("ID") or parsed.get("NAME"):
            rel, evidence = parsed, [got[0]]
            break
    if rel is None:
        fb = _fallback(fs)
        if fb is None:
            return OSInfo(family="unknown")
        rel, evidence = fb

    os_id = _safe_id(rel.get("ID", "")) or "linux"
    id_like = [s for s in (_safe_id(x) for x in rel.get("ID_LIKE", "").split()) if s]
    info = OSInfo(
        id=os_id,
        id_like=id_like,
        name=rel.get("NAME") or None,
        pretty_name=rel.get("PRETTY_NAME") or None,
        version_id=rel.get("VERSION_ID") or None,
        version_codename=rel.get("VERSION_CODENAME") or None,
        variant_id=rel.get("VARIANT_ID") or None,
        build_id=rel.get("BUILD_ID") or None,
        family=os_family(os_id, id_like),
        evidence=evidence,
    )
    # Debian testing/sid: os-release has no VERSION_ID; recover the codename.
    if info.id == "debian" and not info.version_id and not info.version_codename:
        got = _read(fs, "/etc/debian_version")
        if got and got[1].strip():
            value = _clean(got[1].strip().splitlines()[0])
            codename = value.split("/", 1)[0].lower()
            if codename in DEBIAN_CODENAMES:
                info.version_codename = codename
                info.evidence.append(got[0])
            elif _major(value):
                info.version_id = _major(value)
                info.evidence.append(got[0])
        if not info.version_codename and info.pretty_name:
            m = re.search(r"\b([a-z]+)/sid\b", info.pretty_name)
            if m and m.group(1) in DEBIAN_CODENAMES:
                info.version_codename = m.group(1)
    info.vuln_ecosystems = _ecosystems(info, rel)
    return info
