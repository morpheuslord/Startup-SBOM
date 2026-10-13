"""Target OS identification and OSV ecosystem mapping."""

from __future__ import annotations

import sys

import pytest

from fsbuilder import Dir, Symlink
from startup_sbom.distro import (
    derivative_fallback_ecosystem,
    identify,
    os_family,
    osv_ecosystems,
    parse_os_release,
)
from startup_sbom.models import OSInfo

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")


def _osr(**fields: str) -> str:
    return "".join(f'{k}="{v}"\n' for k, v in fields.items())


@pytest.mark.parametrize(
    ("fields", "family", "ecosystems"),
    [
        (
            {"ID": "debian", "VERSION_ID": "12", "VERSION_CODENAME": "bookworm"},
            "debian",
            ["Debian:12"],
        ),
        (
            {
                "ID": "ubuntu",
                "ID_LIKE": "debian",
                "VERSION_ID": "22.04",
                "PRETTY_NAME": "Ubuntu 22.04.4 LTS",
            },
            "debian",
            ["Ubuntu:22.04:LTS"],
        ),
        ({"ID": "ubuntu", "VERSION_ID": "24.04"}, "debian", ["Ubuntu:24.04:LTS"]),
        ({"ID": "ubuntu", "VERSION_ID": "25.10"}, "debian", ["Ubuntu:25.10"]),
        ({"ID": "alpine", "VERSION_ID": "3.20.3"}, "alpine", ["Alpine:v3.20"]),
        ({"ID": "alpine", "VERSION_ID": "3.21.0_alpha20240807"}, "alpine", []),
        ({"ID": "rhel", "ID_LIKE": "fedora", "VERSION_ID": "9.4"}, "rhel", ["Red Hat"]),
        (
            {"ID": "rocky", "ID_LIKE": "rhel centos fedora", "VERSION_ID": "9.4"},
            "rhel",
            ["Rocky Linux:9"],
        ),
        (
            {"ID": "almalinux", "ID_LIKE": "rhel centos fedora", "VERSION_ID": "9.4"},
            "rhel",
            ["AlmaLinux:9"],
        ),
        ({"ID": "centos", "VERSION_ID": "9"}, "rhel", []),
        ({"ID": "amzn", "ID_LIKE": "centos rhel fedora", "VERSION_ID": "2023"}, "rhel", []),
        ({"ID": "ol", "VERSION_ID": "9.4"}, "rhel", []),
        ({"ID": "fedora", "VERSION_ID": "44"}, "fedora", []),
        ({"ID": "bazzite", "ID_LIKE": "fedora", "VERSION_ID": "44"}, "fedora", []),
        ({"ID": "sles", "VERSION_ID": "15.6"}, "suse", ["SUSE"]),
        (
            {"ID": "opensuse-leap", "ID_LIKE": "suse opensuse", "VERSION_ID": "15.6"},
            "suse",
            ["openSUSE:Leap 15.6"],
        ),
        ({"ID": "opensuse-tumbleweed", "VERSION_ID": "20261001"}, "suse", ["openSUSE:Tumbleweed"]),
        ({"ID": "azurelinux", "VERSION_ID": "3.0"}, "rhel", ["Azure Linux:3"]),
        ({"ID": "mariner", "VERSION_ID": "2.0"}, "rhel", ["Azure Linux:2"]),
        (
            {"ID": "openEuler", "VERSION_ID": "22.03", "PRETTY_NAME": "openEuler 22.03 (LTS-SP3)"},
            "rhel",
            ["openEuler:22.03-LTS-SP3"],
        ),
        ({"ID": "wolfi", "VERSION_ID": "20230201"}, "wolfi", ["Wolfi"]),
        ({"ID": "chainguard"}, "wolfi", ["Chainguard"]),
        ({"ID": "arch", "BUILD_ID": "rolling"}, "arch", []),
        ({"ID": "manjaro", "ID_LIKE": "arch"}, "arch", []),
        ({"ID": "gentoo"}, "gentoo", []),
        ({"ID": "void"}, "void", []),
        ({"ID": "photon", "VERSION_ID": "5.0"}, "rhel", []),
        (
            {
                "ID": "linuxmint",
                "ID_LIKE": "ubuntu debian",
                "VERSION_ID": "22",
                "UBUNTU_CODENAME": "jammy",
            },
            "debian",
            ["Ubuntu:22.04:LTS"],
        ),
        (
            {
                "ID": "raspbian",
                "ID_LIKE": "debian",
                "VERSION_ID": "12",
                "VERSION_CODENAME": "bookworm",
            },
            "debian",
            ["Debian:12"],
        ),
        ({"ID": "kali", "ID_LIKE": "debian", "VERSION_ID": "2025.3"}, "debian", ["Debian:14"]),
        ({"ID": "mystery"}, "unknown", []),
    ],
)
def test_os_release_mapping(make_dir_fs, fields, family, ecosystems):
    info = identify(make_dir_fs({"/etc/os-release": _osr(**fields)}))
    assert info.family == family
    assert info.vuln_ecosystems == ecosystems
    assert info.evidence == ["/etc/os-release"]


@needs_symlinks
def test_os_release_symlink_resolved_inside_root(make_fs):
    fs = make_fs(
        {
            "/etc/os-release": Symlink("../usr/lib/os-release"),
            "/usr/lib/os-release": _osr(
                ID="debian", VERSION_ID="13", PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
            ),
        }
    )
    info = identify(fs)
    assert (info.id, info.version_id, info.vuln_ecosystems) == ("debian", "13", ["Debian:13"])
    assert info.evidence == ["/usr/lib/os-release"]


@needs_symlinks
def test_absolute_symlink_never_reads_host(make_dir_fs):
    fs = make_dir_fs(
        {"/etc/os-release": Symlink("/usr/lib/os-release"), "/etc/alpine-release": "3.19.1\n"}
    )
    info = identify(fs)  # /usr/lib/os-release does not exist in the image → fallback
    assert info.id == "alpine"
    assert info.vuln_ecosystems == ["Alpine:v3.19"]
    assert info.evidence == ["/etc/alpine-release"]


def test_usr_lib_fallback(make_fs):
    info = identify(make_fs({"/usr/lib/os-release": _osr(ID="fedora", VERSION_ID="41")}))
    assert info.id == "fedora"
    assert info.evidence == ["/usr/lib/os-release"]


def test_debian_testing_without_version_id(make_fs):
    fs = make_fs(
        {
            "/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux forky/sid"\nNAME="Debian GNU/Linux"\n'
            "ID=debian\n",
            "/etc/debian_version": "forky/sid\n",
        }
    )
    info = identify(fs)
    assert info.version_id is None
    assert info.version_codename == "forky"
    assert info.vuln_ecosystems == ["Debian:14"]
    assert "/etc/debian_version" in info.evidence


def test_debian_testing_codename_from_pretty_name(make_fs):
    info = identify(
        make_fs({"/etc/os-release": 'ID=debian\nPRETTY_NAME="Debian GNU/Linux trixie/sid"\n'})
    )
    assert info.vuln_ecosystems == ["Debian:13"]


@pytest.mark.parametrize(
    ("spec", "os_id", "version", "ecosystems"),
    [
        (
            {
                "/etc/lsb-release": "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=20.04\n"
                "DISTRIB_CODENAME=focal\n"
            },
            "ubuntu",
            "20.04",
            ["Ubuntu:20.04:LTS"],
        ),
        ({"/etc/redhat-release": "CentOS release 6.10 (Final)\n"}, "centos", "6", []),
        (
            {"/etc/redhat-release": "Red Hat Enterprise Linux Server release 7.9 (Maipo)\n"},
            "rhel",
            "7.9",
            ["Red Hat"],
        ),
        (
            {"/etc/redhat-release": "Rocky Linux release 8.10 (Green Obsidian)\n"},
            "rocky",
            "8.10",
            ["Rocky Linux:8"],
        ),
        ({"/etc/system-release": "Amazon Linux AMI release 2018.03\n"}, "amzn", "2018.03", []),
        ({"/etc/debian_version": "11.9\n"}, "debian", "11", ["Debian:11"]),
        ({"/etc/debian_version": "6.0.10\n"}, "debian", "6.0", ["Debian:6.0"]),
        ({"/etc/debian_version": "bookworm/sid\n"}, "debian", None, ["Debian:12"]),
        (
            {
                "/etc/SuSE-release": "SUSE Linux Enterprise Server 11 (x86_64)\n"
                "VERSION = 11\nPATCHLEVEL = 4\n"
            },
            "sles",
            "11.4",
            ["SUSE"],
        ),
        ({"/etc/arch-release": ""}, "arch", None, []),
        ({"/etc/gentoo-release": "Gentoo Base System release 2.15\n"}, "gentoo", "2.15", []),
        (
            {"/etc/mariner-release": "CBL-Mariner 2.0.20240123\n"},
            "mariner",
            "2.0",
            ["Azure Linux:2"],
        ),
    ],
)
def test_legacy_fallbacks(make_fs, spec, os_id, version, ecosystems):
    info = identify(make_fs(spec))
    assert info.id == os_id
    assert info.version_id == version
    assert info.vuln_ecosystems == ecosystems
    assert info.evidence == [next(iter(spec))]


def test_nothing_found(make_fs):
    info = identify(make_fs({"/etc": Dir()}))
    assert info.id == "unknown"
    assert info.family == "unknown"
    assert info.vuln_ecosystems == []


def test_hostile_os_release(make_dir_fs):
    payload = (
        b'\xff\xfe\x00garbage\nID="Deb ian;rm -rf /\x1b[31m"\nID_LIKE=\'unterminated\n'
        b'VERSION_ID="12\nNAME=' + b"A" * 5000 + b"\n=noval\nBAD KEY=1\n"
    )
    info = identify(make_dir_fs({"/etc/os-release": payload}))
    assert info.id == "debianrm-rf31m"
    assert info.name is not None
    assert len(info.name) <= 256
    assert "\x1b" not in (info.pretty_name or "") + info.id


def test_os_release_directory_and_huge_file(make_dir_fs):
    info = identify(
        make_dir_fs(
            {"/etc/os-release": Dir(), "/usr/lib/os-release": "ID=alpine\nVERSION_ID=3.20.0\n"}
        )
    )
    assert info.id == "alpine"
    big = identify(make_dir_fs({"/etc/os-release": "ID=x\n" + "#" * (128 * 1024)}))
    assert big.id == "unknown"  # over the read limit → ignored


def test_parse_os_release_quoting():
    parsed = parse_os_release(
        '# comment\nNAME="Fedora \\"Linux\\""\nOSTREE_VERSION=\'44.20261001\'\nID=fedora\n'
        "EMPTY=\nexport FOO=bar\n"
    )
    assert parsed["NAME"] == 'Fedora "Linux"'
    assert parsed["OSTREE_VERSION"] == "44.20261001"
    assert parsed["EMPTY"] == ""
    assert "EXPORT FOO" not in parsed


def test_osv_ecosystems_helper_and_family():
    assert osv_ecosystems(OSInfo(id="debian", version_codename="trixie")) == ["Debian:13"]
    assert osv_ecosystems(OSInfo(id="ubuntu", version_codename="noble")) == ["Ubuntu:24.04:LTS"]
    assert osv_ecosystems(OSInfo()) == []
    assert os_family("pop", ["ubuntu", "debian"]) == "debian"
    assert os_family("x", ["opensuse-foo"]) == "suse"


# --------------------------------------------------------------------------- derivative fallback
KALI_OS_RELEASE = _osr(
    PRETTY_NAME="Kali GNU/Linux Rolling",
    NAME="Kali GNU/Linux",
    VERSION_ID="2025.3",
    VERSION="2025.3",
    VERSION_CODENAME="kali-rolling",
    ID="kali",
    ID_LIKE="debian",
)


def test_kali_rolling_falls_back_to_debian_testing(make_dir_fs):
    info = identify(make_dir_fs({"/etc/os-release": KALI_OS_RELEASE}))
    assert (info.id, info.id_like, info.family) == ("kali", ["debian"], "debian")
    assert info.vuln_ecosystems == ["Debian:14"]  # forky = current Debian testing
    assert derivative_fallback_ecosystem(info) == "Debian:14"


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        # rolling derivatives (known id, or a rolling/testing/sid codename)
        (OSInfo(id="kali", id_like=["debian"], version_codename="kali-rolling"), "Debian:14"),
        (OSInfo(id="parrot", id_like=["debian"], version_codename="rolling"), "Debian:14"),
        (OSInfo(id="foo", id_like=["debian"], version_codename="foo-testing"), "Debian:14"),
        # exact parent release known, or pinned to an unknown stable codename: no guess
        (OSInfo(id="parrot", id_like=["debian"], version_codename="lory"), None),
        (OSInfo(id="devuan", id_like=["debian"], version_codename="daedalus"), None),
        (OSInfo(id="foo", id_like=["debian"], version_codename="bookworm"), None),
        (OSInfo(id="foo", id_like=["debian"]), None),
        # OSV-native distributions and Ubuntu derivatives never use the fallback
        (OSInfo(id="debian", version_codename="forky"), None),
        (OSInfo(id="ubuntu", id_like=["debian"], version_id="24.04"), None),
        (OSInfo(id="linuxmint", id_like=["ubuntu", "debian"], version_codename="rolling"), None),
        (OSInfo(id="kali"), None),
    ],
)
def test_derivative_fallback_ecosystem(info, expected):
    assert derivative_fallback_ecosystem(info) == expected


def test_derivative_with_debian_codename_still_exact(make_dir_fs):
    osr = _osr(ID="foo", ID_LIKE="debian", VERSION_CODENAME="trixie")
    assert identify(make_dir_fs({"/etc/os-release": osr})).vuln_ecosystems == ["Debian:13"]


def test_debian_and_ubuntu_unchanged_by_fallback(make_dir_fs):
    deb = identify(make_dir_fs({"/etc/os-release": _osr(ID="debian", VERSION_ID="12")}))
    ubu = identify(
        make_dir_fs({"/etc/os-release": _osr(ID="ubuntu", ID_LIKE="debian", VERSION_ID="24.04")})
    )
    assert deb.vuln_ecosystems == ["Debian:12"]
    assert ubu.vuln_ecosystems == ["Ubuntu:24.04:LTS"]
    mint = identify(
        make_dir_fs(
            {
                "/etc/os-release": _osr(
                    ID="linuxmint",
                    ID_LIKE="ubuntu debian",
                    VERSION_CODENAME="wilma",
                    UBUNTU_CODENAME="noble",
                )
            }
        )
    )
    assert mint.vuln_ecosystems == ["Ubuntu:24.04:LTS"]
    assert derivative_fallback_ecosystem(mint) is None
