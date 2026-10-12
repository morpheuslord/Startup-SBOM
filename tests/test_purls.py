"""Package URL construction."""

from __future__ import annotations

import pytest
from packageurl import PackageURL

from startup_sbom.models import OSInfo, PackageType
from startup_sbom.purls import (
    distro_qualifier,
    package_purl,
    purl_namespace,
    split_epoch,
    with_qualifiers,
)

DEBIAN = OSInfo(id="debian", version_id="12")
UBUNTU = OSInfo(id="ubuntu", version_id="24.04", id_like=["debian"])
RHEL = OSInfo(id="rhel", version_id="9.4", id_like=["fedora"])
ALPINE = OSInfo(id="alpine", version_id="3.20.3")
ARCH = OSInfo(id="arch", build_id="rolling")


def test_deb_keeps_epoch_and_upstream_with_version():
    purl = package_purl(
        PackageType.DEB,
        "libssl3",
        "3.0.15-1~deb12u1",
        os_info=DEBIAN,
        arch="amd64",
        source_name="openssl",
        source_version="3.0.15-1~deb12u1",
    )
    assert (
        purl
        == "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12&upstream=openssl"
    )
    binnmu = package_purl(
        PackageType.DEB,
        "zlib1g",
        "1:1.2.13.dfsg-1+b1",
        os_info=DEBIAN,
        arch="amd64",
        source_name="zlib",
        source_version="1:1.2.13.dfsg-1",
    )
    assert binnmu == (
        "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1%2Bb1?arch=amd64&distro=debian-12"
        "&upstream=zlib%401:1.2.13.dfsg-1"
    )
    same = package_purl(
        PackageType.DEB,
        "bash",
        "5.2.15-2",
        os_info=UBUNTU,
        source_name="bash",
        source_version="5.2.15-2",
    )
    assert same == "pkg:deb/ubuntu/bash@5.2.15-2?distro=ubuntu-24.04"


def test_rpm_epoch_moves_to_qualifier():
    purl = package_purl(
        PackageType.RPM,
        "openssl-libs",
        "1:3.0.7-27.el9",
        os_info=RHEL,
        arch="x86_64",
        epoch=1,
        source_name="openssl",
        source_version="1:3.0.7-27.el9",
    )
    assert purl == (
        "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rhel-9.4&epoch=1"
        "&upstream=openssl-3.0.7-27.el9.src.rpm"
    )
    parsed = PackageURL.from_string(purl)
    assert parsed.version == "3.0.7-27.el9"
    # epoch derived from the version string when not given; epoch 0 omitted
    assert "epoch=2" in package_purl(PackageType.RPM, "x", "2:1-1", os_info=RHEL)
    assert "epoch" not in package_purl(PackageType.RPM, "x", "1-1", os_info=RHEL, epoch=0)


def test_rpm_name_case_preserved_and_namespaces():
    assert package_purl(
        PackageType.RPM,
        "NetworkManager",
        "1.46-1.fc44",
        os_info=OSInfo(id="fedora", version_id="44"),
    ).startswith("pkg:rpm/fedora/NetworkManager@")
    cases = {
        "rocky": "rocky",
        "almalinux": "almalinux",
        "centos": "centos",
        "amzn": "amzn",
        "opensuse-leap": "opensuse",
        "opensuse-tumbleweed": "opensuse",
        "sles": "sles",
    }
    for os_id, ns in cases.items():
        assert purl_namespace(PackageType.RPM, OSInfo(id=os_id)) == ns
    assert purl_namespace(PackageType.RPM, OSInfo(id="bazzite", id_like=["fedora"])) == "fedora"
    assert purl_namespace(PackageType.RPM, None) is None


def test_other_os_types():
    assert package_purl(
        PackageType.APK,
        "libcrypto3",
        "3.3.2-r0",
        os_info=ALPINE,
        arch="x86_64",
        source_name="openssl",
        source_version="3.3.2-r0",
    ) == ("pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=x86_64&distro=alpine-3.20.3&upstream=openssl")
    assert purl_namespace(PackageType.APK, OSInfo(id="wolfi")) == "wolfi"
    assert (
        purl_namespace(PackageType.APK, OSInfo(id="postmarketos", id_like=["alpine"]))
        == "postmarketos"
    )
    assert package_purl(PackageType.ALPM, "pacman", "1:6.0.1-1", os_info=ARCH, arch="x86_64") == (
        "pkg:alpm/arch/pacman@1:6.0.1-1?arch=x86_64&distro=arch"
    )
    assert purl_namespace(PackageType.ALPM, OSInfo(id="endeavouros", id_like=["arch"])) == "arch"
    assert (
        purl_namespace(PackageType.DEB, OSInfo(id="linuxmint", id_like=["ubuntu", "debian"]))
        == "ubuntu"
    )
    assert purl_namespace(PackageType.DEB, None) == "debian"


def test_deb_epoch_argument_added_when_missing():
    assert package_purl(PackageType.DEB, "x", "1.0-1", epoch=2).startswith(
        "pkg:deb/debian/x@2:1.0-1"
    )


def test_language_types():
    assert package_purl(PackageType.PYPI, "requests", "2.32.3") == "pkg:pypi/requests@2.32.3"
    assert package_purl(PackageType.NPM, "@babel/core", "7.0.0") == "pkg:npm/%40babel/core@7.0.0"
    assert (
        package_purl(PackageType.GOLANG, "github.com/x/y", "v1.2.3")
        == "pkg:golang/github.com/x/y@v1.2.3"
    )
    assert (
        package_purl(PackageType.MAVEN, "org.apache:commons", "1.0")
        == "pkg:maven/org.apache/commons@1.0"
    )


def test_helpers():
    assert split_epoch("1:2.3-4") == (1, "2.3-4")
    assert split_epoch("2.3-4") == (None, "2.3-4")
    assert split_epoch("a:b") == (None, "a:b")
    assert distro_qualifier(None) is None
    assert distro_qualifier(OSInfo()) is None
    assert distro_qualifier(ARCH) == "arch"
    assert distro_qualifier(DEBIAN) == "debian-12"
    assert with_qualifiers("pkg:deb/debian/a@1?arch=amd64", instance="2") == (
        "pkg:deb/debian/a@1?arch=amd64&instance=2"
    )


@pytest.mark.parametrize("name", ["evil/../name", "a b", "über", "x?y#z@w"])
def test_hostile_names_roundtrip(name):
    purl = package_purl(PackageType.RPM, name, "1-1", os_info=RHEL)
    assert PackageURL.from_string(purl).name == name
