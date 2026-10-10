"""Table-driven tests for native version ordering (dpkg, rpm, apk, pacman, PEP 440, SemVer)."""

from __future__ import annotations

import pytest

from startup_sbom.models import PackageType as T
from startup_sbom.vulns.versions import compare, ecosystem_package_type, sort_versions

DPKG = [
    ("1.0", "1.0", 0),
    ("1.0-1", "1.0-1", 0),
    ("3.0.11-1~deb12u2", "3.0.11-1", -1),  # backport tilde sorts first
    ("3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1),
    ("1:9.2p1-2+deb12u2", "9.9p1-1", 1),  # epoch dominates
    ("2.30-1+b1", "2.30-1", 1),  # binNMU
    ("0:1.2-1", "1.2-1", 0),
    ("1.0~rc1", "1.0", -1),
    ("1.0~~", "1.0~", -1),
    ("1.0~", "1.0", -1),
    ("1.0", "1.0+", -1),
    ("1.0a", "1.0", 1),
    ("1.0", "1.0.0", -1),
    ("1.2.3", "1.2.10", -1),
    ("1.002", "1.2", 0),
    ("1.0-0", "1.0", 0),
    ("1.0-1", "1.0", 1),
    ("7.6p1-4", "7.6-0", 1),
    ("2.4.1+really2.3.0-1", "2.4.1-1", 1),  # Ubuntu "+really" downgrade marker
    ("2.4.1+really2.3.0-1", "2.4.2-1", -1),
    ("1.0-1ubuntu0.1", "1.0-1", 1),
    ("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.14", -1),
    ("1:3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.14", 1),
    ("1.0.2g-1ubuntu4.20+esm11", "1.0.2g-1ubuntu4.20", 1),
    ("a", "b", -1),
    ("1.0-a", "1.0-+", -1),  # letters sort before non-letters
]

RPM = [
    ("1:3.0.7-24.el9", "3.0.7-28.el9_4", 1),
    ("3.0.7-24.el9", "3.0.7-28.el9_4", -1),
    ("1:3.0.7-24.el9", "1:3.0.7-28.el9_4", -1),
    ("1.0~rc1-1", "1.0-1", -1),
    ("1.0^git1-1", "1.0-1", 1),
    ("1.0^git1", "1.0.1", -1),
    ("1.0~rc1^git1", "1.0~rc1", 1),
    ("2.02-0.86.el7", "2.02-0.86.el7_9", -1),
    ("1.0a-1", "1.0-1", 1),
    ("5.0-1.el8", "5.0-1.el8_2.1", -1),
    ("1.0", "1.0", 0),
    ("1.0-1", "1.0", 1),
    ("0:1.0-1", "1.0-1", 0),
    ("1.10", "1.9", 1),
    ("1.010", "1.10", 0),
    ("a", "1", -1),
    ("1.0", "1.0.0", -1),
    ("1.0.", "1.0", 0),
    ("1_0", "1.0", 0),  # separators are equivalent
    ("3.1.4-150600.5.7.1", "3.1.4-150600.5.15.1", -1),
]

APK = [
    ("1.0_rc1", "1.0", -1),
    ("1.0_p1", "1.0", 1),
    ("1.1.1w-r0", "1.1.1v-r0", 1),
    ("1.0_alpha", "1.0_beta", -1),
    ("1.0_beta", "1.0_pre", -1),
    ("1.0_pre", "1.0_rc", -1),
    ("1.0_rc1", "1.0_rc2", -1),
    ("1.0-r1", "1.0-r0", 1),
    ("1.0-r1", "1.0", 1),
    ("3.1.4-r10", "3.1.4-r9", 1),
    ("3.1.4-r1", "3.1.4-r1", 0),
    ("1.0_git20240101", "1.0", 1),
    ("1.0_cvs", "1.0_svn", -1),
    ("1.0_hg", "1.0_p", -1),
    ("1.10", "1.9", 1),
    ("2.0", "10.0", -1),
    ("1.0a", "1.0", 1),
    ("1.0a", "1.0b", -1),
    ("1.0", "1.0.1", -1),
    ("1.0.2", "1.0.2_p1", -1),
    ("3.0.12-r1", "3.1.4-r1", -1),
]

ALPM_CHAIN = [
    "1.0a",
    "1.0alpha",
    "1.0b",
    "1.0beta",
    "1.0p",
    "1.0pre",
    "1.0rc",
    "1.0",
    "1.0.a",
    "1.0.1",
]
ALPM_CHAIN2 = ["1", "1.0", "1.1", "1.1.1", "1.2", "2.0", "3.0.0"]
ALPM = [
    ("1:1.0-1", "2.0-1", 1),
    ("1.0-2", "1.0-1", 1),
    ("1.0", "1.0-1", 0),  # pkgrel only compared when both have one
    ("9.7p1-2", "9.8p1-1", -1),
    ("2.37-2", "2.37-1", 1),
    ("1:1.3-1", "1.3.1-1", 1),
]

PEP440 = [
    ("1.0", "1.0.0", 0),
    ("1.0rc1", "1.0", -1),
    ("1.0a1", "1.0b1", -1),
    ("1.0.dev1", "1.0a1", -1),
    ("1.0.post1", "1.0", 1),
    ("1.0+local", "1.0", 1),
    ("1!0.1", "2.0", 1),
    ("2.10", "2.9", 1),
    ("3.1.3", "3.1.2", 1),
    ("1.0.post1.dev1", "1.0.post1", -1),
    ("1.0rc1.post1", "1.0rc1", 1),
    ("1.0-1", "1.0", 1),  # implicit post release
    ("1.0.0RC1", "1.0rc1", 0),
]

SEMVER = [
    ("1.0.0-alpha", "1.0.0", -1),
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("1.0.0-beta.2", "1.0.0-beta.11", -1),
    ("1.0.0-rc.1", "1.0.0", -1),
    ("v1.2.3", "1.2.3", 0),
    ("1.2", "1.2.0", 0),
    ("1.10.0", "1.9.0", 1),
    ("1.0.0+build.5", "1.0.0", 0),
    ("0.0.0-20210101000000-abcdef", "0.0.1", -1),
]


def _check(ptype: T, a: str, b: str, expected: int) -> None:
    assert compare(ptype, a, b) == expected, (a, b)
    assert compare(ptype, b, a) == -expected, (b, a)


@pytest.mark.parametrize(("a", "b", "expected"), DPKG)
def test_dpkg(a: str, b: str, expected: int) -> None:
    _check(T.DEB, a, b, expected)


@pytest.mark.parametrize(("a", "b", "expected"), RPM)
def test_rpm(a: str, b: str, expected: int) -> None:
    _check(T.RPM, a, b, expected)


@pytest.mark.parametrize(("a", "b", "expected"), APK)
def test_apk(a: str, b: str, expected: int) -> None:
    _check(T.APK, a, b, expected)


@pytest.mark.parametrize(("a", "b", "expected"), ALPM)
def test_alpm(a: str, b: str, expected: int) -> None:
    _check(T.ALPM, a, b, expected)


@pytest.mark.parametrize("chain", [ALPM_CHAIN, ALPM_CHAIN2])
def test_alpm_vercmp_manpage_order(chain: list[str]) -> None:
    for i, lower in enumerate(chain):
        for higher in chain[i + 1 :]:
            _check(T.ALPM, lower, higher, -1)


@pytest.mark.parametrize(("a", "b", "expected"), PEP440)
def test_pep440(a: str, b: str, expected: int) -> None:
    _check(T.PYPI, a, b, expected)


@pytest.mark.parametrize(("a", "b", "expected"), SEMVER)
@pytest.mark.parametrize("ptype", [T.NPM, T.GOLANG, T.CARGO, T.MAVEN, T.GENERIC])
def test_semver(ptype: T, a: str, b: str, expected: int) -> None:
    _check(ptype, a, b, expected)


@pytest.mark.parametrize("ptype", list(T))
@pytest.mark.parametrize("junk", ["", ":", "-", "~", "^^", "1:", "-r", "_", "1..2", "é1"])
def test_never_raises(ptype: T, junk: str) -> None:
    assert compare(ptype, junk, junk) == 0
    assert compare(ptype, junk, "1.0") in (-1, 0, 1)


def test_sort_versions() -> None:
    got = sort_versions(T.DEB, ["1.0-1", "1.0~rc1-1", "1:0.5-1", "1.0-1", "1.0+b1-1"])
    assert got == ["1.0~rc1-1", "1.0-1", "1.0+b1-1", "1:0.5-1"]


@pytest.mark.parametrize(
    ("eco", "ptype"),
    [
        ("Debian:12", T.DEB),
        ("Ubuntu:Pro:22.04:LTS", T.DEB),
        ("Alpine:v3.20", T.APK),
        ("Wolfi", T.APK),
        ("Red Hat:enterprise_linux:9::baseos", T.RPM),
        ("SUSE:Linux Enterprise Server 15 SP6", T.RPM),
        ("TuxCare:Ubuntu:20.04", T.DEB),
        ("TuxCare:CentOS:7", T.RPM),
        ("PyPI", T.PYPI),
        ("crates.io", T.CARGO),
        ("Nonexistent:1", None),
    ],
)
def test_ecosystem_package_type(eco: str, ptype: T | None) -> None:
    assert ecosystem_package_type(eco) == ptype
