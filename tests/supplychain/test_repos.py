"""Repository provenance per package manager."""

from __future__ import annotations

import gzip
import io
import lzma
import tarfile
from collections.abc import Callable

from backports import zstd
from sc_helpers import make_pgp_key, pkg

from fsbuilder import File
from startup_sbom.context import ScanContext
from startup_sbom.models import OSInfo, PackageType
from startup_sbom.rootfs import RootFS
from startup_sbom.supplychain.repos import (
    LOCAL_BUILD,
    NOT_IN_REPO,
    THIRD_PARTY,
    UNKNOWN_KEY,
    UNSIGNED,
    VERSION_MISMATCH,
    analyze_repositories,
    apt_uri_to_filename,
    parse_pgp_keys,
)

LISTS = "/var/lib/apt/lists"
DOCKER_LIST = "download.docker.com_linux_debian_dists_bookworm_stable_binary-amd64_Packages"

DEBIAN_PACKAGES = b"""Package: bash
Version: 5.2.15-2+b2
Architecture: amd64
Maintainer: Matthias Klose <doko@debian.org>
Description: GNU Bourne Again SHell
 continuation line: not a field

Package: openssl
Version: 3.0.11-1~deb12u2
Architecture: amd64

Package: tzdata
Version: 2024a-0+deb12u1
Architecture: all
"""
DOCKER_PACKAGES = b"""Package: docker-ce
Version: 5:27.0.3-1~debian.12~bookworm
Architecture: amd64
"""


def _apt_fs() -> dict[str, object]:
    return {
        "/etc/apt/sources.list.d/debian.sources": (
            "Types: deb\nURIs: http://deb.debian.org/debian\nSuites: bookworm bookworm-updates\n"
            "Components: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
        ),
        "/etc/apt/sources.list.d/docker.list": (
            "# Docker\ndeb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] "
            "https://download.docker.com/linux/debian bookworm stable\n"
        ),
        "/etc/apt/sources.list.d/local.list": "deb [trusted=yes] http://repo.example.com/apt ./\n",
        f"{LISTS}/deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.gz": File(
            gzip.compress(DEBIAN_PACKAGES)
        ),
        f"{LISTS}/deb.debian.org_debian_dists_bookworm_InRelease": (
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Debian\nLabel: Debian\n"
            "Suite: stable\nCodename: bookworm\nSHA256:\n abc 1 main/binary-amd64/Packages\n"
        ),
        f"{LISTS}/{DOCKER_LIST}.xz": File(lzma.compress(DOCKER_PACKAGES)),
        f"{LISTS}/deb.debian.org_debian_dists_bookworm-updates_main_binary-amd64_Packages.lz4": (
            File(b"\x04\x22\x4d\x18garbage")
        ),
        f"{LISTS}/lock": "",
    }


def test_apt_uri_mangling() -> None:
    assert apt_uri_to_filename("http://deb.debian.org/debian") == "deb.debian.org_debian"
    assert apt_uri_to_filename("https://user:pw@h.example/a_b~c") == "h.example_a%5fb%7ec"


def test_apt_exact_mismatch_missing_and_third_party(
    make_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(make_fs(_apt_fs()))  # type: ignore[arg-type]
    ctx.os = OSInfo(id="debian", version_id="12", family="debian")
    bash = pkg("bash", "5.2.15-2+b2")
    openssl = pkg("openssl", "3.0.9-1")
    tzdata = pkg("tzdata", "2024a-0+deb12u1", arch="all")
    docker = pkg("docker-ce", "5:27.0.3-1~debian.12~bookworm")
    mytool = pkg("mytool", "1.0")
    packages = [bash, openssl, tzdata, docker, mytool]
    res = analyze_repositories(ctx, packages)
    res.apply(packages)

    assert bash.repository == "deb.debian.org/debian bookworm/main"
    assert bash.provenance_flags == []
    assert tzdata.repository == "deb.debian.org/debian bookworm/main"
    assert openssl.repository is None
    assert openssl.provenance_flags == [VERSION_MISMATCH]
    assert docker.repository == "download.docker.com/linux/debian bookworm/stable"
    assert docker.provenance_flags == [THIRD_PARTY]
    assert mytool.provenance_flags == [NOT_IN_REPO]

    repos = res.repositories
    assert repos["deb.debian.org/debian bookworm/main"].official is True
    assert repos["deb.debian.org/debian bookworm/main"].origin == "Debian"
    assert repos["download.docker.com/linux/debian bookworm/stable"].third_party
    assert repos["repo.example.com/apt ."].signed is False
    assert any("lz4" in lim for lim in ctx.limitations)


def test_apt_mirror_is_not_third_party(
    make_dir_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    fs = make_dir_fs(
        {
            "/etc/apt/sources.list": "deb http://mirror.example.org/debian bookworm main\n",
            f"{LISTS}/mirror.example.org_debian_dists_bookworm_main_binary-amd64_Packages": File(
                DEBIAN_PACKAGES
            ),
            f"{LISTS}/mirror.example.org_debian_dists_bookworm_Release": "Origin: Debian\n",
        }
    )
    ctx = make_ctx(fs)
    ctx.os = OSInfo(id="debian", version_id="12")
    bash = pkg("bash", "5.2.15-2+b2")
    res = analyze_repositories(ctx, [bash])
    res.apply([bash])
    assert bash.repository == "mirror.example.org/debian bookworm/main"
    assert bash.provenance_flags == []


def test_apt_without_lists_is_a_limitation(
    make_dir_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(
        make_dir_fs({"/etc/apt/sources.list": "deb http://deb.debian.org/debian x main\n"})
    )
    ctx.os = OSInfo(id="debian")
    bash = pkg("bash", "5.2")
    res = analyze_repositories(ctx, [bash])
    res.apply([bash])
    assert bash.provenance_flags == []
    assert any("apt package lists absent" in lim for lim in ctx.limitations)


def test_apt_hostile_inputs_do_not_crash(
    make_dir_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    fs = make_dir_fs(
        {
            "/etc/apt/sources.list": "deb [broken http://x\ndeb\n\x00\xff garbage\n",
            "/etc/apt/sources.list.d/x.sources": "Types deb\n\n\n:::\n",
            f"{LISTS}/x_dists_y_main_binary-amd64_Packages.gz": File(b"\x1f\x8bnot gzip"),
            f"{LISTS}/z_dists_y_main_binary-amd64_Packages.xz": File(b"\xfd7zXZ\x00broken"),
        }
    )
    ctx = make_ctx(fs)
    res = analyze_repositories(ctx, [pkg("bash", "1")])
    assert isinstance(res.repositories, dict)


# --------------------------------------------------------------------------- rpm
def test_rpm_keys_unsigned_third_party_and_insecure_repo(
    make_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    fed_id, fed_fp, fed_key = make_pgp_key("Fedora (44) <fedora-44-primary@fedoraproject.org>", 1)
    ts_id, _ts_fp, ts_key = make_pgp_key(
        "Tailscale Inc. (Package repository signing key) <info@tailscale.com>", 2
    )
    fs = make_fs(
        {
            "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary": File(fed_key),
            "/etc/pki/rpm-gpg/tailscale.asc": File(ts_key),
            "/etc/yum.repos.d/fedora.repo": (
                "[fedora]\nname=Fedora $releasever\n"
                "metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever\n"
                "enabled=1\ngpgcheck=1\n"
                "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-primary\n"
            ),
            "/etc/yum.repos.d/tailscale.repo": (
                "[tailscale-stable]\nname=Tailscale stable\n"
                "baseurl=https://pkgs.tailscale.com/stable/fedora/$basearch\nenabled=1\n"
                "gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/tailscale.asc\n"
            ),
            "/etc/yum.repos.d/sketchy.repo": (
                "[sketchy]\nbaseurl=http://rpm.example.net/el\ngpgcheck=0\n"
            ),
            "/etc/yum.repos.d/broken.repo": "no section header\n=",
        }
    )
    ctx = make_ctx(fs)
    ctx.os = OSInfo(id="fedora", version_id="44", family="fedora")
    rpm_t = PackageType.RPM
    gpg = pkg(
        "gpg-pubkey",
        f"{fed_id[-8:]}-6612a3b0",
        rpm_t,
        summary="Fedora (44) <fedora-44-primary@fedoraproject.org> public key",
    )
    bash = pkg(
        "bash",
        "5.3.0-2.fc44",
        rpm_t,
        vendor="Fedora Project",
        signing_key=fed_id,
        signed=True,
        source_name="bash",
    )
    ts = pkg(
        "tailscale", "1.88.1-1", rpm_t, vendor="Tailscale Inc.", signing_key=ts_id, signed=True
    )
    agent = pkg("custom-agent", "0.1-1", rpm_t, signed=False)
    odd = pkg(
        "odd",
        "1-1",
        rpm_t,
        vendor="Fedora Project",
        signing_key="deadbeefdeadbeef",
        signed=True,
        source_name="odd",
    )
    packages = [gpg, bash, ts, agent, odd]
    res = analyze_repositories(ctx, packages)
    res.apply(packages)

    assert bash.provenance_flags == []
    assert bash.repository == "fedora"
    assert ts.repository == "tailscale-stable"
    assert ts.provenance_flags == [THIRD_PARTY]
    assert agent.provenance_flags == [LOCAL_BUILD, UNSIGNED]
    assert odd.provenance_flags == [UNKNOWN_KEY]
    assert res.repositories["sketchy"].signed is False
    assert res.repositories["sketchy"].third_party
    assert res.repositories["fedora"].official is True
    assert [k.uid for k in res.third_party_keys] == [
        "Tailscale Inc. (Package repository signing key) <info@tailscale.com>"
    ]
    keys = parse_pgp_keys(fed_key, "x")
    assert keys[0].fingerprint == fed_fp
    assert keys[0].key_id == fed_id


# --------------------------------------------------------------------------- apk
def _tar_gz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_apk_index_checksums(
    make_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    index = (
        b"C:Q1aaaa=\nP:musl\nV:1.2.5-r0\nA:x86_64\n\n"
        b"C:Q1bbbb=\nP:busybox\nV:1.36.1-r29\nA:x86_64\n\n"
        b"C:Q1cccc=\nP:zlib\nV:1.3.1-r1\nA:x86_64\n"
    )
    fs = make_fs(
        {
            "/etc/apk/repositories": (
                "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n"
                "@corp https://packages.example.com/apk\n# comment\n"
            ),
            "/etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub": "k",
            "/etc/apk/keys/corp.rsa.pub": "k",
            "/var/cache/apk/APKINDEX.00000000.tar.gz": File(
                _tar_gz({".SIGN.RSA.x": b"sig", "DESCRIPTION": b"v3.20", "APKINDEX": index})
            ),
        }
    )
    ctx = make_ctx(fs)
    ctx.os = OSInfo(id="alpine", version_id="3.20.3")
    apk_t = PackageType.APK
    musl = pkg("musl", "1.2.5-r0", apk_t, properties={"apk:checksum": "Q1aaaa="})
    busybox = pkg("busybox", "1.36.1-r29", apk_t, properties={"apk:checksum": "Q1XXXX="})
    zlib = pkg("zlib", "1.3.0-r0", apk_t)
    corp = pkg("corp-agent", "2.0-r0", apk_t)
    packages = [musl, busybox, zlib, corp]
    res = analyze_repositories(ctx, packages)
    res.apply(packages)
    assert musl.repository == "apk cache APKINDEX.00000000.tar.gz"
    assert musl.provenance_flags == []
    assert busybox.provenance_flags == ["repo_checksum_mismatch"]
    assert zlib.provenance_flags == [VERSION_MISMATCH]
    assert corp.provenance_flags == [NOT_IN_REPO]
    assert res.repositories["packages.example.com/apk (@corp)"].third_party
    assert res.repositories["dl-cdn.alpinelinux.org/alpine/v3.20/main"].official is True
    assert [k.key_id for k in res.third_party_keys] == ["corp.rsa.pub"]


# --------------------------------------------------------------------------- pacman
def _sync_db(names: list[str], *, compress: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for n in names:
            d = tarfile.TarInfo(n + "/")
            d.type = tarfile.DIRTYPE
            tf.addfile(d)
            info = tarfile.TarInfo(n + "/desc")
            data = f"%NAME%\n{n}\n".encode()
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    return gzip.compress(raw) if compress == "gz" else zstd.compress(raw)


def test_pacman_local_build_foreign_and_third_party(
    make_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    fs = make_fs(
        {
            "/etc/pacman.conf": (
                "[options]\nSigLevel = Required DatabaseOptional\n\n"
                "[core]\nInclude = /etc/pacman.d/mirrorlist\n\n"
                "[chaotic-aur]\nSigLevel = Never\nServer = https://cdn-mirror.chaotic.cx/$repo/$arch\n"
            ),
            "/etc/pacman.d/mirrorlist": "Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n",
            "/var/lib/pacman/sync/core.db": File(
                _sync_db(["glibc-2.40-1", "linux-6.11.1-1"], compress="gz")
            ),
            "/var/lib/pacman/sync/chaotic-aur.db": File(_sync_db(["yay-12.3.5-1"], compress="zst")),
        }
    )
    ctx = make_ctx(fs)
    ctx.os = OSInfo(id="arch")
    alpm_t = PackageType.ALPM
    glibc = pkg("glibc", "2.40-1", alpm_t, packager="Frederik Schwan <freswa@archlinux.org>")
    linux = pkg("linux", "6.10.9-1", alpm_t)
    yay = pkg("yay", "12.3.5-1", alpm_t)
    mine = pkg("mypkg", "1.0-1", alpm_t, packager="Unknown Packager")
    packages = [glibc, linux, yay, mine]
    res = analyze_repositories(ctx, packages)
    res.apply(packages)
    assert glibc.repository == "core"
    assert glibc.provenance_flags == []
    assert linux.provenance_flags == [VERSION_MISMATCH]
    assert yay.repository == "chaotic-aur"
    assert yay.provenance_flags == [THIRD_PARTY]
    assert mine.provenance_flags == [LOCAL_BUILD, NOT_IN_REPO]
    assert res.repositories["chaotic-aur"].signed is False
    assert res.repositories["core"].official is True
    assert res.repositories["core"].url == "https://geo.mirror.pkgbuild.com/$repo/os/$arch"


def test_apt_overlong_line_is_bounded(
    make_dir_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    data = b"X-Junk: " + b"A" * 300_000 + b"\n\n" + DEBIAN_PACKAGES
    fs = make_dir_fs(
        {
            "/etc/apt/sources.list": "deb http://deb.debian.org/debian bookworm main\n",
            f"{LISTS}/deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages": File(data),
        }
    )
    ctx = make_ctx(fs)
    ctx.os = OSInfo(id="debian")
    bash = pkg("bash", "5.2.15-2+b2")
    res = analyze_repositories(ctx, [bash])
    assert res.packages[bash.id].repository == "deb.debian.org/debian bookworm/main"


def test_unknown_distro_disables_third_party_detection(
    make_dir_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(make_dir_fs({}))
    ctx.os = OSInfo(id="mystery")
    analyze_repositories(ctx, [pkg("bash", "1")])
    assert any("not recognised" in lim for lim in ctx.limitations)
