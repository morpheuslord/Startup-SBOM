"""open_target on tarballs, docker-archives and OCI layouts built in-process."""

from __future__ import annotations

import gzip
import io
import json
import os
import tarfile
from pathlib import Path

import imgbuild
import pytest

from startup_sbom.errors import TargetError
from startup_sbom.sources import open_target
from startup_sbom.sources.oci import Platform

COMPRESSIONS = [None, "gzip", "xz", "bzip2", "zstd"]


def _assert_flattened(fs: object) -> None:
    from startup_sbom.rootfs import RootFS

    assert isinstance(fs, RootFS)
    assert not fs.exists("/etc/shadow")  # whiteout in layer 2
    assert not fs.exists("/srv/data/old.txt")  # opaque dir in layer 2
    assert fs.read_text("/srv/data/new.txt") == "new"
    assert "app:x:1000" in fs.read_text("/etc/passwd")  # layer 3 wins
    assert fs.stat("/bin/sudo").is_setuid  # through the usr-merge symlink
    assert not fs.lexists("/srv/data/.wh..wh..opq")


# --------------------------------------------------------------------------- rootfs tarballs
@pytest.mark.parametrize("kind", COMPRESSIONS)
def test_rootfs_tarball_compressions(tmp_path: Path, scratch: Path, kind: str | None) -> None:
    data = imgbuild.tar_bytes([*imgbuild.BASE, ("etc/.wh.keep", "f", "real file")])
    f = tmp_path / f"root.tar.{kind or 'raw'}"
    f.write_bytes(imgbuild.compress(data, kind))
    for spec in (f"tar:{f}", str(f)):
        with open_target(spec) as acq:
            assert acq.target.kind == "tar"
            assert acq.container is None
            assert not acq.live_host
            assert acq.fs.stat("/usr/bin/sudo").is_setuid
            assert acq.fs.read_text("/etc/shadow").startswith("root:")
            # flattened export: whiteout processing is off
            assert acq.fs.read_text("/etc/.wh.keep") == "real file"
        assert imgbuild.leftovers(scratch) == []


def test_tar_scheme_on_image_archive_warns(tmp_path: Path, scratch: Path) -> None:
    f = imgbuild.write_outer(
        tmp_path / "img.tar", imgbuild.docker_legacy(imgbuild.default_layers())
    )
    with open_target(f"tar:{f}") as acq:
        assert any("docker-archive" in w for w in acq.warnings)


# --------------------------------------------------------------------------- docker-archive
@pytest.mark.parametrize("outer", [None, "gzip", "zstd"])
def test_docker_archive_legacy(tmp_path: Path, scratch: Path, outer: str | None) -> None:
    f = imgbuild.write_outer(
        tmp_path / "save.tar", imgbuild.docker_legacy(imgbuild.default_layers()), outer
    )
    for spec in (f"docker-archive:{f}", str(f)):
        with open_target(spec) as acq:
            assert acq.target.kind == "docker-archive"
            assert acq.target.platform == "linux/amd64"
            assert acq.target.digest
            assert acq.target.digest.startswith("sha256:")
            _assert_flattened(acq.fs)
            info = acq.container
            assert info is not None
            assert info.kind == "image"
            assert info.engine == "archive"
            assert info.image == "lab:1"
            assert info.user == "app"
            assert info.entrypoint[0] == "/usr/bin/app"
            assert info.cmd == ["serve"]
            assert info.exposed_ports == ["8080/tcp"]
            assert info.working_dir == "/srv"
            assert info.env_keys == ["DB_PASSWORD", "INNOCENT", "PATH"]
            assert info.redacted_env_keys == ["DB_PASSWORD", "INNOCENT"]
            dumped = info.model_dump_json()
            for secret in ("hunter2", "AKIAABCDEFGHIJKLMNOP", "sw0rdfish", '/usr/bin"'):
                assert secret not in dumped
            # metadata is out-of-band: nothing injected into the tree
            assert acq.fs.listdir("/") == ["bin", "etc", "srv", "usr"]
            assert not acq.fs.exists("/.docker_info.json")
        assert imgbuild.leftovers(scratch) == []


def test_uncompressed_members_are_zero_copy(tmp_path: Path, scratch: Path) -> None:
    f = imgbuild.write_outer(
        tmp_path / "save.tar", imgbuild.docker_legacy(imgbuild.default_layers())
    )
    with open_target(f"docker-archive:{f}") as acq:
        ws = acq._workspace
        assert ws is not None
        assert os.listdir(ws.path) == []
        assert ws.used == 0


def test_compressed_layers_decompressed_once(tmp_path: Path, scratch: Path) -> None:
    layers = [imgbuild.compress(raw, "gzip") for raw in imgbuild.default_layers()]
    f = imgbuild.write_outer(tmp_path / "save.tar", imgbuild.docker_legacy(layers))
    with open_target(f"docker-archive:{f}") as acq:
        ws = acq._workspace
        assert ws is not None
        assert len(os.listdir(ws.path)) == 3
        _assert_flattened(acq.fs)
        path = ws.path
    assert not os.path.exists(path)


def test_docker_archive_directory(tmp_path: Path, scratch: Path) -> None:
    d = imgbuild.write_dir(tmp_path / "save", imgbuild.docker_legacy(imgbuild.default_layers()))
    with open_target(f"docker-archive:{d}") as acq:
        _assert_flattened(acq.fs)


def test_docker_archive_dir_refuses_traversal_and_symlinks(tmp_path: Path, scratch: Path) -> None:
    (tmp_path / "outside.json").write_text(json.dumps(imgbuild.image_config()))
    files = imgbuild.docker_legacy(imgbuild.default_layers())
    manifest = json.loads(files["manifest.json"])
    manifest[0]["Config"] = "../outside.json"
    files["manifest.json"] = json.dumps(manifest).encode()
    d = imgbuild.write_dir(tmp_path / "save", files)
    with pytest.raises(TargetError, match="missing"):
        open_target(f"docker-archive:{d}")

    files = imgbuild.docker_legacy(imgbuild.default_layers())
    d2 = imgbuild.write_dir(tmp_path / "save2", files)
    (d2 / "l0" / "layer.tar").unlink()
    try:
        os.symlink(tmp_path / "outside.json", d2 / "l0" / "layer.tar")
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(TargetError):
        open_target(f"docker-archive:{d2}")
    assert imgbuild.leftovers(scratch) == []


def test_docker25_oci_in_save(tmp_path: Path, scratch: Path) -> None:
    raws = imgbuild.default_layers()
    files = imgbuild.oci_files([("amd64", None, raws), ("arm64", "v8", raws[:2])], compression=None)
    idx = json.loads(files["index.json"])
    nested = json.loads(files[imgbuild.blob_path(idx["manifests"][0]["digest"])])
    man = json.loads(files[imgbuild.blob_path(nested["manifests"][0]["digest"])])
    files["manifest.json"] = json.dumps(
        [
            {
                "Config": imgbuild.blob_path(man["config"]["digest"]),
                "RepoTags": ["lab:25"],
                "Layers": [imgbuild.blob_path(layer["digest"]) for layer in man["layers"]],
            }
        ]
    ).encode()
    f = imgbuild.write_outer(tmp_path / "docker25.tar", files)
    with open_target(str(f), platform="linux/amd64") as acq:
        assert acq.target.kind == "docker-archive"
        _assert_flattened(acq.fs)
        assert acq._workspace is not None
        assert os.listdir(acq._workspace.path) == []
    with open_target(str(f)) as acq:
        assert acq.container is not None
        assert acq.container.image == "lab:25"
    # explicit platform uses the OCI index, which can select other platforms
    with open_target(str(f), platform="linux/arm64/v8") as acq:
        assert "app:x" not in acq.fs.read_text("/etc/passwd")
        assert acq.target.platform == "linux/arm64/v8"


def test_docker_archive_windows_image_refused(tmp_path: Path, scratch: Path) -> None:
    cfg = imgbuild.image_config(os_="windows")
    f = imgbuild.write_outer(tmp_path / "w.tar", imgbuild.docker_legacy([b""], cfg))
    with pytest.raises(TargetError, match="Windows"):
        open_target(f"docker-archive:{f}")
    assert imgbuild.leftovers(scratch) == []


# --------------------------------------------------------------------------- OCI
@pytest.mark.parametrize("compression", [None, "gzip", "zstd", "xz"])
def test_oci_dir_platform_selection(tmp_path: Path, scratch: Path, compression: str | None) -> None:
    raws = imgbuild.default_layers()
    files = imgbuild.oci_files(
        [("amd64", None, raws), ("arm64", "v8", raws[:2])], compression=compression
    )
    d = imgbuild.write_dir(tmp_path / "oci", files)
    with open_target(f"oci-dir:{d}", platform="linux/amd64") as acq:
        assert acq.target.kind == "oci-dir"
        assert acq.target.platform == "linux/amd64"
        assert acq.target.digest
        assert acq.target.digest.startswith("sha256:")
        _assert_flattened(acq.fs)
        assert acq.container is not None
        assert acq.container.image == "1.0"
    for plat in ("linux/arm64", "linux/arm64/v8", "arm64"):
        with open_target(str(d), platform=plat) as acq:
            assert "app:x" not in acq.fs.read_text("/etc/passwd")
    with pytest.raises(TargetError, match=r"available: linux/amd64, linux/arm64/v8"):
        open_target(f"oci-dir:{d}", platform="linux/s390x")
    with pytest.raises(TargetError, match="available"):
        open_target(f"oci-dir:{d}", platform="linux/arm64/v7")
    assert imgbuild.leftovers(scratch) == []


def test_oci_default_platform_follows_host(
    tmp_path: Path, scratch: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raws = imgbuild.default_layers()
    files = imgbuild.oci_files([("amd64", None, raws), ("arm64", "v8", raws[:2])])
    f = imgbuild.write_outer(tmp_path / "oci.tar", files)
    monkeypatch.setattr("platform.machine", lambda: "aarch64")
    with open_target(f"oci-archive:{f}") as acq:
        assert acq.target.kind == "oci-archive"
        assert acq.target.platform == "linux/arm64/v8"
    monkeypatch.setattr("platform.machine", lambda: "AMD64")  # Windows spelling
    with open_target(str(f)) as acq:
        assert acq.target.kind == "oci-archive"
        assert acq.target.platform == "linux/amd64"
    monkeypatch.setattr("platform.machine", lambda: "s390x")
    with pytest.raises(TargetError, match="available"):
        open_target(str(f))


def test_single_platform_image_on_other_host(
    tmp_path: Path, scratch: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = imgbuild.oci_files([("amd64", None, imgbuild.default_layers())], nested=False)
    d = imgbuild.write_dir(tmp_path / "oci", files)
    monkeypatch.setattr("platform.machine", lambda: "arm64")
    with open_target(str(d)) as acq:  # only one choice: use it
        assert acq.target.platform == "linux/amd64"


def test_oci_digest_traversal_rejected(tmp_path: Path, scratch: Path) -> None:
    files = imgbuild.oci_files([("amd64", None, [b""])])
    files["index.json"] = json.dumps(
        {"manifests": [{"mediaType": imgbuild.MT_MANIFEST, "digest": "sha256:../../../etc/passwd"}]}
    ).encode()
    d = imgbuild.write_dir(tmp_path / "oci", files)
    with pytest.raises(TargetError, match="invalid blob digest"):
        open_target(f"oci-dir:{d}")


def test_oci_missing_blob_and_bad_media_type(tmp_path: Path, scratch: Path) -> None:
    raws = imgbuild.default_layers()
    files = imgbuild.oci_files([("amd64", None, raws)], nested=False, attestation=False)
    idx = json.loads(files["index.json"])
    mpath = imgbuild.blob_path(idx["manifests"][0]["digest"])
    man = json.loads(files[mpath])
    del files[imgbuild.blob_path(man["layers"][0]["digest"])]
    d = imgbuild.write_dir(tmp_path / "oci", files)
    with pytest.raises(TargetError, match="not present"):
        open_target(f"oci-dir:{d}")

    files = imgbuild.oci_files([("amd64", None, raws)], nested=False, attestation=False)
    man["layers"][0]["mediaType"] = "application/x-evil"
    files[mpath] = json.dumps(man).encode()  # digest no longer matches: we never trust names
    d2 = imgbuild.write_dir(tmp_path / "oci2", files)
    with pytest.raises(TargetError, match="media type"):
        open_target(f"oci-dir:{d2}")


def test_oci_nesting_bomb(tmp_path: Path, scratch: Path) -> None:
    files: dict[str, bytes] = {"oci-layout": b"{}"}
    child = json.dumps({"manifests": []}).encode()
    for _ in range(8):
        files["blobs/sha256/" + imgbuild.sha(child).split(":")[1]] = child
        child = json.dumps(
            {"mediaType": imgbuild.MT_INDEX, "manifests": [{"digest": imgbuild.sha(child)}]}
        ).encode()
    files["index.json"] = child
    d = imgbuild.write_dir(tmp_path / "oci", files)
    with pytest.raises(TargetError):
        open_target(f"oci-dir:{d}")


# --------------------------------------------------------------------------- hostile input
def test_hostile_members(tmp_path: Path, scratch: Path) -> None:
    data = imgbuild.tar_bytes(
        [
            ("etc/", "d"),
            ("etc/hostname", "f", "image-host"),
            ("../escape", "f", "x"),
            ("/abs/x", "f", "abs"),
            ("esc", "l", "../../../../../etc/hostname"),
            ("proc-trick", "l", "/proc/self/root/etc/passwd"),
            ("hl", "h", "../../etc/passwd"),
        ]
    )
    f = tmp_path / "evil.tar"
    f.write_bytes(data)
    with open_target(f"tar:{f}") as acq:
        fs = acq.fs
        assert fs.read_text("/esc") == "image-host"
        assert fs.read_text("/abs/x") == "abs"
        assert not fs.exists("/escape")
        assert not fs.exists("/proc-trick")
        assert not fs.exists("/hl")
        assert any("rejected" in w for w in acq.warnings)


def test_entry_cap(tmp_path: Path, scratch: Path) -> None:
    members = [(f"f{i}", "f", "") for i in range(300)]
    f = tmp_path / "many.tar"
    f.write_bytes(imgbuild.tar_bytes(members))
    with pytest.raises(TargetError, match="entries"):
        open_target(f"tar:{f}", max_entries=50)
    outer = imgbuild.write_outer(tmp_path / "many-outer.tar", {f"m{i}": b"" for i in range(300)})
    with pytest.raises(TargetError, match="entries"):
        open_target(str(outer), max_entries=50)
    assert imgbuild.leftovers(scratch) == []


def test_decompression_bomb_capped(tmp_path: Path, scratch: Path) -> None:
    payload = imgbuild.tar_bytes([("zeros", "f", b"\0" * (4 * 1024 * 1024))])
    f = tmp_path / "bomb.tar.gz"
    f.write_bytes(gzip.compress(payload))
    assert f.stat().st_size < 64 * 1024
    with pytest.raises(TargetError, match="size limit"):
        open_target(f"tar:{f}", max_bytes=1024 * 1024)
    assert imgbuild.leftovers(scratch) == []


def test_corrupt_inputs(tmp_path: Path, scratch: Path) -> None:
    junk = tmp_path / "junk.tar"
    junk.write_bytes(os.urandom(4096))
    gz = tmp_path / "junk.tar.gz"
    gz.write_bytes(b"\x1f\x8b" + os.urandom(1024))
    truncated = tmp_path / "trunc.tar.xz"
    truncated.write_bytes(imgbuild.compress(imgbuild.tar_bytes(imgbuild.BASE), "xz")[:200])
    bad_manifest = imgbuild.write_outer(tmp_path / "bad.tar", {"manifest.json": b"[{]"})
    for spec in (f"tar:{junk}", f"tar:{gz}", str(truncated), f"docker-archive:{bad_manifest}"):
        with pytest.raises(TargetError):
            open_target(spec)
    assert imgbuild.leftovers(scratch) == []


def test_rootfs_with_manifest_json_is_not_misdetected(tmp_path: Path, scratch: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in (("manifest.json", b'{"not": "docker"}'), ("etc/os-release", b"ID=x\n")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    f = tmp_path / "r.tar"
    f.write_bytes(buf.getvalue())
    with open_target(str(f)) as acq:
        assert acq.target.kind == "tar"
        assert acq.fs.is_file("/etc/os-release")


def test_platform_parse() -> None:
    assert str(Platform.parse("linux/arm64/v8")) == "linux/arm64/v8"
    assert str(Platform.parse("linux/x86_64")) == "linux/amd64"
    with pytest.raises(TargetError):
        Platform.parse("linux/../x")
    with pytest.raises(TargetError):
        open_target("host:", platform="bad platform")


def test_dir_target(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text("ID=x\n")
    with open_target(f"dir:{tmp_path}") as acq:
        assert acq.target.kind == "dir"
        assert acq.fs.is_file("/etc/os-release")
        assert not acq.live_host
