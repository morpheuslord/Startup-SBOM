"""parse_target: schemes, auto-detection and strict reference validation."""

from __future__ import annotations

import sys
from pathlib import Path

import imgbuild
import pytest

from startup_sbom.errors import TargetError
from startup_sbom.sources import TargetSpec, parse_target, validate_spec
from startup_sbom.sources.validate import (
    blob_name,
    is_container_ref,
    is_image_ref,
    validate_container_ref,
    validate_image_ref,
)


def test_dir_and_auto_dir(tmp_path: Path) -> None:
    assert parse_target(f"dir:{tmp_path}") == TargetSpec("dir", str(tmp_path))
    assert parse_target(str(tmp_path)) == TargetSpec("dir", str(tmp_path))


def test_auto_oci_dir(tmp_path: Path) -> None:
    imgbuild.write_dir(tmp_path, imgbuild.oci_files([("amd64", None, [b""])]))
    assert parse_target(str(tmp_path)).scheme == "oci-dir"


def test_auto_file_is_archive(tmp_path: Path) -> None:
    f = tmp_path / "x.tar"
    f.write_bytes(imgbuild.tar_bytes([("a", "f", "1")]))
    assert parse_target(str(f)) == TargetSpec("archive", str(f))
    assert parse_target(f"tar:{f}") == TargetSpec("tar", str(f))
    assert parse_target(f"file:{f}").scheme == "tar"
    assert parse_target(f"docker-archive:{f}").scheme == "docker-archive"
    assert parse_target(f"oci-archive:{f}").scheme == "oci-archive"


@pytest.mark.skipif(sys.platform == "win32", reason="NTFS: ':' starts an alternate data stream")
def test_existing_path_named_like_scheme(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "docker:x").write_bytes(b"")
    assert parse_target("docker:x") == TargetSpec("archive", "docker:x")


def test_host() -> None:
    assert parse_target("host:") == TargetSpec("host", "/")
    assert parse_target("host:/") == TargetSpec("host", "/")
    with pytest.raises(TargetError):
        parse_target("host:/etc")


@pytest.mark.parametrize(
    ("spec", "scheme"),
    [
        ("docker:nginx", "docker"),
        ("docker:nginx:1.27", "docker"),
        ("podman:ghcr.io/org/app:v1", "podman"),
        ("nerdctl:localhost:5000/a/b@sha256:" + "a" * 64, "nerdctl"),
        ("docker-container:web_1", "docker-container"),
        ("docker-image:alpine:3.20", "docker-image"),
        ("container:" + "f" * 64, "container"),
        ("image:sha256:" + "b" * 64, "image"),
        ("DOCKER:nginx", "docker"),
    ],
)
def test_engine_refs(spec: str, scheme: str) -> None:
    ts = parse_target(spec)
    assert ts.scheme == scheme
    assert ts.reference == spec.split(":", 1)[1]


@pytest.mark.parametrize(
    "ref",
    ["../../x", "/abs", "-rf", "a;b", "--help", "nginx latest", "a//b", "NGINX:latest:x", "$(id)"],
)
def test_engine_refs_rejected(ref: str) -> None:
    with pytest.raises(TargetError):
        parse_target(f"docker:{ref}")
    with pytest.raises(TargetError):
        parse_target(f"docker-image:{ref}")


def test_container_scheme_rejects_image_syntax() -> None:
    with pytest.raises(TargetError):
        parse_target("docker-container:nginx:latest")


def test_bare_name_rejected_with_hint() -> None:
    with pytest.raises(TargetError, match=r"docker:nginx:latest"):
        parse_target("nginx:latest")
    with pytest.raises(TargetError, match="docker:nginx"):
        parse_target("nginx")
    with pytest.raises(TargetError, match=r"docker:ghcr\.io/org/app:v1"):
        parse_target("ghcr.io/org/app:v1")


def test_missing_paths(tmp_path: Path) -> None:
    with pytest.raises(TargetError, match="does not exist"):
        parse_target(str(tmp_path / "nope"))
    with pytest.raises(TargetError, match="does not exist"):
        parse_target(f"tar:{tmp_path / 'nope.tar'}")
    f = tmp_path / "f"
    f.write_bytes(b"")
    with pytest.raises(TargetError, match="not a directory"):
        parse_target(f"dir:{f}")
    with pytest.raises(TargetError, match="expected a file"):
        parse_target(f"tar:{tmp_path}")


def test_registry_and_unknown() -> None:
    with pytest.raises(TargetError, match="skopeo"):
        parse_target("registry:nginx")
    with pytest.raises(TargetError):
        parse_target("")
    with pytest.raises(TargetError):
        parse_target("docker:")
    with pytest.raises(TargetError):
        parse_target("a\x00b")


def test_validate_spec_rechecks() -> None:
    with pytest.raises(TargetError):
        validate_spec(TargetSpec("docker", "-H=tcp://evil"))
    with pytest.raises(TargetError):
        validate_spec(TargetSpec("bogus", "x"))


def test_reference_grammar() -> None:
    assert is_image_ref("localhost:5000/a/b@sha256:" + "0" * 64)
    assert is_image_ref("ghcr.io/org/app:v1")
    assert not is_image_ref("NGINX")
    assert not is_image_ref("img:tag;rm -rf /")
    assert not is_image_ref("a:" + "t" * 129)
    assert is_container_ref("/web") is False
    assert is_container_ref("web.1-a_b")
    assert not is_container_ref("a")
    validate_container_ref("abcd")
    validate_image_ref("busybox")
    with pytest.raises(TargetError):
        validate_container_ref("../x")


def test_blob_name_rejects_traversal() -> None:
    assert blob_name("sha256:" + "a" * 64) == "blobs/sha256/" + "a" * 64
    for bad in ("sha256:../../../../etc/passwd", "md5:abc", None, 3, "sha256:" + "A" * 64):
        with pytest.raises(TargetError):
            blob_name(bad)
