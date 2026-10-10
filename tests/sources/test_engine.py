"""Live engine acquisition with a fake engine (no docker/podman is ever run)."""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

import imgbuild
import pytest

from startup_sbom.errors import TargetError
from startup_sbom.sources import engine, open_target
from startup_sbom.sources.engine import (
    Engine,
    RunResult,
    container_info_from_inspect,
    is_engine_socket,
    run_capture,
    run_streaming,
)

ANY4 = "0.0.0.0"  # noqa: S104 - inspect fixture data
CID = "c" * 64
IMG_ID = "sha256:" + "d" * 64

INSPECT: dict[str, Any] = {
    "Id": CID,
    "Name": "/web",
    "Image": IMG_ID,
    "Platform": "linux",
    "Config": {
        "Image": "nginx:1",
        "User": "",
        "Env": [
            "PATH=/usr/bin",
            "DB_PASSWORD=hunter2",
            "HARMLESS=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
            "PRIVATE=-----BEGIN RSA PRIVATE KEY-----MIIE",
        ],
        "Entrypoint": ["/docker-entrypoint.sh"],
        "Cmd": ["nginx", "-g", "daemon off;", "--token=abc123"],
        "WorkingDir": "/",
        "ExposedPorts": {"80/tcp": {}},
        "Labels": {"maintainer": "x", "api_token": "s3cr3t"},
    },
    "HostConfig": {
        "Privileged": True,
        "CapAdd": ["SYS_ADMIN", "NET_ADMIN"],
        "CapDrop": ["MKNOD"],
        "SecurityOpt": ["seccomp=unconfined"],
        "NetworkMode": "host",
        "PidMode": "host",
        "IpcMode": "private",
        "ReadonlyRootfs": False,
        "PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]},
    },
    "NetworkSettings": {
        "Ports": {
            "80/tcp": [
                {"HostIp": ANY4, "HostPort": "8080"},
                {"HostIp": "::", "HostPort": "8080"},
            ]
        }
    },
    "Mounts": [
        {
            "Type": "bind",
            "Source": "/var/run/docker.sock",
            "Destination": "/var/run/docker.sock",
            "RW": True,
        },
        {
            "Type": "volume",
            "Source": "/var/lib/docker/volumes/d",
            "Destination": "/data",
            "RW": False,
        },
    ],
}
IMAGE_INSPECT: dict[str, Any] = {
    "Id": IMG_ID,
    "RepoTags": ["nginx:1"],
    "RepoDigests": ["nginx@sha256:" + "e" * 64],
    "Os": "linux",
    "Architecture": "arm64",
    "Variant": "v8",
}
SECRETS = ("hunter2", "abc123", "s3cr3t", "eyJhbGciOiJIUzI1NiJ9", "BEGIN RSA")


class FakeEngine:
    """Replaces :func:`engine.run_streaming`; records argv and serves canned output."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.containers: dict[str, dict[str, Any]] = {"web": INSPECT, CID: INSPECT}
        self.images: dict[str, dict[str, Any]] = {IMG_ID: IMAGE_INSPECT, "nginx:1": IMAGE_INSPECT}
        self.export_data = imgbuild.tar_bytes(imgbuild.BASE)
        self.save_data = imgbuild.write_outer_bytes(
            imgbuild.docker_legacy(
                imgbuild.default_layers(), imgbuild.image_config("arm64", variant="v8")
            )
        )
        self.fail: dict[str, int] = {}

    def __call__(
        self, argv: list[str], out: IO[bytes], *, timeout: float, max_bytes: int
    ) -> RunResult:
        self.calls.append(list(argv))
        args = argv[1:]
        assert os.path.isabs(argv[0])
        assert "--" in args
        verb = " ".join(args[: args.index("--")])
        ref = args[args.index("--") + 1]
        if verb in self.fail:
            return RunResult(self.fail[verb], b"boom\x1b[31m", 0)
        if verb == "container inspect":
            return self._json(out, self.containers.get(ref), max_bytes)
        if verb == "image inspect":
            return self._json(out, self.images.get(ref), max_bytes)
        if verb == "export":
            return self._write(out, self.export_data, max_bytes)
        if verb == "image save":
            return self._write(out, self.save_data, max_bytes)
        return RunResult(125, b"unknown command", 0)

    def _json(self, out: IO[bytes], obj: object, max_bytes: int) -> RunResult:
        if obj is None:
            return RunResult(1, b"Error: No such object", 0)
        return self._write(out, json.dumps([obj]).encode(), max_bytes)

    @staticmethod
    def _write(out: IO[bytes], data: bytes, max_bytes: int) -> RunResult:
        if len(data) > max_bytes:
            raise TargetError("output exceeds the size limit")
        out.write(data)
        return RunResult(0, b"", len(data))


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeEngine:
    fe = FakeEngine()
    monkeypatch.setattr(engine, "run_streaming", fe)
    monkeypatch.setattr(
        shutil, "which", lambda name: f"/fake/bin/{name}" if name == "docker" else None
    )
    return fe


def test_container_acquisition(fake: FakeEngine, scratch: Path) -> None:
    with open_target("docker:web") as acq:
        assert acq.target.kind == "container"
        assert acq.target.reference == "docker:web"
        assert acq.target.platform == "linux/arm64/v8"
        assert acq.target.digest == "sha256:" + "e" * 64
        assert acq.fs.stat("/usr/bin/sudo").is_setuid
        assert acq.fs.read_text("/etc/shadow").startswith("root")
        info = acq.container
        assert info is not None
        assert info.kind == "container"
        assert info.engine == "docker"
        assert info.id == CID
        assert info.name == "web"
        assert info.image == "nginx:1"
        assert info.user is None
        assert info.env_keys == ["DB_PASSWORD", "HARMLESS", "PATH", "PRIVATE"]
        assert info.redacted_env_keys == ["DB_PASSWORD", "HARMLESS", "PRIVATE"]
        assert info.labels == {"api_token": "<redacted>", "maintainer": "x"}
        assert info.cmd[-1] == "--token=<redacted>"
        assert info.privileged is True
        assert info.cap_add == ["NET_ADMIN", "SYS_ADMIN"]
        assert info.cap_drop == ["MKNOD"]
        assert info.security_opt == ["seccomp=unconfined"]
        assert info.network_mode == "host"
        assert info.pid_mode == "host"
        assert info.ipc_mode == "private"
        assert info.readonly_rootfs is False
        assert info.port_bindings == ["0.0.0.0:8080->80/tcp", "[::]:8080->80/tcp"]
        assert [m.destination for m in info.mounts] == ["/data", "/var/run/docker.sock"]
        assert info.mounts[0].read_write is False
        assert info.mounts[0].kind == "volume"
        dumped = info.model_dump_json()
        for secret in SECRETS:
            assert secret not in dumped
        assert any("engine socket" in w for w in acq.warnings)
        assert any("volume contents" in w for w in acq.warnings)
        assert not acq.fs.exists("/.docker_info.json")
    assert imgbuild.leftovers(scratch) == []
    verbs = [c[1:] for c in fake.calls]
    assert verbs[0] == ["container", "inspect", "--", "web"]
    assert ["export", "--", CID] in verbs  # exported by immutable id


def test_image_acquisition(fake: FakeEngine, scratch: Path) -> None:
    with open_target("docker:nginx:1", platform="linux/arm64") as acq:
        assert acq.target.kind == "image"
        assert acq.target.digest == "sha256:" + "e" * 64
        info = acq.container
        assert info is not None
        assert info.kind == "image"
        assert info.engine == "docker"
        assert info.image == "nginx:1"
        assert "DB_PASSWORD" in info.redacted_env_keys
        assert "hunter2" not in info.model_dump_json()
    assert imgbuild.leftovers(scratch) == []
    # "nginx:1" is not a container name: no container inspect was attempted
    assert all(c[1:3] != ["container", "inspect"] for c in fake.calls)
    assert ["image", "save", "--", "nginx:1"] in [c[1:] for c in fake.calls]


def test_container_missing_falls_back_to_image(fake: FakeEngine, scratch: Path) -> None:
    fake.images["web"] = IMAGE_INSPECT
    fake.containers.pop("web")
    with open_target("docker:web", platform="linux/arm64") as acq:
        assert acq.target.kind == "image"


def test_not_found_anywhere(fake: FakeEngine, scratch: Path) -> None:
    with pytest.raises(TargetError, match="not found") as ei:
        open_target("docker:ghost")
    assert "\x1b" not in str(ei.value)
    assert imgbuild.leftovers(scratch) == []


@pytest.mark.parametrize("verb", ["export", "image inspect"])
def test_exit_codes_checked(fake: FakeEngine, scratch: Path, verb: str) -> None:
    fake.fail[verb] = 1
    if verb == "export":
        with pytest.raises(TargetError, match="exit 1"):
            open_target("docker-container:web")
    else:  # image metadata is optional for a container: recorded as a warning
        with open_target("docker-container:web") as acq:
            assert any("image metadata unavailable" in w for w in acq.warnings)
        with pytest.raises(TargetError, match="exit 1"):
            open_target("docker-image:nginx:1")
    assert imgbuild.leftovers(scratch) == []


def test_save_failure_and_size_cap(fake: FakeEngine, scratch: Path) -> None:
    fake.fail["image save"] = 125
    with pytest.raises(TargetError, match="exit 125"):
        open_target("docker-image:nginx:1")
    fake.fail.clear()
    with pytest.raises(TargetError, match="size limit"):
        open_target("docker-container:web", max_bytes=100)
    assert imgbuild.leftovers(scratch) == []


def test_hostile_inspect_output(fake: FakeEngine, scratch: Path) -> None:
    fake.containers["web"] = {**INSPECT, "Id": "../../etc"}
    with pytest.raises(TargetError, match="invalid container id"):
        open_target("docker:web")
    assert not any(c[1] == "export" for c in fake.calls)
    fake.containers["web"] = {**INSPECT, "Platform": "windows"}
    with pytest.raises(TargetError, match="Windows"):
        open_target("docker:web")
    assert imgbuild.leftovers(scratch) == []


def test_invalid_json_from_engine(
    fake: FakeEngine, scratch: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bad(argv: list[str], out: IO[bytes], *, timeout: float, max_bytes: int) -> RunResult:
        out.write(b"[{not json")
        return RunResult(0, b"", 10)

    monkeypatch.setattr(engine, "run_streaming", bad)
    with pytest.raises(TargetError, match="invalid JSON"):
        open_target("docker:web")


def test_no_engine(monkeypatch: pytest.MonkeyPatch, scratch: Path) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(TargetError, match="no container engine"):
        open_target("docker:web")
    assert imgbuild.leftovers(scratch) == []


def test_generic_scheme_engine_order(fake: FakeEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def which(name: str) -> str | None:
        seen.append(name)
        return f"/fake/bin/{name}" if name in ("podman", "nerdctl") else None

    monkeypatch.setattr(shutil, "which", which)
    with open_target("container:web") as acq:
        assert acq.container is not None
        assert acq.container.engine == "podman"
    assert seen == ["docker", "podman", "nerdctl"]
    assert fake.calls[0][0].endswith("podman")


def test_refs_validated_before_any_subprocess(fake: FakeEngine) -> None:
    for bad in ("-rf", "a;b", "../../x", "/abs"):
        with pytest.raises(TargetError):
            open_target(f"docker:{bad}")
    assert fake.calls == []


def test_inspect_mapping_tolerates_garbage() -> None:
    info = container_info_from_inspect(
        {"Config": "x", "HostConfig": [], "Mounts": [1, {"Destination": 3}], "Name": 5},
        engine="docker",
    )
    assert info.env_keys == []
    assert info.mounts == []
    assert info.name is None
    binds = container_info_from_inspect(
        {"HostConfig": {"Binds": ["/run/docker.sock:/var/run/docker.sock:ro", "C:\\x:/y"]}},
        engine="docker",
    )
    assert [(m.source, m.destination, m.read_write) for m in binds.mounts] == [
        ("/run/docker.sock", "/var/run/docker.sock", False),
        ("C:\\x", "/y", True),
    ]
    assert is_engine_socket("/run/user/1000/podman/podman.sock")
    assert not is_engine_socket("/data")


# --------------------------------------------------------------------------- real subprocess
STUB = """\
import sys, time
args = sys.argv[1:]
if args[:2] == ["container", "inspect"]:
    sys.stdout.write(open(sys.argv[0] + ".json").read())
elif args[:1] == ["export"]:
    sys.stdout.buffer.write(open(sys.argv[0] + ".tar", "rb").read())
elif args[:1] == ["sleep"]:
    time.sleep(30)
elif args[:1] == ["big"]:
    sys.stdout.buffer.write(b"x" * 300000)
else:
    sys.stderr.write("unknown " + " ".join(args))
    sys.exit(3)
"""


@pytest.fixture
def stub_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[], Path]:
    if os.name != "posix":
        pytest.skip("stub executable needs a POSIX shebang")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "docker"
    exe.write_text(f"#!{sys.executable}\n" + STUB)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    (bindir / "docker.json").write_text(json.dumps([INSPECT]))
    (bindir / "docker.tar").write_bytes(imgbuild.tar_bytes(imgbuild.BASE))
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    return lambda: exe


def test_stub_executable_end_to_end(stub_engine: Callable[[], Path], scratch: Path) -> None:
    stub_engine()
    with open_target("docker-container:web") as acq:
        assert acq.fs.stat("/usr/bin/sudo").is_setuid
        assert acq.container is not None
        assert acq.container.privileged is True
    assert imgbuild.leftovers(scratch) == []


def test_run_streaming_real_process(stub_engine: Callable[[], Path]) -> None:
    exe = str(stub_engine())
    rc, out, err = run_capture([exe, "nope"])
    assert rc == 3
    assert b"unknown nope" in err
    assert out == b""
    buf = io.BytesIO()
    with pytest.raises(TargetError, match="size limit"):
        run_streaming([exe, "big"], buf, timeout=10, max_bytes=1000)
    with pytest.raises(TargetError, match="timed out"):
        run_streaming([exe, "sleep"], io.BytesIO(), timeout=0.5, max_bytes=1000)
    with pytest.raises(TargetError, match="cannot run"):
        run_streaming([str(Path(exe).parent / "missing")], buf, timeout=1, max_bytes=1)
    assert Engine("docker", exe).name == "docker"
