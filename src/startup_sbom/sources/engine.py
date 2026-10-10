"""Live containers and local images through the docker / podman / nerdctl CLIs.

The CLI (never the socket) is used so contexts, Docker Desktop, rootless
engines and podman machine all work the same on every host OS.  Rules:
references are validated before any call; the CLI path comes from
:func:`shutil.which`; argv lists only (no shell); ``--`` precedes every user
operand; stdin is ``/dev/null``; every call has a timeout; every exit code is
checked; large outputs stream to a size-capped file in the scan workspace and
are read through the tar VFS, never extracted.  Engine output is untrusted.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from typing import IO, Any

from startup_sbom.errors import TargetError
from startup_sbom.models import ContainerInfo, ContainerMount, TargetInfo
from startup_sbom.rootfs import LayerBlob
from startup_sbom.sources.archive import Opened, layered_fs, open_image_path
from startup_sbom.sources.compression import CHUNK, Workspace
from startup_sbom.sources.oci import Platform
from startup_sbom.sources.validate import (
    FULL_ID_RE,
    clean,
    clean_argv,
    clean_labels,
    clean_str_list,
    is_container_ref,
    is_image_ref,
    opt_str,
    sanitize_message,
    split_env,
)

log = logging.getLogger(__name__)

ENGINES = ("docker", "podman", "nerdctl")
INSPECT_TIMEOUT = 60.0
EXPORT_TIMEOUT = 3600.0
MAX_INSPECT_BYTES = 32 * 1024 * 1024
MAX_STDERR = 4096

#: scheme -> (engine names to try, mode); mode is "auto" | "container" | "image"
ENGINE_SCHEMES: dict[str, tuple[tuple[str, ...], str]] = {
    "container": (ENGINES, "container"),
    "image": (ENGINES, "image"),
}
for _name in ENGINES:
    ENGINE_SCHEMES[_name] = ((_name,), "auto")
    ENGINE_SCHEMES[f"{_name}-container"] = ((_name,), "container")
    ENGINE_SCHEMES[f"{_name}-image"] = ((_name,), "image")

_ENGINE_SOCKETS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/podman/podman.sock",
    "/var/run/podman/podman.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/crio/crio.sock",
)
_BIND_RE = re.compile(r"^(?P<src>(?:[A-Za-z]:)?[^:]+):(?P<dst>[^:]+)(?::(?P<opts>[^:]*))?$")


@dataclass(frozen=True, slots=True)
class Engine:
    """A container engine CLI resolved to an absolute path."""

    name: str
    path: str


@dataclass(frozen=True, slots=True)
class RunResult:
    """Outcome of an engine CLI call (stdout went to the caller's file)."""

    returncode: int
    stderr: bytes
    size: int


def find_engines(names: tuple[str, ...]) -> list[Engine]:
    """Engines from ``names`` (in order) that exist on ``PATH``."""
    out: list[Engine] = []
    for name in names:
        path = shutil.which(name)
        if path:
            out.append(Engine(name, os.path.abspath(path)))
    return out


# --------------------------------------------------------------------------- subprocess
def run_streaming(argv: list[str], out: IO[bytes], *, timeout: float, max_bytes: int) -> RunResult:
    """Run ``argv`` (no shell) streaming stdout into ``out`` with a byte cap and timeout."""
    timed_out = threading.Event()
    with tempfile.TemporaryFile() as errf:
        try:
            proc = subprocess.Popen(  # noqa: S603 - absolute CLI path, argv list, validated refs
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errf
            )
        except OSError as exc:
            raise TargetError(f"cannot run {os.path.basename(argv[0])}: {exc}") from exc

        def _kill() -> None:
            timed_out.set()
            proc.kill()

        timer = threading.Timer(timeout, _kill)
        timer.daemon = True
        timer.start()
        total = 0
        try:
            assert proc.stdout is not None  # noqa: S101 - stdout=PIPE
            while chunk := proc.stdout.read(CHUNK):
                total += len(chunk)
                if total > max_bytes:
                    proc.kill()
                    raise TargetError(
                        f"{os.path.basename(argv[0])} output exceeds the size limit "
                        f"of {max_bytes} bytes"
                    )
                out.write(chunk)
            rc = proc.wait()
        except BaseException:
            proc.kill()
            proc.wait()
            raise
        finally:
            timer.cancel()
            if proc.stdout is not None:
                proc.stdout.close()
        if timed_out.is_set():
            raise TargetError(f"{os.path.basename(argv[0])} timed out after {timeout:.0f}s")
        errf.seek(0)
        return RunResult(rc, errf.read(MAX_STDERR), total)


def run_capture(argv: list[str], *, timeout: float = INSPECT_TIMEOUT) -> tuple[int, bytes, bytes]:
    """Run a small-output command; return ``(returncode, stdout, stderr)``."""
    with tempfile.TemporaryFile() as buf:
        res = run_streaming(argv, buf, timeout=timeout, max_bytes=MAX_INSPECT_BYTES)
        buf.seek(0)
        return res.returncode, buf.read(), res.stderr


def _fail(engine: Engine, what: str, rc: int, stderr: bytes) -> TargetError:
    return TargetError(f"{engine.name} {what} failed (exit {rc}): {sanitize_message(stderr)}")


def inspect(engine: Engine, kind: str, ref: str) -> tuple[dict[str, Any] | None, str]:
    """``<cli> container|image inspect -- <ref>``; return ``(object or None, error text)``."""
    rc, out, err = run_capture([engine.path, kind, "inspect", "--", ref])
    if rc != 0:
        return None, f"{engine.name} {kind} inspect: exit {rc}: {sanitize_message(err)}"
    try:
        data = json.loads(out)
    except (ValueError, RecursionError) as exc:
        raise TargetError(f"{engine.name} {kind} inspect returned invalid JSON: {exc}") from exc
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise TargetError(f"{engine.name} {kind} inspect returned unexpected output")
    return data[0], ""


def _stream_to_workspace(engine: Engine, args: list[str], ws: Workspace, what: str) -> str:
    path = ws.new_file(".tar")
    with open(path, "wb") as f:
        res = run_streaming(
            [engine.path, *args],
            f,
            timeout=EXPORT_TIMEOUT,
            max_bytes=max(0, ws.max_bytes - ws.used),
        )
    ws.charge(res.size, f"{engine.name} {what}")
    if res.returncode != 0:
        raise _fail(engine, what, res.returncode, res.stderr)
    if res.size == 0:
        raise TargetError(f"{engine.name} {what} produced no output")
    return path


def export_container(engine: Engine, container_id: str, ws: Workspace) -> str:
    """Stream ``<cli> export -- <id>`` into the workspace; return the tar path."""
    if not FULL_ID_RE.match(container_id):
        raise TargetError("engine returned an invalid container id")
    return _stream_to_workspace(engine, ["export", "--", container_id], ws, "export")


def save_image(engine: Engine, ref: str, ws: Workspace) -> str:
    """Stream ``<cli> image save -- <ref>`` into the workspace; return the archive path."""
    if not is_image_ref(ref):
        raise TargetError(f"invalid image reference: {ref!r}")
    return _stream_to_workspace(engine, ["image", "save", "--", ref], ws, "image save")


# --------------------------------------------------------------------------- metadata
def is_engine_socket(path: str | None) -> bool:
    """True if ``path`` is a container engine API socket (host-root equivalent)."""
    if not path:
        return False
    norm = path.replace("\\", "/").rstrip("/")
    return norm in _ENGINE_SOCKETS or norm.endswith(("/docker.sock", "/podman.sock"))


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _mounts(info: dict[str, Any], hc: dict[str, Any]) -> list[ContainerMount]:
    out: list[ContainerMount] = []
    raw = info.get("Mounts")
    if isinstance(raw, list) and raw:
        for m in raw[:1000]:
            if not isinstance(m, dict) or not isinstance(m.get("Destination"), str):
                continue
            out.append(
                ContainerMount(
                    source=opt_str(m.get("Source")),
                    destination=clean(m["Destination"], 1024),
                    read_write=bool(m.get("RW", True)),
                    kind=opt_str(m.get("Type"), 64),
                )
            )
    else:
        for bind in clean_str_list(hc.get("Binds")):
            mt = _BIND_RE.match(bind)
            if mt:
                opts = (mt.group("opts") or "").split(",")
                out.append(
                    ContainerMount(
                        source=mt.group("src"),
                        destination=mt.group("dst"),
                        read_write="ro" not in opts,
                        kind="bind",
                    )
                )
    for mount in out:
        mount.engine_socket = is_engine_socket(mount.destination) or (
            mount.source is not None and is_engine_socket(mount.source)
        )
    return sorted(out, key=lambda m: (m.destination, m.source or ""))


def _port_bindings(info: dict[str, Any], hc: dict[str, Any]) -> list[str]:
    ports = _dict(info.get("NetworkSettings")).get("Ports") or hc.get("PortBindings")
    out: set[str] = set()
    for cport, binds in _dict(ports).items():
        if not isinstance(binds, list):
            continue
        for b in binds[:100]:
            if not isinstance(b, dict):
                continue
            ip = clean(b.get("HostIp") or "0.0.0.0", 64)  # noqa: S104 - descriptive, not a bind
            host_port = clean(b.get("HostPort") or "", 16)
            host = f"[{ip}]" if ":" in ip else ip
            out.add(f"{host}:{host_port}->{clean(cport, 32)}")
    return sorted(out)


def _repo_digest(image_info: dict[str, Any]) -> str | None:
    digests = image_info.get("RepoDigests")
    if isinstance(digests, list):
        for d in digests:
            if isinstance(d, str) and "@" in d:
                return clean(d.rsplit("@", 1)[1], 200)
    return None


def _image_platform(image_info: dict[str, Any]) -> str | None:
    plat = Platform.from_dict(
        {
            "os": image_info.get("Os"),
            "architecture": image_info.get("Architecture"),
            "variant": image_info.get("Variant"),
        }
    )
    return str(plat) if plat else None


def container_info_from_inspect(
    info: dict[str, Any], *, engine: str, image_info: dict[str, Any] | None = None
) -> ContainerInfo:
    """Out-of-band :class:`ContainerInfo` from ``container inspect`` JSON (env values dropped)."""
    cfg = _dict(info.get("Config"))
    hc = _dict(info.get("HostConfig"))
    img = image_info or {}
    keys, redacted = split_env(cfg.get("Env"))
    exposed = cfg.get("ExposedPorts")
    name = opt_str(info.get("Name"), 256)
    privileged = hc.get("Privileged")
    readonly = hc.get("ReadonlyRootfs")
    return ContainerInfo(
        kind="container",
        engine=engine,
        id=opt_str(info.get("Id"), 128),
        name=name.lstrip("/") if name else None,
        image=opt_str(cfg.get("Image"), 512) or opt_str(info.get("ImageName"), 512),
        image_digest=_repo_digest(img) or opt_str(info.get("Image"), 200),
        platform=_image_platform(img) or opt_str(info.get("Platform"), 64),
        entrypoint=clean_argv(cfg.get("Entrypoint")),
        cmd=clean_argv(cfg.get("Cmd")),
        working_dir=opt_str(cfg.get("WorkingDir")),
        user=opt_str(cfg.get("User"), 256),
        exposed_ports=sorted(clean(p, 64) for p in list(_dict(exposed))[:1000]),
        env_keys=keys,
        redacted_env_keys=redacted,
        labels=clean_labels(cfg.get("Labels")),
        privileged=privileged if isinstance(privileged, bool) else None,
        cap_add=sorted(clean_str_list(hc.get("CapAdd"))),
        cap_drop=sorted(clean_str_list(hc.get("CapDrop"))),
        security_opt=sorted(clean_str_list(hc.get("SecurityOpt"))),
        mounts=_mounts(info, hc),
        network_mode=opt_str(hc.get("NetworkMode"), 256),
        pid_mode=opt_str(hc.get("PidMode"), 256),
        ipc_mode=opt_str(hc.get("IpcMode"), 256),
        port_bindings=_port_bindings(info, hc),
        readonly_rootfs=readonly if isinstance(readonly, bool) else None,
    )


def _refuse_windows(*docs: dict[str, Any]) -> None:
    for d in docs:
        for key in ("Platform", "Os"):
            if str(d.get(key, "")).lower() == "windows":
                raise TargetError("Windows containers/images are not supported")


def _mount_warnings(info: ContainerInfo) -> list[str]:
    out: list[str] = []
    if info.mounts:
        out.append(
            "container export does not include mounted volume contents: "
            + ", ".join(m.destination for m in info.mounts)
        )
    out.extend(
        f"container mounts the container engine socket at {m.destination} "
        "(equivalent to root on the host)"
        for m in info.mounts
        if is_engine_socket(m.source) or is_engine_socket(m.destination)
    )
    return out


# --------------------------------------------------------------------------- acquisition
def acquire_container(
    engine: Engine,
    info: dict[str, Any],
    ws: Workspace,
    *,
    reference: str,
    max_entries: int,
) -> Opened:
    """Export an inspected container by its immutable id and open it as a rootfs tar."""
    _refuse_windows(info)
    cid = info.get("Id")
    if not isinstance(cid, str):
        raise TargetError("engine inspect output has no container id")
    path = export_container(engine, cid, ws)
    image_info: dict[str, Any] | None = None
    warnings: list[str] = []
    image_id = info.get("Image")
    if isinstance(image_id, str) and is_image_ref(image_id):
        image_info, err = inspect(engine, "image", image_id)
        if image_info is None:
            warnings.append(f"image metadata unavailable: {err}")
        else:
            _refuse_windows(image_info)
    container = container_info_from_inspect(info, engine=engine.name, image_info=image_info)
    blob = LayerBlob(path, 0, os.path.getsize(path), label="container export")
    fs = layered_fs([blob], ws, whiteouts=False, name="container", max_entries=max_entries)
    target = TargetInfo(
        kind="container",
        reference=reference,
        digest=container.image_digest,
        platform=container.platform,
    )
    warnings += _mount_warnings(container) + fs.warnings
    return Opened(fs, target, container, warnings)


def acquire_image(
    engine: Engine,
    ref: str,
    image_info: dict[str, Any],
    ws: Workspace,
    *,
    reference: str,
    platform: Platform | None,
    max_entries: int,
) -> Opened:
    """``image save`` an inspected image and open the archive through the image reader."""
    _refuse_windows(image_info)
    path = save_image(engine, ref, ws)
    opened = open_image_path(
        path, ws, "image", reference=reference, platform=platform, max_entries=max_entries
    )
    if opened.container is not None:
        tags = image_info.get("RepoTags")
        tag = tags[0] if isinstance(tags, list) and tags and isinstance(tags[0], str) else ref
        opened.container = opened.container.model_copy(
            update={
                "engine": engine.name,
                "image": clean(tag, 512),
                "image_digest": _repo_digest(image_info) or opened.container.image_digest,
            }
        )
        opened.target = opened.target.model_copy(update={"digest": opened.container.image_digest})
    return opened


def open_engine_target(
    scheme: str,
    ref: str,
    ws: Workspace,
    *,
    reference: str,
    platform: Platform | None = None,
    max_entries: int,
) -> Opened:
    """Resolve ``<scheme>:<ref>`` through local engine CLIs (container first, then image)."""
    if scheme not in ENGINE_SCHEMES:
        raise TargetError(f"not an engine scheme: {scheme!r}")
    names, mode = ENGINE_SCHEMES[scheme]
    want_container = mode in ("auto", "container") and is_container_ref(ref)
    want_image = mode in ("auto", "image") and is_image_ref(ref)
    if not (want_container or want_image):
        raise TargetError(
            f"invalid {mode if mode != 'auto' else 'container/image'} reference: {ref!r}"
        )
    engines = find_engines(names)
    if not engines:
        raise TargetError(
            f"no container engine CLI found on PATH (tried {', '.join(names)}); "
            "alternatively export the image with `docker save -o img.tar` and scan "
            "docker-archive:img.tar"
        )
    errors: list[str] = []
    for engine in engines:
        if want_container:
            info, err = inspect(engine, "container", ref)
            if info is not None:
                return acquire_container(
                    engine, info, ws, reference=reference, max_entries=max_entries
                )
            errors.append(err)
        if want_image:
            image_info, err = inspect(engine, "image", ref)
            if image_info is not None:
                return acquire_image(
                    engine,
                    ref,
                    image_info,
                    ws,
                    reference=reference,
                    platform=platform,
                    max_entries=max_entries,
                )
            errors.append(err)
    what = {"auto": "container or image", "container": "container", "image": "image"}[mode]
    raise TargetError(f"{what} {ref!r} not found: " + "; ".join(errors))
