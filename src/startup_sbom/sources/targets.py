"""Target strings → :class:`TargetSpec` → :class:`AcquiredTarget`.

Grammar (``startup-sbom scan <target>``)::

    dir:<path>            host directory / mounted disk
    host:                 the running Linux host ``/``
    tar:<file>            flattened rootfs tarball (docker export, debootstrap ...)
    docker-archive:<p>    docker/podman save (file or directory; legacy or Docker >= 25)
    oci-dir:<dir>         OCI image layout directory
    oci-archive:<file>    OCI image layout tarball
    docker:<ref>          live engine: container first, then image (also podman:, nerdctl:)
    docker-container:<c>  container only (also podman-/nerdctl-container:, container:)
    docker-image:<ref>    image only (also podman-/nerdctl-image:, image:)

An existing path is auto-detected.  A bare non-path string is rejected instead
of silently pulling from a registry.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field

from startup_sbom.errors import RootFSError, TargetError
from startup_sbom.models import ContainerInfo, TargetInfo
from startup_sbom.rootfs import DirectoryRootFS, RootFS
from startup_sbom.sources.archive import (
    DEFAULT_MAX_ENTRIES,
    DOCKER_ARCHIVE,
    OCI_ARCHIVE,
    OCI_DIR,
    ROOTFS_TAR,
    Opened,
    open_archive_auto,
    open_image_path,
    open_rootfs_tar,
    sniff_directory,
)
from startup_sbom.sources.compression import DEFAULT_MAX_BYTES, Workspace
from startup_sbom.sources.engine import ENGINE_SCHEMES, open_engine_target
from startup_sbom.sources.host import open_host
from startup_sbom.sources.oci import Platform
from startup_sbom.sources.validate import is_container_ref, is_image_ref

DIR = "dir"
HOST = "host"
ARCHIVE = "archive"  # file whose kind is sniffed on open

PATH_SCHEMES = frozenset({DIR, ROOTFS_TAR, DOCKER_ARCHIVE, OCI_DIR, OCI_ARCHIVE, ARCHIVE})
SCHEME_ALIASES = {"file": ROOTFS_TAR, "rootfs": ROOTFS_TAR}
SCHEMES = frozenset({*PATH_SCHEMES, HOST, *ENGINE_SCHEMES})

_WIN_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True, slots=True)
class TargetSpec:
    """A parsed target: ``scheme`` plus a validated ``reference`` (path or engine ref)."""

    scheme: str
    reference: str

    def __str__(self) -> str:
        return f"{self.scheme}:{self.reference}"


@dataclass(slots=True)
class AcquiredTarget:
    """An opened target.  Use as a context manager; :meth:`close` removes temp files."""

    fs: RootFS
    target: TargetInfo
    container: ContainerInfo | None = None
    live_host: bool = False
    warnings: list[str] = field(default_factory=list)
    _workspace: Workspace | None = field(default=None, repr=False)

    def close(self) -> None:
        """Release the filesystem and delete the scan workspace (idempotent)."""
        try:
            self.fs.close()
        finally:
            if self._workspace is not None:
                ws, self._workspace = self._workspace, None
                ws.close()

    def __enter__(self) -> AcquiredTarget:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _hint(spec: str) -> str:
    return (
        f"{spec!r} is not an existing path. Prefix it with a scheme, e.g. "
        f"docker:{spec} (local container or image), docker-image:{spec}, "
        f"podman:{spec}, docker-archive:<file>, oci-archive:<file>, tar:<file> or dir:<path>. "
        "Images are never pulled from a registry implicitly; use `docker pull` or "
        "`skopeo copy` first."
    )


def _looks_like_path(spec: str) -> bool:
    return (
        bool(_WIN_DRIVE.match(spec))
        or spec.startswith((".", "~", "/", "\\"))
        or "/" in spec.split(":", 1)[0]
        or os.sep in spec
    )


def _existing(spec: str) -> bool:
    prefix, sep, _ = spec.partition(":")
    if os.name == "nt" and sep and len(prefix) > 1:
        return False  # "docker:x" on Windows would address an NTFS alternate data stream
    return os.path.lexists(spec)


def _auto_path(spec: str) -> TargetSpec:
    if os.path.isdir(spec):
        return TargetSpec(sniff_directory(spec), spec)
    return TargetSpec(ARCHIVE, spec)


def parse_target(spec: str) -> TargetSpec:
    """Parse and validate a target string (no subprocess, no network, no extraction)."""
    if not isinstance(spec, str) or not spec.strip():
        raise TargetError("empty target")
    if "\x00" in spec:
        raise TargetError("NUL byte in target")
    spec = spec.strip()
    # 1. an existing path wins (keeps ./docker:x and C:\x working)
    if _WIN_DRIVE.match(spec) or _existing(spec):
        if not os.path.exists(spec):
            raise TargetError(f"path does not exist (dangling symlink?): {spec}")
        return _auto_path(spec)
    scheme, sep, rest = spec.partition(":")
    scheme = SCHEME_ALIASES.get(scheme.lower(), scheme.lower()) if sep else ""
    if scheme == "registry":
        raise TargetError(
            "registry: pulls are not supported; fetch the image first, e.g. "
            "`skopeo copy docker://<ref> oci-archive:img.tar`, then scan oci-archive:img.tar"
        )
    if scheme not in SCHEMES:
        if _looks_like_path(spec) and not (is_image_ref(spec) or is_container_ref(spec)):
            raise TargetError(f"path does not exist: {spec}")
        raise TargetError(_hint(spec))
    if scheme == HOST:
        if rest not in ("", "/"):
            raise TargetError("host: takes no argument (it always scans the running host '/')")
        return TargetSpec(HOST, "/")
    if scheme in PATH_SCHEMES:
        return _parse_path(scheme, rest)
    return _parse_engine(scheme, rest)


def validate_spec(ts: TargetSpec) -> TargetSpec:
    """Re-validate a caller-constructed :class:`TargetSpec`."""
    if ts.scheme == HOST:
        return TargetSpec(HOST, "/")
    if ts.scheme in PATH_SCHEMES:
        return _parse_path(ts.scheme, ts.reference)
    if ts.scheme in ENGINE_SCHEMES:
        return _parse_engine(ts.scheme, ts.reference)
    raise TargetError(f"unsupported target scheme {ts.scheme!r}")


def _parse_path(scheme: str, rest: str) -> TargetSpec:
    if not rest:
        raise TargetError(f"{scheme}: requires a path")
    path = os.path.expanduser(rest)
    if not os.path.exists(path):
        raise TargetError(f"{scheme}: path does not exist: {rest}")
    is_dir = os.path.isdir(path)
    if scheme in (DIR, OCI_DIR) and not is_dir:
        raise TargetError(f"{scheme}: not a directory: {rest}")
    if scheme in (ROOTFS_TAR, OCI_ARCHIVE, ARCHIVE) and is_dir:
        raise TargetError(f"{scheme}: expected a file, got a directory: {rest}")
    return TargetSpec(scheme, path)


def _parse_engine(scheme: str, ref: str) -> TargetSpec:
    _, mode = ENGINE_SCHEMES[scheme]
    if not ref:
        raise TargetError(f"{scheme}: requires a container or image reference")
    ok_container = mode in ("auto", "container") and is_container_ref(ref)
    ok_image = mode in ("auto", "image") and is_image_ref(ref)
    if not (ok_container or ok_image):
        kind = {"auto": "container name/id or image reference", "container": "container name/id"}
        raise TargetError(
            f"{scheme}: invalid {kind.get(mode, 'image reference')}: {ref!r} "
            "(names are [a-zA-Z0-9][a-zA-Z0-9_.-]+, images follow the distribution "
            "reference grammar, e.g. nginx:1.27 or ghcr.io/org/app@sha256:...)"
        )
    return TargetSpec(scheme, ref)


def open_target(
    spec: str | TargetSpec,
    *,
    platform: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> AcquiredTarget:
    """Acquire a target as a read-only :class:`RootFS` plus out-of-band metadata.

    ``platform`` selects a manifest of a multi-platform image (default: linux/<host
    arch>).  ``max_bytes`` caps engine output, decompressed data and total layer
    size; ``max_entries`` caps archive/VFS entries.  Temp files live in one private
    ``mkdtemp`` directory removed by :meth:`AcquiredTarget.close` (and on errors).
    """
    ts = validate_spec(spec) if isinstance(spec, TargetSpec) else parse_target(spec)
    plat = Platform.parse(platform) if platform else None
    reference = ts.reference if ts.scheme == ARCHIVE else str(ts)
    if ts.scheme == HOST:
        fs = open_host()
        return AcquiredTarget(fs, TargetInfo(kind=HOST, reference="/"), None, live_host=True)
    if ts.scheme == DIR:
        try:
            dfs = DirectoryRootFS(ts.reference)
        except (RootFSError, OSError) as exc:
            raise TargetError(f"cannot open directory {ts.reference}: {exc}") from exc
        warnings = ["--platform ignored for a directory target"] if plat else []
        return AcquiredTarget(dfs, TargetInfo(kind=DIR, reference=reference), None, False, warnings)

    ws = Workspace(max_bytes=max_bytes)
    try:
        opened = _open_in_workspace(ts, ws, reference, plat, max_entries)
    except BaseException:
        ws.close()
        raise
    return AcquiredTarget(opened.fs, opened.target, opened.container, False, opened.warnings, ws)


def _open_in_workspace(
    ts: TargetSpec, ws: Workspace, reference: str, plat: Platform | None, max_entries: int
) -> Opened:
    if ts.scheme == ROOTFS_TAR:
        return open_rootfs_tar(ts.reference, ws, reference=reference, max_entries=max_entries)
    if ts.scheme == ARCHIVE:
        return open_archive_auto(
            ts.reference, ws, reference=reference, platform=plat, max_entries=max_entries
        )
    if ts.scheme in (DOCKER_ARCHIVE, OCI_DIR, OCI_ARCHIVE):
        return open_image_path(
            ts.reference,
            ws,
            ts.scheme,
            reference=reference,
            platform=plat,
            max_entries=max_entries,
        )
    if ts.scheme in ENGINE_SCHEMES:
        if sys.platform == "win32" and ts.scheme.startswith("nerdctl"):
            raise TargetError("nerdctl is not available on Windows hosts")
        return open_engine_target(
            ts.scheme, ts.reference, ws, reference=reference, platform=plat, max_entries=max_entries
        )
    raise TargetError(f"unsupported target scheme {ts.scheme!r}")
