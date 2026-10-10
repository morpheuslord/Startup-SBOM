"""Tar-based targets: rootfs tarballs, docker-archives and OCI layouts.

Outer archives are indexed header-only; uncompressed members are addressed in
place as :class:`LayerBlob` windows (zero-copy) and compressed ones are
decompressed once into the scan :class:`Workspace`.  Member names taken from
``manifest.json``/``index.json`` are attacker-controlled: they are only ever
used as keys into the archive's own member map, or (for directories) resolved
component-wise with ``..``, absolute paths and symlinks refused.
"""

from __future__ import annotations

import hashlib
import os
import stat as st_mod
import tarfile
from dataclasses import dataclass, field
from typing import Any, cast

from startup_sbom.errors import RootFSError, TargetError
from startup_sbom.models import ContainerInfo, TargetInfo
from startup_sbom.rootfs import LayerBlob, LayeredTarRootFS
from startup_sbom.sources.compression import Workspace
from startup_sbom.sources.oci import (
    MAX_LAYERS,
    ImageSource,
    Platform,
    check_image_os,
    config_platform,
    image_container_info,
    load_oci,
    parse_json,
    read_json,
    read_json_bytes,
)
from startup_sbom.sources.validate import clean, clean_str_list

DEFAULT_MAX_ENTRIES = 5_000_000
TAR_BLOCK = 512

DOCKER_ARCHIVE = "docker-archive"
OCI_DIR = "oci-dir"
OCI_ARCHIVE = "oci-archive"
ROOTFS_TAR = "tar"


@dataclass(slots=True)
class Opened:
    """Result of opening a target: filesystem plus out-of-band metadata."""

    fs: LayeredTarRootFS
    target: TargetInfo
    container: ContainerInfo | None = None
    warnings: list[str] = field(default_factory=list)


def _norm_member(name: str) -> str | None:
    if "\x00" in name:
        return None
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


_TAR_ERRORS: tuple[type[Exception], ...] = (tarfile.TarError, OSError, ValueError, EOFError)
_INDEX_ERRORS: tuple[type[Exception], ...] = (RootFSError, *_TAR_ERRORS)


def _forget_members(tf: tarfile.TarFile) -> None:
    """Drop cached TarInfo objects so a header scan runs in constant memory."""
    cast("Any", tf).members.clear()


class TarStore:
    """Members of an *uncompressed* outer tar, addressed as zero-copy windows."""

    def __init__(self, path: str, *, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self.path = path
        self.members: dict[str, tuple[int, int]] = {}
        count = 0
        try:
            with tarfile.open(path, mode="r:") as tf:
                while (m := tf.next()) is not None:
                    _forget_members(tf)
                    count += 1
                    if count > max_entries:
                        raise TargetError(
                            f"archive has more than {max_entries} entries (possible tar bomb)"
                        )
                    if not m.isreg() or m.issparse():
                        continue
                    name = _norm_member(m.name)
                    if name is not None:
                        self.members[name] = (m.offset_data, m.size)
        except TargetError:
            raise
        except _TAR_ERRORS as exc:
            raise TargetError(f"not a readable tar archive: {exc}") from exc
        self.count = count

    def has(self, name: str) -> bool:
        key = _norm_member(name)
        return key is not None and key in self.members

    def blob(self, name: str) -> LayerBlob:
        key = _norm_member(name)
        if key is None or key not in self.members:
            raise TargetError(f"archive member missing: {clean(name, 200)!r}")
        off, size = self.members[key]
        return LayerBlob(self.path, off, size, label=key)


class DirStore:
    """Files of an image layout directory; ``..``, absolute names and symlinks refused."""

    def __init__(self, path: str) -> None:
        real = os.path.realpath(path)
        if not os.path.isdir(real):
            raise TargetError(f"not a directory: {path}")
        self.path = real

    def _host(self, name: str) -> str | None:
        if "\x00" in name or "\\" in name or ":" in name or name.startswith("/"):
            return None
        parts = [p for p in name.split("/") if p not in ("", ".")]
        if not parts or ".." in parts:
            return None
        cur = self.path
        for i, part in enumerate(parts):
            cur = os.path.join(cur, part)
            try:
                st = os.lstat(cur)
            except OSError:
                return None
            last = i == len(parts) - 1
            if st_mod.S_ISLNK(st.st_mode):
                return None
            if (last and not st_mod.S_ISREG(st.st_mode)) or (
                not last and not st_mod.S_ISDIR(st.st_mode)
            ):
                return None
        return cur

    def has(self, name: str) -> bool:
        return self._host(name) is not None

    def blob(self, name: str) -> LayerBlob:
        host = self._host(name)
        if host is None:
            raise TargetError(f"layout member missing or not a regular file: {clean(name, 200)!r}")
        return LayerBlob(host, 0, os.path.getsize(host), label=name)


Store = TarStore | DirStore


# --------------------------------------------------------------------------- VFS
def _count_members(blob: LayerBlob, cap: int) -> None:
    count = 0
    try:
        with blob.open() as f, tarfile.open(fileobj=f, mode="r:") as tf:
            while tf.next() is not None:
                _forget_members(tf)
                count += 1
                if count > cap:
                    raise TargetError(
                        f"layer {blob.label or ''} has more than {cap} entries (possible tar bomb)"
                    )
    except TargetError:
        raise
    except _TAR_ERRORS as exc:
        raise TargetError(f"layer {blob.label or ''} is not a readable tar: {exc}") from exc


def layered_fs(
    layers: list[LayerBlob],
    ws: Workspace,
    *,
    whiteouts: bool,
    name: str,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> LayeredTarRootFS:
    """Build the tar VFS with byte/entry caps; it removes ``ws`` when closed."""
    total = sum(b.size or 0 for b in layers)
    if total > ws.max_bytes:
        raise TargetError(f"image layers total {total} bytes, over the limit of {ws.max_bytes}")
    for blob in layers:
        # LayeredTarRootFS lists a layer's headers in memory before applying its
        # cap; pre-count (streaming) any layer big enough to hold too many entries.
        if (blob.size or 0) // TAR_BLOCK > max_entries:
            _count_members(blob, max_entries)
    try:
        return LayeredTarRootFS(
            layers, whiteouts=whiteouts, name=name, max_entries=max_entries, cleanup=ws.close
        )
    except _INDEX_ERRORS as exc:
        raise TargetError(f"cannot index {name}: {exc}") from exc


# --------------------------------------------------------------------------- docker-archive
def _docker_entries(store: Store) -> list[dict[str, Any]] | None:
    """Valid ``manifest.json`` entries, or ``None`` if absent/not a docker manifest."""
    if not store.has("manifest.json"):
        return None
    try:
        manifest = read_json(store, "manifest.json")
    except TargetError:
        return None
    if not isinstance(manifest, list):
        return None
    entries = [
        e
        for e in manifest[:MAX_LAYERS]
        if isinstance(e, dict)
        and isinstance(e.get("Config"), str)
        and isinstance(e.get("Layers"), list)
        and len(e["Layers"]) <= MAX_LAYERS
        and all(isinstance(x, str) for x in e["Layers"])
    ]
    return entries or None


def load_docker_archive(
    store: Store, ws: Workspace, *, platform: Platform | None = None
) -> ImageSource:
    """Resolve a ``docker save``/``podman save`` archive (legacy or Docker ≥25)."""
    entries = _docker_entries(store)
    if entries is None:
        raise TargetError("not a docker-archive: missing or invalid manifest.json")
    want = platform or Platform.host_default()
    parsed: list[tuple[dict[str, Any], dict[str, Any], bytes, Platform | None]] = []
    chosen = None
    for entry in entries:
        raw = read_json_bytes(store, entry["Config"])
        config = parse_json(raw, "image config")
        if not isinstance(config, dict):
            raise TargetError("image config is not a JSON object")
        item = (entry, config, raw, config_platform(config))
        parsed.append(item)
        if item[3] is None or want.matches(item[3]):
            chosen = item
            break
    if chosen is None:
        if platform is not None or len(parsed) > 1:
            avail = ", ".join(sorted({str(p[3]) for p in parsed}))
            raise TargetError(f"platform {want} not found in archive; available: {avail}")
        chosen = parsed[0]  # single-platform image on a different host arch
    entry, config, raw, plat = chosen
    check_image_os(config)
    layers = [
        ws.materialize(store.blob(name), key=f"docker-archive:{name}") for name in entry["Layers"]
    ]
    return ImageSource(
        kind=DOCKER_ARCHIVE,
        layers=layers,
        config=config,
        config_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        repo_tags=clean_str_list(entry.get("RepoTags")),
        platform=str(plat) if plat else None,
    )


def _is_oci_layout(store: Store) -> bool:
    return store.has("oci-layout") and store.has("index.json")


def _image_opened(src: ImageSource, ws: Workspace, reference: str, max_entries: int) -> Opened:
    fs = layered_fs(src.layers, ws, whiteouts=True, name=src.kind, max_entries=max_entries)
    target = TargetInfo(
        kind=src.kind,
        reference=reference,
        digest=src.manifest_digest or src.config_digest,
        platform=src.platform,
    )
    warnings = [*src.warnings, *fs.warnings]
    return Opened(fs, target, image_container_info(src), warnings)


def load_image(
    store: Store, ws: Workspace, kind: str, *, platform: Platform | None = None
) -> ImageSource:
    """Resolve an image store as docker-archive or OCI layout (``kind`` is the label)."""
    has_docker = _docker_entries(store) is not None
    has_oci = _is_oci_layout(store)
    # Docker >= 25 writes both; manifest.json is simpler (one image per entry) but
    # only the OCI index can select among several platforms.
    if has_docker and not (has_oci and platform is not None):
        src = load_docker_archive(store, ws, platform=platform)
    elif has_oci:
        src = load_oci(store, ws, kind, platform=platform)
    else:
        raise TargetError(f"not a {kind}: no manifest.json or OCI layout (oci-layout + index.json)")
    src.kind = kind
    return src


# --------------------------------------------------------------------------- openers
def outer_tar(path: str, ws: Workspace) -> str:
    """Host path of an uncompressed version of the archive at ``path``."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise TargetError(f"cannot read {path}: {exc}") from exc
    src = LayerBlob(path, 0, size, label=os.path.basename(path))
    blob = ws.materialize(src, key=f"outer:{path}")
    return blob.path


def open_rootfs_tar(
    path: str, ws: Workspace, *, reference: str, max_entries: int = DEFAULT_MAX_ENTRIES
) -> Opened:
    """A flattened rootfs tarball (``docker export``, debootstrap...); no whiteouts."""
    plain = outer_tar(path, ws)
    blob = LayerBlob(plain, 0, os.path.getsize(plain), label=os.path.basename(path))
    fs = layered_fs([blob], ws, whiteouts=False, name=ROOTFS_TAR, max_entries=max_entries)
    warnings = list(fs.warnings)
    if fs.is_file("/manifest.json") and not fs.is_dir("/etc"):
        warnings.append("tarball looks like an image archive; did you mean docker-archive:?")
    return Opened(fs, TargetInfo(kind=ROOTFS_TAR, reference=reference), None, warnings)


def open_image_path(
    path: str,
    ws: Workspace,
    kind: str,
    *,
    reference: str,
    platform: Platform | None = None,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> Opened:
    """Open a docker-archive or OCI layout given as a directory or (compressed) tar file."""
    store: Store
    if os.path.isdir(path):
        store = DirStore(path)
    else:
        store = TarStore(outer_tar(path, ws), max_entries=max_entries)
    src = load_image(store, ws, kind, platform=platform)
    return _image_opened(src, ws, reference, max_entries)


def open_archive_auto(
    path: str,
    ws: Workspace,
    *,
    reference: str,
    platform: Platform | None = None,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> Opened:
    """Sniff a file: docker-archive, OCI archive, else plain rootfs tarball."""
    plain = outer_tar(path, ws)
    store = TarStore(plain, max_entries=max_entries)
    if _docker_entries(store) is not None:
        kind = DOCKER_ARCHIVE
    elif _is_oci_layout(store):
        kind = OCI_ARCHIVE
    else:
        del store
        return open_rootfs_tar(path, ws, reference=reference, max_entries=max_entries)
    src = load_image(store, ws, kind, platform=platform)
    return _image_opened(src, ws, reference, max_entries)


def sniff_directory(path: str) -> str:
    """``oci-dir`` for an OCI layout directory, else ``dir``."""
    if os.path.isfile(os.path.join(path, "oci-layout")) and os.path.isfile(
        os.path.join(path, "index.json")
    ):
        return OCI_DIR
    return "dir"
