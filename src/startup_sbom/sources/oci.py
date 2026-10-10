"""OCI image layouts: index/manifest selection, platforms and image configs.

Every JSON document read here is attacker-controlled: sizes are capped,
digests are validated before they become blob names, nesting is bounded and
every field is type-checked.  Image configs are turned into an out-of-band
:class:`ContainerInfo`; nothing is ever written into the analysed tree.
"""

from __future__ import annotations

import hashlib
import json
import platform as _platform
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from startup_sbom.errors import TargetError
from startup_sbom.models import ContainerInfo
from startup_sbom.rootfs import LayerBlob
from startup_sbom.sources.compression import Workspace
from startup_sbom.sources.validate import (
    blob_name,
    clean,
    clean_argv,
    clean_labels,
    opt_str,
    split_env,
)

MAX_JSON = 16 * 1024 * 1024
MAX_LAYERS = 1000
MAX_INDEX_DEPTH = 4

MT_OCI_INDEX = "application/vnd.oci.image.index.v1+json"
MT_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MT_DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
MT_DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
INDEX_TYPES = frozenset({MT_OCI_INDEX, MT_DOCKER_LIST})
MANIFEST_TYPES = frozenset({MT_OCI_MANIFEST, MT_DOCKER_MANIFEST})
LAYER_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.docker.image.rootfs.diff.tar",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.docker.image.rootfs.diff.tar.zstd",
        "application/vnd.oci.image.layer.nondistributable.v1.tar",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
        "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
    }
)
REF_NAME = "org.opencontainers.image.ref.name"

_PLATFORM_RE = re.compile(r"^[a-z0-9]+(/[a-z0-9_]+(/[a-z0-9]+)?)?$")
_ARCH_ALIASES = {
    "x86_64": "amd64",
    "x86-64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv8": "arm64",
    "armv7l": "arm",
    "armv7": "arm",
    "armv6l": "arm",
    "arm": "arm",
    "i386": "386",
    "i686": "386",
    "x86": "386",
    "386": "386",
    "ppc64le": "ppc64le",
    "s390x": "s390x",
    "riscv64": "riscv64",
    "mips64le": "mips64le",
    "loong64": "loong64",
}
_DEFAULT_VARIANT = {"arm64": "v8", "arm": "v7", "amd64": "v1"}


@dataclass(frozen=True, slots=True)
class Platform:
    """An OCI platform (``os/architecture[/variant]``)."""

    os: str = "linux"
    architecture: str = "amd64"
    variant: str | None = None

    @classmethod
    def parse(cls, spec: str) -> Platform:
        """Parse ``linux/arm64/v8``, ``linux/amd64`` or a bare architecture (``arm64``)."""
        text = spec.strip().lower()
        if not _PLATFORM_RE.match(text):
            raise TargetError(f"invalid platform {spec!r} (expected os/arch[/variant])")
        parts = text.split("/")
        if len(parts) == 1:
            if parts[0] == "linux":
                return cls.host_default()
            return cls("linux", _ARCH_ALIASES.get(parts[0], parts[0]))
        arch = _ARCH_ALIASES.get(parts[1], parts[1])
        return cls(parts[0], arch, parts[2] if len(parts) > 2 else None)

    @classmethod
    def host_default(cls) -> Platform:
        """``linux/<host arch>``: containers are Linux even on macOS/Windows hosts."""
        machine = _platform.machine().lower()
        return cls("linux", _ARCH_ALIASES.get(machine, "amd64"))

    @classmethod
    def from_dict(cls, data: object) -> Platform | None:
        """Platform from an OCI descriptor ``platform`` or an image config."""
        if not isinstance(data, dict):
            return None
        os_ = data.get("os")
        arch = data.get("architecture")
        if not isinstance(os_, str) or not isinstance(arch, str) or not os_ or not arch:
            return None
        variant = data.get("variant")
        return cls(
            clean(os_, 32).lower(),
            clean(arch, 32).lower(),
            clean(variant, 32).lower() if isinstance(variant, str) and variant else None,
        )

    def matches(self, other: Platform) -> bool:
        """True if ``other`` satisfies this (requested) platform."""
        if other.os != self.os or other.architecture != self.architecture:
            return False
        if self.variant is None:
            return True
        default = _DEFAULT_VARIANT.get(self.architecture)
        return (other.variant or default) == (self.variant or default)

    def __str__(self) -> str:
        return "/".join(p for p in (self.os, self.architecture, self.variant) if p)


class BlobStore(Protocol):
    """Name-addressed members of an image archive or layout directory."""

    def has(self, name: str) -> bool: ...

    def blob(self, name: str) -> LayerBlob: ...


def read_json_bytes(store: BlobStore, name: str) -> bytes:
    """Read a JSON member's raw bytes (size capped)."""
    b = store.blob(name)
    size = b.size if b.size is not None else MAX_JSON + 1
    if size > MAX_JSON:
        raise TargetError(f"{name}: JSON document too large")
    try:
        with b.open() as f:
            return f.read(MAX_JSON + 1)
    except OSError as exc:
        raise TargetError(f"cannot read {name}: {exc}") from exc


def parse_json(raw: bytes, name: str) -> Any:
    """Decode a JSON document, mapping every failure to :class:`TargetError`."""
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise TargetError(f"{name}: invalid JSON: {exc}") from exc


def read_json(store: BlobStore, name: str) -> Any:
    """Read and decode a JSON member."""
    return parse_json(read_json_bytes(store, name), name)


def _dict(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TargetError(f"{what}: expected a JSON object")
    return value


@dataclass(slots=True)
class ImageSource:
    """A resolved image: its layer blobs (lowest first) and metadata."""

    kind: str  # docker-archive | oci-dir | oci-archive
    layers: list[LayerBlob]
    config: dict[str, Any]
    config_digest: str | None = None
    manifest_digest: str | None = None
    repo_tags: list[str] = field(default_factory=list)
    platform: str | None = None
    warnings: list[str] = field(default_factory=list)


def check_image_os(config: dict[str, Any]) -> None:
    """Refuse Windows images (content lives under ``Files/``, unsupported)."""
    if str(config.get("os", "")).lower() == "windows":
        raise TargetError("Windows container images are not supported")


def config_platform(config: dict[str, Any]) -> Platform | None:
    """The platform recorded in an image config."""
    return Platform.from_dict(config)


def _is_attestation(desc: dict[str, Any]) -> bool:
    ann = desc.get("annotations")
    plat = desc.get("platform")
    if isinstance(ann, dict) and ann.get("vnd.docker.reference.type") == "attestation-manifest":
        return True
    return isinstance(plat, dict) and plat.get("os") == "unknown"


def _descriptors(index: dict[str, Any]) -> list[dict[str, Any]]:
    raw = index.get("manifests")
    if not isinstance(raw, list):
        raise TargetError("image index has no 'manifests' list")
    return [d for d in raw[:MAX_LAYERS] if isinstance(d, dict) and not _is_attestation(d)]


def select_manifest(
    store: BlobStore,
    index: dict[str, Any],
    want: Platform,
    *,
    explicit: bool,
    ref: str | None = None,
    depth: int = 0,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Walk (nested) indexes and return ``(descriptor, manifest)`` for ``want``."""
    if depth > MAX_INDEX_DEPTH:
        raise TargetError("image index nesting too deep")
    cands = _descriptors(index)
    if ref:
        cands = [
            d
            for d in cands
            if isinstance(d.get("annotations"), dict) and d["annotations"].get(REF_NAME) == ref
        ]
    if not cands:
        raise TargetError("no usable manifest in image index")
    with_plat = [(d, Platform.from_dict(d.get("platform"))) for d in cands]
    known = [(d, p) for d, p in with_plat if p is not None]
    if known:
        matching = [d for d, p in known if want.matches(p)]
        if not matching:
            if explicit or len(known) > 1:
                avail = ", ".join(sorted({str(p) for _, p in known}))
                raise TargetError(f"platform {want} not found in image; available: {avail}")
            matching = [known[0][0]]
        desc = matching[0]  # image-index.md: the first match SHOULD be used
    else:
        desc = cands[0]
    doc = _dict(read_json(store, blob_name(desc.get("digest"))), "manifest")
    media = doc.get("mediaType") or desc.get("mediaType")
    if media in INDEX_TYPES or ("manifests" in doc and "layers" not in doc):
        return select_manifest(store, doc, want, explicit=explicit, depth=depth + 1)
    if media is not None and media not in MANIFEST_TYPES:
        raise TargetError(f"unsupported manifest media type {clean(media, 100)!r}")
    return desc, doc


def load_oci(
    store: BlobStore,
    ws: Workspace,
    kind: str,
    *,
    platform: Platform | None = None,
    ref: str | None = None,
) -> ImageSource:
    """Resolve an OCI layout (``oci-layout`` + ``index.json``) into an :class:`ImageSource`."""
    index = _dict(read_json(store, "index.json"), "index.json")
    want = platform or Platform.host_default()
    desc, manifest = select_manifest(store, index, want, explicit=platform is not None, ref=ref)
    cfg_desc = _dict(manifest.get("config"), "manifest config")
    cfg_name = blob_name(cfg_desc.get("digest"))
    cfg_raw = read_json_bytes(store, cfg_name)
    config = _dict(parse_json(cfg_raw, cfg_name), "image config")
    check_image_os(config)
    cfg_plat = config_platform(config)
    if platform is not None and cfg_plat is not None and not platform.matches(cfg_plat):
        raise TargetError(f"platform {platform} not found in image; available: {cfg_plat}")
    layer_descs = manifest.get("layers")
    if not isinstance(layer_descs, list) or len(layer_descs) > MAX_LAYERS:
        raise TargetError("manifest has no valid 'layers' list")
    layers: list[LayerBlob] = []
    for raw_desc in layer_descs:
        ld = _dict(raw_desc, "layer descriptor")
        media = ld.get("mediaType", "")
        if media not in LAYER_TYPES:
            raise TargetError(f"unsupported layer media type {clean(media, 100)!r}")
        name = blob_name(ld.get("digest"))
        if not store.has(name):
            raise TargetError(f"layer blob {ld.get('digest')} not present (foreign layer?)")
        layers.append(ws.materialize(store.blob(name), key=str(ld.get("digest"))))
    digest = desc.get("digest")
    return ImageSource(
        kind=kind,
        layers=layers,
        config=config,
        config_digest="sha256:" + hashlib.sha256(cfg_raw).hexdigest(),
        manifest_digest=digest if isinstance(digest, str) else None,
        repo_tags=_ref_names(index),
        platform=str(cfg_plat) if cfg_plat else None,
    )


def _ref_names(index: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for d in _descriptors(index):
        ann = d.get("annotations")
        if isinstance(ann, dict):
            for key in ("io.containerd.image.name", REF_NAME):
                val = ann.get(key)
                if isinstance(val, str) and val:
                    out.append(clean(val, 256))
                    break
    return out


def image_container_info(
    src: ImageSource, *, engine: str = "archive", image: str | None = None
) -> ContainerInfo:
    """Out-of-band :class:`ContainerInfo` (``kind="image"``) from an image config."""
    cfg = src.config.get("config")
    if not isinstance(cfg, dict):
        cfg = {}
    keys, redacted = split_env(cfg.get("Env"))
    ports = cfg.get("ExposedPorts")
    exposed = sorted(clean(p, 64) for p in list(ports)[:1000]) if isinstance(ports, dict) else []
    return ContainerInfo(
        kind="image",
        engine=engine,
        id=src.config_digest,
        image=image or (src.repo_tags[0] if src.repo_tags else None),
        image_digest=src.manifest_digest or src.config_digest,
        platform=src.platform,
        entrypoint=clean_argv(cfg.get("Entrypoint")),
        cmd=clean_argv(cfg.get("Cmd")),
        working_dir=opt_str(cfg.get("WorkingDir")),
        user=opt_str(cfg.get("User"), 256),
        exposed_ports=exposed,
        env_keys=keys,
        redacted_env_keys=redacted,
        labels=clean_labels(cfg.get("Labels")),
    )
