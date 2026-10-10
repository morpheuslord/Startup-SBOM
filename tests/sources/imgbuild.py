"""Builders for synthetic tar layers, docker-archives and OCI layouts (tests only)."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import sys
import tarfile
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd

MT_INDEX = "application/vnd.oci.image.index.v1+json"
MT_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MT_CONFIG = "application/vnd.oci.image.config.v1+json"
MT_LAYER = {
    None: "application/vnd.oci.image.layer.v1.tar",
    "gzip": "application/vnd.oci.image.layer.v1.tar+gzip",
    "zstd": "application/vnd.oci.image.layer.v1.tar+zstd",
    "xz": "application/vnd.oci.image.layer.v1.tar",  # mislabelled on purpose: we sniff
}

# (name, kind, payload[, mode]) with kind f=file d=dir l=symlink h=hardlink w=whiteout
Member = tuple[Any, ...]


def tar_bytes(members: list[Member]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for m in members:
            name, kind = m[0], m[1]
            payload = m[2] if len(m) > 2 else None
            ti = tarfile.TarInfo(name)
            ti.mtime = 1_700_000_000
            ti.mode = m[3] if len(m) > 3 else (0o755 if kind == "d" else 0o644)
            data: bytes | None = None
            if kind == "f":
                data = payload if isinstance(payload, bytes) else str(payload or "").encode()
                ti.size = len(data)
            elif kind == "d":
                ti.type = tarfile.DIRTYPE
            elif kind == "l":
                ti.type, ti.linkname = tarfile.SYMTYPE, str(payload)
            elif kind == "h":
                ti.type, ti.linkname = tarfile.LNKTYPE, str(payload)
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def compress(data: bytes, kind: str | None) -> bytes:
    if kind is None:
        return data
    if kind == "gzip":
        return gzip.compress(data)
    if kind == "xz":
        return lzma.compress(data)
    if kind == "bzip2":
        return bz2.compress(data)
    if kind == "zstd":
        return bytes(zstd.compress(data))
    raise ValueError(kind)


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write_outer_bytes(files: dict[str, bytes]) -> bytes:
    """``files`` as an uncompressed outer tar."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def write_outer(path: Path, files: dict[str, bytes], kind: str | None = None) -> Path:
    """Write ``files`` as an (optionally compressed) outer tar."""
    path.write_bytes(compress(write_outer_bytes(files), kind))
    return path


def write_dir(root: Path, files: dict[str, bytes]) -> Path:
    for name, data in files.items():
        p = root.joinpath(*name.split("/"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


BASE = [
    ("etc/", "d"),
    ("etc/os-release", "f", 'ID=debian\nVERSION_ID="12"\n'),
    ("etc/passwd", "f", "root:x:0:0::/root:/bin/sh\n"),
    ("etc/shadow", "f", "root:*:1::::::\n", 0o640),
    ("usr/", "d"),
    ("usr/bin/", "d"),
    ("usr/bin/sudo", "f", "ELF-sudo", 0o4755),
    ("bin", "l", "usr/bin"),
    ("srv/", "d"),
    ("srv/data/", "d"),
    ("srv/data/old.txt", "f", "old"),
]
LAYER2 = [
    ("etc/.wh.shadow", "w"),
    ("srv/data/.wh..wh..opq", "f", ""),
    ("srv/data/new.txt", "f", "new"),
    ("etc/app.conf", "f", "x=1\n"),
]
LAYER3 = [
    ("usr/bin/app", "f", "ELF-app", 0o755),
    ("etc/passwd", "f", "root:x:0:0::/root:/bin/sh\napp:x:1000:1000::/:/bin/sh\n"),
]


def layer(members: list[Member]) -> bytes:
    out: list[Member] = []
    for m in members:
        if m[1] == "w":
            out.append((m[0], "f", b""))
        else:
            out.append(m)
    return tar_bytes(out)


def default_layers() -> list[bytes]:
    return [layer(BASE), layer(LAYER2), layer(LAYER3)]


def image_config(
    arch: str = "amd64", *, variant: str | None = None, os_: str = "linux"
) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "architecture": arch,
        "os": os_,
        "config": {
            "User": "app",
            "Env": [
                "PATH=/usr/bin",
                "DB_PASSWORD=hunter2",
                "INNOCENT=AKIAABCDEFGHIJKLMNOP",
            ],
            "Entrypoint": ["/usr/bin/app", "--password=sw0rdfish"],
            "Cmd": ["serve"],
            "ExposedPorts": {"8080/tcp": {}},
            "WorkingDir": "/srv",
            "Labels": {"org.opencontainers.image.source": "https://example.test/x"},
        },
        "rootfs": {"type": "layers", "diff_ids": []},
    }
    if variant:
        cfg["variant"] = variant
    return cfg


def docker_legacy(layers: list[bytes], config: dict[str, Any] | None = None) -> dict[str, bytes]:
    cfg = config or image_config()
    files = {"cfgid.json": json.dumps(cfg).encode()}
    names = []
    for i, data in enumerate(layers):
        files[f"l{i}/layer.tar"] = data
        files[f"l{i}/VERSION"] = b"1.0"
        names.append(f"l{i}/layer.tar")
    files["manifest.json"] = json.dumps(
        [{"Config": "cfgid.json", "RepoTags": ["lab:1"], "Layers": names}]
    ).encode()
    return files


def oci_files(
    platforms: list[tuple[str, str | None, list[bytes]]],
    *,
    compression: str | None = "gzip",
    nested: bool = True,
    attestation: bool = True,
) -> dict[str, bytes]:
    """OCI layout with one manifest per (arch, variant, layers)."""
    files: dict[str, bytes] = {"oci-layout": b'{"imageLayoutVersion": "1.0.0"}'}

    def add(data: bytes) -> str:
        files["blobs/sha256/" + hashlib.sha256(data).hexdigest()] = data
        return sha(data)

    manifests = []
    for arch, variant, raws in platforms:
        cd = add(json.dumps(image_config(arch, variant=variant)).encode())
        lds = []
        for r in raws:
            c = compress(r, compression)
            lds.append({"mediaType": MT_LAYER[compression], "digest": add(c), "size": len(c)})
        man = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": MT_MANIFEST,
                "config": {"mediaType": MT_CONFIG, "digest": cd, "size": 1},
                "layers": lds,
            }
        ).encode()
        plat: dict[str, str] = {"os": "linux", "architecture": arch}
        if variant:
            plat["variant"] = variant
        manifests.append(
            {"mediaType": MT_MANIFEST, "digest": add(man), "size": len(man), "platform": plat}
        )
    if attestation:
        att = add(b'{"schemaVersion":2,"layers":[]}')
        manifests.append(
            {
                "mediaType": MT_MANIFEST,
                "digest": att,
                "size": 1,
                "platform": {"os": "unknown", "architecture": "unknown"},
                "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
            }
        )
    index = {"schemaVersion": 2, "mediaType": MT_INDEX, "manifests": manifests}
    if nested:
        inner = json.dumps(index).encode()
        index = {
            "schemaVersion": 2,
            "mediaType": MT_INDEX,
            "manifests": [
                {
                    "mediaType": MT_INDEX,
                    "digest": add(inner),
                    "size": len(inner),
                    "annotations": {"org.opencontainers.image.ref.name": "1.0"},
                }
            ],
        }
    files["index.json"] = json.dumps(index).encode()
    return files


def blob_path(digest: str) -> str:
    alg, hexd = digest.split(":", 1)
    return f"blobs/{alg}/{hexd}"


def leftovers(scratch: Path) -> list[str]:
    """Names left in the redirected temp directory."""
    return sorted(p.name for p in scratch.iterdir())
