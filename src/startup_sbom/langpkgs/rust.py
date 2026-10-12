"""Rust crate inventory from cargo-auditable's ``.dep-v0`` ELF section.

The section holds zlib-compressed JSON ``{"packages": [{"name", "version",
"source", "kind", "dependencies": [index...], "root": bool}]}``.  Per
cargo-auditable's ``PARSING.md`` the decompressed size is capped, exactly one
root is required and dependency cycles are rejected.  Build-time and builtin
(standard library) crates are not reported.
"""

from __future__ import annotations

import json
import re
import zlib

from packageurl import PackageURL

from startup_sbom.binaries.elf import ElfInfo, read_section
from startup_sbom.models import Package, PackageType
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.rootfs import RootFS

SECTION = ".dep-v0"
MAX_COMPRESSED = 4 * 1024 * 1024
MAX_DECOMPRESSED = 8 * 1024 * 1024
MAX_PACKAGES = 50_000

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def decompress(data: bytes) -> bytes | None:
    """zlib-inflate at most :data:`MAX_DECOMPRESSED` bytes; ``None`` if larger or corrupt."""
    d = zlib.decompressobj()
    try:
        out = d.decompress(data, MAX_DECOMPRESSED)
    except zlib.error:
        return None
    if d.unconsumed_tail:
        return None
    return out


def _acyclic(deps: list[list[int]]) -> bool:
    state = [0] * len(deps)  # 0 new, 1 on stack, 2 done
    for start in range(len(deps)):
        if state[start]:
            continue
        stack: list[tuple[int, int]] = [(start, 0)]
        state[start] = 1
        while stack:
            node, idx = stack[-1]
            if idx < len(deps[node]):
                stack[-1] = (node, idx + 1)
                nxt = deps[node][idx]
                if state[nxt] == 1:
                    return False
                if state[nxt] == 0:
                    state[nxt] = 1
                    stack.append((nxt, 0))
            else:
                state[node] = 2
                stack.pop()
    return True


def parse_dep_v0(raw: bytes) -> list[dict[str, object]] | None:
    """Validated package list from compressed ``.dep-v0`` data (``None`` if invalid)."""
    data = decompress(raw)
    if data is None:
        return None
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError):
        return None
    pkgs = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(pkgs, list) or not 0 < len(pkgs) <= MAX_PACKAGES:
        return None
    out: list[dict[str, object]] = []
    deps: list[list[int]] = []
    roots = 0
    for p in pkgs:
        if not isinstance(p, dict):
            return None
        name, version = p.get("name"), p.get("version")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            return None
        if not isinstance(version, str) or not 0 < len(version) <= 128:
            return None
        d = p.get("dependencies", [])
        if not isinstance(d, list) or not all(
            isinstance(i, int) and not isinstance(i, bool) and 0 <= i < len(pkgs) for i in d
        ):
            return None
        is_root = p.get("root") is True
        roots += is_root
        source = p.get("source", "crates.io")
        kind = p.get("kind", "runtime")
        out.append(
            {
                "name": name,
                "version": version,
                "source": source if isinstance(source, str) else "unknown",
                "kind": kind if isinstance(kind, str) else "runtime",
                "root": is_root,
                "dependencies": d,
            }
        )
        deps.append(d)
    if roots != 1 or not _acyclic(deps):
        return None
    return out


def extract(fs: RootFS, path: str, info: ElfInfo, owners: FileOwnerIndex) -> list[PackageRecord]:
    """Crates embedded in the ELF at ``path`` (empty if it has no valid ``.dep-v0``)."""
    sec = info.sections.get(SECTION)
    if sec is None:
        return []
    raw = read_section(fs, path, sec, MAX_COMPRESSED)
    if raw is None:
        return []
    pkgs = parse_dep_v0(raw)
    if pkgs is None:
        fs.warnings.append(f"invalid cargo-auditable data in {path}")
        return []
    owner = owners.owner(path)
    names = [str(p["name"]) for p in pkgs]
    out: list[PackageRecord] = []
    for p in pkgs:
        source, kind = str(p["source"]), str(p["kind"])
        if source == "builtin" or kind == "build":
            continue
        name, version = str(p["name"]), str(p["version"])
        purl = PackageURL(type="cargo", name=name, version=version).to_string()
        props = {"binary": path, "source": source, "kind": kind}
        if owner:
            props["managed_by"] = owner
        root = bool(p["root"])
        if root:
            props["root_crate"] = "true"
        dep_idx = p["dependencies"]
        depends = [names[i] for i in dep_idx] if isinstance(dep_idx, list) else []
        pkg = Package(
            id=purl,
            type=PackageType.CARGO,
            name=name,
            version=version,
            purl=purl,
            depends=sorted(set(depends)),
            file_count=1 if root else 0,
            location=path,
            properties=props,
        )
        out.append(PackageRecord(package=pkg, files=[path] if root else []))
    return out
