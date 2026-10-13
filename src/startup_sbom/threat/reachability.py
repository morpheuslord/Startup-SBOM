"""Where a vulnerable package sits in the running system.

Reachability is decided only from what the scan observed (service definitions,
resolved executables, ELF link closures, file modes); anything not observed
stays ``installed``.  Every classification carries a witness path such as
``["systemd:ssh.service", "/usr/sbin/sshd", "/usr/lib/.../libsystemd.so.0",
"/usr/lib/.../liblzma.so.5", "pkg:deb/debian/liblzma5@5.6.1-1"]``.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

from startup_sbom.models import (
    Activation,
    Binary,
    Confidence,
    InitSystem,
    LibraryLink,
    ListenAddress,
    Package,
    PackageType,
    Reachability,
    Report,
    Service,
)
from startup_sbom.rootfs.caps import DANGEROUS_CAPS

#: Strongest first (same order as the :class:`Reachability` enum).
ORDER = list(Reachability)
ON_DEMAND = frozenset({Activation.SOCKET, Activation.TIMER, Activation.PATH, Activation.DBUS})
KERNEL_RE = re.compile(
    r"^(?:linux-image-.+|linux-modules-.+|linux-signed-image-.+|kernel|kernel-core|"
    r"kernel-default|kernel-rt|kernel-rt-core|kernel-uek|kernel-uek-core|kernel-lts|"
    r"kernel-64k|kernel-64k-core|linux|linux-lts|linux-zen|linux-hardened|linux-rt|"
    r"linux-virt|linux-edge|linux-generic|linux-image)$"
)
#: The C library / dynamic loader: mapped into every dynamically linked process,
#: setuid ones included, even when no link closure was recorded.
LOADER_RE = re.compile(r"^(?:libc6|glibc|musl)$")
_CONF_RANK = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}
MAX_PATHS = 8
MAX_LOADERS = 4
_OS_TYPES = frozenset({PackageType.DEB, PackageType.RPM, PackageType.APK, PackageType.ALPM})


def is_kernel_package(pkg: Package) -> bool:
    """Installed kernel image packages (headers, firmware and tools excluded)."""
    return bool(KERNEL_RE.match(pkg.name))


def is_loader_package(pkg: Package) -> bool:
    """The C library / dynamic loader package (``libc6``, ``glibc``, ``musl``)."""
    return pkg.type in _OS_TYPES and bool(LOADER_RE.match(pkg.name))


def strongest(levels: list[Reachability]) -> Reachability:
    """Strongest of ``levels`` (``installed`` when empty)."""
    return min(levels, key=ORDER.index) if levels else Reachability.INSTALLED


def service_user(svc: Service) -> str:
    """Account the service runs as (``dynamic:<name>`` for ``DynamicUser=yes``)."""
    h = svc.hardening
    if h.dynamic_user:
        return f"dynamic:{svc.name}"
    return "root" if h.user in ("root", "0", "") else h.user


def _blocks_inet(families: list[str] | None) -> bool:
    if families is None:
        return False
    deny = [f.lstrip("~") for f in families if f.startswith("~")]
    allow = [f for f in families if not f.startswith("~")]
    inet = {"AF_INET", "AF_INET6"}
    if deny:
        return inet <= set(deny)
    return not (inet & set(allow))


@dataclass(slots=True)
class Exposure:
    """Effective network exposure of one service."""

    listens: list[ListenAddress]
    blocked_by: list[str]

    @property
    def exposed(self) -> bool:
        return bool(self.listens)


@dataclass(slots=True)
class ReachInfo:
    """Reachability verdict for one package, with witnesses."""

    level: Reachability
    paths: list[list[str]] = field(default_factory=list)
    services: list[str] = field(default_factory=list)  # every service involved
    primary_service: str | None = None  # the service behind ``level`` (if any)
    binaries: list[str] = field(default_factory=list)
    setuid_binaries: list[Binary] = field(default_factory=list)
    #: Root-granting setuid/capability binaries of *other* packages that load this
    #: package's code (each a loader path ``[binary, ..., library]``).
    privileged_loaders: list[list[str]] = field(default_factory=list)
    link: LibraryLink | None = None  # weakest edge of the strongest library path
    evidence: list[str] = field(default_factory=list)
    network_exposed: bool = False
    listens: list[ListenAddress] = field(default_factory=list)


class SystemIndex:
    """Lookup tables over a report, built once per analysis."""

    def __init__(self, report: Report) -> None:
        self.report = report
        self.packages = report.package_by_id()
        self.services = {s.id: s for s in sorted(report.services, key=lambda s: s.id)}
        self.binaries = {b.path: b for b in sorted(report.binaries, key=lambda b: b.path)}
        self.by_package: dict[str, list[Binary]] = {}
        for b in self.binaries.values():
            if b.package:
                self.by_package.setdefault(b.package, []).append(b)
        self.service_binaries: dict[str, list[Binary]] = {}
        for svc in self.services.values():
            seen: dict[str, Binary] = {}
            for path in svc.executables:
                if path in self.binaries:
                    seen[path] = self.binaries[path]
            for b in self.binaries.values():
                if svc.id in b.used_by:
                    seen.setdefault(b.path, b)
            self.service_binaries[svc.id] = [seen[k] for k in sorted(seen)]
        self.exposure = {sid: self._exposure(svc) for sid, svc in self.services.items()}
        #: Binaries that run with root privilege whoever executes them.
        self.privileged = [b for b in self.binaries.values() if setuid_root(b) or dangerous_caps(b)]

    # ------------------------------------------------------------------ services
    def is_entrypoint(self, svc: Service) -> bool:
        return svc.init_system is InitSystem.CONTAINER or Activation.ENTRYPOINT in svc.activation

    def _exposure(self, svc: Service) -> Exposure:
        h = svc.hardening
        listens = [li for li in svc.listens if li.scope == "network"]
        container = self.report.container
        if container is not None and self.is_entrypoint(svc) and not listens:
            listens = [_port_listen(p) for p in sorted(set(container.exposed_ports))]
        blocked: list[str] = []
        if listens and h.private_network and Activation.SOCKET not in svc.activation:
            blocked.append("PrivateNetwork=yes")
        if listens and _blocks_inet(h.restrict_address_families):
            blocked.append("RestrictAddressFamilies= excludes AF_INET/AF_INET6")
        if container is not None and self.is_entrypoint(svc) and container.network_mode == "none":
            blocked.append("container network_mode=none")
        if blocked or not svc.starts_automatically:
            return Exposure([], blocked)
        return Exposure(sorted(listens, key=_listen_key), [])

    def owned_executables(self, svc: Service, pkg_id: str) -> list[str]:
        """Executables of ``svc`` shipped by ``pkg_id``."""
        exes = [p for p in svc.executables if (b := self.binaries.get(p)) and b.package == pkg_id]
        if exes:
            return sorted(exes)
        if pkg_id in svc.packages:
            unknown = [p for p in svc.executables if not self.binaries.get(p)]
            if len(set(svc.packages)) == 1:
                return sorted(svc.executables)
            return sorted(unknown)
        return []

    # ------------------------------------------------------------------ linkage
    def library_path(self, start: Binary, pkg_id: str) -> tuple[list[str], LibraryLink] | None:
        """Shortest loader path from ``start`` to a library shipped by ``pkg_id``."""
        prev: dict[str, tuple[str, LibraryLink]] = {}
        queue = deque([start.path])
        seen = {start.path}
        while queue:
            cur = queue.popleft()
            node = self.binaries.get(cur)
            if node is None:
                continue
            direct = [li for li in node.libraries if li.depth <= 1 and li.path]
            for li in sorted(direct, key=lambda x: (x.path or "", x.soname)):
                if li.path is None or li.path in seen:
                    continue
                seen.add(li.path)
                prev[li.path] = (cur, li)
                if li.package == pkg_id:
                    return self._unwind(prev, li.path), self._weakest(prev, li.path)
                queue.append(li.path)
        # Fallback: the closure lists the library but intermediates were not recorded.
        hits = sorted(
            (li for li in start.libraries if li.package == pkg_id and li.path),
            key=lambda x: (x.depth, x.path or ""),
        )
        if hits:
            return [start.path, hits[0].path or hits[0].soname], hits[0]
        return None

    @staticmethod
    def _unwind(prev: dict[str, tuple[str, LibraryLink]], end: str) -> list[str]:
        out = [end]
        while out[-1] in prev:
            out.append(prev[out[-1]][0])
        return out[::-1]

    @staticmethod
    def _weakest(prev: dict[str, tuple[str, LibraryLink]], end: str) -> LibraryLink:
        links = []
        cur = end
        while cur in prev:
            parent, li = prev[cur]
            links.append(li)
            cur = parent
        return min(
            links,
            key=lambda li: (_CONF_RANK[li.confidence], li.via == "needed", -li.depth),
        )


def _port_listen(spec: str) -> ListenAddress:
    port, _, proto = spec.partition("/")
    return ListenAddress(
        protocol=(proto or "tcp").lower(),
        port=int(port) if port.isdigit() else None,
        scope="network",
        source="container image ExposedPorts",
    )


def _listen_key(li: ListenAddress) -> tuple[str, int, str, str]:
    return (li.protocol, li.port or 0, li.address or "", li.path or "")


def describe_listen(li: ListenAddress) -> str:
    """``tcp/22`` / ``tcp 0.0.0.0:443`` / ``unix /run/x.sock``."""
    if li.path:
        return f"{li.protocol} {li.path}"
    if li.address and li.port is not None:
        return f"{li.protocol} {li.address}:{li.port}"
    if li.port is not None:
        return f"{li.protocol}/{li.port}"
    return li.protocol


def _svc_rank(index: SystemIndex, svc: Service) -> tuple[int, int, str]:
    """Most dangerous service first: exposed, root, then id."""
    exp = index.exposure[svc.id].exposed
    root = service_user(svc) == "root"
    return (0 if exp else 1, 0 if root else 1, svc.id)


def classify(index: SystemIndex, pkg: Package) -> ReachInfo:
    """Reachability of ``pkg`` with witness paths, strongest level first."""
    found: list[tuple[Reachability, list[str], Service | None]] = []
    services: set[str] = set()
    binaries: set[str] = set()
    evidence: list[str] = []
    weakest_link: LibraryLink | None = None
    link_level_svc: Service | None = None

    for svc in sorted(index.services.values(), key=lambda s: _svc_rank(index, s)):
        if svc.masked:
            continue
        exes = index.owned_executables(svc, pkg.id)
        if exes:
            level = _service_level(index, svc)
            if level is None:
                evidence.append(f"{svc.id} runs {exes[0]} but is not started automatically")
                continue
            services.add(svc.id)
            binaries.update(exes)
            found.extend((level, [svc.id, exe, pkg.id], svc) for exe in exes)
            continue
        if not svc.starts_automatically:
            continue
        for b in index.service_binaries.get(svc.id, []):
            if b.package == pkg.id:
                continue
            hit = index.library_path(b, pkg.id)
            if hit is None:
                continue
            chain, link = hit
            services.add(svc.id)
            binaries.add(b.path)
            found.append((Reachability.LINKED_BY_SERVICE, [svc.id, *chain, pkg.id], svc))
            if link_level_svc is None:
                weakest_link, link_level_svc = link, svc
                evidence.append(
                    f"{chain[-1]} is loaded by {b.path} of {svc.id} "
                    f"(via {link.via}, confidence {link.confidence.value}, depth {len(chain) - 1})"
                )

    setuid = [b for b in index.by_package.get(pkg.id, []) if b.setuid or b.setgid or b.capabilities]
    for b in setuid:
        binaries.add(b.path)
        found.append((Reachability.SETUID, [b.path, pkg.id], None))
        evidence.append(f"{b.path} is {_privilege_label(b)}")
    loaders = _privileged_loaders(index, pkg)
    for chain, why in loaders:
        binaries.add(chain[0])
        found.append((Reachability.SETUID, [*chain, pkg.id], None))
        evidence.append(why)
    if is_kernel_package(pkg):
        found.append((Reachability.KERNEL, [pkg.id], None))
        if index.report.container is not None:
            evidence.append(
                "kernel package inside a container image: the host kernel runs instead, "
                "so this package is not executed"
            )
    if not found:
        found.append((Reachability.INSTALLED, [pkg.id], None))

    found.sort(key=lambda f: (ORDER.index(f[0]), f[1]))
    level, _, primary = found[0]
    paths: list[list[str]] = []
    for _, path, _svc in found:
        if path not in paths:
            paths.append(path)
    info = ReachInfo(
        level=level,
        paths=paths[:MAX_PATHS],
        services=sorted(services),
        primary_service=primary.id if primary else None,
        binaries=sorted(binaries),
        setuid_binaries=setuid,
        privileged_loaders=[chain for chain, _ in loaders],
        link=weakest_link if level is Reachability.LINKED_BY_SERVICE else None,
        evidence=evidence,
    )
    listens: list[ListenAddress] = []
    for sid in info.services:
        listens.extend(index.exposure[sid].listens)
    info.listens = sorted({_listen_key(li): li for li in listens}.values(), key=_listen_key)
    info.network_exposed = bool(info.listens)
    for sid in info.services:
        blocked = index.exposure[sid].blocked_by
        if blocked:
            info.evidence.append(f"{sid}: network listener neutralised by {', '.join(blocked)}")
    return info


def _privileged_loaders(index: SystemIndex, pkg: Package) -> list[tuple[list[str], str]]:
    """``(loader path, evidence)`` for root-granting binaries that load ``pkg``'s code.

    Only a recorded link edge counts: a setuid binary merely *present* on the
    system says nothing about a library it never maps.  The C library/loader is
    the one exception, assumed when a privileged ELF has no recorded closure
    (link analysis off or the closure unreadable) because every dynamically
    linked program maps it.
    """
    out: list[tuple[list[str], str]] = []
    for b in index.privileged:
        if b.package == pkg.id:
            continue  # the package's own privileged binaries are SETUID already
        hit = index.library_path(b, pkg.id)
        if hit is not None:
            chain, link = hit
            out.append(
                (
                    chain,
                    f"{chain[-1]} is loaded by the {_privilege_label(b)} binary {b.path} "
                    f"(via {link.via}, confidence {link.confidence.value})",
                )
            )
        elif is_loader_package(pkg) and b.kind == "elf" and b.needed and not b.libraries:
            out.append(
                (
                    [b.path],
                    f"{b.path} ({_privilege_label(b)}) is dynamically linked, so it maps "
                    f"the C library/loader from {pkg.name} (assumed: no closure recorded)",
                )
            )
        if len(out) >= MAX_LOADERS:
            break
    return out


def _service_level(index: SystemIndex, svc: Service) -> Reachability | None:
    if not svc.starts_automatically:
        return None
    if index.exposure[svc.id].exposed:
        return Reachability.NETWORK_SERVICE
    if Activation.BOOT in svc.activation or index.is_entrypoint(svc):
        return Reachability.BOOT_SERVICE
    if set(svc.activation) & ON_DEMAND:
        return Reachability.ON_DEMAND_SERVICE
    return Reachability.BOOT_SERVICE


def setuid_root(b: Binary) -> bool:
    """Setuid binary owned by root (owner unknown is treated as root: the common case)."""
    return b.setuid and b.owner_uid in (0, None)


def dangerous_caps(b: Binary) -> list[str]:
    """File capabilities of ``b`` that are near-equivalent to root."""
    return sorted({c.lower().removeprefix("cap_") for c in b.capabilities} & DANGEROUS_CAPS)


def _privilege_label(b: Binary) -> str:
    parts = []
    if b.setuid:
        owner = "root" if b.owner_uid in (0, None) else f"uid {b.owner_uid}"
        parts.append(f"setuid-{owner}")
    if b.setgid:
        parts.append("setgid")
    if b.capabilities:
        parts.append("file capabilities " + ",".join(sorted(b.capabilities)))
    return " + ".join(parts)
