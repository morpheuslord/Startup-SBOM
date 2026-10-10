"""Service-manager analysis: what every init system in the image would start.

:func:`discover_all` runs each analyzer whose ``detect()`` is true, then
reconciles them into one view of the machine:

* **PID 1** is the container entry process when ``ctx.container`` is set,
  otherwise ``/sbin/init`` resolved inside the root.  Service managers that are
  neither PID 1 nor launched by an automatically started service (e.g. an
  ``ENTRYPOINT`` running ``supervisord``, a systemd unit running ``runsvdir``,
  an inittab line running ``openrc``) have their automatic activations
  downgraded to ``MANUAL`` with the reason recorded in ``evidence``.
* Services of a manager launched by another service inherit that service's
  activation (``ENTRYPOINT`` for container children) and boot path.
* A SysV script shadowed by a systemd unit of the same name is reported once,
  by systemd (unless sysvinit itself is PID 1).

Results are sorted by ``Service.id`` (``"<init>:<name>"``).
"""

from __future__ import annotations

import posixpath
from collections.abc import Iterable

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import (
    BUSYBOX,
    DEFAULT_PATH,
    OPENRC,
    RUNIT,
    S6,
    SUPERVISORD,
    SYSTEMD,
    SYSV_RC,
    SYSVINIT,
    detect_launcher,
    which,
)
from startup_sbom.models import Activation, InitSystem, Service
from startup_sbom.rootfs import RootFS

__all__ = ["InitAnalyzer", "analyzers", "discover_all"]

#: Service managers started by each launcher kind.
LAUNCHES: dict[str, InitSystem] = {
    SYSTEMD: InitSystem.SYSTEMD,
    SYSVINIT: InitSystem.INITTAB,
    BUSYBOX: InitSystem.INITTAB,
    OPENRC: InitSystem.OPENRC,
    RUNIT: InitSystem.RUNIT,
    S6: InitSystem.S6,
    SUPERVISORD: InitSystem.SUPERVISORD,
    SYSV_RC: InitSystem.SYSV,
}
_AUTO = frozenset(
    {Activation.BOOT, Activation.SOCKET, Activation.TIMER, Activation.PATH, Activation.DBUS}
)
_BINARIES: dict[InitSystem, tuple[str, ...]] = {
    InitSystem.SYSTEMD: ("/usr/lib/systemd/systemd", "/lib/systemd/systemd"),
    InitSystem.OPENRC: (
        "/sbin/openrc",
        "/usr/sbin/openrc",
        "/sbin/openrc-run",
        "/usr/sbin/openrc-run",
    ),
}
_PATH_BINARIES: dict[InitSystem, str] = {
    InitSystem.RUNIT: "runsvdir",
    InitSystem.S6: "s6-svscan",
    InitSystem.SUPERVISORD: "supervisord",
}


def analyzers() -> list[InitAnalyzer]:
    """One instance of every analyzer, in a fixed order."""
    from startup_sbom.initsys.container import ContainerAnalyzer
    from startup_sbom.initsys.inittab import InittabAnalyzer
    from startup_sbom.initsys.openrc import OpenRCAnalyzer
    from startup_sbom.initsys.runit import RunitAnalyzer
    from startup_sbom.initsys.s6 import S6Analyzer
    from startup_sbom.initsys.supervisord import SupervisordAnalyzer
    from startup_sbom.initsys.systemd.analyzer import SystemdAnalyzer
    from startup_sbom.initsys.sysv import SysVAnalyzer

    return [
        SystemdAnalyzer(),
        SysVAnalyzer(),
        OpenRCAnalyzer(),
        RunitAnalyzer(),
        S6Analyzer(),
        SupervisordAnalyzer(),
        InittabAnalyzer(),
        ContainerAnalyzer(),
    ]


def _installed(fs: RootFS, system: InitSystem) -> bool | None:
    """Whether the manager's own binary exists (``None``: not checked)."""
    if system in _BINARIES:
        return any(fs.is_file(p) for p in _BINARIES[system])
    if system in _PATH_BINARIES:
        path = ["/command", *DEFAULT_PATH, "/usr/local/bin"]
        return which(fs, _PATH_BINARIES[system], path) is not None
    return None


def _launchers(fs: RootFS, svc: Service) -> list[tuple[str, list[str], str]]:
    """``(launcher kind, argv, executable)`` for every manager this service starts."""
    out: list[tuple[str, list[str], str]] = []
    for cmd in svc.commands:
        if cmd.directive in ("ExecStop", "ExecStopPost", "ExecReload", "stop"):
            continue
        for exe in [*cmd.wrapped_by, cmd.executable]:
            if not exe:
                continue
            invoked = next(
                (a for a in cmd.argv if posixpath.basename(a) == posixpath.basename(exe)), exe
            )
            kind = detect_launcher(fs, exe, invoked)
            if kind is not None and all(k != kind for k, _, _ in out):
                out.append((kind, cmd.argv, exe))
    return out


def _supervisord_conf(argv: list[str]) -> str | None:
    for i, a in enumerate(argv):
        if a in ("-c", "--configuration") and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--configuration="):
            return a.split("=", 1)[1]
        if a.startswith("-c") and len(a) > 2 and not a.startswith("--"):
            return a[2:]
    return None


def _pid1(ctx: ScanContext, by_system: dict[InitSystem, list[Service]]) -> tuple[str | None, str]:
    """Launcher kind of PID 1 (``"app"`` for a plain container process) and a description."""
    entries = by_system.get(InitSystem.CONTAINER, [])
    if ctx.container is not None and entries:
        kinds = _launchers(ctx.fs, entries[0])
        return (kinds[0][0] if kinds else "app"), "container entrypoint"
    exe = ctx.fs.try_resolve("/sbin/init")
    if exe is None:
        return None, "no /sbin/init"
    return detect_launcher(ctx.fs, exe, "/sbin/init"), f"/sbin/init → {exe}"


def _dedupe_sysv(by_system: dict[InitSystem, list[Service]], pid1: str | None) -> None:
    if pid1 in (SYSVINIT, BUSYBOX) or InitSystem.SYSV not in by_system:
        return
    names: set[str] = set()
    for svc in by_system.get(InitSystem.SYSTEMD, []):
        names.add(svc.name.removesuffix(".service"))
        names.update(
            e.removeprefix("alias: ").removesuffix(".service")
            for e in svc.evidence
            if e.startswith("alias: ")
        )
    by_system[InitSystem.SYSV] = [s for s in by_system[InitSystem.SYSV] if s.name not in names]


def _shorten(steps: list[str]) -> list[str]:
    return steps if len(steps) <= 8 else [*steps[:2], "…", *steps[-5:]]


def _reconcile(
    ctx: ScanContext, by_system: dict[InitSystem, list[Service]], pid1: str | None, pid1_desc: str
) -> None:
    fs = ctx.fs
    # system -> (inherited activation or None for native, boot path prefix)
    active: dict[InitSystem, tuple[list[Activation] | None, list[str]]] = {}
    queue: list[InitSystem] = []
    if InitSystem.CONTAINER in by_system:
        active[InitSystem.CONTAINER] = (None, [])
        queue.append(InitSystem.CONTAINER)
    if pid1 is None:
        # unknown PID 1: every self-starting manager keeps its own view
        for system in by_system:
            if system not in (InitSystem.SUPERVISORD, InitSystem.CONTAINER):
                active[system] = (None, [])
                queue.append(system)
    elif pid1 in LAUNCHES and InitSystem.CONTAINER not in by_system:
        root = LAUNCHES[pid1]
        active[root] = (None, [])
        queue.append(root)
    while queue:
        system = queue.pop(0)
        for svc in sorted(by_system.get(system, []), key=lambda s: s.id):
            autos = [a for a in svc.activation if a in _AUTO or a is Activation.ENTRYPOINT]
            if not autos or svc.masked:
                continue
            for kind, argv, exe in _launchers(fs, svc):
                target = LAUNCHES.get(kind)
                if target is None or target == system or target in active:
                    continue
                if target is InitSystem.SUPERVISORD:
                    _supervisord_children(ctx, by_system, svc, argv)
                prefix = _shorten([*svc.boot_path, f"{svc.id} → {posixpath.basename(exe)}"])
                active[target] = (autos, prefix)
                queue.append(target)
    for system, services in by_system.items():
        installed = _installed(fs, system)
        state = active.get(system)
        for svc in services:
            autos = [a for a in svc.activation if a in _AUTO]
            if not autos:
                continue
            reason = None
            if installed is False:
                reason = f"{system.value} is not installed in the image"
            elif state is None and pid1 is not None:
                reason = (
                    f"not started: PID 1 is {pid1} ({pid1_desc}) and no started "
                    f"service launches {system.value}"
                )
            if reason is not None:
                svc.activation = [a for a in svc.activation if a not in _AUTO] or [
                    Activation.MANUAL
                ]
                svc.evidence.append(reason)
                continue
            if state is None:
                continue
            inherited, prefix = state
            if inherited is not None and Activation.BOOT in svc.activation:
                acts = [a for a in svc.activation if a is not Activation.BOOT]
                svc.activation = list(dict.fromkeys([*inherited, *acts]))
                svc.boot_path = _shorten([*prefix, *svc.boot_path])


def _supervisord_children(
    ctx: ScanContext, by_system: dict[InitSystem, list[Service]], launcher: Service, argv: list[str]
) -> None:
    from startup_sbom.initsys.netconf import dedupe
    from startup_sbom.initsys.supervisord import find_config, parse_config

    conf = _supervisord_conf(argv) or find_config(ctx.fs)
    if conf is None or not ctx.fs.is_file(conf):
        return
    try:
        cfg = parse_config(ctx.fs, conf)
    except Exception as exc:  # noqa: BLE001 - hostile config never aborts the scan
        ctx.warn(f"supervisord: {conf} skipped: {exc}")
        return
    by_system[InitSystem.SUPERVISORD] = cfg.programs
    launcher.listens = dedupe([*launcher.listens, *cfg.listens])
    launcher.evidence.extend(f for f in cfg.files if f not in launcher.evidence)
    if cfg.user:
        launcher.evidence.append(f"supervisord runs as user {cfg.user} ([supervisord] user=)")


def _merge(groups: Iterable[list[Service]]) -> list[Service]:
    out: dict[str, Service] = {}
    for services in groups:
        for svc in services:
            out.setdefault(svc.id, svc)
    return [out[k] for k in sorted(out)]


def discover_all(ctx: ScanContext) -> list[Service]:
    """Run every applicable analyzer and reconcile the results (sorted by id)."""
    by_system: dict[InitSystem, list[Service]] = {}
    for analyzer in analyzers():
        try:
            if not analyzer.detect(ctx):
                continue
            services = analyzer.discover(ctx)
        except Exception as exc:  # noqa: BLE001 - an analyzer failure never aborts the scan
            ctx.warn(f"{analyzer.name.value}: analysis failed: {type(exc).__name__}: {exc}")
            continue
        by_system[analyzer.name] = services
    pid1, pid1_desc = _pid1(ctx, by_system)
    _dedupe_sysv(by_system, pid1)
    try:
        _reconcile(ctx, by_system, pid1, pid1_desc)
    except Exception as exc:  # noqa: BLE001
        ctx.warn(f"initsys: reconciliation failed: {type(exc).__name__}: {exc}")
    return _merge(by_system[s] for s in sorted(by_system, key=lambda s: s.value))
