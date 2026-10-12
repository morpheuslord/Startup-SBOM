"""sysvinit and BusyBox ``/etc/inittab``: what init itself spawns.

Format ``id:runlevels:action:process`` (inittab(5)).  sysvinit honours the
runlevel field and ``initdefault``; BusyBox ignores runlevels, treats ``id``
as the controlling tty and falls back to a built-in table when the file is
missing.  Each spawning entry becomes one :class:`Service`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import (
    BUSYBOX,
    detect_launcher,
    main_command,
    parse_shell,
    unwrap_command,
)
from startup_sbom.initsys.netconf import base_hardening, finish_service
from startup_sbom.models import Activation, Command, InitSystem, Service
from startup_sbom.rootfs import RootFS

INITTAB = "/etc/inittab"
_LINE_RE = re.compile(r"^(?P<id>[^:#]*):(?P<rl>[^:]*):(?P<action>[A-Za-z]+):(?P<proc>.*)$")
SYSV_BOOT = frozenset({"sysinit", "boot", "bootwait"})
SYSV_RUNLEVEL = frozenset({"wait", "once", "respawn"})
BUSYBOX_BOOT = frozenset({"sysinit", "wait", "once", "respawn", "askfirst"})
BUSYBOX_DEFAULT = (
    "::sysinit:/etc/init.d/rcS\n"
    "::askfirst:/bin/sh\n"
    "::ctrlaltdel:/sbin/reboot\n"
    "::shutdown:/sbin/swapoff -a\n"
    "::shutdown:/bin/umount -a -r\n"
    "::restart:/sbin/init\n"
    "tty2::askfirst:/bin/sh\n"
    "tty3::askfirst:/bin/sh\n"
    "tty4::askfirst:/bin/sh\n"
)


@dataclass(frozen=True, slots=True)
class InittabEntry:
    id: str
    runlevels: str
    action: str
    process: str
    line: int


def parse_inittab(text: str) -> list[InittabEntry]:
    """Parse inittab text (comments, ``\\`` continuations) into entries."""
    out: list[InittabEntry] = []
    pending = ""
    start = 0
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not pending:
            start = lineno
        line = pending + raw
        if line.endswith("\\"):
            pending = line[:-1]
            continue
        pending = ""
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _LINE_RE.match(stripped)
        if m:
            out.append(
                InittabEntry(
                    m.group("id").strip(),
                    m.group("rl").strip(),
                    m.group("action").strip().lower(),
                    m.group("proc").strip(),
                    start,
                )
            )
    return out


def is_busybox_init(fs: RootFS) -> bool:
    """True if ``/sbin/init`` is BusyBox."""
    exe = fs.try_resolve("/sbin/init")
    return detect_launcher(fs, exe, "/sbin/init") == BUSYBOX


def default_runlevel(fs: RootFS) -> tuple[str, str]:
    """Default SysV runlevel and how it was determined."""
    text = fs.try_read_text(INITTAB, 1024 * 1024)
    if text:
        for e in parse_inittab(text):
            if e.action == "initdefault" and e.runlevels:
                return e.runlevels[0], f"{INITTAB} initdefault"
    if fs.is_file("/etc/redhat-release") or (
        fs.is_dir("/etc/rc.d/init.d") and not fs.is_symlink("/etc/rc.d/init.d")
    ):
        return "3", "default runlevel 3 (RHEL family)"
    return "2", "default runlevel 2 (Debian)"


class InittabAnalyzer(InitAnalyzer):
    """Services spawned directly by sysvinit / BusyBox init."""

    name = InitSystem.INITTAB

    def detect(self, ctx: ScanContext) -> bool:
        return ctx.fs.is_file(INITTAB) or is_busybox_init(ctx.fs)

    def discover(self, ctx: ScanContext) -> list[Service]:
        fs = ctx.fs
        busybox = is_busybox_init(fs)
        text = fs.try_read_text(INITTAB, 1024 * 1024)
        source = INITTAB
        if text is None:
            if not busybox:
                return []
            text, source = BUSYBOX_DEFAULT, "BusyBox built-in inittab"
        entries = parse_inittab(text)
        runlevel, _ = default_runlevel(fs)
        out: list[Service] = []
        counters: dict[str, int] = {}
        used: set[str] = set()
        for e in entries:
            if e.action == "initdefault" or not e.process:
                continue
            try:
                svc = self._service(fs, e, busybox, runlevel, source, counters, used)
            except Exception as exc:  # noqa: BLE001 - one bad entry never aborts the scan
                ctx.warn(f"inittab: entry at line {e.line} skipped: {exc}")
                continue
            out.append(svc)
        return out

    def _service(
        self,
        fs: RootFS,
        e: InittabEntry,
        busybox: bool,
        runlevel: str,
        source: str,
        counters: dict[str, int],
        used: set[str],
    ) -> Service:
        counters[e.action] = counters.get(e.action, 0) + 1
        if e.id and not busybox:
            name = e.id
        elif e.id:
            name = f"{e.action}@{e.id}"
        else:
            name = f"{e.action}-{counters[e.action]}"
        base_name, k = name, 2
        while name in used:
            name = f"{base_name}-{k}"
            k += 1
        used.add(name)
        proc = e.process.lstrip("+-" if busybox else "+").strip()
        commands = parse_shell(proc)
        main, others = main_command(commands) if commands else (None, [])
        argv = main or []
        res = unwrap_command(fs, argv) if argv else None
        cmds: list[Command] = []
        if res is not None:
            cmds.append(
                Command(
                    directive=e.action,
                    argv=argv,
                    raw=e.process,
                    executable=res.executable,
                    wrapped_by=res.wrappers,
                )
            )
        for side in others:
            sres = unwrap_command(fs, side)
            cmds.append(
                Command(
                    directive=e.action,
                    argv=side,
                    raw=e.process,
                    executable=sres.executable,
                    wrapped_by=sres.wrappers,
                )
            )
        if busybox:
            boot = e.action in BUSYBOX_BOOT
        else:
            boot = e.action in SYSV_BOOT or (
                e.action in SYSV_RUNLEVEL and (not e.runlevels or runlevel in e.runlevels)
            )
        user = res.user if res is not None and res.user else "root"
        svc = Service(
            id=f"inittab:{name}",
            name=name,
            init_system=InitSystem.INITTAB,
            description=f"{e.action} entry {e.id or '-'}:{e.runlevels}",
            unit_path=INITTAB if source == INITTAB else None,
            enabled=e.action != "off",
            activation=[Activation.BOOT if boot else Activation.MANUAL],
            boot_path=[f"{source}: {e.id}:{e.runlevels}:{e.action}"] if boot else [],
            commands=cmds,
            hardening=base_hardening(user=user),
            evidence=[source if source == INITTAB else f"{source} (no {INITTAB})"],
        )
        if res is not None and res.notes:
            svc.evidence.extend(res.notes)
        return finish_service(fs, svc)
