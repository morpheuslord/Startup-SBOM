"""runit (Void, Artix, phusion/baseimage): stages, runsvdir service trees, ``run`` scripts.

A service is enabled when it is linked into the active runsvdir and has no
``down`` file.  Offline ``/run`` is empty, so Void's ``/var/service`` chain is
read from ``/etc/runit/runsvdir/current`` (default ``.../default``).  The
command is the final ``exec`` of ``run`` with ``chpst``/``setuidgid`` and other
wrappers unwrapped; ``log/run`` loggers are reported as separate services.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import (
    SCRIPT_LIMIT,
    ShellEnv,
    execline_split,
    main_command,
    parse_shell,
    shebang,
    unwrap_command,
)
from startup_sbom.initsys.netconf import base_hardening, command_from, finish_service
from startup_sbom.models import Activation, Command, InitSystem, Service
from startup_sbom.rootfs import RootFS

SV_DIRS = ("/etc/sv", "/etc/runit/sv")
STAGES = ("/etc/runit/1", "/etc/runit/2")
MY_INIT_D = "/etc/my_init.d"


@dataclass(frozen=True, slots=True)
class ServiceDir:
    name: str
    path: str  # canonical service directory
    link: str | None  # entry in the active runsvdir (None: not linked)


def active_dirs(fs: RootFS) -> list[str]:
    """Candidate active runsvdir directories present in the image (in-image paths)."""
    out: list[str] = []
    current = fs.try_resolve("/etc/runit/runsvdir/current")
    for d in (current, "/etc/runit/runsvdir/default", "/etc/service", "/service", "/var/service"):
        if d and fs.is_dir(d) and d not in out:
            out.append(d)
    return out


def run_command(fs: RootFS, run: str) -> tuple[list[str] | None, list[list[str]]]:
    """Main argv (final ``exec``) and other commands of a ``run`` script (shell or execline)."""
    text = fs.try_read_text(run, SCRIPT_LIMIT)
    if text is None:
        return None, []
    sb = shebang(fs, run) or []
    if sb and posixpath.basename(sb[0]) in ("execlineb", "execline"):
        words = execline_split(text)
        return (words or None), []
    commands = parse_shell(text, ShellEnv())
    if not commands:
        return None, []
    return main_command(commands)


def service_from_dir(
    fs: RootFS,
    init: InitSystem,
    sid: str,
    name: str,
    sdir: str,
    *,
    boot: bool,
    enabled: bool,
    boot_path: list[str],
    evidence: list[str],
    path_env: list[str] | None = None,
    script: str = "run",
) -> Service | None:
    """Build a :class:`Service` from a supervision directory with a ``run`` script."""
    run = posixpath.join(sdir, script)
    st = fs.try_stat(run)
    if st is None or not st.is_file:
        return None
    run_canon = fs.try_resolve(run) or run
    commands: list[Command] = [Command(directive=script, argv=[run], raw=run, executable=run_canon)]
    main, others = run_command(fs, run)
    user: str | None = None
    group: str | None = None
    notes: list[str] = []
    execline = bool((shebang(fs, run) or [""])[0].endswith(("execlineb", "execline")))
    if main:
        res = unwrap_command(fs, main, path_env=path_env, execline=execline)
        commands.append(command_from("exec", main, " ".join(main), res))
        user, group = res.user, res.group
        notes.extend(res.notes)
        for side in res.side_commands:
            sres = unwrap_command(fs, side, path_env=path_env, execline=execline)
            if sres.executable:
                commands.append(command_from(script, side, " ".join(side), sres))
    for side in others:
        sres = unwrap_command(fs, side, path_env=path_env)
        if sres.executable:
            commands.append(command_from(script, side, " ".join(side), sres))
    svc = Service(
        id=sid,
        name=name,
        init_system=init,
        unit_path=run,
        enabled=enabled,
        activation=[Activation.BOOT if boot else Activation.MANUAL],
        boot_path=boot_path if boot else [],
        commands=commands,
        hardening=base_hardening(user=user or "root", group=group),
        evidence=[*evidence, run, *notes],
    )
    return finish_service(fs, svc)


class RunitAnalyzer(InitAnalyzer):
    """runit service trees (``runsvdir``)."""

    name = InitSystem.RUNIT

    def detect(self, ctx: ScanContext) -> bool:
        fs = ctx.fs
        return (
            fs.is_dir("/etc/runit")
            or any(fs.is_dir(d) for d in SV_DIRS)
            or fs.is_dir(MY_INIT_D)
            or (
                any(
                    fs.is_file(posixpath.join(d, "runsvdir"))
                    for d in ("/sbin", "/usr/sbin", "/usr/bin", "/bin")
                )
                and fs.is_dir("/etc/service")
            )
        )

    def discover(self, ctx: ScanContext) -> list[Service]:
        fs = ctx.fs
        dirs: dict[str, ServiceDir] = {}
        for active in active_dirs(fs):
            for entry in fs.safe_listdir(active):
                p = posixpath.join(active, entry)
                canon = fs.try_resolve(p)
                if canon is None or not fs.is_dir(canon) or entry.startswith("."):
                    continue
                dirs.setdefault(entry, ServiceDir(entry, canon, p))
        linked = {d.path for d in dirs.values()}
        for base in SV_DIRS:
            for entry in fs.safe_listdir(base):
                p = posixpath.join(base, entry)
                canon = fs.try_resolve(p)
                if canon is None or canon in linked or not fs.is_dir(canon) or entry in dirs:
                    continue
                dirs[entry] = ServiceDir(entry, canon, None)
        out: list[Service] = []
        for name in sorted(dirs):
            sd = dirs[name]
            try:
                out.extend(self._services(fs, sd))
            except Exception as exc:  # noqa: BLE001 - one bad service never aborts the scan
                ctx.warn(f"runit: {sd.path} skipped: {exc}")
        out.extend(self._oneshots(fs))
        return out

    def _services(self, fs: RootFS, sd: ServiceDir) -> list[Service]:
        down = fs.lexists(posixpath.join(sd.path, "down"))
        enabled = sd.link is not None and not down
        evidence = [sd.link or sd.path]
        if down:
            evidence.append(f"{posixpath.join(sd.path, 'down')} present: not started at boot")
        boot_path = [f"runsvdir {posixpath.dirname(sd.link)}", sd.link] if sd.link else []
        out: list[Service] = []
        svc = service_from_dir(
            fs, InitSystem.RUNIT, f"runit:{sd.name}", sd.name, sd.path,
            boot=enabled, enabled=enabled, boot_path=boot_path, evidence=evidence,
        )  # fmt: skip
        if svc is not None:
            out.append(svc)
        log_dir = posixpath.join(sd.path, "log")
        if fs.is_dir(log_dir):
            log = service_from_dir(
                fs, InitSystem.RUNIT, f"runit:{sd.name}/log", f"{sd.name}/log", log_dir,
                boot=enabled, enabled=enabled, boot_path=[*boot_path, f"{sd.name}/log"],
                evidence=list(evidence),
            )  # fmt: skip
            if log is not None:
                out.append(log)
        return out

    def _oneshots(self, fs: RootFS) -> list[Service]:
        out: list[Service] = []
        for stage in STAGES:
            st = fs.try_stat(stage)
            if st is None or not st.is_file:
                continue
            name = f"stage-{posixpath.basename(stage)}"
            svc = service_from_dir(
                fs, InitSystem.RUNIT, f"runit:{name}", name, posixpath.dirname(stage),
                boot=True, enabled=True, boot_path=[f"runit {stage}"], evidence=[stage],
                script=posixpath.basename(stage),
            )  # fmt: skip
            if svc is not None:
                out.append(svc)
        for fname in fs.safe_listdir(MY_INIT_D):
            p = posixpath.join(MY_INIT_D, fname)
            st = fs.try_stat(p)
            if st is None or not st.is_file:
                continue
            name = f"my_init.d/{fname}"
            out.append(
                finish_service(
                    fs,
                    Service(
                        id=f"runit:{name}",
                        name=name,
                        init_system=InitSystem.RUNIT,
                        unit_path=p,
                        enabled=True,
                        activation=[Activation.BOOT],
                        boot_path=[f"my_init {MY_INIT_D}", fname],
                        commands=[
                            Command(
                                directive="my_init.d", argv=[p], raw=p, executable=fs.try_resolve(p)
                            )
                        ],
                        hardening=base_hardening(),
                        evidence=[p],
                    ),
                )
            )
        return out
