"""Cron: jobs a cron daemon runs on a schedule (or once at boot with ``@reboot``).

Sources, all read statically:

* ``/etc/crontab`` and ``/etc/cron.d/*`` (system format: five schedule fields,
  then the **user**, then the command);
* per-user crontabs in ``/var/spool/cron/crontabs/<user>`` (Debian) and
  ``/var/spool/cron/<user>`` (RHEL, Arch) - the file name is the user;
* executables in ``/etc/cron.{hourly,daily,weekly,monthly}``, which
  ``run-parts`` / anacron run as root.

Each job becomes a :class:`Service` (``init_system=cron``) with ``TIMER``
activation (``BOOT`` for ``@reboot``).  Whether a cron daemon actually starts
is decided later, in :func:`startup_sbom.initsys.gate_scheduled_jobs`; without
one every job is downgraded to ``MANUAL`` with the reason recorded.
"""

from __future__ import annotations

import posixpath
import re

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import main_command, parse_shell, unwrap_command
from startup_sbom.initsys.netconf import base_hardening, command_from, finish_service
from startup_sbom.models import Activation, Command, InitSystem, Service
from startup_sbom.rootfs import RootFS

SYSTEM_TABS = ("/etc/crontab",)
SYSTEM_DIRS = ("/etc/cron.d",)
USER_DIRS = ("/var/spool/cron/crontabs", "/var/spool/cron")
PERIODIC = {
    "/etc/cron.hourly": "hourly",
    "/etc/cron.daily": "daily",
    "/etc/cron.weekly": "weekly",
    "/etc/cron.monthly": "monthly",
}
MAX_FILE = 256 * 1024
MAX_JOBS = 2_000
MAX_FILES = 500
#: run-parts (Debian) only runs names made of these characters.
_RUN_PARTS_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
_ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
_SPECIAL = frozenset(
    {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}
)
_USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}\$?$")


def _command_text(text: str) -> str:
    """Cut a cron command at the first unescaped ``%`` (the rest is stdin)."""
    out: list[str] = []
    escaped = False
    for ch in text:
        if escaped:
            out.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
            out.append(ch)
        elif ch == "%":
            break
        else:
            out.append(ch)
    return "".join(out).strip()


def parse_crontab(text: str, *, system: bool) -> list[tuple[int, str, str | None, str]]:
    """``[(line, schedule, user, command)]``; ``user`` is ``None`` for per-user tabs."""
    jobs: list[tuple[int, str, str | None, str]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or _ENV_LINE.match(line):
            continue
        fields = line.split(None, 1)
        if fields[0] in _SPECIAL:
            schedule, rest = fields[0], fields[1] if len(fields) > 1 else ""
        else:
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            schedule, rest = " ".join(parts[:5]), parts[5]
        user: str | None = None
        if system:
            split = rest.split(None, 1)
            if len(split) < 2 or not _USER_RE.match(split[0]):
                continue
            user, rest = split[0], split[1]
        command = _command_text(rest)
        if command:
            jobs.append((lineno, schedule, user, command))
        if len(jobs) >= MAX_JOBS:
            break
    return jobs


class CronAnalyzer(InitAnalyzer):
    """Scheduled jobs from crontabs and the periodic ``cron.*`` directories."""

    name = InitSystem.CRON

    def detect(self, ctx: ScanContext) -> bool:
        fs = ctx.fs
        return any(fs.is_file(p) for p in SYSTEM_TABS) or any(
            fs.is_dir(d) for d in (*SYSTEM_DIRS, *USER_DIRS, *PERIODIC)
        )

    def discover(self, ctx: ScanContext) -> list[Service]:
        fs = ctx.fs
        out: dict[str, Service] = {}
        files = 0
        tabs: list[tuple[str, bool, str | None]] = [(p, True, None) for p in SYSTEM_TABS]
        for d in SYSTEM_DIRS:
            tabs += [(p, True, None) for p in _list_files(fs, d)]
        for d in USER_DIRS:
            tabs += [(p, False, posixpath.basename(p)) for p in _list_files(fs, d)]
        for path, system, owner in tabs:
            if files >= MAX_FILES or len(out) >= MAX_JOBS:
                ctx.limit("cron: too many crontabs or jobs; the rest were not analysed")
                break
            text = fs.try_read_text(path, MAX_FILE)
            if text is None:
                continue
            files += 1
            if owner is not None and not _USER_RE.match(owner):
                continue
            for lineno, schedule, user, command in parse_crontab(text, system=system):
                try:
                    svc = _job(fs, path, lineno, schedule, user or owner or "root", command)
                except Exception as exc:  # noqa: BLE001 - one bad line never aborts the scan
                    ctx.warn(f"cron: {path}:{lineno} skipped: {exc}")
                    continue
                out.setdefault(svc.id, svc)
        for d, period in PERIODIC.items():
            for path in _list_files(fs, d):
                name = posixpath.basename(path)
                st = fs.try_stat(path)
                if st is None or not _RUN_PARTS_NAME.match(name) or not st.mode & 0o111:
                    continue
                svc = _periodic(fs, path, period)
                out.setdefault(svc.id, svc)
        return [out[k] for k in sorted(out)]


def _list_files(fs: RootFS, d: str) -> list[str]:
    cdir = fs.try_resolve(d)
    if cdir is None or not fs.is_dir(cdir):
        return []
    names = sorted(fs.safe_listdir(cdir))[:MAX_FILES]
    return [
        f"{cdir.rstrip('/')}/{n}"
        for n in names
        if not n.startswith(".")
        and not n.endswith(("~", ".dpkg-old", ".dpkg-dist", ".rpmnew"))
        and fs.is_file(f"{cdir.rstrip('/')}/{n}")
    ]


def _job(fs: RootFS, path: str, lineno: int, schedule: str, user: str, command: str) -> Service:
    commands = parse_shell(command)
    main, others = main_command(commands) if commands else (None, [])
    cmds: list[Command] = []
    for argv in ([main] if main else []) + others:
        res = unwrap_command(fs, argv)
        cmds.append(command_from("cron", argv, command, res))
    boot = schedule == "@reboot"
    name = f"{posixpath.basename(path)}:{lineno}"
    svc = Service(
        id=f"cron:{path}:{lineno}",
        name=name,
        init_system=InitSystem.CRON,
        description=f"{schedule} as {user}: {command[:120]}",
        unit_path=path,
        enabled=True,
        activation=[Activation.BOOT if boot else Activation.TIMER],
        boot_path=[f"{path}:{lineno} @reboot"] if boot else [],
        commands=cmds,
        hardening=base_hardening(user=user),
        evidence=[f"{path}:{lineno}: {schedule} {user}"],
    )
    return finish_service(fs, svc, netconf=False)


def _periodic(fs: RootFS, path: str, period: str) -> Service:
    res = unwrap_command(fs, [path])
    svc = Service(
        id=f"cron:{path}",
        name=posixpath.basename(path),
        init_system=InitSystem.CRON,
        description=f"run {period} by run-parts/anacron as root",
        unit_path=path,
        enabled=True,
        activation=[Activation.TIMER],
        commands=[command_from("run-parts", [path], path, res)],
        hardening=base_hardening(user="root"),
        evidence=[f"{posixpath.dirname(path)} ({period}, run-parts)"],
    )
    return finish_service(fs, svc, netconf=False)
