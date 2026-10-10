"""SysV init scripts: ``/etc/init.d`` + ``rc?.d`` start links, LSB/chkconfig headers.

Enablement comes from ``S<NN>name`` links (any number of digits) in ``rcS.d``
and the default runlevel's ``rcN.d`` — never from ``Default-Start:``.  The
daemon a script launches is recovered heuristically from
``start-stop-daemon --start`` (``--startas``/``--exec``, ``--chuid``), RHEL
``daemon [--user u] prog``, ``init-d-script`` ``DAEMON=`` and literal
``DAEMON=``/``exec=`` assignments, with ``/etc/default/<name>`` and
``/etc/sysconfig/<name>`` overrides.  Link targets are resolved in-root.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import (
    SCRIPT_LIMIT,
    ShellEnv,
    parse_shell,
    shebang,
    strip_functions,
    unwrap_command,
)
from startup_sbom.initsys.inittab import default_runlevel
from startup_sbom.initsys.netconf import base_hardening, command_from, finish_service
from startup_sbom.models import Activation, Command, InitSystem, Service
from startup_sbom.rootfs import RootFS

INIT_DIRS = ("/etc/init.d", "/etc/rc.d/init.d")
RC_BASES = ("/etc", "/etc/rc.d")
RUNLEVELS = ("S", "0", "1", "2", "3", "4", "5", "6")
LINK_RE = re.compile(r"^(?P<kind>[SK])(?P<prio>\d+)(?P<name>.+)$")
SKIP = frozenset(
    {
        "README", "skeleton", "functions", "rc", "rcS", "halt", "reboot", "single",
        "killall", "sendsigs", "umountfs", "umountroot", "umountnfs.sh", ".depend.boot",
        ".depend.start", ".depend.stop", ".legacy-bootordering",
    }
)  # fmt: skip
SKIP_SUFFIX = (".dpkg-old", ".dpkg-new", ".dpkg-dist", ".rpmsave", ".rpmnew", ".orig", "~", ".bak")
DISABLE_KEYS = frozenset({"ENABLED", "ENABLE", "RUN", "START", "START_DAEMON", "RUN_DAEMON"})
FALSE_VALUES = frozenset({"0", "no", "false", "off", "n"})
DAEMON_VARS = ("DAEMON", "exec", "BINARY", "COMMAND", "DAEMON_PATH")
ARGS_VARS = ("DAEMON_ARGS", "DAEMON_OPTS", "OPTIONS", "ARGS", "OPTS")
SSD_WITH_ARG = frozenset(
    {
        "-x", "--exec", "-a", "--startas", "-c", "--chuid", "-u", "--user", "-p", "--pidfile",
        "-n", "--name", "-g", "--group", "-r", "--chroot", "-d", "--chdir", "-N", "--nicelevel",
        "-P", "--procsched", "-I", "--iosched", "-k", "--umask", "-R", "--retry", "-s",
        "--signal", "--remove-pidfile", "--notify-timeout", "--output", "-O",
    }
)  # fmt: skip


@dataclass(slots=True)
class SysvScript:
    """One init script and its enablement."""

    name: str
    path: str
    canonical: str
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    start_links: dict[str, list[str]] = field(default_factory=dict)

    @property
    def description(self) -> str | None:
        h = self.headers
        return h.get("short-description") or h.get("description") or h.get("chkconfig-description")


def parse_headers(text: str) -> dict[str, str]:
    """LSB ``INIT INFO`` block (lower-cased keys) plus chkconfig/``# description:`` headers."""
    out: dict[str, str] = {}
    lines = text.splitlines()[:400]
    in_lsb = False
    last: str | None = None
    for raw in lines:
        line = raw.rstrip()
        if line.strip() == "### BEGIN INIT INFO":
            in_lsb = True
            continue
        if line.strip() == "### END INIT INFO":
            in_lsb = False
            last = None
            continue
        if in_lsb:
            m = re.match(r"^#\s*([A-Za-z][A-Za-z0-9-]*):\s*(.*)$", line)
            if m and not re.match(r"^#(\t|  )", line):
                last = m.group(1).lower()
                out[last] = m.group(2).strip()
            elif last == "description" and re.match(r"^#(\t|  )", line):
                out[last] = (out[last] + " " + line[1:].strip()).strip()
            continue
        m = re.match(
            r"^#\s*(chkconfig|description|processname|pidfile|config):\s*(.*)$", line, re.I
        )
        if m:
            key = m.group(1).lower()
            key = "chkconfig-description" if key == "description" else key
            value = m.group(2).strip()
            out.setdefault(key, value.rstrip("\\").strip())
    return out


def _is_openrc(fs: RootFS, path: str) -> bool:
    sb = shebang(fs, path) or []
    return bool(sb) and posixpath.basename(sb[0]) in ("openrc-run", "runscript")


def find_scripts(fs: RootFS) -> list[SysvScript]:
    """Every SysV init script with the ``S`` links that start it (sorted by name)."""
    scripts: dict[str, SysvScript] = {}
    by_canon: dict[str, SysvScript] = {}
    for d in INIT_DIRS:
        for fname in fs.safe_listdir(d):
            if fname in SKIP or fname.startswith(".") or fname.endswith(SKIP_SUFFIX):
                continue
            path = posixpath.join(d, fname)
            st = fs.try_stat(path)
            if st is None or not st.is_file:
                continue
            canon = fs.try_resolve(path)
            if canon is None or canon in by_canon:
                continue
            if _is_openrc(fs, path):
                continue
            text = fs.try_read_text(path, SCRIPT_LIMIT) or ""
            name = fname[:-3] if fname.endswith(".sh") else fname
            if name in scripts:
                continue
            sc = SysvScript(name=name, path=path, canonical=canon, text=text)
            sc.headers = parse_headers(text)
            scripts[name] = sc
            by_canon[canon] = sc
    for base in RC_BASES:
        for rl in RUNLEVELS:
            rcdir = posixpath.join(base, f"rc{rl}.d")
            for entry in fs.safe_listdir(rcdir):
                m = LINK_RE.match(entry)
                if not m or m.group("kind") != "S":
                    continue
                target = fs.try_resolve(posixpath.join(rcdir, entry))
                owner = by_canon.get(target or "")
                if owner is None:
                    continue
                label = f"{posixpath.relpath(rcdir, '/etc')}/{entry}"
                owner.start_links.setdefault(rl, []).append(label)
    # Buildroot/BusyBox style: rcS loops over /etc/init.d/S??*
    rcs = fs.try_read_text("/etc/init.d/rcS", 256 * 1024) or ""
    if re.search(r"/etc/init\.d/S\?\?\*|S\[0-9\]\[0-9\]\*", rcs):
        for sc in scripts.values():
            if LINK_RE.match(posixpath.basename(sc.path)):
                sc.start_links.setdefault("S", []).append(
                    f"init.d/{posixpath.basename(sc.path)} (rcS loop)"
                )
    return [scripts[k] for k in sorted(scripts)]


def _defaults(fs: RootFS, name: str) -> tuple[dict[str, str], list[str]]:
    env: dict[str, str] = {}
    files: list[str] = []
    for d in ("/etc/default", "/etc/sysconfig", "/etc/conf.d"):
        path = posixpath.join(d, name)
        text = fs.try_read_text(path, 256 * 1024)
        if text is None:
            continue
        files.append(path)
        parse_shell(strip_functions(text), ShellEnv(env))
    return env, files


def ssd_command(cmd: list[str]) -> tuple[list[str], str | None] | None:
    """``start-stop-daemon --start``: return (argv, user) or ``None``."""
    if not any(a in ("--start", "-S") for a in cmd):
        return None
    exe = startas = user = None
    args: list[str] = []
    i = 1
    while i < len(cmd):
        a = cmd[i]
        if a == "--":
            args = cmd[i + 1 :]
            break
        key, eq, val = a.partition("=")
        if key in SSD_WITH_ARG:
            if not eq:
                val = cmd[i + 1] if i + 1 < len(cmd) else ""
                i += 1
            if key in ("-x", "--exec"):
                exe = val
            elif key in ("-a", "--startas"):
                startas = val
            elif key in ("-c", "--chuid") or (key in ("-u", "--user") and user is None):
                user = val.split(":", 1)[0]
        i += 1
    prog = startas or exe
    if not prog:
        return None
    return [prog, *args], user


def _daemon_command(cmd: list[str]) -> tuple[list[str], str | None] | None:
    """RHEL ``daemon [+/-nice] [--check n] [--user u] [--pidfile f] [--force] prog args``."""
    user = None
    i = 1
    while i < len(cmd):
        a = cmd[i]
        if a in ("--check", "--user", "--pidfile"):
            if a == "--user" and i + 1 < len(cmd):
                user = cmd[i + 1]
            i += 2
            continue
        if a.startswith("--user="):
            user = a.split("=", 1)[1]
            i += 1
            continue
        if a.startswith(("--", "+", "-")):
            i += 1
            continue
        return cmd[i:], user
    return None


def script_daemons(
    text: str, env: dict[str, str]
) -> tuple[list[tuple[str, list[str]]], str | None]:
    """Heuristic: ``[(directive, argv)]`` of daemons a script starts, and the run-as user."""
    found: list[tuple[str, list[str]]] = []
    user: str | None = None
    commands = parse_shell(text, ShellEnv(dict(env)))
    for cmd in commands:
        base = posixpath.basename(cmd[0])
        parsed = None
        if base == "start-stop-daemon":
            parsed = ssd_command(cmd)
            directive = "start-stop-daemon"
        elif base == "daemon":
            parsed = _daemon_command(cmd)
            directive = "daemon"
        if parsed is None:
            continue
        argv, u = parsed
        if argv not in [a for _, a in found]:
            found.append((directive, argv))
        user = user or u
    if not found:
        for var in DAEMON_VARS:
            value = env.get(var)
            if value and value.startswith("/"):
                args = next((env[a] for a in ARGS_VARS if env.get(a)), "")
                found.append((var, [value, *args.split()]))
                break
    return found, user


class SysVAnalyzer(InitAnalyzer):
    """SysV / LSB init scripts."""

    name = InitSystem.SYSV

    def detect(self, ctx: ScanContext) -> bool:
        fs = ctx.fs
        return any(
            fs.is_dir(d) and any(not _is_openrc(fs, p) for p in fs.glob_dir(d)[:64])
            for d in INIT_DIRS
        )

    def discover(self, ctx: ScanContext) -> list[Service]:
        fs = ctx.fs
        runlevel, rl_source = default_runlevel(fs)
        out: list[Service] = []
        errors = 0
        for sc in find_scripts(fs):
            try:
                out.append(self._service(fs, sc, runlevel, rl_source))
            except Exception as exc:  # noqa: BLE001 - one bad script never aborts the scan
                errors += 1
                if errors <= 5:
                    ctx.warn(f"sysv: {sc.path} skipped: {exc}")
        return out

    def _service(self, fs: RootFS, sc: SysvScript, runlevel: str, rl_source: str) -> Service:
        top_env: dict[str, str] = {"NAME": sc.name}
        lines = sc.text.splitlines()
        sb = lines[0] if lines and lines[0].startswith("#!") else ""
        parse_shell(strip_functions(sc.text), ShellEnv(top_env))
        overrides, default_files = _defaults(fs, sc.name)
        env = {**top_env, **overrides}
        evidence = [sc.path, *default_files]
        disabled = [
            k for k, v in overrides.items() if k in DISABLE_KEYS and v.lower() in FALSE_VALUES
        ]
        starts = sc.start_links.get("S", []) + sc.start_links.get(runlevel, [])
        boot = bool(starts) and not disabled
        enabled = bool(starts or any(sc.start_links.get(r) for r in "2345")) and not disabled
        if disabled:
            evidence.append(
                f"disabled by {', '.join(default_files)}: {', '.join(sorted(disabled))}"
            )
        daemons, user = script_daemons(sc.text, env)
        if "init-d-script" in sb and not daemons and env.get("DAEMON"):
            daemons = [("DAEMON", [env["DAEMON"], *env.get("DAEMON_ARGS", "").split()])]
        commands: list[Command] = [
            Command(
                directive="script",
                argv=[sc.path, "start"],
                raw=f"{sc.path} start",
                executable=sc.canonical,
            )
        ]
        for directive, argv in daemons:
            res = unwrap_command(fs, argv)
            commands.append(command_from(directive, argv, " ".join(argv), res))
            user = user or res.user
            evidence.extend(res.notes)
        rl_label = f"runlevel {runlevel} ({rl_source})"
        boot_path = [rl_label, starts[0]] if boot else []
        svc = Service(
            id=f"sysv:{sc.name}",
            name=sc.name,
            init_system=InitSystem.SYSV,
            description=sc.description,
            unit_path=sc.path,
            enabled=enabled,
            activation=[Activation.BOOT if boot else Activation.MANUAL],
            boot_path=boot_path,
            commands=commands,
            hardening=base_hardening(user=user or "root"),
            evidence=evidence
            + ["daemon command recovered heuristically from shell"] * bool(daemons),
        )
        return finish_service(fs, svc)
