"""OpenRC (Alpine, Gentoo, Artix): runlevels, ``depend()`` pull-ins and ``openrc-run`` scripts.

Boot set = services of ``sysinit`` ∪ ``boot`` ∪ ``default`` (stacked runlevels
followed with loop detection) plus everything they ``need``/``want``
(virtual ``provide`` names resolved).  Per service, variables are evaluated in
openrc-run order — ``conf.d/<base>``, ``conf.d/<svc>``, ``/etc/rc.conf``, then the
script (``: ${var:=default}`` only fills unset values) — to recover
``command``/``command_args``/``command_user``/``capabilities``/``no_new_privs``.
"""

from __future__ import annotations

import posixpath
import re
from collections import deque
from dataclasses import dataclass, field

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import (
    SCRIPT_LIMIT,
    SHELL_BUILTINS,
    ShellEnv,
    parse_shell,
    shebang,
    shell_function_body,
    strip_functions,
    unwrap_command,
    which,
)
from startup_sbom.initsys.netconf import base_hardening, command_from, finish_service
from startup_sbom.initsys.sysv import ssd_command
from startup_sbom.models import Activation, Command, InitSystem, Service
from startup_sbom.rootfs import RootFS

INIT_DIRS = ("/etc/init.d", "/etc/rc/init.d", "/usr/local/etc/init.d", "/usr/local/etc/rc/init.d")
RUNLEVELS = "/etc/runlevels"
BOOT_LEVELS = ("sysinit", "boot", "default")
MAX_STACK = 16
HELPERS = frozenset(
    {
        "ebegin", "eend", "einfo", "einfon", "ewarn", "ewarnn", "eerror", "eerrorn",
        "vebegin", "veend", "veinfo", "vewarn", "eindent", "eoutdent", "checkpath",
        "yesno", "service_set_value", "service_get_value", "mark_service_started",
        "mark_service_stopped", "service_started", "default_start", "default_stop",
        "start-stop-daemon", "supervise-daemon", "get_bootparam", "is_older_than",
        "is_newer_than", "rc-service", "openrc", "need", "use", "want", "after",
        "before", "provide", "keyword", "config",
    }
)  # fmt: skip


@dataclass(slots=True)
class OpenRCScript:
    name: str
    path: str
    canonical: str
    text: str
    need: list[str] = field(default_factory=list)
    want: list[str] = field(default_factory=list)
    provide: list[str] = field(default_factory=list)
    keyword: list[str] = field(default_factory=list)


def is_openrc_script(fs: RootFS, path: str) -> bool:
    sb = shebang(fs, path) or []
    return bool(sb) and posixpath.basename(sb[0]) in ("openrc-run", "runscript")


def _depend(text: str) -> dict[str, list[str]]:
    body = shell_function_body(text, "depend") or ""
    out: dict[str, list[str]] = {}
    for line in body.replace(";", "\n").splitlines():
        words = line.split()
        if words and words[0] in ("need", "want", "use", "after", "before", "provide", "keyword"):
            out.setdefault(words[0], []).extend(w for w in words[1:] if not w.startswith("#"))
    return out


def find_scripts(fs: RootFS) -> dict[str, OpenRCScript]:
    """OpenRC service scripts by name (first init directory wins)."""
    out: dict[str, OpenRCScript] = {}
    for d in INIT_DIRS:
        for name in fs.safe_listdir(d):
            if name in out or name.startswith("."):
                continue
            path = posixpath.join(d, name)
            st = fs.try_stat(path)
            if st is None or not st.is_file or not is_openrc_script(fs, path):
                continue
            text = fs.try_read_text(path, SCRIPT_LIMIT) or ""
            dep = _depend(text)
            out[name] = OpenRCScript(
                name=name,
                path=path,
                canonical=fs.try_resolve(path) or path,
                text=text,
                need=dep.get("need", []),
                want=dep.get("want", []),
                provide=dep.get("provide", []),
                keyword=dep.get("keyword", []),
            )
    return out


def runlevel_services(fs: RootFS, level: str) -> list[tuple[str, str]]:
    """``(service, label)`` in a runlevel, following stacked runlevels."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    stack = [(level, f"runlevel {level}")]
    while stack and len(seen) < MAX_STACK:
        lvl, label = stack.pop(0)
        if lvl in seen:
            continue
        seen.add(lvl)
        d = posixpath.join(RUNLEVELS, lvl)
        for entry in fs.safe_listdir(d):
            p = posixpath.join(d, entry)
            if fs.is_dir(p):
                stack.append((entry, f"{label} → stacked runlevel {entry}"))
            else:
                out.append((entry, f"{label}: {posixpath.relpath(p, '/etc')}"))
    return out


def _env_for(
    fs: RootFS, sc: OpenRCScript, base_env: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    env = dict(base_env)
    env.update({"RC_SVCNAME": sc.name, "SVCNAME": sc.name, "RC_RUNLEVEL": "default"})
    files: list[str] = []
    base = sc.name.split(".", 1)[0]
    confd = posixpath.join(posixpath.dirname(posixpath.dirname(sc.path)), "conf.d")
    for cand in dict.fromkeys([posixpath.join(confd, base), posixpath.join(confd, sc.name)]):
        text = fs.try_read_text(cand, 256 * 1024)
        if text is not None:
            files.append(cand)
            parse_shell(strip_functions(text), ShellEnv(env))
    rc_conf = fs.try_read_text("/etc/rc.conf", 256 * 1024)
    if rc_conf is not None:
        files.append("/etc/rc.conf")
        parse_shell(strip_functions(rc_conf), ShellEnv(env))
    parse_shell(strip_functions(sc.text), ShellEnv(env))
    return env, files


def _caps(value: str) -> list[str]:
    out: list[str] = []
    for raw in re.split(r"[,\s]+", value):
        tok = raw.strip().lstrip("^+=").split("=", 1)[0].split("+", 1)[0]
        if not tok:
            continue
        cap = tok.upper()
        out.append(cap if cap.startswith("CAP_") else f"CAP_{cap}")
    return sorted(set(out))


class OpenRCAnalyzer(InitAnalyzer):
    """OpenRC runlevels and ``openrc-run`` service scripts."""

    name = InitSystem.OPENRC

    def detect(self, ctx: ScanContext) -> bool:
        fs = ctx.fs
        return fs.is_dir(RUNLEVELS) or fs.exists("/sbin/openrc-run") or fs.exists("/sbin/openrc")

    def discover(self, ctx: ScanContext) -> list[Service]:
        fs = ctx.fs
        scripts = find_scripts(fs)
        global_env: dict[str, str] = {}
        rc_conf = fs.try_read_text("/etc/rc.conf", 256 * 1024)
        if rc_conf is not None:
            parse_shell(strip_functions(rc_conf), ShellEnv(global_env))
        rc_sys = global_env.get("rc_sys", "").strip()
        providers: dict[str, list[str]] = {}
        for sc in scripts.values():
            for p in sc.provide:
                providers.setdefault(p, []).append(sc.name)
        envs: dict[str, tuple[dict[str, str], list[str]]] = {}

        def env_of(name: str) -> tuple[dict[str, str], list[str]]:
            if name not in envs:
                envs[name] = _env_for(fs, scripts[name], {})
            return envs[name]

        boot: dict[str, list[str]] = {}
        queue: deque[tuple[str, list[str]]] = deque()
        for level in BOOT_LEVELS:
            for svc, label in runlevel_services(fs, level):
                queue.append((svc, [label]))
        excluded: dict[str, str] = {}
        while queue:
            name, path = queue.popleft()
            if name in boot or name not in scripts:
                continue
            sc = scripts[name]
            if rc_sys and f"-{rc_sys}" in sc.keyword:
                excluded[name] = f"keyword -{rc_sys} with rc_sys={rc_sys}"
                continue
            boot[name] = path
            env, _ = env_of(name)
            deps = (
                sc.need + sc.want + env.get("rc_need", "").split() + env.get("rc_want", "").split()
            )
            for dep in deps:
                if dep.startswith("!"):
                    continue
                if dep in scripts:
                    queue.append((dep, [*path, f"{name} need {dep}"]))
                    continue
                provs = sorted(providers.get(dep, []))
                chosen = [p for p in provs if p in boot] or provs[:1]
                for p in chosen:
                    queue.append((p, [*path, f"{name} need {dep} (provided by {p})"]))
        out: list[Service] = []
        errors = 0
        for name in sorted(scripts):
            try:
                out.append(
                    self._service(
                        fs, scripts[name], env_of(name), boot.get(name), excluded.get(name)
                    )
                )
            except Exception as exc:  # noqa: BLE001 - one bad script never aborts the scan
                errors += 1
                if errors <= 5:
                    ctx.warn(f"openrc: {scripts[name].path} skipped: {exc}")
        return out

    def _service(
        self,
        fs: RootFS,
        sc: OpenRCScript,
        env_files: tuple[dict[str, str], list[str]],
        boot_path: list[str] | None,
        excluded: str | None,
    ) -> Service:
        env, files = env_files
        evidence = [sc.path, *files]
        commands: list[Command] = []
        ssd = which(fs, "start-stop-daemon", ["/sbin", "/usr/sbin", "/bin", "/usr/bin"])
        supervisor = env.get("supervisor", "").strip()
        sup_exe = which(fs, "supervise-daemon", ["/sbin", "/usr/sbin", "/bin", "/usr/bin"])
        user = env.get("command_user", "").strip() or None
        start_body = shell_function_body(sc.text, "start")
        if start_body is not None:
            for cmd in parse_shell(start_body, ShellEnv(dict(env))):
                base = posixpath.basename(cmd[0])
                parsed = ssd_command(cmd) if base == "start-stop-daemon" else None
                if parsed is not None:
                    argv, u = parsed
                    user = user or u
                    res = unwrap_command(fs, argv)
                    c = command_from("start", argv, " ".join(cmd), res)
                    if ssd:
                        c.wrapped_by = [ssd, *c.wrapped_by]
                    commands.append(c)
                elif (
                    base not in HELPERS
                    and base not in SHELL_BUILTINS
                    and (cmd[0].startswith("/") or which(fs, cmd[0]))
                ):
                    commands.append(
                        command_from("start", cmd, " ".join(cmd), unwrap_command(fs, cmd))
                    )
        elif env.get("command"):
            parsed_cmd = parse_shell(env["command"]) or [[env["command"]]]
            argv0 = parsed_cmd[0]
            extra = env.get("command_args", "")
            if supervisor == "supervise-daemon":
                extra = f"{extra} {env.get('command_args_foreground', '')}"
            args = [w for c in parse_shell(extra) for w in c] if extra.strip() else []
            full = [*argv0, *args]
            res = unwrap_command(fs, full)
            c = command_from("command", full, " ".join(full), res)
            launcher = sup_exe if supervisor == "supervise-daemon" else ssd
            if launcher:
                c.wrapped_by = [launcher, *c.wrapped_by]
            commands.append(c)
            evidence.extend(res.notes)
        for hook in ("start_pre", "start_post", "checkconfig"):
            body = shell_function_body(sc.text, hook)
            if not body:
                continue
            for cmd in parse_shell(body, ShellEnv(dict(env))):
                base = posixpath.basename(cmd[0])
                if base in HELPERS or base in SHELL_BUILTINS:
                    continue
                if cmd[0].startswith("/") or which(fs, cmd[0]):
                    commands.append(command_from(hook, cmd, " ".join(cmd), unwrap_command(fs, cmd)))
        for logger_var in ("output_logger", "error_logger"):
            if env.get(logger_var):
                cmds = parse_shell(env[logger_var])
                if cmds:
                    commands.append(
                        command_from(
                            logger_var, cmds[0], env[logger_var], unwrap_command(fs, cmds[0])
                        )
                    )
        if sc.name == "local":
            for d in ("/etc/local.d",):
                for fname in fs.safe_listdir(d):
                    p = posixpath.join(d, fname)
                    st = fs.try_stat(p)
                    if fname.endswith(".start") and st is not None and st.is_executable:
                        commands.append(
                            Command(
                                directive="local.d", argv=[p], raw=p, executable=fs.try_resolve(p)
                            )
                        )
        group = None
        if user and ":" in user:
            user, group = user.split(":", 1)
        nnp = (env.get("no_new_privs") or "").strip().lower() in ("yes", "true", "1", "on")
        caps = _caps(env.get("capabilities", ""))
        if excluded:
            evidence.append(f"excluded: {excluded}")
        boot = boot_path is not None
        svc = Service(
            id=f"openrc:{sc.name}",
            name=sc.name,
            init_system=InitSystem.OPENRC,
            description=env.get("description") or env.get("name") or None,
            unit_path=sc.path,
            enabled=boot,
            activation=[Activation.BOOT if boot else Activation.MANUAL],
            boot_path=boot_path or [],
            commands=commands,
            hardening=base_hardening(
                user=user or "root",
                group=group,
                no_new_privileges=nnp,
                ambient=caps,
                root_directory=env.get("chroot") or None,
            ),
            evidence=evidence,
        )
        return finish_service(fs, svc, [sc.canonical])
