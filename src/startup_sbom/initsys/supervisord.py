"""supervisord: ``[program:x]``/``[fcgi-program:x]``/``[eventlistener:x]`` and ``[include]``.

INI with ConfigParser semantics (inline ``;`` comments need preceding
whitespace, ``%(here)s``/``%(program_name)s``/``%(process_num)d`` expanded).
``[include] files=`` globs are relative to the including file and not
recursive.  ``autostart`` defaults to true; ``user=`` defaults to supervisord's
own identity.  The daemon's own listeners (``[inet_http_server]``) are exposed
through :func:`parse_config` so the launcher can carry them.
"""

from __future__ import annotations

import configparser
import posixpath
import re
from dataclasses import dataclass, field

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import (
    DEFAULT_PATH,
    fs_glob,
    parse_shell,
    split_path_env,
    unwrap_command,
)
from startup_sbom.initsys.netconf import (
    base_hardening,
    command_from,
    finish_service,
    split_host_port,
)
from startup_sbom.models import Activation, InitSystem, ListenAddress, Service
from startup_sbom.rootfs import RootFS

CONFIG_CANDIDATES = (
    "/etc/supervisord.conf",
    "/etc/supervisor/supervisord.conf",
    "/usr/local/etc/supervisord.conf",
    "/etc/supervisor.conf",
)
CONFIG_LIMIT = 1024 * 1024
MAX_INCLUDES = 256
PROGRAM_PREFIXES = ("program:", "fcgi-program:", "eventlistener:")
_INTERP_RE = re.compile(r"%\((?P<key>[A-Za-z0-9_]+)\)(?P<fmt>[-#0 +]*\d*)[sd]")


@dataclass(slots=True)
class SupervisordConfig:
    """Parsed supervisord configuration."""

    path: str
    programs: list[Service] = field(default_factory=list)
    listens: list[ListenAddress] = field(default_factory=list)
    user: str | None = None
    files: list[str] = field(default_factory=list)


def find_config(fs: RootFS) -> str | None:
    return next((c for c in CONFIG_CANDIDATES if fs.is_file(c)), None)


def _interp(value: str, values: dict[str, str]) -> str:
    def rep(m: re.Match[str]) -> str:
        key = m.group("key")
        if key in values:
            return values[key]
        if key.startswith("ENV_"):
            return f"${{{key[4:]}}}"
        return m.group(0)

    return _INTERP_RE.sub(rep, value)


def _parser() -> configparser.RawConfigParser:
    cp = configparser.RawConfigParser(
        strict=False,
        interpolation=None,
        inline_comment_prefixes=(";",),
        comment_prefixes=(";", "#"),
    )
    cp.optionxform = str  # type: ignore[assignment,method-assign]
    return cp


def _read(fs: RootFS, path: str, cp: configparser.RawConfigParser) -> bool:
    text = fs.try_read_text(path, CONFIG_LIMIT)
    if text is None:
        return False
    try:
        cp.read_string(text, source=path)
    except configparser.Error:
        # tolerate garbage: keep what parsed so far, retry line-filtered
        cleaned = "\n".join(
            ln for ln in text.splitlines() if ln.strip().startswith(("[", ";", "#")) or "=" in ln
        )
        try:
            cp.read_string(cleaned, source=path)
        except configparser.Error:
            return False
    return True


def parse_config(fs: RootFS, path: str) -> SupervisordConfig:
    """Parse a supervisord configuration (and its includes) into program services."""
    cfg = SupervisordConfig(path=path)
    main = _parser()
    if not _read(fs, path, main):
        return cfg
    cfg.files.append(path)
    sources: list[tuple[str, configparser.RawConfigParser]] = [(path, main)]
    if main.has_section("include"):
        here = posixpath.dirname(path)
        files = _interp(main.get("include", "files", fallback=""), {"here": here})
        for pat in files.split():
            for inc in fs_glob(fs, pat, cwd=here)[:MAX_INCLUDES]:
                cp = _parser()
                if _read(fs, inc, cp):
                    cfg.files.append(inc)
                    sources.append((inc, cp))
    for src, cp in sources:
        if cp.has_section("supervisord") and cp.has_option("supervisord", "user"):
            cfg.user = cp.get("supervisord", "user").strip() or cfg.user
        if cp.has_section("inet_http_server") and cp.has_option("inet_http_server", "port"):
            host, port = split_host_port(cp.get("inet_http_server", "port"))
            if port is not None:
                cfg.listens.append(
                    ListenAddress(
                        protocol="tcp",
                        address=None if host in (None, "", "*") else host,
                        port=port,
                        scope="loopback"
                        if host in ("127.0.0.1", "localhost", "::1")
                        else "network",
                        source=f"{src} [inet_http_server]",
                    )
                )
        if cp.has_section("unix_http_server") and cp.has_option("unix_http_server", "file"):
            cfg.listens.append(
                ListenAddress(
                    protocol="unix",
                    path=_interp(
                        cp.get("unix_http_server", "file"), {"here": posixpath.dirname(src)}
                    ),
                    scope="local",
                    source=f"{src} [unix_http_server]",
                )
            )
    seen: set[str] = set()
    for src, cp in sources:
        for section in cp.sections():
            if not section.startswith(PROGRAM_PREFIXES):
                continue
            kind, _, pname = section.partition(":")
            pname = pname.strip()
            if not pname or pname in seen:
                continue
            seen.add(pname)
            svc = _program(fs, cfg, src, cp, section, kind, pname)
            if svc is not None:
                cfg.programs.append(svc)
    return cfg


def _program(
    fs: RootFS,
    cfg: SupervisordConfig,
    src: str,
    cp: configparser.RawConfigParser,
    section: str,
    kind: str,
    pname: str,
) -> Service | None:
    values = {
        "program_name": pname,
        "process_num": "0",
        "group_name": pname,
        "here": posixpath.dirname(src),
        "host_node_name": "<hostname>",
    }

    def opt(key: str, default: str = "") -> str:
        return _interp(cp.get(section, key, fallback=default), values).strip()

    command = opt("command")
    if not command:
        return None
    path_env = list(DEFAULT_PATH)
    m = re.search(r"(?:^|,)\s*PATH\s*=\s*\"?([^\",]+)", opt("environment"))
    if m:
        path_env = split_path_env(m.group(1)) or path_env
    cmds = parse_shell(command)
    argv = cmds[0] if cmds else command.split()
    cwd = opt("directory") or "/"
    res = unwrap_command(fs, argv, path_env=path_env, cwd=cwd)
    autostart = opt("autostart", "true").lower() not in ("false", "0", "no", "off")
    user = opt("user") or res.user or cfg.user or "root"
    listens: list[ListenAddress] = []
    if kind == "fcgi-program":
        sock = opt("socket")
        if sock.startswith("tcp://"):
            host, port = split_host_port(sock[6:])
            listens.append(
                ListenAddress(
                    protocol="tcp",
                    address=None if host in (None, "", "*") else host,
                    port=port,
                    scope="loopback" if host in ("127.0.0.1", "localhost", "::1") else "network",
                    source=f"{src} [{section}] socket",
                )
            )
        elif sock.startswith("unix://"):
            listens.append(
                ListenAddress(
                    protocol="unix",
                    path=sock[7:],
                    scope="local",
                    source=f"{src} [{section}] socket",
                )
            )
    svc = Service(
        id=f"supervisord:{pname}",
        name=pname,
        init_system=InitSystem.SUPERVISORD,
        description=f"supervisord [{section}]",
        unit_path=src,
        enabled=autostart,
        activation=[Activation.BOOT if autostart else Activation.MANUAL],
        boot_path=[f"supervisord {cfg.path}", f"[{section}] autostart=true"] if autostart else [],
        commands=[command_from("command", argv, command, res)],
        hardening=base_hardening(user=user),
        listens=listens,
        evidence=[src, *res.notes],
    )
    return finish_service(fs, svc)


class SupervisordAnalyzer(InitAnalyzer):
    """supervisord programs (default config locations; see :func:`parse_config`)."""

    name = InitSystem.SUPERVISORD

    def __init__(self, config: str | None = None) -> None:
        self.config = config

    def detect(self, ctx: ScanContext) -> bool:
        return (self.config is not None and ctx.fs.is_file(self.config)) or find_config(
            ctx.fs
        ) is not None

    def discover(self, ctx: ScanContext) -> list[Service]:
        path = self.config if self.config and ctx.fs.is_file(self.config) else find_config(ctx.fs)
        if path is None:
            return []
        try:
            return parse_config(ctx.fs, path).programs
        except Exception as exc:  # noqa: BLE001
            ctx.warn(f"supervisord: {path} skipped: {exc}")
            return []
