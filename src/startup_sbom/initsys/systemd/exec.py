"""``Exec*=`` lines → :class:`~startup_sbom.models.Command` with resolved executables."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from startup_sbom.initsys.cmdline import DEFAULT_PATH, Resolution, unwrap_command
from startup_sbom.initsys.systemd.loader import Settings
from startup_sbom.initsys.systemd.parser import expand_specifiers, parse_exec
from startup_sbom.models import Command
from startup_sbom.rootfs import RootFS

#: Safe superset of systemd's built-in search path for bare ``ExecStart=`` names.
SYSTEMD_PATH: tuple[str, ...] = DEFAULT_PATH
SERVICE_EXEC_KEYS = (
    "ExecCondition",
    "ExecStartPre",
    "ExecStart",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
)
SOCKET_EXEC_KEYS = ("ExecStartPre", "ExecStartPost", "ExecStopPre", "ExecStopPost")


@dataclass(slots=True)
class ExecResult:
    commands: list[Command] = field(default_factory=list)
    executables: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    resolutions: list[tuple[str, Resolution]] = field(default_factory=list)
    start_count: int = 0


def build_commands(
    fs: RootFS,
    settings: Settings,
    table: Mapping[str, str],
    *,
    section: str = "Service",
    keys: tuple[str, ...] = SERVICE_EXEC_KEYS,
) -> ExecResult:
    """Parse, specifier-expand and resolve every ``Exec*=`` line of ``section``."""
    out = ExecResult()
    for key in keys:
        for value in settings.values(section, key):
            for spec in parse_exec(value):
                if key == "ExecStart":
                    out.start_count += 1
                argv = [expand_specifiers(a, table) for a in spec.argv]
                path = expand_specifiers(spec.path, table)
                # '@': argv[0] is a fake name, the program is still ``path``
                resolve_argv = ["/bin/sh", *argv[1:]] if spec.via_shell else [path, *argv[1:]]
                res = unwrap_command(fs, resolve_argv, path_env=SYSTEMD_PATH)
                out.resolutions.append((key, res))
                out.commands.append(
                    Command(
                        directive=key,
                        argv=argv,
                        raw=spec.raw,
                        executable=res.executable,
                        full_privileges=spec.full_privileges,
                        wrapped_by=res.wrappers,
                    )
                )
                for exe in [res.executable, *res.wrappers, *res.side_executables]:
                    if exe and exe not in out.executables:
                        out.executables.append(exe)
                if spec.full_privileges:
                    out.notes.append(f"{key}=+{path}: runs with full privileges (sandbox bypassed)")
                if spec.no_setuid:
                    out.notes.append(
                        f"{key}=!{path}: User=/Group= ignored, runs with root identity"
                    )
                if spec.argv0_override and argv:
                    out.notes.append(f"{key}=@{path}: argv[0] masqueraded as {argv[0]!r}")
                for err in spec.errors:
                    out.notes.append(f"{key}: invalid command: {err}")
                if res.executable is None and path:
                    out.notes.append(f"{key}: executable {path!r} not found in image")
                out.notes.extend(res.notes)
    return out
