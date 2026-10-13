"""udev: programs the device manager runs as root when matching device events occur.

Rules in ``/etc/udev/rules.d``, ``/run/udev/rules.d`` and ``/usr/lib/udev/rules.d``
(``/lib/udev/rules.d`` on unmerged-/usr systems) are read with udev's own
precedence: a file in ``/etc`` overrides the same name in ``/run``, which
overrides ``/usr/lib``.  Every program a rule executes - ``RUN+=`` /
``RUN{program}+=``, ``PROGRAM==`` and ``IMPORT{program}=`` - becomes one
:class:`Service` (``init_system=udev``, ``DEVICE`` activation, running as root),
aggregated by executable with every rule that runs it as evidence.  Builtins
(``RUN{builtin}``, ``IMPORT{builtin}``) execute no program and are skipped.

Programs only run when a udev daemon starts; see
:func:`startup_sbom.initsys.gate_scheduled_jobs`.
"""

from __future__ import annotations

import posixpath
import re
import shlex

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import unwrap_command
from startup_sbom.initsys.netconf import base_hardening, command_from, finish_service
from startup_sbom.models import Activation, Command, InitSystem, Service
from startup_sbom.rootfs import RootFS

RULE_DIRS = ("/etc/udev/rules.d", "/run/udev/rules.d", "/usr/lib/udev/rules.d", "/lib/udev/rules.d")
PROGRAM_DIRS = ("/usr/lib/udev", "/lib/udev")
MAX_RULE_FILES = 1_000
MAX_FILE = 512 * 1024
MAX_PROGRAMS = 500
_KEY = re.compile(
    r"(?P<key>RUN|PROGRAM|IMPORT)(?:\{(?P<attr>[a-z]+)\})?\s*(?P<op>\+=|:=|==|=)\s*"
    r'"(?P<value>(?:[^"\\]|\\.)*)"'
)


def rule_files(fs: RootFS) -> list[str]:
    """Effective rule files in udev order (by file name, earlier directories win)."""
    chosen: dict[str, str] = {}
    for d in RULE_DIRS:
        cdir = fs.try_resolve(d)
        if cdir is None or not fs.is_dir(cdir):
            continue
        for name in fs.safe_listdir(cdir):
            if name.endswith(".rules") and name not in chosen:
                path = f"{cdir.rstrip('/')}/{name}"
                if fs.is_file(path) or fs.is_symlink(path):
                    chosen[name] = path
    return [chosen[n] for n in sorted(chosen)][:MAX_RULE_FILES]


def rule_programs(text: str) -> list[tuple[int, str]]:
    """``[(line, program command line)]`` for every program a rules file executes."""
    out: list[tuple[int, str]] = []
    pending = ""
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = pending + raw
        if line.endswith("\\"):
            pending = line[:-1]
            continue
        pending = ""
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for m in _KEY.finditer(stripped):
            key, attr, op = m.group("key"), m.group("attr"), m.group("op")
            if key == "IMPORT" and attr != "program":
                continue
            if key == "RUN" and attr not in (None, "program"):
                continue
            if key == "RUN" and op == "==":
                continue  # a match on RUN is not an assignment
            value = m.group("value").strip()
            if value:
                out.append((lineno, value))
    return out


def _resolve_program(fs: RootFS, word: str) -> str | None:
    if word.startswith("/"):
        return fs.try_resolve(word)
    for d in PROGRAM_DIRS:
        found = fs.try_resolve(f"{d}/{word}")
        if found is not None and fs.is_file(found):
            return found
    return None


class UdevAnalyzer(InitAnalyzer):
    """Programs executed by udev rules on device events."""

    name = InitSystem.UDEV

    def detect(self, ctx: ScanContext) -> bool:
        return any(ctx.fs.is_dir(d) for d in RULE_DIRS)

    def discover(self, ctx: ScanContext) -> list[Service]:
        fs = ctx.fs
        programs: dict[str, tuple[list[str], list[str], str]] = {}  # exe -> argv, evidence, raw
        for path in rule_files(fs):
            text = fs.try_read_text(path, MAX_FILE)
            if text is None:
                continue
            for lineno, value in rule_programs(text):
                try:
                    argv = shlex.split(value)
                except ValueError:
                    continue
                if not argv or "$" in argv[0] or "%" in argv[0]:
                    continue
                exe = _resolve_program(fs, argv[0])
                if exe is None:
                    continue
                argv = [exe, *argv[1:]]
                entry = programs.setdefault(exe, (argv, [], value))
                if len(entry[1]) < 10:
                    entry[1].append(f"{path}:{lineno}")
                if len(programs) >= MAX_PROGRAMS:
                    ctx.limit("udev: too many rule programs; the rest were not analysed")
                    break
        out: list[Service] = []
        for exe in sorted(programs):
            argv, evidence, raw = programs[exe]
            res = unwrap_command(fs, argv)
            cmd: Command = command_from("RUN", argv, raw, res)
            svc = Service(
                id=f"udev:{exe}",
                name=posixpath.basename(exe),
                init_system=InitSystem.UDEV,
                description=f"run by udev on device events ({len(evidence)} rule(s))",
                unit_path=evidence[0].rsplit(":", 1)[0] if evidence else None,
                enabled=True,
                activation=[Activation.DEVICE],
                commands=[cmd],
                hardening=base_hardening(user="root"),
                evidence=[f"udev rule {e}" for e in evidence],
            )
            out.append(finish_service(fs, svc, netconf=False))
        return out
