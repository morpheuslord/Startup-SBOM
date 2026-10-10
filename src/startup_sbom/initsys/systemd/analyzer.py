"""systemd analyzer: every service unit, how it is activated, what it runs and exposes."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import main_command, parse_shell, unwrap_command
from startup_sbom.initsys.netconf import base_hardening, daemon_listens, dedupe
from startup_sbom.initsys.systemd.boot import BootGraph, shorten, traverse
from startup_sbom.initsys.systemd.exec import build_commands
from startup_sbom.initsys.systemd.hardening import from_settings, to_hardening
from startup_sbom.initsys.systemd.loader import GeneratedUnit, Unit, UnitLoader, search_path
from startup_sbom.initsys.systemd.parser import (
    SpecifierContext,
    expand_specifiers,
    parse_bool,
    parse_unit_name,
    parse_unit_text,
)
from startup_sbom.initsys.systemd.sockets import LISTEN_KEYS, loopback_restricted, parse_listen
from startup_sbom.models import Activation, Command, InitSystem, ListenAddress, Service
from startup_sbom.rootfs import RootFS

DBUS_DIRS = (
    "/etc/dbus-1/system-services",
    "/usr/local/share/dbus-1/system-services",
    "/usr/share/dbus-1/system-services",
    "/lib/dbus-1/system-services",
)
RUNLEVEL_TARGETS = {
    "1": "rescue.target",
    "2": "multi-user.target",
    "3": "multi-user.target",
    "4": "multi-user.target",
    "5": "graphical.target",
}
_ACT_ORDER = {
    Activation.BOOT: 0,
    Activation.SOCKET: 1,
    Activation.TIMER: 2,
    Activation.PATH: 3,
    Activation.DBUS: 4,
    Activation.ENTRYPOINT: 5,
    Activation.MANUAL: 6,
}


@dataclass(slots=True)
class _Trigger:
    activation: Activation
    unit: Unit
    path: list[str]


@dataclass(slots=True)
class _State:
    triggers: dict[str, list[_Trigger]] = field(default_factory=dict)
    dbus_files: dict[str, list[str]] = field(default_factory=dict)


def has_units(fs: RootFS) -> bool:
    """True if any unit search directory contains a unit file."""
    return any(parse_unit_name(n) is not None for d in search_path(fs) for n in fs.safe_listdir(d))


def _mangle(name: str) -> str:
    out = []
    for ch in name:
        if ch.isalnum() or ch in ":_.-":
            out.append(ch)
        else:
            out.extend(f"\\x{b:02x}" for b in ch.encode("utf-8", "replace"))
    return "".join(out)


def _quote(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


class SystemdAnalyzer(InitAnalyzer):
    """systemd system manager (offline emulation of unit loading and the boot transaction)."""

    name = InitSystem.SYSTEMD

    def detect(self, ctx: ScanContext) -> bool:
        return has_units(ctx.fs)

    def discover(self, ctx: ScanContext) -> list[Service]:
        return _Discovery(ctx).run()


class _Discovery:
    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self.fs = ctx.fs
        self.loader = UnitLoader(self.fs)
        hostname = (self.fs.try_read_text("/etc/hostname", 4096) or "").strip().split("\n")[0]
        machine_id = (self.fs.try_read_text("/etc/machine-id", 4096) or "").strip()
        osr = {
            "ID": ctx.os.id if ctx.os.id != "unknown" else "",
            "VERSION_ID": ctx.os.version_id or "",
            "VARIANT_ID": ctx.os.variant_id or "",
            "BUILD_ID": ctx.os.build_id or "",
        }
        self._spec_base = SpecifierContext(
            name="", hostname=hostname or None, machine_id=machine_id or None, os_release=osr
        )
        self._tables: dict[str, dict[str, str]] = {}
        self.errors = 0

    def table(self, unit: Unit) -> dict[str, str]:
        t = self._tables.get(unit.name)
        if t is None:
            sc = SpecifierContext(
                name=unit.name,
                fragment=unit.content_path or unit.fragment,
                hostname=self._spec_base.hostname,
                machine_id=self._spec_base.machine_id,
                os_release=self._spec_base.os_release,
            )
            t = sc.table()
            self._tables[unit.name] = t
        return t

    # -- generators ---------------------------------------------------------------
    def _emulate_generators(self) -> None:
        from startup_sbom.initsys import sysv

        loader, fs = self.loader, self.fs
        if loader.generator_present("systemd-sysv-generator"):
            for sc in sysv.find_scripts(fs):
                unit_name = f"{_mangle(sc.name)}.service"
                if parse_unit_name(unit_name) is None or loader.has_unit(unit_name):
                    continue
                desc = sc.description or f"LSB: {sc.name}"
                entries = [
                    ("Unit", "Description", desc),
                    ("Unit", "SourcePath", sc.path),
                    ("Service", "Type", "forking"),
                    ("Service", "ExecStart", f"{_quote(sc.path)} start"),
                    ("Service", "ExecStop", f"{_quote(sc.path)} stop"),
                ]
                wanted: list[tuple[str, str]] = []
                for rl, labels in sorted(sc.start_links.items()):
                    target = RUNLEVEL_TARGETS.get(rl)
                    if target:
                        wanted.append(
                            (target, f"{target}.wants/{unit_name} (sysv-generator: {labels[0]})")
                        )
                loader.add_generated(
                    GeneratedUnit(unit_name, sc.path, entries, "systemd-sysv-generator"), wanted
                )
        if loader.generator_present("systemd-rc-local-generator"):
            for path in ("/etc/rc.local", "/etc/rc.d/rc.local"):
                st = fs.try_stat(path)
                if st is None or not st.is_file or not st.mode & 0o100:
                    continue
                if not loader.has_unit("rc-local.service"):
                    entries = [
                        ("Unit", "Description", f"{path} Compatibility"),
                        ("Unit", "ConditionFileIsExecutable", path),
                        ("Service", "Type", "forking"),
                        ("Service", "ExecStart", f"{_quote(path)} start"),
                    ]
                    loader.add_generated(
                        GeneratedUnit(
                            "rc-local.service", path, entries, "systemd-rc-local-generator"
                        )
                    )
                loader.add_generated_want(
                    "multi-user.target",
                    "rc-local.service",
                    "multi-user.target.wants/rc-local.service (rc-local-generator)",
                )
                break

    # -- main -----------------------------------------------------------------------
    def run(self) -> list[Service]:
        self._emulate_generators()
        goal = "initrd.target" if self.fs.exists("/etc/initrd-release") else "default.target"
        boot = traverse(self.loader, goal=goal, tables=self.table)
        if boot.truncated:
            self.ctx.warn("systemd: boot traversal truncated (unit limit reached)")
        state = _State()
        self._collect_triggers(boot, state)
        dbus_services = self._scan_dbus(state)
        refs = self.loader.enablement_refs()
        names: set[str] = set()
        for n in self.loader.known_names():
            un = parse_unit_name(n)
            entry = self.loader.map.get(n)
            if un is None or un.type != "service" or (entry is not None and entry.kind == "alias"):
                continue
            names.add(n)
        for n in [*boot.paths, *boot.masked, *state.triggers, *state.dbus_files, *refs]:
            un = parse_unit_name(n)
            if un is not None and un.type == "service":
                names.add(n)
        units: dict[str, Unit] = {}
        for n in sorted(names):
            u = self.loader.load(n)
            if (u.found or u.masked) and u.type == "service":
                units.setdefault(u.name, u)
        # drop templates that only exist to back instances (keep socket Accept=yes targets)
        instance_templates = {
            u.parsed.template
            for u in units.values()
            if u.parsed is not None and u.parsed.is_instance
        }
        for n in list(units):
            u = units[n]
            if (
                u.parsed is not None
                and u.parsed.is_template
                and n in instance_templates
                and n not in state.triggers
                and n not in boot.paths
            ):
                del units[n]
        out: list[Service] = []
        for name in sorted(units):
            try:
                out.append(self._service(units[name], boot, state, refs))
            except Exception as exc:  # noqa: BLE001 - one bad unit never aborts the scan
                self.errors += 1
                if self.errors <= 5:
                    self.ctx.warn(f"systemd: unit {name} skipped: {exc}")
        out.extend(dbus_services)
        if self.errors > 5:
            self.ctx.warn(f"systemd: {self.errors} units could not be analysed")
        return out

    def _collect_triggers(self, boot: BootGraph, state: _State) -> None:
        for name, path in boot.paths.items():
            u = self.loader.load(name)
            if u.masked or not u.found or u.type not in ("socket", "timer", "path"):
                continue
            s = u.settings
            prefix = u.parsed.prefix if u.parsed else name.rsplit(".", 1)[0]
            if u.type == "socket":
                accept = bool(parse_bool(s.get("Socket", "Accept")))
                target = s.get("Socket", "Service")
                if accept or not target:
                    target = f"{prefix}@.service" if accept else f"{prefix}.service"
                act = Activation.SOCKET
            else:
                section = "Timer" if u.type == "timer" else "Path"
                target = s.get(section, "Unit") or f"{prefix}.service"
                act = Activation.TIMER if u.type == "timer" else Activation.PATH
            target = expand_specifiers(target.strip(), self.table(u))
            final = self.loader.resolve_name(target)
            state.triggers.setdefault(final, []).append(
                _Trigger(act, u, shorten([*path, f"{u.name}→{final}"]))
            )

    def _scan_dbus(self, state: _State) -> list[Service]:
        seen: set[str] = set()
        out: list[Service] = []
        for d in DBUS_DIRS:
            for fname in self.fs.safe_listdir(d):
                if not fname.endswith(".service") or fname in seen:
                    continue
                seen.add(fname)
                path = posixpath.join(d, fname)
                text = self.fs.try_read_text(path, 256 * 1024)
                if text is None:
                    continue
                vals = {k: v for sec, k, v in parse_unit_text(text) if sec == "D-BUS Service"}
                bus_name = vals.get("Name", fname[: -len(".service")])
                unit = vals.get("SystemdService")
                if unit:
                    final = self.loader.resolve_name(unit.strip())
                    state.dbus_files.setdefault(final, []).append(path)
                    continue
                exec_line = vals.get("Exec")
                if not exec_line:
                    continue
                try:
                    out.append(self._dbus_service(bus_name, path, exec_line, vals.get("User")))
                except Exception as exc:  # noqa: BLE001
                    self.ctx.warn(f"systemd: D-Bus service {path} skipped: {exc}")
        return out

    def _dbus_service(self, bus_name: str, path: str, exec_line: str, user: str | None) -> Service:
        cmds = parse_shell(exec_line)
        main, _ = main_command(cmds) if cmds else (None, [])
        argv = main or []
        res = unwrap_command(self.fs, argv) if argv else None
        commands = (
            [
                Command(
                    directive="Exec",
                    argv=argv,
                    raw=exec_line,
                    executable=res.executable,
                    wrapped_by=res.wrappers,
                )
            ]
            if res is not None
            else []
        )
        exes = sorted({e for c in commands for e in [c.executable, *c.wrapped_by] if e})
        return Service(
            id=f"systemd:dbus:{bus_name}",
            name=f"dbus:{bus_name}",
            init_system=InitSystem.SYSTEMD,
            description=f"D-Bus activatable service {bus_name} (spawned by dbus-daemon)",
            unit_path=path,
            enabled=True,
            activation=[Activation.DBUS],
            commands=commands,
            executables=exes,
            hardening=base_hardening(user=(user or "root").strip()),
            evidence=[path],
        )

    def _socket_listens(self, sock: Unit) -> list[ListenAddress]:
        s = sock.settings
        table = self.table(sock)
        entries: list[tuple[str, str]] = []
        for section, key, value in s.ordered:
            if section != "Socket" or key not in LISTEN_KEYS:
                continue
            if value == "":
                entries = []
            else:
                entries.append((key, value))
        loop = loopback_restricted(
            s.words("Socket", "IPAddressDeny"),
            s.words("Socket", "IPAddressAllow"),
            s.get("Socket", "BindToDevice"),
        )
        proto = (s.get("Socket", "SocketProtocol") or "").strip().lower() or None
        source = sock.content_path or sock.fragment or sock.name
        out: list[ListenAddress] = []
        for key, value in entries:
            la = parse_listen(
                key,
                expand_specifiers(value, table),
                source=source,
                socket_protocol=proto,
                loopback_only=loop,
            )
            if la is not None:
                out.append(la)
        return out

    def _service(self, unit: Unit, boot: BootGraph, state: _State, refs: dict[str, str]) -> Service:
        sid = f"systemd:{unit.name}"
        evidence = [p for p in (unit.fragment, unit.content_path) if p]
        if unit.masked:
            return Service(
                id=sid,
                name=unit.name,
                init_system=InitSystem.SYSTEMD,
                unit_path=unit.fragment,
                enabled=False,
                masked=True,
                activation=[Activation.MANUAL],
                boot_path=boot.masked.get(unit.name, []),
                evidence=[*evidence, "masked (symlink to /dev/null or empty unit file)"],
            )
        s = unit.settings
        table = self.table(unit)
        ex = build_commands(self.fs, s, table)
        activation: list[Activation] = []
        boot_path: list[str] = []
        if unit.name in boot.paths:
            activation.append(Activation.BOOT)
            boot_path = boot.paths[unit.name]
        listens: list[ListenAddress] = []
        for trig in sorted(state.triggers.get(unit.name, []), key=lambda t: t.unit.name):
            if trig.activation not in activation:
                activation.append(trig.activation)
            if not boot_path:
                boot_path = trig.path
            evidence.append(trig.unit.content_path or trig.unit.fragment or trig.unit.name)
            if trig.activation is Activation.SOCKET:
                listens.extend(self._socket_listens(trig.unit))
        if unit.name in state.dbus_files:
            activation.append(Activation.DBUS)
            evidence.extend(state.dbus_files[unit.name])
        enabled = bool(activation) or any(n in refs for n in unit.names)
        if not activation:
            activation = [Activation.MANUAL]
        activation.sort(key=lambda a: _ACT_ORDER[a])
        if not any(la.protocol in ("tcp", "udp", "sctp") for la in listens):
            for key, res in ex.resolutions:
                if key != "ExecStart":
                    continue
                found, ev = daemon_listens(self.fs, res.executable, res.argv)
                listens.extend(found)
                evidence.extend(ev)
        sec = from_settings(
            s.section("Service"),
            default_dependencies=parse_bool(s.get("Unit", "DefaultDependencies")) is not False,
            unit_prefix=unit.parsed.prefix if unit.parsed else None,
        )
        hardening = to_hardening(sec, group=(s.get("Service", "Group") or None))
        typ = (s.get("Service", "Type") or "").strip() or (
            "simple" if ex.start_count else "oneshot"
        )
        notes = list(ex.notes)
        if ex.start_count > 1 and typ != "oneshot":
            notes.append(f"bad-setting: {ex.start_count} ExecStart= lines for Type={typ}")
        if not ex.commands:
            notes.append("bad-setting: no Exec*= commands")
        if unit.generated:
            notes.append(f"generated by {unit.generated} from {unit.fragment}")
        evidence.extend(unit.dropins)
        evidence.extend(f"alias: {a}" for a in unit.aliases if a != unit.name)
        evidence.extend(unit.notes)
        evidence.extend(notes)
        desc = s.get("Unit", "Description")
        return Service(
            id=sid,
            name=unit.name,
            init_system=InitSystem.SYSTEMD,
            description=expand_specifiers(desc, table) if desc else None,
            unit_path=unit.fragment,
            enabled=enabled,
            masked=False,
            activation=activation,
            boot_path=boot_path,
            commands=ex.commands,
            executables=sorted(ex.executables),
            hardening=hardening,
            listens=dedupe(listens),
            evidence=list(dict.fromkeys(evidence)),
        )
