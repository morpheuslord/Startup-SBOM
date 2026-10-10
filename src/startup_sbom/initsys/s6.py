"""s6 and s6-overlay: ``cont-init.d`` one-shots, s6-rc ``user`` bundle, legacy ``services.d``.

s6-overlay v3 stage 2 order: ``/etc/cont-init.d/*`` (lexical), the s6-rc
services of bundle ``user`` (``s6-rc.d/user/contents.d/<name>``, dependencies
followed, bundles expanded), legacy ``/etc/services.d/<name>/run`` longruns.
Oneshot ``up`` files are single execline command lines.  Plain s6 scan
directories (``/etc/s6/sv``, s6-linux-init ``run-image/service``) are read too.
"""

from __future__ import annotations

import posixpath
from collections import deque

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import DEFAULT_PATH, execline_split, unwrap_command
from startup_sbom.initsys.netconf import base_hardening, command_from, finish_service
from startup_sbom.initsys.runit import service_from_dir
from startup_sbom.models import Activation, Command, InitSystem, Service
from startup_sbom.rootfs import RootFS

S6_PATH = ["/command", *DEFAULT_PATH]
RC_DIRS = ("/etc/s6-overlay/s6-rc.d", "/etc/s6-rc/source", "/etc/s6/sv", "/etc/s6/adminsv")
CONT_INIT = "/etc/cont-init.d"
SERVICES_D = "/etc/services.d"
SCAN_DIRS = ("/etc/s6-linux-init/current/run-image/service", "/etc/s6/current", "/service")
MAX_RC = 2_000


def _read_first(fs: RootFS, path: str) -> str:
    return (fs.try_read_text(path, 64 * 1024) or "").strip()


def _list_names(fs: RootFS, base: str, name: str) -> list[str]:
    """Names from a ``<name>`` file (one per line) and/or ``<name>.d/`` directory."""
    out = [w for w in _read_first(fs, posixpath.join(base, name)).split() if not w.startswith("#")]
    out += [n for n in fs.safe_listdir(posixpath.join(base, name + ".d")) if not n.startswith(".")]
    return sorted(set(out))


def is_s6(fs: RootFS) -> bool:
    return (
        fs.is_dir("/etc/s6-overlay")
        or fs.is_dir("/package/admin/s6-overlay")
        or fs.is_dir(SERVICES_D)
        or fs.is_dir(CONT_INIT)
        or any(fs.is_dir(d) for d in RC_DIRS)
        or fs.lexists("/command/s6-svscan")
    )


class S6Analyzer(InitAnalyzer):
    """s6 / s6-overlay supervision trees."""

    name = InitSystem.S6

    def detect(self, ctx: ScanContext) -> bool:
        return is_s6(ctx.fs)

    def discover(self, ctx: ScanContext) -> list[Service]:
        fs = ctx.fs
        out: list[Service] = []
        try:
            out.extend(self._cont_init(fs))
        except Exception as exc:  # noqa: BLE001
            ctx.warn(f"s6: cont-init.d skipped: {exc}")
        for rc_dir in RC_DIRS:
            if fs.is_dir(rc_dir):
                try:
                    out.extend(self._s6rc(fs, rc_dir))
                except Exception as exc:  # noqa: BLE001
                    ctx.warn(f"s6: {rc_dir} skipped: {exc}")
        for base in (SERVICES_D, *SCAN_DIRS):
            for entry in fs.safe_listdir(base):
                sdir = fs.try_resolve(posixpath.join(base, entry))
                if sdir is None or not fs.is_dir(sdir) or entry.startswith("."):
                    continue
                down = fs.lexists(posixpath.join(sdir, "down"))
                label = f"{base}/{entry}"
                try:
                    svc = service_from_dir(
                        fs, InitSystem.S6, f"s6:{entry}", entry, sdir,
                        boot=not down, enabled=not down, boot_path=[f"s6-svscan {base}", label],
                        evidence=[label], path_env=S6_PATH,
                    )  # fmt: skip
                except Exception as exc:  # noqa: BLE001
                    ctx.warn(f"s6: {label} skipped: {exc}")
                    continue
                if svc is not None and all(s.id != svc.id for s in out):
                    out.append(svc)
        return out

    def _cont_init(self, fs: RootFS) -> list[Service]:
        out: list[Service] = []
        for fname in fs.safe_listdir(CONT_INIT):
            p = posixpath.join(CONT_INIT, fname)
            st = fs.try_stat(p)
            if st is None or not st.is_file or fname.startswith("."):
                continue
            name = f"cont-init.d/{fname}"
            svc = Service(
                id=f"s6:{name}",
                name=name,
                init_system=InitSystem.S6,
                unit_path=p,
                enabled=True,
                activation=[Activation.BOOT],
                boot_path=["s6-overlay stage 2", name],
                commands=[
                    Command(directive="cont-init", argv=[p], raw=p, executable=fs.try_resolve(p))
                ],
                hardening=base_hardening(),
                evidence=[p],
            )
            out.append(finish_service(fs, svc, netconf=False))
        return out

    def _s6rc(self, fs: RootFS, rc_dir: str) -> list[Service]:
        names = sorted(n for n in fs.safe_listdir(rc_dir) if fs.is_dir(posixpath.join(rc_dir, n)))
        types = {n: _read_first(fs, posixpath.join(rc_dir, n, "type")) for n in names}
        # boot closure from bundle "user" (s6-overlay) or "default" (s6-rc distros)
        boot: dict[str, list[str]] = {}
        queue: deque[tuple[str, list[str]]] = deque()
        for root in ("user", "user2", "default"):
            if types.get(root) == "bundle":
                queue.append((root, [f"s6-rc bundle {root}"]))
        while queue and len(boot) < MAX_RC:
            name, path = queue.popleft()
            if name in boot or name not in types:
                continue
            boot[name] = path
            sdir = posixpath.join(rc_dir, name)
            if types[name] == "bundle":
                for member in _list_names(fs, sdir, "contents"):
                    queue.append((member, [*path, f"{name}/contents.d/{member}"]))
            for dep in _list_names(fs, sdir, "dependencies"):
                queue.append((dep, [*path, f"{name} depends on {dep}"]))
        out: list[Service] = []
        for name in names:
            typ = types[name]
            if typ not in ("longrun", "oneshot"):
                continue
            sdir = posixpath.join(rc_dir, name)
            in_boot = name in boot
            evidence = [posixpath.join(sdir, "type")]
            if typ == "longrun":
                svc = service_from_dir(
                    fs, InitSystem.S6, f"s6:{name}", name, sdir,
                    boot=in_boot, enabled=in_boot, boot_path=boot.get(name, []),
                    evidence=evidence, path_env=S6_PATH,
                )  # fmt: skip
                if svc is not None:
                    out.append(svc)
                continue
            up = posixpath.join(sdir, "up")
            words = execline_split(fs.try_read_text(up, 64 * 1024) or "")
            commands: list[Command] = []
            user = None
            if words:
                res = unwrap_command(fs, words, path_env=S6_PATH, execline=True)
                commands.append(command_from("up", words, " ".join(words), res))
                user = res.user
            svc = Service(
                id=f"s6:{name}",
                name=name,
                init_system=InitSystem.S6,
                unit_path=up,
                enabled=in_boot,
                activation=[Activation.BOOT if in_boot else Activation.MANUAL],
                boot_path=boot.get(name, []),
                commands=commands,
                hardening=base_hardening(user=user or "root"),
                evidence=[*evidence, up],
            )
            out.append(finish_service(fs, svc))
        return out
