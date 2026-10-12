"""Container entrypoint: ``Entrypoint + Cmd`` resolved, unwrapped and placed in its sandbox.

argv is ``Entrypoint + Cmd`` (``Cmd`` alone without an entrypoint); a
shell-form entrypoint (``["/bin/sh", "-c", "..."]``) receives the ``Cmd`` words
as ``$0 $1 ...`` exactly as at runtime.  Bare names are searched in the default
OCI PATH (image ``Env`` values are never recorded), relative paths against
``WorkingDir``.  Identity comes from ``User`` (empty = root, overridden by
gosu/su-exec style wrappers), the sandbox from the runtime fields when known and
Docker's defaults otherwise, and ``ExposedPorts`` become network listeners.
"""

from __future__ import annotations

from startup_sbom.context import ScanContext
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.initsys.cmdline import DEFAULT_PATH, unwrap_command
from startup_sbom.initsys.netconf import (
    command_from,
    daemon_argv,
    daemon_listens,
    dedupe,
    exposed_port_listens,
    finish_service,
)
from startup_sbom.initsys.systemd.hardening import (
    ALL_CAP_SET,
    CONTAINER_DEFAULT_CAPS,
    NAMESPACES,
    SecurityInput,
    expand_group,
    to_hardening,
)
from startup_sbom.models import (
    Activation,
    ContainerInfo,
    Hardening,
    InitSystem,
    ListenAddress,
    Service,
)

ENTRY_ID = "container:entrypoint"
#: Syscall groups refused by Docker's default seccomp profile for unprivileged containers.
_DEFAULT_SECCOMP_DENY = (
    "@clock", "@cpu-emulation", "@module", "@mount", "@obsolete", "@raw-io", "@reboot", "@swap",
)  # fmt: skip


def _cap(name: str) -> str:
    n = name.strip().upper()
    return n if n.startswith("CAP_") or n == "ALL" else f"CAP_{n}"


def container_argv(info: ContainerInfo) -> list[str]:
    """The process argv the runtime would execute."""
    if info.entrypoint:
        return [*info.entrypoint, *info.cmd]
    return list(info.cmd)


def container_hardening(info: ContainerInfo, user: str | None, group: str | None) -> Hardening:
    """Map container runtime settings onto the systemd-analyze exposure model."""
    privileged = bool(info.privileged)
    add = {_cap(c) for c in info.cap_add}
    drop = {_cap(c) for c in info.cap_drop}
    if privileged or "ALL" in add:
        caps = set(ALL_CAP_SET)
    else:
        caps = set() if "ALL" in drop else set(CONTAINER_DEFAULT_CAPS) - drop
        caps |= add - {"ALL"}
    opts = [o.strip().lower() for o in info.security_opt]
    nnp = any(o.startswith("no-new-privileges") and not o.endswith(("false", "=0")) for o in opts)
    unconfined = privileged or any(o in ("seccomp=unconfined", "seccomp:unconfined") for o in opts)
    deny: set[str] = set()
    for g in _DEFAULT_SECCOMP_DENY:
        deny |= expand_group(g)
    s = SecurityInput(
        user=user or None,
        no_new_privileges=nnp,
        capability_bounding_set=frozenset(caps),
        private_tmp="no" if privileged else "yes",
        private_devices=not privileged,
        private_mounts=True,
        private_network=(info.network_mode or "") == "none",
        protect_control_groups="no" if privileged else "yes",
        protect_kernel_tunables=not privileged,
        protect_kernel_modules="CAP_SYS_MODULE" not in caps,
        protect_kernel_logs="CAP_SYSLOG" not in caps,
        protect_clock="CAP_SYS_TIME" not in caps,
        protect_system="strict" if info.readonly_rootfs else "no",
        protect_hostname=(info.network_mode or "") != "host",
        restrict_namespaces_allowed=NAMESPACES if "CAP_SYS_ADMIN" in caps else frozenset(),
        sc_mode=None if unconfined else "deny",
        sc_set=frozenset() if unconfined else frozenset(deny),
        device_policy="auto" if privileged else "closed",
        device_allow=not privileged,
    )
    return to_hardening(s, group=group)


class ContainerAnalyzer(InitAnalyzer):
    """The container's entry process (from image config / ``docker inspect``)."""

    name = InitSystem.CONTAINER

    def detect(self, ctx: ScanContext) -> bool:
        info = ctx.container
        return info is not None and bool(info.entrypoint or info.cmd)

    def discover(self, ctx: ScanContext) -> list[Service]:
        info = ctx.container
        if info is None:
            return []
        fs = ctx.fs
        argv = container_argv(info)
        if not argv:
            return []
        cwd = info.working_dir if (info.working_dir or "").startswith("/") else "/"
        path_env = list(info.path) or list(DEFAULT_PATH)
        res = unwrap_command(fs, argv, path_env=path_env, cwd=cwd or "/")
        cfg_user, _, cfg_group = (info.user or "").partition(":")
        user = res.user or cfg_user or "root"
        group = res.group or cfg_group or None
        commands = [
            command_from("Entrypoint" if info.entrypoint else "Cmd", argv, " ".join(argv), res)
        ]
        for side in res.side_commands:
            sres = unwrap_command(fs, side, path_env=path_env, cwd=cwd or "/")
            if sres.executable:
                commands.append(command_from("Entrypoint-shell", side, " ".join(side), sres))
        evidence = ["image config Entrypoint/Cmd"]
        if info.kind == "image" or info.privileged is None:
            evidence.append("container runtime settings unknown: Docker defaults assumed")
        if info.path:
            evidence.append("image PATH: " + ":".join(info.path))
        elif "PATH" in info.env_keys:
            evidence.append("image sets PATH but it was unusable: default OCI PATH used")
        evidence.extend(res.notes)
        listens: list[ListenAddress] = []
        if (info.network_mode or "") != "none":
            listens = exposed_port_listens(info.exposed_ports, "image config ExposedPorts")
        svc = Service(
            id=ENTRY_ID,
            name="entrypoint",
            init_system=InitSystem.CONTAINER,
            description=f"Container entry process of {info.image or info.name or 'image'}",
            enabled=True,
            activation=[Activation.ENTRYPOINT],
            boot_path=[f"container start → {res.executable or argv[0]}"],
            commands=commands,
            hardening=container_hardening(info, user, group),
            listens=listens,
            evidence=evidence,
        )
        svc = finish_service(fs, svc, netconf=False)
        found = list(svc.listens)
        for cmd in svc.commands:  # daemon config applies in addition to ExposedPorts
            extra, ev = daemon_listens(fs, cmd.executable, daemon_argv(cmd))
            found.extend(extra)
            svc.evidence.extend(e for e in ev if e not in svc.evidence)
        if (info.network_mode or "") != "none":
            svc.listens = dedupe(found)
        return [svc]
