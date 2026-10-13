"""Activation triggers: what makes vulnerable code run, and who can cause it.

Reachability says *where* a package sits; a trigger says *what executes it*
(boot, a socket connection, a timer or cron job, a D-Bus request, a device
event, a local user running a setuid binary, any system call into the kernel)
and the least-privileged party able to fire it.  A threat with no trigger is
installed code that nothing on the system runs on anyone else's behalf.
"""

from __future__ import annotations

from startup_sbom.models import (
    Activation,
    InitSystem,
    Package,
    Service,
    Trigger,
    TriggerKind,
)
from startup_sbom.threat.reachability import (
    Exposure,
    ReachInfo,
    SystemIndex,
    dangerous_caps,
    describe_listen,
    is_kernel_package,
    service_user,
    setuid_root,
)

NETWORK = "network"
LOCAL_USER = "local user"
SYSTEM = "system"
DEVICE = "device"
MAX_TRIGGERS = 16
#: Shown when a threat has no trigger at all.
NO_TRIGGER = (
    "no trigger observed: no started service, scheduled job, device rule, setuid "
    "binary or kernel path runs this code"
)

_KIND: dict[Activation, TriggerKind] = {
    Activation.BOOT: TriggerKind.BOOT,
    Activation.SOCKET: TriggerKind.SOCKET,
    Activation.TIMER: TriggerKind.TIMER,
    Activation.PATH: TriggerKind.PATH,
    Activation.DBUS: TriggerKind.DBUS,
    Activation.DEVICE: TriggerKind.DEVICE,
    Activation.ENTRYPOINT: TriggerKind.ENTRYPOINT,
}
#: Who can fire each activation when the service has no network listener.
_FIRED_BY: dict[TriggerKind, str] = {
    TriggerKind.BOOT: SYSTEM,
    TriggerKind.ENTRYPOINT: SYSTEM,
    TriggerKind.TIMER: SYSTEM,
    TriggerKind.CRON: SYSTEM,
    TriggerKind.PATH: SYSTEM,
    TriggerKind.DEVICE: DEVICE,
    TriggerKind.SOCKET: LOCAL_USER,  # a unix/loopback socket any local process may open
    TriggerKind.DBUS: LOCAL_USER,  # bus activation is requested by any permitted client
}
_DETAIL: dict[TriggerKind, str] = {
    TriggerKind.BOOT: "started at boot",
    TriggerKind.ENTRYPOINT: "container entry process",
    TriggerKind.TIMER: "started on a schedule",
    TriggerKind.CRON: "run by the cron daemon on a schedule",
    TriggerKind.PATH: "started when a watched path changes",
    TriggerKind.DEVICE: "run by udev on a matching device event",
    TriggerKind.SOCKET: "started on the first connection to its socket",
    TriggerKind.DBUS: "started on demand by a D-Bus request",
}
#: Strongest (most attacker-accessible) first, for deterministic ordering.
_FIRED_RANK = {NETWORK: 0, LOCAL_USER: 1, DEVICE: 2, SYSTEM: 3}


def build_triggers(index: SystemIndex, info: ReachInfo, pkg: Package) -> list[Trigger]:
    """Every observed activation path of ``pkg``, most attacker-accessible first."""
    out: dict[tuple[str, str], Trigger] = {}
    for sid in info.services:
        svc = index.services.get(sid)
        if svc is None or not svc.starts_automatically:
            continue
        for trig in service_triggers(svc, index.exposure.get(sid)):
            out.setdefault((trig.kind.value, trig.subject), trig)
    for b in info.setuid_binaries:
        runs_as = "root" if setuid_root(b) or dangerous_caps(b) else _owner(b.owner_uid)
        out.setdefault(
            (TriggerKind.SETUID.value, b.path),
            Trigger(
                kind=TriggerKind.SETUID,
                subject=b.path,
                fired_by=LOCAL_USER,
                runs_as=runs_as,
                detail="privileged binary shipped by the package; any local user may run it",
            ),
        )
    for chain in info.privileged_loaders:
        out.setdefault(
            (TriggerKind.SETUID.value, chain[0]),
            Trigger(
                kind=TriggerKind.SETUID,
                subject=chain[0],
                fired_by=LOCAL_USER,
                runs_as="root",
                via=list(chain[1:]),
                detail="privileged binary that loads the vulnerable library",
            ),
        )
    if is_kernel_package(pkg) and index.report.container is None:
        out.setdefault(
            (TriggerKind.KERNEL.value, pkg.id),
            Trigger(
                kind=TriggerKind.KERNEL,
                subject=pkg.id,
                fired_by=LOCAL_USER,
                runs_as="kernel",
                detail="installed kernel image; reached through system calls",
            ),
        )
    ranked = sorted(
        out.values(), key=lambda t: (_FIRED_RANK.get(t.fired_by, 9), t.kind.value, t.subject)
    )
    return ranked[:MAX_TRIGGERS]


def service_triggers(svc: Service, exposure: Exposure | None) -> list[Trigger]:
    """The triggers of one automatically started service."""
    runs_as = service_user(svc)
    listens = ""
    exposed = exposure is not None and exposure.exposed
    if exposure is not None and exposed:
        listens = ", ".join(describe_listen(li) for li in exposure.listens[:3])
    out: list[Trigger] = []
    for act in svc.activation:
        kind = _KIND.get(act)
        if kind is None:
            continue
        if kind is TriggerKind.TIMER and svc.init_system is InitSystem.CRON:
            kind = TriggerKind.CRON
        detail = _DETAIL[kind]
        fired_by = _FIRED_BY[kind]
        if exposed:
            fired_by = NETWORK
            detail = f"{detail}; network input on {listens}"
        out.append(
            Trigger(kind=kind, subject=svc.id, fired_by=fired_by, runs_as=runs_as, detail=detail)
        )
    return out


def describe_trigger(t: Trigger) -> str:
    """``setuid /usr/bin/sudo (fired by local user, runs as root) via libfoo.so``."""
    head = f"{t.kind.value} {t.subject} (fired by {t.fired_by}"
    head += f", runs as {t.runs_as})" if t.runs_as else ")"
    if t.via:
        head += " via " + " → ".join(t.via)
    return head


def _owner(uid: int | None) -> str:
    return "root" if uid in (0, None) else f"uid {uid}"
