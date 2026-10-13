"""Cron jobs and udev rule programs: discovery, parsing and daemon gating."""

from __future__ import annotations

from collections.abc import Callable

from images import DEBIAN_SYSTEMD, ELF, exe

from fsbuilder import Spec, Symlink
from startup_sbom.context import ScanContext
from startup_sbom.initsys import discover_all
from startup_sbom.initsys.cron import parse_crontab
from startup_sbom.initsys.udev import rule_programs
from startup_sbom.models import Activation, InitSystem, Service
from startup_sbom.rootfs import RootFS

MakeFS = Callable[[Spec], RootFS]
MakeCtx = Callable[..., ScanContext]

CRONTAB = """\
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
@reboot         root    /usr/local/bin/warmup --quick
*/5 * * * *     backup  /usr/local/bin/backup.sh % stdin goes here
bad line
"""

UDEV_RULE = """\
# comment
ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/local/sbin/usb-hook %k"
ACTION=="add", RUN{builtin}+="kmod load $env{MODALIAS}"
KERNEL=="sd*", IMPORT{program}="disk-id $devnode"
KERNEL=="x", PROGRAM=="/usr/bin/true", \\
  RUN+="/usr/local/sbin/usb-hook again"
"""

ENABLE_CRON: Spec = {
    "/etc/systemd/system/multi-user.target.wants/cron.service": Symlink(
        "/usr/lib/systemd/system/cron.service"
    ),
}

UDEVD: Spec = {
    "/usr/lib/systemd/systemd-udevd": ELF,
    "/usr/lib/systemd/system/systemd-udevd.service": (
        "[Unit]\nDescription=udev\n[Service]\nExecStart=/usr/lib/systemd/systemd-udevd\n"
    ),
    "/usr/lib/systemd/system/sysinit.target.wants/systemd-udevd.service": Symlink(
        "../systemd-udevd.service"
    ),
}

JOBS: Spec = {
    "/etc/crontab": CRONTAB,
    "/etc/cron.daily/logrotate": exe(),
    "/etc/cron.daily/not-run.sh": exe(),  # run-parts ignores names with dots
    "/etc/cron.daily/not-executable": "#!/bin/sh\n",
    "/var/spool/cron/crontabs/alice": "0 3 * * * /usr/local/bin/sync-photos\n",
    "/usr/local/bin/warmup": ELF,
    "/usr/local/bin/backup.sh": exe(),
    "/usr/local/bin/sync-photos": ELF,
    "/etc/udev/rules.d/90-usb.rules": UDEV_RULE,
    "/usr/local/sbin/usb-hook": ELF,
    "/usr/lib/udev/disk-id": ELF,
}


def _by_id(services: list[Service]) -> dict[str, Service]:
    return {s.id: s for s in services}


def test_parse_crontab_system_and_user_formats() -> None:
    jobs = parse_crontab(CRONTAB, system=True)
    assert [(s, u) for _, s, u, _ in jobs] == [
        ("17 * * * *", "root"),
        ("@reboot", "root"),
        ("*/5 * * * *", "backup"),
    ]
    assert jobs[2][3] == "/usr/local/bin/backup.sh"  # cut at the unescaped %
    user = parse_crontab("@daily /bin/true\n15 1 * * * /bin/echo hi\n", system=False)
    assert [(s, u, c) for _, s, u, c in user] == [
        ("@daily", None, "/bin/true"),
        ("15 1 * * *", None, "/bin/echo hi"),
    ]


def test_rule_programs_skips_builtins_and_joins_continuations() -> None:
    progs = [v for _, v in rule_programs(UDEV_RULE)]
    assert progs == [
        "/usr/local/sbin/usb-hook %k",
        "disk-id $devnode",
        "/usr/bin/true",
        "/usr/local/sbin/usb-hook again",
    ]


def test_jobs_are_manual_without_a_running_daemon(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    services = _by_id(discover_all(make_ctx(make_fs({**DEBIAN_SYSTEMD, **JOBS}))))
    cron = [s for s in services.values() if s.init_system is InitSystem.CRON]
    udev = [s for s in services.values() if s.init_system is InitSystem.UDEV]
    assert cron
    assert udev
    for svc in cron + udev:
        assert svc.activation == [Activation.MANUAL], svc.id
        assert any(e.startswith("not run: no ") for e in svc.evidence)


def test_jobs_run_when_the_daemon_starts(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec = {**DEBIAN_SYSTEMD, **JOBS, **ENABLE_CRON, **UDEVD}
    services = _by_id(discover_all(make_ctx(make_fs(spec))))

    reboot = services["cron:/etc/crontab:5"]
    assert reboot.activation == [Activation.BOOT]
    assert reboot.executables == ["/usr/local/bin/warmup"]
    assert reboot.hardening.user == "root"
    assert any("cron daemon of systemd:cron.service" in e for e in reboot.evidence)

    backup = services["cron:/etc/crontab:6"]
    assert backup.activation == [Activation.TIMER]
    assert backup.hardening.user == "backup"

    alice = services["cron:/var/spool/cron/crontabs/alice:1"]
    assert alice.hardening.user == "alice"
    assert alice.activation == [Activation.TIMER]

    assert services["cron:/etc/cron.daily/logrotate"].activation == [Activation.TIMER]
    assert "cron:/etc/cron.daily/not-run.sh" not in services
    assert "cron:/etc/cron.daily/not-executable" not in services

    hook = services["udev:/usr/local/sbin/usb-hook"]
    assert hook.activation == [Activation.DEVICE]
    assert hook.starts_automatically
    assert len([e for e in hook.evidence if e.startswith("udev rule")]) == 2
    assert services["udev:/usr/lib/udev/disk-id"].executables == ["/usr/lib/udev/disk-id"]


def test_etc_rules_override_vendor_rules(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec = {
        **DEBIAN_SYSTEMD,
        **UDEVD,
        "/usr/lib/udev/rules.d/50-x.rules": 'RUN+="/usr/local/sbin/vendor-hook"\n',
        "/etc/udev/rules.d/50-x.rules": "# disabled by the admin\n",
        "/usr/local/sbin/vendor-hook": ELF,
    }
    services = _by_id(discover_all(make_ctx(make_fs(spec))))
    assert "udev:/usr/local/sbin/vendor-hook" not in services
