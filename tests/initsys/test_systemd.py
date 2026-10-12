"""systemd analyzer: loading, drop-ins, masks, aliases, templates, boot graph, activation."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from images import DEBIAN_SYSTEMD, ELF, USRMERGE

from fsbuilder import File, Spec, Symlink
from startup_sbom.context import ScanContext
from startup_sbom.initsys.systemd.analyzer import SystemdAnalyzer
from startup_sbom.initsys.systemd.loader import UnitLoader, search_path
from startup_sbom.models import Activation, Service
from startup_sbom.rootfs import RootFS

MakeFS = Callable[[Spec], RootFS]
MakeCtx = Callable[..., ScanContext]


def run(make_fs: MakeFS, make_ctx: MakeCtx, spec: Spec) -> dict[str, Service]:
    ctx = make_ctx(make_fs(spec))
    analyzer = SystemdAnalyzer()
    assert analyzer.detect(ctx)
    return {s.id: s for s in analyzer.discover(ctx)}


@pytest.fixture
def debian(make_fs: MakeFS, make_ctx: MakeCtx) -> dict[str, Service]:
    return run(make_fs, make_ctx, DEBIAN_SYSTEMD)


def test_alias_enablement_and_boot_path(debian: dict[str, Service]) -> None:
    ssh = debian["systemd:ssh.service"]
    assert "systemd:sshd.service" not in debian  # alias resolves to ssh.service
    assert ssh.enabled
    assert ssh.activation[0] is Activation.BOOT
    assert ssh.boot_path == [
        "default.target→multi-user.target",
        "multi-user.target.wants/ssh.service",
    ]
    assert ssh.unit_path == "/usr/lib/systemd/system/ssh.service"
    assert ssh.description == "OpenBSD Secure Shell server"
    assert "alias: sshd.service" in ssh.evidence
    directives = [c.directive for c in ssh.commands]
    assert directives == ["ExecStartPre", "ExecStart", "ExecReload", "ExecReload"]
    assert ssh.commands[1].argv == ["/usr/sbin/sshd", "-D", "$SSHD_OPTS"]
    assert ssh.executables == ["/usr/bin/kill", "/usr/sbin/sshd"]


def test_socket_activation_network_listener_on_aliased_service(debian: dict[str, Service]) -> None:
    ssh = debian["systemd:ssh.service"]
    assert Activation.SOCKET in ssh.activation
    assert [(la.protocol, la.address, la.port, la.scope) for la in ssh.listens] == [
        ("tcp", None, 22, "network")
    ]
    assert ssh.listens[0].source == "/usr/lib/systemd/system/sshd.socket"
    assert ssh.network_exposed


def test_loopback_and_unix_socket_listeners(debian: dict[str, Service]) -> None:
    cups = debian["systemd:cups.service"]
    assert cups.activation == [Activation.SOCKET]
    got = {(la.protocol, la.address, la.port, la.path, la.scope) for la in cups.listens}
    assert got == {
        ("tcp", "127.0.0.1", 631, None, "loopback"),
        ("tcp", "::1", 631, None, "loopback"),
        ("unix", None, None, "/run/cups/cups.sock", "local"),
    }
    assert not cups.network_exposed
    assert cups.boot_path[-1] == "cups.socket→cups.service"


def test_dropin_reset_and_dropin_masking(debian: dict[str, Service]) -> None:
    cron = debian["systemd:cron.service"]
    starts = [c for c in cron.commands if c.directive == "ExecStart"]
    assert [c.argv for c in starts] == [["/usr/sbin/cron", "-f", "-L", "15"]]
    assert "/etc/systemd/system/cron.service.d/override.conf" in cron.evidence
    # /usr/lib vendor.conf (User=vendor) is masked by /etc/.../vendor.conf -> /dev/null
    assert cron.hardening.user == "root"
    assert not cron.enabled
    assert cron.activation == [Activation.MANUAL]


def test_masked_units(debian: dict[str, Service]) -> None:
    bt = debian["systemd:bluetooth.service"]
    assert bt.masked
    assert not bt.enabled
    assert not bt.starts_automatically
    assert bt.commands == []
    empty = debian["systemd:emptied.service"]
    assert empty.masked


def test_template_instance_specifiers(debian: dict[str, Service]) -> None:
    getty = debian["systemd:getty@tty1.service"]
    assert "systemd:getty@.service" not in debian
    assert getty.description == "Getty on tty1"
    assert getty.commands[0].argv == [
        "/sbin/agetty",
        "-o",
        "-p -- \\u",
        "--noclear",
        "tty1",
        "$TERM",
    ]
    assert getty.commands[0].executable == "/usr/sbin/agetty"
    assert getty.boot_path[-1] == "getty.target.wants/getty@tty1.service"
    assert Activation.BOOT in getty.activation


def test_timer_activation(debian: dict[str, Service]) -> None:
    apt = debian["systemd:apt-daily.service"]
    assert apt.activation == [Activation.TIMER]
    assert apt.enabled
    assert apt.boot_path[-2:] == [
        "timers.target.wants/apt-daily.timer",
        "apt-daily.timer→apt-daily.service",
    ]
    assert "/usr/lib/systemd/system/apt-daily.timer" in apt.evidence


def test_quoting_continuations_and_prefixes(debian: dict[str, Service]) -> None:
    q = debian["systemd:quoting.service"]
    by = [(c.directive, c.argv, c.executable, c.full_privileges) for c in q.commands]
    assert by[0] == (
        "ExecStartPre",
        ["/usr/bin/mkdir", "-p", "/run/quoting"],
        "/usr/bin/mkdir",
        True,
    )
    assert by[1] == ("ExecStartPre", ["/usr/bin/true"], "/usr/bin/true", False)
    assert by[2][1] == [
        "/usr/bin/python3", "-c", "print('a b')", "--flag", "quoted arg", "single q", "A", "tail",
    ]  # fmt: skip
    assert by[3] == ("ExecStart", ["fake-argv0", "--opt"], "/usr/bin/python3", False)
    assert by[4][1] == ["/usr/bin/echo", "one"]
    assert by[5][1] == ["/usr/bin/echo", "two", ";", "three"]
    assert by[6][0] == "ExecStop"
    assert by[6][1] == ["sh", "-c", "echo stopping now"]
    assert by[6][2] == "/usr/bin/dash"  # '|' runs through the shell
    assert by[7] == ("ExecStopPost", ["udevadm", "info", "--cleanup-db"], "/usr/bin/udevadm", False)
    assert any("full privileges" in e for e in q.evidence)
    assert any("masqueraded" in e for e in q.evidence)


def test_exposure_unhardened_and_hardened(debian: dict[str, Service]) -> None:
    ssh = debian["systemd:ssh.service"].hardening
    assert (ssh.exposure, ssh.exposure_rating) == (9.6, "UNSAFE")
    assert ssh.weaknesses[0].startswith("PrivateNetwork=")
    assert len(ssh.weaknesses) == 8
    hard = debian["systemd:hardened.service"].hardening
    assert hard.exposure is not None
    assert hard.exposure <= 1.0
    assert hard.exposure_rating in ("SAFE", "PERFECT", "OK")
    assert hard.dynamic_user
    assert hard.user == "hardened"
    assert hard.capability_bounding_set == []
    assert hard.private_network
    assert hard.no_new_privileges
    assert hard.system_call_filter
    assert hard.restrict_address_families == ["AF_UNIX"]
    assert hard.protect_system == "strict"


def test_in_root_symlinks_and_hostile_units(debian: dict[str, Service]) -> None:
    inimage = debian["systemd:inimage.service"]
    assert inimage.commands[0].argv == ["/usr/sbin/cron", "-inimage"]
    assert "/etc/inimage-unit" in inimage.evidence
    assert "systemd:leak.service" not in debian  # resolves in-root to a missing /etc/passwd
    assert "systemd:loop1.service" not in debian
    garbage = debian["systemd:garbage.service"]
    assert garbage.commands == []
    assert any("bad-setting" in e for e in garbage.evidence)


def test_deterministic(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    fs = make_fs(DEBIAN_SYSTEMD)
    a = [s.model_dump() for s in SystemdAnalyzer().discover(make_ctx(fs))]
    b = [s.model_dump() for s in SystemdAnalyzer().discover(make_ctx(fs))]
    assert a == b


SPLIT_USR: Spec = {
    "/lib/systemd/system/foo.service": "[Service]\nExecStart=/bin/old\n",
    "/usr/lib/systemd/system/foo.service": "[Service]\nExecStart=/bin/new\n",
    "/usr/lib/systemd/system/bar.service": "[Service]\nExecStart=/bin/bar\n",
    "/usr/local/lib/systemd/system/bar.service": "[Service]\nExecStart=/usr/local/bin/bar\n",
    "/bin/old": ELF,
    "/bin/new": ELF,
    "/bin/bar": ELF,
    "/usr/local/bin/bar": ELF,
}


def test_non_usrmerged_lib_precedes_usr_lib(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    fs = make_fs(SPLIT_USR)
    assert search_path(fs)[-2:] == ["/lib/systemd/system", "/usr/lib/systemd/system"]
    got = run(make_fs, make_ctx, SPLIT_USR)
    assert got["systemd:foo.service"].commands[0].executable == "/bin/old"
    assert got["systemd:bar.service"].commands[0].executable == "/usr/local/bin/bar"


def test_usrmerged_lib_not_duplicated(make_fs: MakeFS) -> None:
    fs = make_fs(
        {**USRMERGE, "/usr/lib/systemd/system/x.service": "[Service]\nExecStart=/bin/true\n"}
    )
    assert "/lib/systemd/system" not in search_path(fs)


def test_default_target_requires_and_usr_lib_wants(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec: Spec = {
        **USRMERGE,
        "/usr/sbin/gdm3": ELF,
        "/usr/sbin/rsyslogd": ELF,
        "/usr/lib/systemd/systemd-journald": ELF,
        "/usr/lib/systemd/system/default.target": Symlink("graphical.target"),
        "/usr/lib/systemd/system/graphical.target": (
            "[Unit]\nRequires=multi-user.target\nWants=display-manager.service\n"
        ),
        "/usr/lib/systemd/system/multi-user.target": "[Unit]\nRequires=basic.target\n",
        "/usr/lib/systemd/system/basic.target": "[Unit]\nRequires=sysinit.target\n",
        "/usr/lib/systemd/system/sysinit.target": "[Unit]\n",
        "/usr/lib/systemd/system/sysinit.target.wants/systemd-journald.service": Symlink(
            "../systemd-journald.service"
        ),
        "/usr/lib/systemd/system/systemd-journald.service": (
            "[Unit]\nDefaultDependencies=no\n[Service]\nExecStart=/usr/lib/systemd/systemd-journald\n"
        ),
        "/usr/lib/systemd/system/gdm.service": "[Service]\nExecStart=/usr/sbin/gdm3\n",
        "/etc/systemd/system/display-manager.service": Symlink(
            "/usr/lib/systemd/system/gdm.service"
        ),
        "/usr/lib/systemd/system/rsyslog.service": "[Service]\nExecStart=/usr/sbin/rsyslogd -n\n",
        "/etc/systemd/system/multi-user.target.wants/rsyslog.service": Symlink(
            "/usr/lib/systemd/system/rsyslog.service"
        ),
    }
    got = run(make_fs, make_ctx, spec)
    gdm = got["systemd:gdm.service"]
    assert gdm.boot_path == [
        "default.target→graphical.target",
        "graphical.target Wants=display-manager.service",
        "display-manager.service→gdm.service",
    ]
    journald = got["systemd:systemd-journald.service"]
    assert journald.boot_path[-1] == "sysinit.target.wants/systemd-journald.service"
    assert got["systemd:rsyslog.service"].boot_path[-2:] == [
        "graphical.target Requires=multi-user.target",
        "multi-user.target.wants/rsyslog.service",
    ]
    # DefaultDependencies=no makes the PrivateTmp/ProtectHome/ProtectSystem checks N/A
    assert journald.hardening.exposure != got["systemd:rsyslog.service"].hardening.exposure


def test_missing_targets_use_builtin_skeleton(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec: Spec = {
        **USRMERGE,
        "/usr/sbin/app": ELF,
        "/etc/systemd/system/app.service": "[Service]\nExecStart=app --serve\n",
        "/etc/systemd/system/multi-user.target.wants/app.service": Symlink("../app.service"),
    }
    got = run(make_fs, make_ctx, spec)
    app = got["systemd:app.service"]
    assert app.activation == [Activation.BOOT]
    assert app.boot_path[0].startswith("default.target missing")
    assert app.commands[0].executable == "/usr/sbin/app"  # bare name via built-in PATH


def test_sysv_generator_emulated_only_if_present(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    base: Spec = {
        **USRMERGE,
        "/usr/lib/systemd/system/multi-user.target": "[Unit]\n",
        "/etc/systemd/system/default.target": Symlink("/usr/lib/systemd/system/multi-user.target"),
        "/usr/lib/systemd/system/native.service": "[Service]\nExecStart=/bin/true\n",
        "/etc/init.d/legacy": File(
            "#!/bin/sh\n### BEGIN INIT INFO\n# Provides: legacy\n"
            "# Short-Description: Legacy daemon\n### END INIT INFO\n",
            mode=0o755,
        ),
        "/etc/init.d/native": File("#!/bin/sh\n", mode=0o755),
        "/etc/rc2.d/S01legacy": Symlink("../init.d/legacy"),
        "/etc/rc2.d/S01native": Symlink("../init.d/native"),
    }
    without = run(make_fs, make_ctx, base)
    assert "systemd:legacy.service" not in without
    with_gen = run(
        make_fs,
        make_ctx,
        {**base, "/usr/lib/systemd/system-generators/systemd-sysv-generator": ELF},
    )
    legacy = with_gen["systemd:legacy.service"]
    assert legacy.description == "Legacy daemon"
    assert legacy.activation == [Activation.BOOT]
    assert legacy.commands[0].argv == ["/etc/init.d/legacy", "start"]
    assert "sysv-generator" in legacy.boot_path[-1]
    assert legacy.hardening.exposure == 9.6
    native = with_gen["systemd:native.service"]
    assert native.activation == [Activation.MANUAL]  # native unit wins over the script


def test_unit_loader_dropin_candidates() -> None:
    assert UnitLoader.dropin_candidates("foo-bar-baz.service") == [
        "foo-bar-baz.service", "foo-bar-.service", "foo-.service",
    ]  # fmt: skip
    assert UnitLoader.dropin_candidates("a-b@i.service") == [
        "a-b@i.service", "a-b@.service", "a-@i.service", "a-@.service",
    ]  # fmt: skip
    assert UnitLoader.dropin_candidates("foo-.service") == ["foo-.service"]


def test_prefix_and_type_dropins_order(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec: Spec = {
        **USRMERGE,
        "/usr/lib/systemd/system/foo-bar.service": "[Service]\nExecStart=/bin/true\nUser=a\n",
        "/usr/lib/systemd/system/service.d/10-all.conf": "[Service]\nUser=typewide\n",
        "/usr/lib/systemd/system/foo-.service.d/20-prefix.conf": "[Service]\nUser=prefix\n",
        "/etc/systemd/system/foo-bar.service.d/30-exact.conf": "[Service]\nUser=exact\n",
    }
    got = run(make_fs, make_ctx, spec)
    svc = got["systemd:foo-bar.service"]
    assert svc.hardening.user == "exact"  # lexicographic by basename: 10, 20, 30
    assert svc.hardening.exposure is not None
    assert svc.hardening.exposure < 9.6
