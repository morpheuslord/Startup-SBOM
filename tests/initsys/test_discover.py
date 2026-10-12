"""discover_all reconciliation and the container entrypoint analyzer."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from images import DEBIAN_SYSTEMD, ELF, USRMERGE, exe

from fsbuilder import Spec, Symlink
from startup_sbom.context import ScanContext
from startup_sbom.initsys import discover_all
from startup_sbom.initsys.base import InitAnalyzer
from startup_sbom.models import Activation, ContainerInfo, InitSystem, Service
from startup_sbom.rootfs import RootFS

MakeFS = Callable[[Spec], RootFS]
MakeCtx = Callable[..., ScanContext]

NGINX_IMAGE: Spec = {
    **USRMERGE,
    "/usr/sbin/tini": ELF,
    "/usr/sbin/nginx": ELF,
    "/etc/nginx/nginx.conf": (
        "user  nginx;\nworker_processes  auto;\nevents {\n    worker_connections  1024;\n}\n"
        "http {\n    include       /etc/nginx/mime.types;\n"
        "    include /etc/nginx/conf.d/*.conf;\n}\n"
    ),
    "/etc/nginx/conf.d/default.conf": (
        "server {\n    listen       80;\n    listen  [::]:80;\n    server_name  localhost;\n}\n"
        "server {\n    listen 127.0.0.1:8081; # status\n}\n"
    ),
    # leftover units from packages: systemd itself is not installed
    "/usr/lib/systemd/system/apt-daily.timer": "[Timer]\nOnCalendar=daily\n",
    "/usr/lib/systemd/system/apt-daily.service": "[Service]\nExecStart=/usr/bin/true\n",
    "/usr/lib/systemd/system/timers.target.wants/apt-daily.timer": Symlink("../apt-daily.timer"),
}


def by_id(services: list[Service]) -> dict[str, Service]:
    return {s.id: s for s in services}


def test_tini_sh_c_entrypoint_unwrapped_with_nginx_listen(
    make_fs: MakeFS, make_ctx: MakeCtx
) -> None:
    ctx = make_ctx(make_fs(NGINX_IMAGE))
    ctx.container = ContainerInfo(
        kind="image",
        image="nginx:1.27",
        entrypoint=["/sbin/tini", "--"],
        cmd=["/bin/sh", "-c", "exec nginx -g 'daemon off;'"],
        user="",
    )
    got = by_id(discover_all(ctx))
    entry = got["container:entrypoint"]
    assert entry.init_system is InitSystem.CONTAINER
    assert entry.activation == [Activation.ENTRYPOINT]
    cmd = entry.commands[0]
    assert cmd.executable == "/usr/sbin/nginx"
    assert cmd.wrapped_by == ["/usr/sbin/tini", "/usr/bin/dash"]
    assert entry.executables == ["/usr/bin/dash", "/usr/sbin/nginx", "/usr/sbin/tini"]
    assert entry.hardening.user == "root"
    got_listens = {(la.protocol, la.address, la.port, la.scope) for la in entry.listens}
    assert got_listens == {
        ("tcp", None, 80, "network"),
        ("tcp", "::", 80, "network"),
        ("tcp", "127.0.0.1", 8081, "loopback"),
    }
    assert entry.network_exposed
    # systemd units shipped in the image never run: PID 1 is the app and systemd is absent
    apt = got["systemd:apt-daily.service"]
    assert apt.activation == [Activation.MANUAL]
    assert any("not installed" in e or "not started" in e for e in apt.evidence)


def test_container_user_ports_and_runtime_hardening(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec: Spec = {
        **USRMERGE,
        "/usr/sbin/gosu": ELF,
        "/usr/lib/postgresql/16/bin/postgres": ELF,
        "/usr/local/bin/docker-entrypoint.sh": exe(
            '#!/usr/bin/env bash\nset -Eeo pipefail\nif [ "$(id -u)" = "0" ]; then\n'
            '  exec gosu postgres "$BASH_SOURCE" "$@"\nfi\nexec "$@"\n'
        ),
        "/usr/local/bin/postgres": Symlink("/usr/lib/postgresql/16/bin/postgres"),
    }
    ctx = make_ctx(make_fs(spec))
    ctx.container = ContainerInfo(
        kind="container",
        entrypoint=["docker-entrypoint.sh"],
        cmd=["postgres"],
        user="999:999",
        exposed_ports=["5432/tcp", "53/udp"],
        privileged=False,
        cap_add=["NET_ADMIN"],
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        env_keys=["PATH", "POSTGRES_PASSWORD"],
    )
    entry = by_id(discover_all(ctx))["container:entrypoint"]
    cmd = entry.commands[0]
    assert cmd.executable == "/usr/lib/postgresql/16/bin/postgres"
    assert cmd.wrapped_by == ["/usr/local/bin/docker-entrypoint.sh"]
    h = entry.hardening
    assert (h.user, h.group) == ("999", "999")
    assert h.capability_bounding_set == ["CAP_NET_ADMIN"]
    assert h.no_new_privileges
    assert h.private_devices
    assert h.exposure is not None
    assert h.exposure < 9.6
    assert {(la.protocol, la.port) for la in entry.listens} == {("tcp", 5432), ("udp", 53)}
    assert any("PATH" in e for e in entry.evidence)


def test_sysv_script_shadowed_by_native_unit(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec: Spec = {
        **DEBIAN_SYSTEMD,
        "/etc/init.d/ssh": exe("#!/bin/sh\nDAEMON=/usr/sbin/sshd\n"),
        "/etc/rc2.d/S01ssh": Symlink("../init.d/ssh"),
        "/etc/init.d/legacy": exe("#!/bin/sh\nDAEMON=/usr/sbin/cron\n"),
        "/etc/rc2.d/S02legacy": Symlink("../init.d/legacy"),
    }
    got = by_id(discover_all(make_ctx(make_fs(spec))))
    assert "sysv:ssh" not in got  # reported once, by systemd
    assert got["systemd:ssh.service"].activation[0] is Activation.BOOT
    legacy = got["sysv:legacy"]  # systemd is PID 1 and has no sysv-generator
    assert legacy.activation == [Activation.MANUAL]
    assert any("PID 1 is systemd" in e for e in legacy.evidence)
    with_gen = by_id(
        discover_all(
            make_ctx(
                make_fs({**spec, "/usr/lib/systemd/system-generators/systemd-sysv-generator": ELF})
            )
        )
    )
    assert "sysv:legacy" not in with_gen
    assert with_gen["systemd:legacy.service"].activation == [Activation.BOOT]


def test_systemd_in_container_and_launched_supervisor(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec: Spec = {
        **DEBIAN_SYSTEMD,
        "/usr/bin/supervisord": exe("#!/usr/bin/python3\n"),
        "/etc/supervisor/supervisord.conf": "[program:app]\ncommand=/usr/sbin/cron -f\n",
        "/usr/lib/systemd/system/supervisor.service": (
            "[Service]\nExecStart=/usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf\n"
        ),
        "/etc/systemd/system/multi-user.target.wants/supervisor.service": Symlink(
            "/lib/systemd/system/supervisor.service"
        ),
    }
    got = by_id(discover_all(make_ctx(make_fs(spec))))
    app = got["supervisord:app"]
    assert app.activation == [Activation.BOOT]
    assert app.boot_path[0] == "default.target→multi-user.target"
    assert any("systemd:supervisor.service → supervisord" in step for step in app.boot_path)


def test_failing_analyzer_is_isolated(
    make_fs: MakeFS, make_ctx: MakeCtx, monkeypatch: pytest.MonkeyPatch
) -> None:
    from startup_sbom import initsys

    class Boom(InitAnalyzer):
        name = InitSystem.RUNIT

        def detect(self, ctx: ScanContext) -> bool:
            return True

        def discover(self, ctx: ScanContext) -> list[Service]:
            raise RuntimeError("kaboom")

    real = initsys.analyzers
    monkeypatch.setattr(initsys, "analyzers", lambda: [*real(), Boom()])
    ctx = make_ctx(make_fs(DEBIAN_SYSTEMD))
    services = discover_all(ctx)
    assert any(s.id == "systemd:ssh.service" for s in services)
    assert any("kaboom" in w for w in ctx.warnings)


def test_sorted_and_deterministic(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    fs = make_fs(DEBIAN_SYSTEMD)
    first = discover_all(make_ctx(fs))
    second = discover_all(make_ctx(fs))
    assert [s.id for s in first] == sorted(s.id for s in first)
    assert [s.model_dump() for s in first] == [s.model_dump() for s in second]
    for s in first:
        assert s.executables == sorted(s.executables)
        assert s.id == f"{s.init_system.value}:{s.name}"


def test_backends_agree(
    make_dir_fs: Callable[[Spec], RootFS], make_tar_fs: Callable[..., RootFS], make_ctx: MakeCtx
) -> None:
    a = [s.model_dump() for s in discover_all(make_ctx(make_dir_fs(DEBIAN_SYSTEMD)))]
    b = [s.model_dump() for s in discover_all(make_ctx(make_tar_fs(DEBIAN_SYSTEMD)))]
    assert a == b


def test_empty_root(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    assert discover_all(make_ctx(make_fs({"/etc/os-release": "ID=scratch\n"}))) == []
