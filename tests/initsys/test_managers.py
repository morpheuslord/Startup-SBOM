"""SysV, inittab, OpenRC, runit, s6-overlay and supervisord analyzers (via discover_all)."""

from __future__ import annotations

from collections.abc import Callable

from images import ELF, USRMERGE, exe

from fsbuilder import Dir, File, Spec, Symlink
from startup_sbom.context import ScanContext
from startup_sbom.initsys import discover_all
from startup_sbom.models import Activation, ContainerInfo, Service
from startup_sbom.rootfs import RootFS

MakeFS = Callable[[Spec], RootFS]
MakeCtx = Callable[..., ScanContext]

SSH_INIT = """\
#! /bin/sh

### BEGIN INIT INFO
# Provides:\t\tsshd
# Required-Start:\t$remote_fs $syslog
# Required-Stop:\t$remote_fs $syslog
# Default-Start:\t2 3 4 5
# Default-Stop:
# Short-Description:\tOpenBSD Secure Shell server
### END INIT INFO

set -e

# /etc/init.d/ssh: start and stop the OpenBSD "secure shell(tm)" daemon

test -x /usr/sbin/sshd || exit 0
( /usr/sbin/sshd -\\? 2>&1 | grep -q OpenSSH ) 2>/dev/null || exit 0

umask 022

if test -f /etc/default/ssh; then
    . /etc/default/ssh
fi

. /lib/lsb/init-functions

case "$1" in
  start)
\tcheck_privsep_dir
\tcheck_for_no_start
\tcheck_dev_null
\tlog_daemon_msg "Starting OpenBSD Secure Shell server" "sshd" || true
\tif start-stop-daemon --start --quiet --oknodo --chuid 0:0 --pidfile /run/sshd.pid \\
\t\t--exec /usr/sbin/sshd -- $SSHD_OPTS; then
\t    log_end_msg 0 || true
\telse
\t    log_end_msg 1 || true
\tfi
\t;;
  stop)
\tstart-stop-daemon --stop --quiet --oknodo --retry 30 --pidfile /run/sshd.pid --exec /usr/sbin/sshd
\t;;
esac

exit 0
"""

NGINX_INIT = """\
#!/bin/sh
### BEGIN INIT INFO
# Provides:          nginx
# Short-Description: starts the nginx web server
# Description:       starts nginx using start-stop-daemon
#                    and a second description line
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/nginx
NAME=nginx
PID=/run/nginx.pid

do_start()
{
\tstart-stop-daemon --start --quiet --pidfile $PID --exec $DAEMON -- $DAEMON_OPTS 2>/dev/null \\
\t\t|| return 2
}
"""

RHEL_INIT = """\
#!/bin/bash
#
# crond          Start/Stop the cron clock daemon.
#
# chkconfig: 2345 90 60
# description: cron is a standard UNIX program that runs user-specified \\
#              programs at periodic scheduled times.

. /etc/init.d/functions
exec=/usr/sbin/crond
prog="crond"
start() {
    daemon --user root $exec $CRONDARGS
}
"""

NGINX_CONF = (
    "user www-data;\nevents { worker_connections 768; }\n"
    "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n"
)
NGINX_DEFAULT = (
    "server {\n    listen       80;\n    listen  [::]:80;\n    server_name  localhost;\n"
    "    location / { root /usr/share/nginx/html; }\n}\n"
)

DEBIAN_SYSV: Spec = {
    **USRMERGE,
    "/usr/sbin/init": ELF,  # sysvinit
    "/etc/inittab": (
        "# /etc/inittab: init(8) configuration.\nid:2:initdefault:\n"
        "si::sysinit:/etc/init.d/rcS\n~~:S:wait:/sbin/sulogin\n"
        "l0:0:wait:/etc/init.d/rc 0\nl2:2:wait:/etc/init.d/rc 2\n"
        "ca:12345:ctrlaltdel:/sbin/shutdown -t1 -a -r now\n"
        "1:2345:respawn:/sbin/getty --noclear 38400 tty1\n"
        "7:7:respawn:/sbin/getty 38400 tty7\n"
    ),
    "/etc/init.d/rc": exe(),
    "/etc/init.d/rcS": exe(),
    "/etc/init.d/README": "docs\n",
    "/etc/init.d/ssh": exe(SSH_INIT),
    "/etc/init.d/nginx": exe(NGINX_INIT),
    "/etc/init.d/exim4": exe("#!/bin/sh\nDAEMON=/usr/sbin/exim4\n"),
    "/etc/init.d/foo": exe("#!/bin/sh\nDAEMON=/usr/sbin/foo\n"),
    "/etc/default/nginx": 'DAEMON_OPTS="-c /etc/nginx/alt.conf"\n',
    "/etc/default/foo": "ENABLED=0\n",
    "/etc/rc2.d/S01ssh": Symlink("../init.d/ssh"),
    "/etc/rc2.d/S105nginx": Symlink("/etc/init.d/nginx"),
    "/etc/rc2.d/K01exim4": Symlink("../init.d/exim4"),
    "/etc/rc3.d/S01exim4": Symlink("../init.d/exim4"),
    "/etc/rc2.d/S02foo": Symlink("../init.d/foo"),
    "/etc/rc2.d/S99dangling": Symlink("../init.d/gone"),
    "/usr/sbin/sshd": ELF,
    "/usr/sbin/nginx": ELF,
    "/usr/sbin/exim4": ELF,
    "/usr/sbin/foo": ELF,
    "/usr/sbin/getty": ELF,
    "/usr/sbin/sulogin": ELF,
    "/usr/sbin/shutdown": ELF,
    "/etc/nginx/alt.conf": NGINX_CONF,
    "/etc/nginx/conf.d/default.conf": NGINX_DEFAULT,
}


def by_id(services: list[Service]) -> dict[str, Service]:
    return {s.id: s for s in services}


def test_sysv_only_debian(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    ctx = make_ctx(make_fs(DEBIAN_SYSV))
    got = by_id(discover_all(ctx))
    ssh = got["sysv:ssh"]
    assert ssh.activation == [Activation.BOOT]
    assert ssh.enabled
    assert ssh.description == "OpenBSD Secure Shell server"
    assert ssh.boot_path[-2:] == ["runlevel 2 (/etc/inittab initdefault)", "rc2.d/S01ssh"]
    assert ssh.boot_path[0].startswith("/etc/inittab")  # launched by inittab's rc line
    assert ssh.commands[0].argv == ["/etc/init.d/ssh", "start"]
    daemon = ssh.commands[1]
    assert daemon.directive == "start-stop-daemon"
    assert daemon.executable == "/usr/sbin/sshd"
    assert ssh.executables == ["/etc/init.d/ssh", "/usr/sbin/sshd"]
    assert ssh.hardening.user == "0"
    assert ssh.hardening.exposure == 9.6
    # sshd_config absent: default port 22 on all addresses
    assert [(la.port, la.scope) for la in ssh.listens] == [(22, "network")]

    nginx = got["sysv:nginx"]  # three-digit priority, absolute link, /etc/default override
    assert nginx.activation == [Activation.BOOT]
    assert nginx.commands[1].argv == ["/usr/sbin/nginx", "-c", "/etc/nginx/alt.conf"]
    assert nginx.description == "starts the nginx web server"
    assert {(la.address, la.port, la.scope) for la in nginx.listens} == {
        (None, 80, "network"), ("::", 80, "network"),
    }  # fmt: skip

    exim = got["sysv:exim4"]  # only linked in rc3.d; default runlevel is 2
    assert exim.activation == [Activation.MANUAL]
    assert exim.enabled
    foo = got["sysv:foo"]
    assert foo.activation == [Activation.MANUAL]
    assert not foo.enabled
    assert any("ENABLED" in e for e in foo.evidence)
    assert "sysv:README" not in got
    assert "sysv:rc" not in got

    getty = got["inittab:1"]
    assert getty.activation == [Activation.BOOT]
    assert getty.commands[0].executable == "/usr/sbin/getty"
    assert got["inittab:7"].activation == [Activation.MANUAL]  # runlevel 7 only
    assert got["inittab:ca"].activation == [Activation.MANUAL]
    assert got["inittab:l2"].commands[0].executable == "/etc/init.d/rc"


def test_rhel_chkconfig_script(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec: Spec = {
        **USRMERGE,
        "/etc/rc.d/init.d/crond": exe(RHEL_INIT),
        "/etc/init.d": Symlink("rc.d/init.d"),
        "/etc/rc.d/rc3.d/S90crond": Symlink("../init.d/crond"),
        "/etc/redhat-release": "CentOS release 6.10 (Final)\n",
        "/usr/sbin/crond": ELF,
    }
    got = by_id(discover_all(make_ctx(make_fs(spec))))
    crond = got["sysv:crond"]
    assert crond.activation == [Activation.BOOT]
    assert crond.boot_path[-1] == "rc.d/rc3.d/S90crond"
    assert crond.description is not None
    assert crond.description.startswith("cron is a standard")
    assert crond.commands[1].directive == "daemon"
    assert crond.commands[1].executable == "/usr/sbin/crond"


ALPINE: Spec = {
    "/bin/busybox": ELF,
    "/bin/sh": Symlink("/bin/busybox"),
    "/sbin/init": Symlink("/bin/busybox"),
    "/sbin/getty": Symlink("/bin/busybox"),
    "/sbin/openrc": ELF,
    "/sbin/openrc-run": ELF,
    "/sbin/start-stop-daemon": ELF,
    "/sbin/checkpath": ELF,
    "/usr/sbin/nginx": ELF,
    "/usr/sbin/sshd": ELF,
    "/usr/sbin/crond": ELF,
    "/etc/inittab": (
        "# /etc/inittab\n::sysinit:/sbin/openrc sysinit\n::sysinit:/sbin/openrc boot\n"
        "::wait:/sbin/openrc default\ntty1::respawn:/sbin/getty 38400 tty1\n"
        "::ctrlaltdel:/sbin/reboot\n::shutdown:/sbin/openrc shutdown\n"
    ),
    "/etc/init.d/nginx": exe(
        '#!/sbin/openrc-run\n\nname="nginx"\ndescription="Nginx http and reverse proxy server"\n'
        'extra_commands="checkconfig"\n\ncfgfile=${cfgfile:-/etc/nginx/nginx.conf}\n'
        "pidfile=/run/nginx/nginx.pid\ncommand=${command:-/usr/sbin/nginx}\n"
        'command_args="-c $cfgfile"\ncommand_background=true\n: ${command_user:="nobody"}\n'
        'required_files="$cfgfile"\n\ndepend() {\n\tneed net\n\tuse dns logger netmount\n}\n\n'
        "start_pre() {\n\tcheckpath --directory --owner $command_user --mode 0775 /run/nginx\n"
        "\t$command $command_args -t -q\n}\n"
    ),
    "/etc/conf.d/nginx": (
        'command_user="nginx:www-data"\ncapabilities="^cap_net_bind_service"\nno_new_privs=yes\n'
    ),
    "/etc/init.d/networking": exe(
        "#!/sbin/openrc-run\ndepend() {\n\tprovide net\n\tneed localmount\n}\n"
    ),
    "/etc/init.d/localmount": exe('#!/sbin/openrc-run\ndescription="Mounts disks"\n'),
    "/etc/init.d/sshd": exe('#!/sbin/openrc-run\ncommand=/usr/sbin/sshd\ncommand_args="-D"\n'),
    "/etc/init.d/crond": exe('#!/sbin/openrc-run\ncommand=/usr/sbin/crond\ncommand_args="-f"\n'),
    "/etc/runlevels/boot/localmount": Symlink("/etc/init.d/localmount"),
    "/etc/runlevels/default/nginx": Symlink("/etc/init.d/nginx"),
    "/etc/runlevels/default/extra": Symlink("../extra"),
    "/etc/runlevels/extra/crond": Symlink("/etc/init.d/crond"),
    "/etc/runlevels/sysinit": Dir(),
    "/etc/nginx/nginx.conf": "events {}\nhttp { server { listen 8080; } }\n",
}


def test_openrc_alpine(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    got = by_id(discover_all(make_ctx(make_fs(ALPINE))))
    nginx = got["openrc:nginx"]
    assert nginx.activation == [Activation.BOOT]
    assert nginx.boot_path[0].startswith("BusyBox") or nginx.boot_path[0].startswith("/etc/inittab")
    h = nginx.hardening
    assert (h.user, h.group) == ("nginx", "www-data")  # conf.d beats ': ${command_user:=...}'
    assert h.ambient_capabilities == ["CAP_NET_BIND_SERVICE"]
    assert h.no_new_privileges
    main = nginx.commands[0]
    assert main.argv == ["/usr/sbin/nginx", "-c", "/etc/nginx/nginx.conf"]
    assert main.executable == "/usr/sbin/nginx"
    assert main.wrapped_by == ["/sbin/start-stop-daemon"]
    pre = [c for c in nginx.commands if c.directive == "start_pre"]
    assert pre
    assert pre[0].argv[-2:] == ["-t", "-q"]
    assert [(la.port, la.scope) for la in nginx.listens] == [(8080, "network")]
    assert nginx.description == "Nginx http and reverse proxy server"
    networking = got["openrc:networking"]
    assert networking.activation == [Activation.BOOT]
    assert "nginx need net (provided by networking)" in networking.boot_path
    assert got["openrc:crond"].activation == [Activation.BOOT]  # stacked runlevel
    assert got["openrc:sshd"].activation == [Activation.MANUAL]
    assert got["inittab:sysinit-1"].commands[0].executable == "/sbin/openrc"
    assert "sysv:nginx" not in got  # openrc-run scripts are not SysV scripts


RUNIT: Spec = {
    **USRMERGE,
    "/usr/sbin/runit-init": ELF,
    "/usr/sbin/init": Symlink("runit-init"),
    "/usr/bin/runsvdir": ELF,
    "/usr/bin/chpst": ELF,
    "/usr/bin/svlogd": ELF,
    "/usr/bin/ssh-keygen": ELF,
    "/usr/sbin/sshd": ELF,
    "/usr/sbin/nginx": ELF,
    "/etc/runit/2": exe(
        "#!/bin/sh\nPATH=/usr/bin:/usr/sbin\nexec runsvdir -P /run/runit/runsvdir/current\n"
    ),
    "/etc/sv/sshd/run": exe(
        "#!/bin/sh\nexec 2>&1\n[ -r conf ] && . ./conf\nssh-keygen -A >/dev/null 2>&1\n"
        "exec /usr/sbin/sshd -D $OPTS\n"
    ),
    "/etc/sv/sshd/log/run": exe("#!/bin/sh\nexec chpst -u _sshd:adm svlogd -tt /var/log/sshd\n"),
    "/etc/sv/nginx/run": exe("#!/bin/sh\nexec chpst -u www-data nginx -g 'daemon off;'\n"),
    "/etc/sv/nginx/down": "",
    "/etc/sv/unlinked/run": exe("#!/bin/sh\nexec /usr/sbin/nginx\n"),
    "/etc/runit/runsvdir/default/sshd": Symlink("/etc/sv/sshd"),
    "/etc/runit/runsvdir/default/nginx": Symlink("/etc/sv/nginx"),
    "/etc/runit/runsvdir/current": Symlink("default"),
}


def test_runit_service_dirs(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    got = by_id(discover_all(make_ctx(make_fs(RUNIT))))
    sshd = got["runit:sshd"]
    assert sshd.activation == [Activation.BOOT]
    assert sshd.enabled
    assert sshd.boot_path[-1] == "/etc/runit/runsvdir/default/sshd"
    assert "/usr/sbin/sshd" in sshd.executables
    assert "/usr/bin/ssh-keygen" in sshd.executables
    assert "/etc/sv/sshd/run" in sshd.executables
    log = got["runit:sshd/log"]
    assert (log.hardening.user, log.hardening.group) == ("_sshd", "adm")
    exec_cmd = next(c for c in log.commands if c.directive == "exec")
    assert exec_cmd.executable == "/usr/bin/svlogd"
    assert exec_cmd.wrapped_by == ["/usr/bin/chpst"]
    nginx = got["runit:nginx"]
    assert nginx.activation == [Activation.MANUAL]
    assert not nginx.enabled  # down file
    assert nginx.hardening.user == "www-data"
    assert got["runit:unlinked"].activation == [Activation.MANUAL]
    stage2 = got["runit:stage-2"]
    assert any(c.executable == "/usr/bin/runsvdir" for c in stage2.commands)


S6_OVERLAY: Spec = {
    **USRMERGE,
    "/init": exe("#!/bin/sh -e\nexec /package/admin/s6-overlay/libexec/preinit\n"),
    "/package/admin/s6-overlay": Dir(),
    "/command/s6-svscan": ELF,
    "/command/execlineb": ELF,
    "/command/with-contenv": ELF,
    "/command/s6-setuidgid": ELF,
    "/command/s6-notifyoncheck": ELF,
    "/usr/sbin/nginx": ELF,
    "/etc/s6-overlay/s6-rc.d/user/type": "bundle\n",
    "/etc/s6-overlay/s6-rc.d/user/contents.d/nginx": "",
    "/etc/s6-overlay/s6-rc.d/nginx/type": "longrun\n",
    "/etc/s6-overlay/s6-rc.d/nginx/run": exe(
        '#!/command/execlineb -P\nwith-contenv\ns6-setuidgid www-data\nnginx -g "daemon off;"\n'
    ),
    "/etc/s6-overlay/s6-rc.d/nginx/dependencies.d/init-setup": "",
    "/etc/s6-overlay/s6-rc.d/init-setup/type": "oneshot\n",
    "/etc/s6-overlay/s6-rc.d/init-setup/up": "/etc/s6-overlay/scripts/init-setup\n",
    "/etc/s6-overlay/scripts/init-setup": exe("#!/command/with-contenv sh\nmkdir -p /config\n"),
    "/etc/s6-overlay/s6-rc.d/unused/type": "longrun\n",
    "/etc/s6-overlay/s6-rc.d/unused/run": exe("#!/bin/sh\nexec nginx\n"),
    "/etc/cont-init.d/10-adduser": exe("#!/command/with-contenv bash\nusermod -o -u $PUID abc\n"),
}


def test_s6_overlay_entrypoint(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    ctx = make_ctx(make_fs(S6_OVERLAY))
    ctx.container = ContainerInfo(kind="image", entrypoint=["/init"], exposed_ports=["80/tcp"])
    got = by_id(discover_all(ctx))
    entry = got["container:entrypoint"]
    assert entry.commands[0].executable == "/init"
    nginx = got["s6:nginx"]
    assert nginx.activation == [Activation.ENTRYPOINT]
    assert nginx.boot_path[0].startswith("container start")
    assert nginx.hardening.user == "www-data"
    main = next(c for c in nginx.commands if c.directive == "exec")
    assert main.executable == "/usr/sbin/nginx"
    assert main.wrapped_by == ["/command/with-contenv", "/command/s6-setuidgid"]
    setup = got["s6:init-setup"]
    assert setup.activation == [Activation.ENTRYPOINT]
    assert setup.commands[0].executable == "/etc/s6-overlay/scripts/init-setup"
    assert got["s6:cont-init.d/10-adduser"].activation == [Activation.ENTRYPOINT]
    assert got["s6:unused"].activation == [Activation.MANUAL]


SUPERVISOR: Spec = {
    **USRMERGE,
    "/usr/bin/supervisord": exe("#!/usr/bin/python3\n"),
    "/opt/venv/bin/python3": ELF,
    "/usr/sbin/nginx": ELF,
    "/usr/sbin/php-fpm": ELF,
    "/etc/supervisor/supervisord.conf": (
        "; supervisor config file\n\n[unix_http_server]\n"
        "file=/var/run/supervisor.sock   ; (the path to the socket file)\nchmod=0700\n\n"
        "[supervisord]\nlogfile=/var/log/supervisor/supervisord.log\nnodaemon=true\n\n"
        "[inet_http_server]\nport=*:9001\n\n[include]\nfiles = /etc/supervisor/conf.d/*.conf\n"
    ),
    "/etc/supervisor/conf.d/app.conf": (
        '[program:nginx]\ncommand=/usr/sbin/nginx -g "daemon off;"\nautostart=true\n\n'
        "[program:worker]\ncommand=python3 /app/worker.py --queue %(program_name)s\nuser=app\n"
        'directory=/app\nautostart=false\nenvironment=PATH="/opt/venv/bin:/usr/bin",X="1"\n\n'
        "[fcgi-program:php]\nsocket=tcp://127.0.0.1:9000\ncommand=/usr/sbin/php-fpm -F\n"
    ),
    "/etc/supervisor/conf.d/broken.conf": "[program:bad\ncommand=\n\x00\xff garbage\n",
}


def test_supervisord_programs_under_entrypoint(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    ctx = make_ctx(make_fs(SUPERVISOR))
    ctx.container = ContainerInfo(
        entrypoint=["/usr/bin/supervisord"], cmd=["-n", "-c", "/etc/supervisor/supervisord.conf"]
    )
    got = by_id(discover_all(ctx))
    nginx = got["supervisord:nginx"]
    assert nginx.activation == [Activation.ENTRYPOINT]
    assert nginx.commands[0].argv == ["/usr/sbin/nginx", "-g", "daemon off;"]
    worker = got["supervisord:worker"]
    assert worker.activation == [Activation.MANUAL]
    assert worker.hardening.user == "app"
    assert worker.commands[0].executable == "/opt/venv/bin/python3"
    assert worker.commands[0].argv[-1] == "worker"
    php = got["supervisord:php"]
    assert [(la.address, la.port, la.scope) for la in php.listens] == [
        ("127.0.0.1", 9000, "loopback")
    ]
    entry = got["container:entrypoint"]
    assert (None, 9001, "network") in {(la.address, la.port, la.scope) for la in entry.listens}
    assert any(la.path == "/var/run/supervisor.sock" for la in entry.listens)


def test_supervisord_without_launcher_is_manual(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec = {**SUPERVISOR, "/usr/sbin/init": ELF, "/etc/inittab": "id:2:initdefault:\n"}
    got = by_id(discover_all(make_ctx(make_fs(spec))))
    nginx = got["supervisord:nginx"]
    assert nginx.activation == [Activation.MANUAL]
    assert any("no started service launches supervisord" in e for e in nginx.evidence)


def test_busybox_builtin_inittab(make_fs: MakeFS, make_ctx: MakeCtx) -> None:
    spec: Spec = {
        "/bin/busybox": ELF,
        "/sbin/init": Symlink("/bin/busybox"),
        "/bin/sh": Symlink("busybox"),
        "/etc/init.d/rcS": exe("#!/bin/sh\nfor i in /etc/init.d/S??* ;do\n  $i start\ndone\n"),
        "/etc/init.d/S01syslogd": exe("#!/bin/sh\nDAEMON=/sbin/syslogd\n"),
        "/sbin/syslogd": Symlink("/bin/busybox"),
    }
    got = by_id(discover_all(make_ctx(make_fs(spec))))
    assert got["inittab:sysinit-1"].commands[0].executable == "/etc/init.d/rcS"
    assert got["inittab:askfirst@tty2"].activation == [Activation.BOOT]
    syslogd = got["sysv:S01syslogd"]
    assert syslogd.activation == [Activation.BOOT]
    assert File  # keep import used for spec helpers
