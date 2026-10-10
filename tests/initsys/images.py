"""Realistic synthetic root filesystems for init-system tests (unit idioms from Debian/Fedora)."""

from __future__ import annotations

from fsbuilder import Dir, File, Spec, Symlink

ELF = File(b"\x7fELF\x02\x01\x01" + b"\x00" * 9, mode=0o755)


def exe(text: str = "#!/bin/sh\n") -> File:
    return File(text, mode=0o755)


USRMERGE: Spec = {
    "/bin": Symlink("usr/bin"),
    "/sbin": Symlink("usr/sbin"),
    "/lib": Symlink("usr/lib"),
    "/usr/bin/dash": ELF,
    "/usr/bin/sh": Symlink("dash"),
    "/usr/bin/kill": ELF,
    "/usr/bin/true": ELF,
    "/usr/bin/echo": ELF,
    "/usr/bin/mkdir": ELF,
    "/usr/bin/udevadm": ELF,
    "/usr/bin/python3": ELF,
}

SSH_SERVICE = """\
[Unit]
Description=OpenBSD Secure Shell server
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/usr/sbin/sshd -t
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
Alias=sshd.service
"""

SSHD_SOCKET = """\
[Unit]
Description=OpenBSD Secure Shell server socket
Before=sockets.target
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Socket]
ListenStream=22
Accept=no

[Install]
WantedBy=sockets.target
"""

CRON_SERVICE = """\
[Unit]
Description=Regular background program processing daemon
Documentation=man:cron(8)
After=remote-fs.target nss-user-lookup.target

[Service]
EnvironmentFile=-/etc/default/cron
ExecStart=/usr/sbin/cron -f -P $EXTRA_OPTS
IgnoreSIGPIPE=false
KillMode=process
Restart=on-failure
SyslogFacility=cron

[Install]
WantedBy=multi-user.target
"""

GETTY_TEMPLATE = """\
[Unit]
Description=Getty on %I
Documentation=man:agetty(8) man:systemd-getty-generator(8)
After=systemd-user-sessions.service plymouth-quit-wait.service getty-pre.target
Before=getty.target
IgnoreOnIsolate=yes
ConditionPathExists=/dev/tty0

[Service]
ExecStart=-/sbin/agetty -o '-p -- \\\\u' --noclear %I $TERM
Type=idle
Restart=always
RestartSec=0
UtmpIdentifier=%I
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/%I
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes
IgnoreSIGPIPE=no
SendSIGHUP=yes

[Install]
WantedBy=getty.target
DefaultInstance=tty1
"""

APT_TIMER = """\
[Unit]
Description=Daily apt download activities

[Timer]
OnCalendar=*-*-* 6,18:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
"""

APT_SERVICE = """\
[Unit]
Description=Daily apt download activities
Documentation=man:apt(8)
ConditionACPower=true
After=network.target network-online.target systemd-networkd.service \\
    NetworkManager.service connman.service

[Service]
Type=oneshot
ExecStartPre=-/usr/lib/apt/apt-helper wait-online
ExecStart=/usr/lib/apt/apt.systemd.daily update
"""

HARDENED_SERVICE = """\
[Unit]
Description=Hardened example daemon

[Service]
ExecStart=/usr/bin/python3 -m http.server --bind 127.0.0.1 8000
DynamicUser=yes
CapabilityBoundingSet=
PrivateNetwork=yes
PrivateDevices=yes
PrivateUsers=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
UMask=0077
IPAddressDeny=any
DevicePolicy=closed
RootDirectory=/srv/hardened

[Install]
WantedBy=multi-user.target
"""

QUOTING_SERVICE = """\
[Unit]
Description=Quoting and prefixes

[Service]
Type=oneshot
ExecStartPre=+/usr/bin/mkdir -p /run/quoting
ExecStartPre=-!/usr/bin/true
ExecStart=/usr/bin/python3 -c "print('a b')" \\
    --flag \\
# a comment inside a continuation is dropped
    "quoted arg" 'single q' \\x41 \\
    tail
ExecStart=@/usr/bin/python3 fake-argv0 --opt
ExecStartPost=/usr/bin/echo one ; /usr/bin/echo two \\; three
ExecStop=|echo stopping now
ExecStopPost=udevadm info --cleanup-db
"""


def target(desc: str, extra: str = "") -> str:
    return f"[Unit]\nDescription={desc}\n{extra}"


DEBIAN_SYSTEMD: Spec = {
    **USRMERGE,
    "/usr/lib/systemd/systemd": ELF,
    "/usr/sbin/init": Symlink("../lib/systemd/systemd"),
    "/usr/sbin/sshd": ELF,
    "/usr/sbin/cron": ELF,
    "/usr/sbin/agetty": ELF,
    "/usr/sbin/cupsd": ELF,
    "/usr/lib/apt/apt.systemd.daily": exe(),
    "/usr/lib/apt/apt-helper": ELF,
    "/etc/hostname": "testhost\n",
    "/etc/machine-id": "0123456789abcdef0123456789abcdef\n",
    # targets
    "/usr/lib/systemd/system/default.target": Symlink("graphical.target"),
    "/usr/lib/systemd/system/graphical.target": target(
        "Graphical Interface",
        "Requires=multi-user.target\nWants=display-manager.service\nAfter=multi-user.target\n",
    ),
    "/usr/lib/systemd/system/multi-user.target": target(
        "Multi-User System",
        "Requires=basic.target\nConflicts=rescue.service rescue.target\n"
        "After=basic.target rescue.service rescue.target\nAllowIsolate=yes\n",
    ),
    "/usr/lib/systemd/system/basic.target": target(
        "Basic System",
        "Requires=sysinit.target\nWants=sockets.target timers.target paths.target slices.target\n",
    ),
    "/usr/lib/systemd/system/sysinit.target": target(
        "System Initialization", "Wants=local-fs.target swap.target\n"
    ),
    "/usr/lib/systemd/system/sockets.target": target("Sockets"),
    "/usr/lib/systemd/system/timers.target": target("Timers"),
    "/usr/lib/systemd/system/paths.target": target("Path Units"),
    "/usr/lib/systemd/system/slices.target": target("Slice Units"),
    "/usr/lib/systemd/system/local-fs.target": target("Local File Systems"),
    "/usr/lib/systemd/system/swap.target": target("Swaps"),
    "/usr/lib/systemd/system/getty.target": target("Login Prompts"),
    "/usr/lib/systemd/system/multi-user.target.wants/getty.target": Symlink("../getty.target"),
    "/etc/systemd/system/default.target": Symlink("/lib/systemd/system/multi-user.target"),
    # ssh: alias + enablement symlink in /etc, socket in sockets.target.wants
    "/usr/lib/systemd/system/ssh.service": SSH_SERVICE,
    "/usr/lib/systemd/system/sshd.socket": SSHD_SOCKET,
    "/etc/systemd/system/sshd.service": Symlink("/lib/systemd/system/ssh.service"),
    "/etc/systemd/system/multi-user.target.wants/ssh.service": Symlink(
        "/lib/systemd/system/ssh.service"
    ),
    "/etc/systemd/system/sockets.target.wants/sshd.socket": Symlink(
        "/lib/systemd/system/sshd.socket"
    ),
    # cron: installed, not enabled, with drop-ins
    "/usr/lib/systemd/system/cron.service": CRON_SERVICE,
    "/usr/lib/systemd/system/cron.service.d/vendor.conf": "[Service]\nNice=5\nUser=vendor\n",
    "/etc/systemd/system/cron.service.d/vendor.conf": Symlink("/dev/null"),
    "/etc/systemd/system/cron.service.d/override.conf": (
        "[Service]\nExecStart=\nExecStart=/usr/sbin/cron -f -L 15\n"
    ),
    # getty template instance enabled via getty.target.wants
    "/usr/lib/systemd/system/getty@.service": GETTY_TEMPLATE,
    "/etc/systemd/system/getty.target.wants/getty@tty1.service": Symlink(
        "/lib/systemd/system/getty@.service"
    ),
    # timer activation
    "/usr/lib/systemd/system/apt-daily.timer": APT_TIMER,
    "/usr/lib/systemd/system/apt-daily.service": APT_SERVICE,
    "/etc/systemd/system/timers.target.wants/apt-daily.timer": Symlink(
        "/lib/systemd/system/apt-daily.timer"
    ),
    # loopback + unix socket activation
    "/usr/lib/systemd/system/cups.socket": (
        "[Unit]\nDescription=CUPS Scheduler\n\n[Socket]\nListenStream=/run/cups/cups.sock\n"
        "ListenStream=127.0.0.1:631\nListenStream=[::1]:631\n\n[Install]\nWantedBy=sockets.target\n"
    ),
    "/usr/lib/systemd/system/cups.service": (
        "[Unit]\nDescription=CUPS Scheduler\n\n[Service]\nExecStart=/usr/sbin/cupsd -l\n"
        "Type=notify\n"
    ),
    "/etc/systemd/system/sockets.target.wants/cups.socket": Symlink(
        "/lib/systemd/system/cups.socket"
    ),
    # masked: symlink to /dev/null (pulled in by wants) and an empty file
    "/usr/lib/systemd/system/bluetooth.service": (
        "[Unit]\nDescription=Bluetooth service\n\n[Service]\nExecStart=/usr/libexec/bluetoothd\n"
    ),
    "/etc/systemd/system/bluetooth.service": Symlink("/dev/null"),
    "/etc/systemd/system/multi-user.target.wants/bluetooth.service": Symlink(
        "/lib/systemd/system/bluetooth.service"
    ),
    "/etc/systemd/system/emptied.service": "",
    # hardened + quoting units, enabled
    "/usr/lib/systemd/system/hardened.service": HARDENED_SERVICE,
    "/etc/systemd/system/multi-user.target.wants/hardened.service": Symlink(
        "/lib/systemd/system/hardened.service"
    ),
    "/usr/lib/systemd/system/quoting.service": QUOTING_SERVICE,
    # hostile: in-root absolute symlinks and garbage
    "/etc/systemd/system/inimage.service": Symlink("/etc/inimage-unit"),
    "/etc/inimage-unit": "[Service]\nExecStart=/usr/sbin/cron -inimage\n",
    "/etc/systemd/system/leak.service": Symlink("../../../../../../../../etc/passwd"),
    "/etc/systemd/system/garbage.service": b"\x00\xff\xfe[Service\x00]\nExecStart\x00=\xff\n" * 50,
    "/etc/systemd/system/loop1.service": Symlink("loop2.service"),
    "/etc/systemd/system/loop2.service": Symlink("loop1.service"),
    "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n",
    "/etc/ssh/sshd_config.d": Dir(),
}
