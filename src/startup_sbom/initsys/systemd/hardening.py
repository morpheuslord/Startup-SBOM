"""Offline reimplementation of ``systemd-analyze security`` (``analyze-security.c``).

:class:`SecurityInput` holds the merged, *derived* sandbox settings of a unit;
:func:`assess` runs the 81 weighted checks and returns the 0.0–10.0 exposure,
its label and the worst failing checks.  :func:`from_settings` builds the input
from merged unit settings with systemd's parsing and derivation rules
(``CapabilityBoundingSet``/``RestrictNamespaces``/``RestrictAddressFamilies``/
``SystemCallFilter`` list semantics, ``DynamicUser=`` and ``Private*=`` implied
settings).  Syscall groups are vendored from ``seccomp-util.c`` (systemd main,
2026-10).
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import cache

from startup_sbom.initsys.systemd.parser import parse_bool, split_words
from startup_sbom.models import Hardening

ALL_CAPS: tuple[str, ...] = (
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
    "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
    "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
    "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
)  # fmt: skip
_ALL = frozenset(ALL_CAPS)
ALL_CAP_SET = _ALL
NAMESPACES = frozenset({"cgroup", "ipc", "net", "mnt", "pid", "user", "uts", "time"})
#: Default capability set of a Docker/Podman container (moby ``oci/caps/defaults.go``).
CONTAINER_DEFAULT_CAPS = frozenset(
    {
        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
        "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW",
        "CAP_SYS_CHROOT", "CAP_MKNOD", "CAP_AUDIT_WRITE", "CAP_SETFCAP",
    }
)  # fmt: skip

# --------------------------------------------------------------------------- syscall groups
_GROUPS_RAW: dict[str, str] = {
    "@default": (
        "@sandbox arch_prctl brk cacheflush clock_getres clock_getres_time64 clock_gettime "
        "clock_gettime64 clock_nanosleep clock_nanosleep_time64 execve exit exit_group futex "
        "futex_time64 futex_waitv get_robust_list get_thread_area getegid getegid32 geteuid "
        "geteuid32 getgid getgid32 getgroups getgroups32 getpgid getpgrp getpid getppid "
        "getrandom getresgid getresgid32 getresuid getresuid32 getrlimit getsid gettid "
        "gettimeofday getuid getuid32 lsm_get_self_attr lsm_list_modules membarrier mmap "
        "mmap2 mprotect mseal munmap nanosleep pause prlimit64 restart_syscall "
        "riscv_flush_icache riscv_hwprobe rseq rt_sigreturn sched_getaffinity sched_yield "
        "set_robust_list set_thread_area set_tid_address set_tls sigreturn time ugetrlimit "
        "uretprobe"
    ),
    "@sandbox": "landlock_add_rule landlock_create_ruleset landlock_restrict_self seccomp",
    "@aio": (
        "io_cancel io_destroy io_getevents io_pgetevents io_pgetevents_time64 io_setup "
        "io_submit io_uring_enter io_uring_register io_uring_setup"
    ),
    "@basic-io": (
        "_llseek close close_range dup dup2 dup3 llseek lseek pread64 preadv preadv2 pwrite64 "
        "pwritev pwritev2 read readv write writev"
    ),
    "@chown": "chown chown32 fchown fchown32 fchownat lchown lchown32",
    "@clock": "adjtimex clock_adjtime clock_adjtime64 clock_settime clock_settime64 settimeofday",
    "@cpu-emulation": "modify_ldt subpage_prot switch_endian vm86 vm86old",
    "@debug": (
        "lookup_dcookie perf_event_open pidfd_getfd ptrace rtas s390_runtime_instr "
        "sys_debug_setcontext"
    ),
    "@file-system": (
        "access chdir chmod close creat faccessat faccessat2 fallocate fchdir fchmod fchmodat "
        "fchmodat2 fcntl fcntl64 fgetxattr file_getattr file_setattr flistxattr fremovexattr "
        "fsetxattr fstat fstat64 fstatat fstatat64 fstatfs fstatfs64 ftruncate ftruncate64 "
        "futimesat getcwd getdents getdents64 getxattr getxattrat inotify_add_watch "
        "inotify_init inotify_init1 inotify_rm_watch lgetxattr link linkat listmount "
        "listxattr listxattrat llistxattr lremovexattr lsetxattr lstat lstat64 mkdir mkdirat "
        "mknod mknodat newfstat newfstatat oldfstat oldlstat oldstat open open_tree openat "
        "openat2 readlink readlinkat removexattr removexattrat rename renameat renameat2 "
        "rmdir setxattr setxattrat stat stat64 statfs statfs64 statmount statx symlink "
        "symlinkat truncate truncate64 unlink unlinkat utime utimensat utimensat_time64 "
        "utimes"
    ),
    "@io-event": (
        "_newselect epoll_create epoll_create1 epoll_ctl epoll_ctl_old epoll_pwait "
        "epoll_pwait2 epoll_wait epoll_wait_old eventfd eventfd2 poll ppoll ppoll_time64 "
        "pselect6 pselect6_time64 select"
    ),
    "@ipc": (
        "ipc memfd_create mq_getsetattr mq_notify mq_open mq_timedreceive "
        "mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 mq_unlink msgctl msgget "
        "msgrcv msgsnd pipe pipe2 process_madvise process_vm_readv process_vm_writev semctl "
        "semget semop semtimedop semtimedop_time64 shmat shmctl shmdt shmget"
    ),
    "@keyring": "add_key keyctl request_key",
    "@memlock": "mlock mlock2 mlockall munlock munlockall",
    "@module": "delete_module finit_module init_module",
    "@mount": (
        "chroot fsconfig fsmount fsopen fspick mount mount_setattr move_mount open_tree_attr "
        "pivot_root umount umount2"
    ),
    "@network-io": (
        "accept accept4 bind connect getpeername getsockname getsockopt listen recv recvfrom "
        "recvmmsg recvmmsg_time64 recvmsg send sendmmsg sendmsg sendto setsockopt shutdown "
        "socket socketcall socketpair"
    ),
    "@obsolete": (
        "_sysctl afs_syscall bdflush break create_module ftime get_kernel_syms getpmsg gtty "
        "idle lock mpx prof profil putpmsg query_module security sgetmask ssetmask stime stty "
        "sysfs tuxcall ulimit uselib ustat vserver"
    ),
    "@pkey": "pkey_alloc pkey_free pkey_mprotect",
    "@privileged": (
        "@chown @clock @module @raw-io @reboot @swap _sysctl acct bpf capset chroot "
        "fanotify_init fanotify_mark nfsservctl open_by_handle_at pivot_root quotactl "
        "quotactl_fd setdomainname setfsuid setfsuid32 setgroups setgroups32 sethostname "
        "setresuid setresuid32 setreuid setreuid32 setuid setuid32 vhangup"
    ),
    "@process": (
        "capget clone clone3 execveat fork getrusage kill pidfd_open pidfd_send_signal prctl "
        "rt_sigqueueinfo rt_tgsigqueueinfo setns swapcontext tgkill times tkill unshare vfork "
        "wait4 waitid waitpid"
    ),
    "@raw-io": (
        "ioperm iopl pciconfig_iobase pciconfig_read pciconfig_write s390_pci_mmio_read "
        "s390_pci_mmio_write"
    ),
    "@reboot": "kexec_file_load kexec_load reboot",
    "@resources": (
        "ioprio_set mbind migrate_pages move_pages nice sched_setaffinity sched_setattr "
        "sched_setparam sched_setscheduler set_mempolicy set_mempolicy_home_node setpriority "
        "setrlimit"
    ),
    "@setuid": (
        "setgid setgid32 setgroups setgroups32 setregid setregid32 setresgid setresgid32 "
        "setresuid setresuid32 setreuid setreuid32 setuid setuid32"
    ),
    "@signal": (
        "rt_sigaction rt_sigpending rt_sigprocmask rt_sigsuspend rt_sigtimedwait "
        "rt_sigtimedwait_time64 sigaction sigaltstack signal signalfd signalfd4 sigpending "
        "sigprocmask sigsuspend"
    ),
    "@swap": "swapoff swapon",
    "@sync": "fdatasync fsync msync sync sync_file_range sync_file_range2 syncfs",
    "@timer": (
        "alarm getitimer setitimer timer_create timer_delete timer_getoverrun timer_gettime "
        "timer_gettime64 timer_settime timer_settime64 timerfd_create timerfd_gettime "
        "timerfd_gettime64 timerfd_settime timerfd_settime64 times"
    ),
    "@system-service": (
        "@aio @basic-io @chown @default @file-system @io-event @ipc @keyring @memlock "
        "@network-io @process @resources @setuid @signal @sync @timer arm_fadvise64_64 capget "
        "capset copy_file_range fadvise64 fadvise64_64 flock get_mempolicy getcpu getpriority "
        "ioctl ioprio_get kcmp madvise mremap name_to_handle_at oldolduname olduname "
        "personality readahead readdir remap_file_pages sched_get_priority_max "
        "sched_get_priority_min sched_getattr sched_getparam sched_getscheduler "
        "sched_rr_get_interval sched_rr_get_interval_time64 sched_yield sendfile sendfile64 "
        "setfsgid setfsgid32 setfsuid setfsuid32 setpgid setsid splice sysinfo tee umask "
        "uname userfaultfd vmsplice"
    ),
}


@cache
def expand_group(name: str) -> frozenset[str]:
    """Expand a syscall or ``@group`` recursively (unknown groups expand to nothing)."""
    if not name.startswith("@"):
        return frozenset({name})
    if name == "@known":
        return KNOWN_SYSCALLS
    out: set[str] = set()
    for member in _GROUPS_RAW.get(name, "").split():
        out |= expand_group(member) if member != name else set()
    return frozenset(out)


KNOWN_SYSCALLS: frozenset[str] = frozenset(
    s for v in _GROUPS_RAW.values() for s in v.split() if not s.startswith("@")
)


# --------------------------------------------------------------------------- input model
@dataclass(slots=True)
class SecurityInput:
    """Derived sandbox settings of one unit, as consumed by the assessors."""

    user: str | None = None  # None/"" = root
    dynamic_user: bool = False
    user_scope: bool = False
    supplementary_groups: bool = False
    private_devices: bool = False
    private_mounts: bool = False
    private_network: bool = False
    private_tmp: str = "no"
    private_users: bool = False
    protect_control_groups: str = "no"
    protect_kernel_modules: bool = False
    protect_kernel_tunables: bool = False
    protect_kernel_logs: bool = False
    protect_clock: bool = False
    protect_home: str = "no"
    protect_hostname: bool = False
    protect_system: str = "no"
    root_directory: str | None = None
    root_image: str | None = None
    lock_personality: bool = False
    memory_deny_write_execute: bool = False
    no_new_privileges: bool = False
    capability_bounding_set: frozenset[str] = _ALL
    ambient_capabilities: frozenset[str] = frozenset()
    umask: int = 0o022
    keyring_mode: str = "private"
    protect_proc: str = "default"
    proc_subset: str = "all"
    notify_access: str = "none"
    remove_ipc: bool = False
    delegate: bool = False
    restrict_realtime: bool = False
    restrict_suid_sgid: bool = False
    restrict_namespaces_allowed: frozenset[str] = NAMESPACES
    af_mode: str | None = None  # None (unrestricted) | "allow" | "deny"
    af_set: frozenset[str] = frozenset()
    syscall_archs: frozenset[str] = frozenset()
    sc_mode: str | None = None  # None | "allow" | "deny"
    sc_set: frozenset[str] = frozenset()
    ip_deny: tuple[str, ...] = ()
    ip_allow: tuple[str, ...] = ()
    ip_custom_filters: bool = False
    device_policy: str = "auto"
    device_allow: bool = False
    default_dependencies: bool = True

    @property
    def privileged(self) -> bool:
        if self.user_scope:
            return False
        return (self.user or "") in ("", "root", "0") and not self.dynamic_user


@dataclass(frozen=True, slots=True)
class CheckResult:
    id: str
    weight: int
    range: int
    badness: int | None  # None = not applicable
    description: str

    @property
    def contribution(self) -> int:
        if self.badness is None:
            return 0
        return math.ceil(self.badness * self.weight / self.range)


@dataclass(slots=True)
class Assessment:
    exposure: float
    rating: str
    checks: list[CheckResult] = field(default_factory=list)

    def weaknesses(self, limit: int = 8) -> list[str]:
        failing = [c for c in self.checks if c.badness]
        failing.sort(key=lambda c: -c.contribution)
        return [f"{c.id}: {c.description}" for c in failing[:limit]]


_Check = tuple[str, int, int, Callable[[SecurityInput], int | None], str, bool]


def _cap(*names: str) -> Callable[[SecurityInput], int | None]:
    return lambda s: int(any(n in s.capability_bounding_set for n in names))


def _ns(name: str) -> Callable[[SecurityInput], int | None]:
    return lambda s: int(name in s.restrict_namespaces_allowed)


def _af_allowed(s: SecurityInput, families: Iterable[str]) -> bool:
    fams = set(families)
    if s.af_mode is None:
        return True
    if s.af_mode == "allow":
        return bool(fams & s.af_set)
    return not fams <= s.af_set


_AF_NAMED = frozenset({"AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK", "AF_PACKET"})


def _af_other(s: SecurityInput) -> int:
    if s.af_mode is None:
        return 1
    if s.af_mode == "allow":
        return int(bool(s.af_set - _AF_NAMED))
    return 1  # a deny-list never covers every other family


def _syscalls(group: str) -> Callable[[SecurityInput], int | None]:
    def check(s: SecurityInput) -> int:
        members = expand_group(group)
        if s.sc_mode is None:
            return 10
        if s.sc_mode == "allow":
            return 9 if members & s.sc_set else 0
        return 10 if members - s.sc_set else 0

    return check


def _user(s: SecurityInput) -> int:
    if s.user_scope:
        return 0
    if (s.user or "") == "nobody":
        return 9
    if s.dynamic_user:
        return 0
    return 10 if s.privileged else 0


def _umask(s: SecurityInput) -> int:
    if not s.umask & 0o002:
        return 10
    if not s.umask & 0o004:
        return 5
    if not s.umask & 0o020:
        return 2
    if not s.umask & 0o040:
        return 1
    return 0


def _nets(entries: Iterable[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    keywords = {
        "any": ["0.0.0.0/0", "::/0"],
        "localhost": ["127.0.0.0/8", "::1/128"],
        "link-local": ["169.254.0.0/16", "fe80::/64"],
        "multicast": ["224.0.0.0/4", "ff00::/8"],
    }
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for e in entries:
        for item in keywords.get(e, [e]):
            try:
                out.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
    return out


def _ip_deny(s: SecurityInput) -> int:
    if s.ip_custom_filters:
        return 0
    deny = _nets(s.ip_deny)
    all4 = any(n.version == 4 and n.prefixlen == 0 for n in deny)
    all6 = any(n.version == 6 and n.prefixlen == 0 for n in deny)
    if not (all4 and all6):
        return 10
    allow = _nets(s.ip_allow)
    if not allow:
        return 0
    if all(n.is_loopback for n in allow):
        return 2
    return 5


def _device_allow(s: SecurityInput) -> int:
    if s.device_policy in ("strict", "closed"):
        return 5 if s.device_allow else 0
    return 10


def _protect_home(s: SecurityInput) -> int:
    return {"yes": 0, "true": 0, "tmpfs": 1, "read-only": 5}.get(s.protect_home, 10)


def _protect_system(s: SecurityInput) -> int:
    return {"strict": 0, "full": 3, "yes": 5, "true": 5}.get(s.protect_system, 10)


def _archs(s: SecurityInput) -> int:
    if not s.syscall_archs:
        return 10
    return 0 if s.syscall_archs == {"native"} else 8


# (id, weight, range, assess, description of the bad state, default_dependencies_only)
CHECKS: tuple[_Check, ...] = (
    ("User=/DynamicUser=", 2000, 10, _user, "Service runs as root user", False),
    (
        "SupplementaryGroups=",
        200,
        1,
        lambda s: None if s.privileged else int(s.supplementary_groups),
        "Service runs with supplementary groups",
        False,
    ),
    (
        "PrivateDevices=",
        1000,
        1,
        lambda s: int(not s.private_devices),
        "Service potentially has access to hardware devices",
        False,
    ),
    (
        "PrivateMounts=",
        1000,
        1,
        lambda s: int(not s.private_mounts),
        "Service may install system mounts",
        False,
    ),
    (
        "PrivateNetwork=",
        2500,
        1,
        lambda s: int(not s.private_network),
        "Service has access to the host's network",
        False,
    ),
    (
        "PrivateTmp=",
        1000,
        1,
        lambda s: int(s.private_tmp == "no"),
        "Service has access to other software's temporary files",
        True,
    ),
    (
        "PrivateUsers=",
        1000,
        1,
        lambda s: int(not s.private_users),
        "Service has access to other users",
        False,
    ),
    (
        "ProtectControlGroups=",
        1000,
        1,
        lambda s: int(s.protect_control_groups == "no"),
        "Service may modify the control group file system",
        False,
    ),
    (
        "ProtectKernelModules=",
        1000,
        1,
        lambda s: int(not s.protect_kernel_modules),
        "Service may load or read kernel modules",
        False,
    ),
    (
        "ProtectKernelTunables=",
        1000,
        1,
        lambda s: int(not s.protect_kernel_tunables),
        "Service may alter kernel tunables",
        False,
    ),
    (
        "ProtectKernelLogs=",
        1000,
        1,
        lambda s: int(not s.protect_kernel_logs),
        "Service may read from or write to the kernel log ring buffer",
        False,
    ),
    (
        "ProtectClock=",
        1000,
        1,
        lambda s: int(not s.protect_clock),
        "Service may write to the hardware clock or system clock",
        False,
    ),
    ("ProtectHome=", 1000, 10, _protect_home, "Service has full access to home directories", True),
    (
        "ProtectHostname=",
        50,
        1,
        lambda s: int(not s.protect_hostname),
        "Service may change system host/domainname",
        False,
    ),
    (
        "ProtectSystem=",
        1000,
        10,
        _protect_system,
        "Service has full access to the OS file hierarchy",
        True,
    ),
    (
        "RootDirectory=/RootImage=",
        200,
        1,
        lambda s: int((s.root_directory or "/") == "/" and (s.root_image or "/") == "/"),
        "Service runs within the host's root directory",
        True,
    ),
    (
        "LockPersonality=",
        100,
        1,
        lambda s: int(not s.lock_personality),
        "Service may change ABI personality",
        False,
    ),
    (
        "MemoryDenyWriteExecute=",
        100,
        1,
        lambda s: int(not s.memory_deny_write_execute),
        "Service may create writable executable memory mappings",
        False,
    ),
    (
        "NoNewPrivileges=",
        1000,
        1,
        lambda s: int(not s.no_new_privileges),
        "Service processes may acquire new privileges",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYS_ADMIN",
        1500,
        1,
        _cap("CAP_SYS_ADMIN"),
        "Service has administrator privileges",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SET(UID|GID|PCAP)",
        1500,
        1,
        _cap("CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"),
        "Service can change UID/GID identities/capabilities",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYS_PTRACE",
        1500,
        1,
        _cap("CAP_SYS_PTRACE"),
        "Service has ptrace() debugging abilities",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYS_TIME",
        1000,
        1,
        _cap("CAP_SYS_TIME"),
        "Service processes can change the system clock",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_NET_ADMIN",
        1000,
        1,
        _cap("CAP_NET_ADMIN"),
        "Service has network configuration privileges",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYS_RAWIO",
        1000,
        1,
        _cap("CAP_SYS_RAWIO"),
        "Service has raw I/O access",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYS_MODULE",
        1000,
        1,
        _cap("CAP_SYS_MODULE"),
        "Service may load kernel modules",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_AUDIT_*",
        500,
        1,
        _cap("CAP_AUDIT_CONTROL", "CAP_AUDIT_READ", "CAP_AUDIT_WRITE"),
        "Service has audit subsystem access",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYSLOG",
        500,
        1,
        _cap("CAP_SYSLOG"),
        "Service has access to kernel logging",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYS_(NICE|RESOURCE)",
        500,
        1,
        _cap("CAP_SYS_NICE", "CAP_SYS_RESOURCE"),
        "Service has privileges to change resource use parameters",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_MKNOD",
        500,
        1,
        _cap("CAP_MKNOD"),
        "Service may create device nodes",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_(CHOWN|FSETID|SETFCAP)",
        1000,
        1,
        _cap("CAP_CHOWN", "CAP_FSETID", "CAP_SETFCAP"),
        "Service may change file ownership/access mode/capabilities",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_(DAC_*|FOWNER|IPC_OWNER)",
        1000,
        1,
        _cap("CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_IPC_OWNER"),
        "Service may override UNIX file/IPC permission checks",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_KILL",
        500,
        1,
        _cap("CAP_KILL"),
        "Service may send UNIX signals to arbitrary processes",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_NET_(BIND_SERVICE|BROADCAST|RAW)",
        500,
        1,
        _cap("CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_RAW"),
        "Service has elevated networking privileges",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYS_BOOT",
        100,
        1,
        _cap("CAP_SYS_BOOT"),
        "Service may issue reboot()",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_MAC_*",
        100,
        1,
        _cap("CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE"),
        "Service may adjust SMACK MAC",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_LINUX_IMMUTABLE",
        75,
        1,
        _cap("CAP_LINUX_IMMUTABLE"),
        "Service may mark files immutable",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_IPC_LOCK",
        50,
        1,
        _cap("CAP_IPC_LOCK"),
        "Service may lock memory into RAM",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYS_CHROOT",
        50,
        1,
        _cap("CAP_SYS_CHROOT"),
        "Service may issue chroot()",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_BLOCK_SUSPEND",
        25,
        1,
        _cap("CAP_BLOCK_SUSPEND"),
        "Service may establish wake locks",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_WAKE_ALARM",
        25,
        1,
        _cap("CAP_WAKE_ALARM"),
        "Service may program timers that wake up the system",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_LEASE",
        25,
        1,
        _cap("CAP_LEASE"),
        "Service may create file leases",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYS_TTY_CONFIG",
        25,
        1,
        _cap("CAP_SYS_TTY_CONFIG"),
        "Service may issue vhangup()",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_SYS_PACCT",
        25,
        1,
        _cap("CAP_SYS_PACCT"),
        "Service may use acct()",
        False,
    ),
    (
        "CapabilityBoundingSet=~CAP_BPF",
        25,
        1,
        _cap("CAP_BPF"),
        "Service may load BPF programs",
        False,
    ),
    ("UMask=", 100, 10, _umask, "Files created by service are world-readable by default", False),
    (
        "KeyringMode=",
        1000,
        1,
        lambda s: int(s.keyring_mode != "private"),
        "Service shares key chain with other services",
        False,
    ),
    (
        "ProtectProc=",
        1000,
        3,
        lambda s: {"noaccess": 1, "invisible": 0, "ptraceable": 0}.get(s.protect_proc, 3),
        "Service has full access to process tree (/proc hidepid=)",
        False,
    ),
    (
        "ProcSubset=",
        10,
        1,
        lambda s: int(s.proc_subset != "pid"),
        "Service has full access to non-process /proc files (/proc subset=)",
        False,
    ),
    (
        "NotifyAccess=",
        1000,
        1,
        lambda s: int(s.notify_access == "all"),
        "Service child processes may alter service state",
        False,
    ),
    (
        "RemoveIPC=",
        100,
        1,
        lambda s: None if s.privileged or s.user_scope else int(not s.remove_ipc),
        "Service user may leave SysV IPC objects around",
        False,
    ),
    (
        "Delegate=",
        100,
        1,
        lambda s: int(s.delegate),
        "Service maintains its own delegated control group subtree",
        False,
    ),
    (
        "RestrictRealtime=",
        500,
        1,
        lambda s: int(not s.restrict_realtime),
        "Service may acquire realtime scheduling",
        False,
    ),
    (
        "RestrictSUIDSGID=",
        1000,
        1,
        lambda s: int(not s.restrict_suid_sgid),
        "Service may create SUID/SGID files",
        False,
    ),
    ("RestrictNamespaces=~user", 1500, 1, _ns("user"), "Service may create user namespaces", False),
    (
        "RestrictNamespaces=~mnt",
        500,
        1,
        _ns("mnt"),
        "Service may create file system namespaces",
        False,
    ),
    ("RestrictNamespaces=~ipc", 500, 1, _ns("ipc"), "Service may create IPC namespaces", False),
    ("RestrictNamespaces=~pid", 500, 1, _ns("pid"), "Service may create process namespaces", False),
    (
        "RestrictNamespaces=~cgroup",
        500,
        1,
        _ns("cgroup"),
        "Service may create cgroup namespaces",
        False,
    ),
    ("RestrictNamespaces=~net", 500, 1, _ns("net"), "Service may create network namespaces", False),
    (
        "RestrictNamespaces=~uts",
        100,
        1,
        _ns("uts"),
        "Service may create hostname namespaces",
        False,
    ),
    (
        "RestrictAddressFamilies=~AF_(INET|INET6)",
        1500,
        1,
        lambda s: int(_af_allowed(s, ("AF_INET", "AF_INET6"))),
        "Service may allocate Internet sockets",
        False,
    ),
    (
        "RestrictAddressFamilies=~AF_UNIX",
        25,
        1,
        lambda s: int(_af_allowed(s, ("AF_UNIX",))),
        "Service may allocate local sockets",
        False,
    ),
    (
        "RestrictAddressFamilies=~AF_NETLINK",
        200,
        1,
        lambda s: int(_af_allowed(s, ("AF_NETLINK",))),
        "Service may allocate netlink sockets",
        False,
    ),
    (
        "RestrictAddressFamilies=~AF_PACKET",
        1000,
        1,
        lambda s: int(_af_allowed(s, ("AF_PACKET",))),
        "Service may allocate packet sockets",
        False,
    ),
    (
        "RestrictAddressFamilies=~…",
        1250,
        1,
        _af_other,
        "Service may allocate exotic sockets",
        False,
    ),
    (
        "SystemCallArchitectures=",
        1000,
        10,
        _archs,
        "Service may execute system calls with all ABIs",
        False,
    ),
    (
        "SystemCallFilter=~@swap",
        1000,
        10,
        _syscalls("@swap"),
        "Service may activate swap devices",
        False,
    ),
    (
        "SystemCallFilter=~@obsolete",
        250,
        10,
        _syscalls("@obsolete"),
        "Service may use unusual or obsolete system calls",
        False,
    ),
    (
        "SystemCallFilter=~@clock",
        1000,
        10,
        _syscalls("@clock"),
        "Service may change system clock",
        False,
    ),
    (
        "SystemCallFilter=~@cpu-emulation",
        250,
        10,
        _syscalls("@cpu-emulation"),
        "Service may use CPU emulation system calls",
        False,
    ),
    (
        "SystemCallFilter=~@debug",
        1000,
        10,
        _syscalls("@debug"),
        "Service may use debugging/tracing system calls",
        False,
    ),
    (
        "SystemCallFilter=~@mount",
        1000,
        10,
        _syscalls("@mount"),
        "Service may use file system mounting system calls",
        False,
    ),
    (
        "SystemCallFilter=~@module",
        1000,
        10,
        _syscalls("@module"),
        "Service may load kernel modules",
        False,
    ),
    (
        "SystemCallFilter=~@raw-io",
        1000,
        10,
        _syscalls("@raw-io"),
        "Service may use raw I/O system calls",
        False,
    ),
    (
        "SystemCallFilter=~@reboot",
        1000,
        10,
        _syscalls("@reboot"),
        "Service may reboot the system",
        False,
    ),
    (
        "SystemCallFilter=~@privileged",
        700,
        10,
        _syscalls("@privileged"),
        "Service may use privileged system calls",
        False,
    ),
    (
        "SystemCallFilter=~@resources",
        700,
        10,
        _syscalls("@resources"),
        "Service may change system resource limits",
        False,
    ),
    (
        "IPAddressDeny=",
        1000,
        10,
        _ip_deny,
        "Service may communicate with arbitrary IP hosts",
        False,
    ),
    ("DeviceAllow=", 1000, 10, _device_allow, "Service has no device ACL", False),
    (
        "AmbientCapabilities=",
        500,
        1,
        lambda s: int(bool(s.ambient_capabilities)),
        "Service process receives ambient capabilities",
        False,
    ),
)

_LABELS = (
    (100, "DANGEROUS"),
    (90, "UNSAFE"),
    (75, "EXPOSED"),
    (50, "MEDIUM"),
    (10, "OK"),
    (1, "SAFE"),
    (0, "PERFECT"),
)


def assess(s: SecurityInput) -> Assessment:
    """Run every check and compute the systemd exposure score and label."""
    badness_sum = 0
    weight_sum = 0
    results: list[CheckResult] = []
    for cid, weight, rng, fn, desc, dd_only in CHECKS:
        badness = None if dd_only and not s.default_dependencies else fn(s)
        results.append(CheckResult(cid, weight, rng, badness, desc))
        if badness is None:
            continue
        badness_sum += math.ceil(badness * weight / rng)
        weight_sum += weight
    exposure = math.ceil(badness_sum * 100 / weight_sum) if weight_sum else 0
    rating = next(label for threshold, label in _LABELS if exposure >= threshold)
    return Assessment(exposure=exposure / 10, rating=rating, checks=results)


# --------------------------------------------------------------------------- settings → input
class SettingsView:
    """Minimal accessor protocol over merged ``[Service]`` settings (implemented by loader)."""

    def get(self, key: str) -> str | None:  # pragma: no cover - interface
        raise NotImplementedError

    def values(self, key: str) -> list[str]:  # pragma: no cover - interface
        raise NotImplementedError


def capability_set(values: list[str], *, ambient: bool = False) -> frozenset[str]:
    """Evaluate ``CapabilityBoundingSet=`` (default all) / ``AmbientCapabilities=`` (default none).

    Mirrors ``config_parse_capability_set``: an empty assignment yields the empty
    set, the first assignment (or one made while the set is still at its default)
    replaces, later plain lists OR in and ``~`` lists remove.
    """
    initial = frozenset() if ambient else _ALL
    current = initial
    for raw in values:
        invert = raw.startswith("~")
        words = split_words(raw[1:] if invert else raw)
        names = frozenset(
            (w if w.upper().startswith("CAP_") else f"CAP_{w}").upper() for w in words
        )
        if not names or current == initial:
            current = (_ALL - names) if invert else names
        else:
            current = (current - names) if invert else (current | names)
    return current


def namespaces_allowed(values: list[str]) -> frozenset[str]:
    """Evaluate ``RestrictNamespaces=`` into the set of *allowed* namespace types."""
    allowed: frozenset[str] = NAMESPACES
    initialized = False
    for raw in values:
        b = parse_bool(raw) if raw else False
        if raw == "" or b is False:
            allowed, initialized = NAMESPACES, False
            continue
        if b is True:
            allowed, initialized = frozenset(), True
            continue
        invert = raw.startswith("~")
        names = frozenset(w for w in split_words(raw[1:] if invert else raw) if w in NAMESPACES)
        if invert:
            allowed = allowed - names
        elif initialized:
            allowed = allowed | names
        else:
            allowed = names
        initialized = True
    return allowed


def address_families(values: list[str]) -> tuple[str | None, frozenset[str]]:
    """Evaluate ``RestrictAddressFamilies=`` into ``(mode, families)``."""
    mode: str | None = None
    fams: set[str] = set()
    for raw in values:
        if raw == "":
            mode, fams = None, set()
            continue
        invert = raw.startswith("~")
        words = split_words(raw[1:] if invert else raw)
        if words == ["none"]:
            mode, fams = "allow", set()
            continue
        polarity = "deny" if invert else "allow"
        if mode is None:
            mode, fams = polarity, set(words)
        elif mode == polarity:
            fams |= set(words)
        else:
            fams -= set(words)
    return mode, frozenset(fams)


def syscall_filter(values: list[str]) -> tuple[str | None, frozenset[str]]:
    """Evaluate ``SystemCallFilter=`` into ``(mode, expanded syscall set)``."""
    mode: str | None = None
    calls: set[str] = set()
    for raw in values:
        if raw == "":
            mode, calls = None, set()
            continue
        invert = raw.startswith("~")
        words = [w.split(":", 1)[0] for w in split_words(raw[1:] if invert else raw)]
        expanded: set[str] = set()
        for w in words:
            expanded |= expand_group(w)
        polarity = "deny" if invert else "allow"
        if mode is None:
            mode = polarity
            calls = set(expand_group("@default")) | expanded if polarity == "allow" else expanded
        elif mode == polarity:
            calls |= expanded
        else:
            calls -= expanded
    return mode, frozenset(calls)


def _list(values: list[str]) -> list[str]:
    out: list[str] = []
    for raw in values:
        if raw == "":
            out = []
        else:
            out.extend(split_words(raw))
    return out


def _flag(view: SettingsView, key: str) -> bool:
    return bool(parse_bool(view.get(key)))


def _tri(view: SettingsView, key: str, *, true: str = "yes") -> str:
    """Normalise a boolean-or-keyword setting (``ProtectSystem=``, ``ProtectHome=``, ...)."""
    v = (view.get(key) or "").strip().lower()
    if not v:
        return "no"
    b = parse_bool(v)
    if b is True:
        return true
    if b is False:
        return "no"
    return v


def from_settings(
    view: SettingsView, *, default_dependencies: bool = True, unit_prefix: str | None = None
) -> SecurityInput:
    """Build a :class:`SecurityInput` from merged ``[Service]`` settings (derivations applied).

    ``unit_prefix`` names the user ``DynamicUser=yes`` allocates when ``User=`` is unset.
    """
    s = SecurityInput(default_dependencies=default_dependencies)
    s.user = (view.get("User") or "").strip() or None
    s.dynamic_user = _flag(view, "DynamicUser")
    s.supplementary_groups = bool(_list(view.values("SupplementaryGroups")))
    s.private_devices = _flag(view, "PrivateDevices")
    s.private_network = _flag(view, "PrivateNetwork") or bool(view.get("NetworkNamespacePath"))
    s.private_tmp = _tri(view, "PrivateTmp")
    s.private_users = (view.get("PrivateUsers") or "no").strip().lower() not in BOOL_FALSE_SET
    s.protect_control_groups = _tri(view, "ProtectControlGroups")
    s.protect_kernel_modules = _flag(view, "ProtectKernelModules")
    s.protect_kernel_tunables = _flag(view, "ProtectKernelTunables")
    s.protect_kernel_logs = _flag(view, "ProtectKernelLogs")
    s.protect_clock = _flag(view, "ProtectClock")
    s.protect_home = _tri(view, "ProtectHome")
    s.protect_hostname = (view.get("ProtectHostname") or "no").strip().lower() not in BOOL_FALSE_SET
    s.protect_system = _tri(view, "ProtectSystem")
    s.root_directory = (view.get("RootDirectory") or "").strip() or None
    s.root_image = (view.get("RootImage") or "").strip() or None
    s.lock_personality = _flag(view, "LockPersonality")
    s.memory_deny_write_execute = _flag(view, "MemoryDenyWriteExecute")
    s.no_new_privileges = _flag(view, "NoNewPrivileges")
    s.capability_bounding_set = capability_set(view.values("CapabilityBoundingSet"))
    s.ambient_capabilities = capability_set(view.values("AmbientCapabilities"), ambient=True)
    um = (view.get("UMask") or "").strip()
    try:
        s.umask = int(um, 8) if um else 0o022
    except ValueError:
        s.umask = 0o022
    s.keyring_mode = (view.get("KeyringMode") or "private").strip().lower()
    s.protect_proc = (view.get("ProtectProc") or "default").strip().lower()
    s.proc_subset = (view.get("ProcSubset") or "all").strip().lower()
    typ = (view.get("Type") or "").strip().lower()
    s.notify_access = (
        (view.get("NotifyAccess") or ("main" if typ in ("notify", "notify-reload") else "none"))
        .strip()
        .lower()
    )
    s.remove_ipc = _flag(view, "RemoveIPC")
    delegate = (view.get("Delegate") or "no").strip().lower()
    s.delegate = parse_bool(delegate) is not False and delegate != ""
    s.restrict_realtime = _flag(view, "RestrictRealtime")
    s.restrict_suid_sgid = _flag(view, "RestrictSUIDSGID")
    s.restrict_namespaces_allowed = namespaces_allowed(view.values("RestrictNamespaces"))
    s.af_mode, s.af_set = address_families(view.values("RestrictAddressFamilies"))
    s.syscall_archs = frozenset(_list(view.values("SystemCallArchitectures")))
    s.sc_mode, s.sc_set = syscall_filter(view.values("SystemCallFilter"))
    s.ip_deny = tuple(_list(view.values("IPAddressDeny")))
    s.ip_allow = tuple(_list(view.values("IPAddressAllow")))
    s.ip_custom_filters = bool(
        _list(view.values("IPIngressFilterPath")) or _list(view.values("IPEgressFilterPath"))
    )
    s.device_policy = (view.get("DevicePolicy") or "auto").strip().lower()
    s.device_allow = bool([v for v in view.values("DeviceAllow") if v])
    explicit_private_mounts = _flag(view, "PrivateMounts")
    derive(s, dynamic_name=unit_prefix)
    s.private_mounts = explicit_private_mounts or s.private_mounts
    return s


BOOL_FALSE_SET = frozenset({"0", "no", "n", "false", "f", "off", ""})


def derive(s: SecurityInput, *, dynamic_name: str | None = None) -> None:
    """Apply systemd's implied settings (``unit_patch_contexts``) in place."""
    caps = set(s.capability_bounding_set)
    if s.private_devices:
        caps -= {"CAP_MKNOD", "CAP_SYS_RAWIO"}
        if s.device_policy == "auto":
            s.device_policy = "closed"
    if s.protect_kernel_modules:
        caps.discard("CAP_SYS_MODULE")
    if s.protect_kernel_logs:
        caps.discard("CAP_SYSLOG")
    if s.protect_clock:
        caps -= {"CAP_SYS_TIME", "CAP_WAKE_ALARM"}
    s.capability_bounding_set = frozenset(caps)
    if s.dynamic_user:
        if not s.user:
            s.user = dynamic_name or "<dynamic>"
        if s.private_tmp == "no":
            s.private_tmp = "disconnected"
        s.remove_ipc = True
        s.protect_system = "strict"
        if s.protect_home == "no":
            s.protect_home = "read-only"
        s.no_new_privileges = True
        s.restrict_suid_sgid = True
    s.private_mounts = (
        s.private_mounts
        or s.private_devices
        or s.private_tmp != "no"
        or s.protect_control_groups != "no"
        or s.protect_kernel_tunables
        or s.protect_kernel_modules
        or s.protect_home != "no"
        or s.protect_system != "no"
        or bool(s.root_image)
    )


def to_hardening(s: SecurityInput, *, group: str | None = None) -> Hardening:
    """Project a :class:`SecurityInput` and its assessment onto the report model."""
    a = assess(s)
    user = s.user or "root"
    caps = None if s.capability_bounding_set == _ALL else sorted(s.capability_bounding_set)
    afs = (
        None
        if s.af_mode is None
        else (sorted(s.af_set) if s.af_mode == "allow" else [f"~{f}" for f in sorted(s.af_set)])
    )
    return Hardening(
        user=user,
        group=group,
        dynamic_user=s.dynamic_user,
        no_new_privileges=s.no_new_privileges,
        capability_bounding_set=caps,
        ambient_capabilities=sorted(s.ambient_capabilities),
        private_network=s.private_network,
        private_tmp=s.private_tmp != "no",
        private_devices=s.private_devices,
        private_users=s.private_users,
        protect_system=None if s.protect_system == "no" else s.protect_system,
        protect_home=None if s.protect_home == "no" else s.protect_home,
        restrict_suid_sgid=s.restrict_suid_sgid,
        system_call_filter=s.sc_mode is not None,
        restrict_address_families=afs,
        root_directory=s.root_directory,
        exposure=a.exposure,
        exposure_rating=a.rating,
        weaknesses=a.weaknesses(),
    )
