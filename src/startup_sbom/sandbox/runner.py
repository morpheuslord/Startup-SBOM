"""Run a program *from the target root* inside an unprivileged bubblewrap sandbox.

This is the only place startup-sbom ever executes code that belongs to the
analysed system, and only in ``--mode chroot``/``auto``.  The 1.x chroot mode
bind-mounted the target over the host and ran its binaries as root; this one:

* creates a **new user namespace** and runs the program as ``nobody``
  (uid/gid 65534) with **every capability dropped** and ``no_new_privs`` set
  (by bubblewrap), so setuid bits in the target are inert;
* never lets that identity map to host root: when startup-sbom itself runs as
  root (``sudo``), bubblewrap is started as host ``nobody`` with no
  supplementary groups, so the namespace maps to an unprivileged host account;
* unshares **every** namespace (net, pid, ipc, uts, cgroup): there is no network
  at all, and the program cannot see or signal host processes;
* forbids nested user namespaces (``--disable-userns``), a common kernel
  exploitation primitive;
* mounts the target root **read-only** as ``/``, with a fresh ``/proc``, a
  minimal ``/dev`` and small private tmpfs mounts for ``/tmp`` and ``/run``;
  nothing of the host filesystem is visible, and the target's own user data
  (``/home``, ``/root``, ``/mnt``, ``/media``) and ``/sys`` are hidden behind
  empty tmpfs mounts because no probe needs them;
* clears the environment, detaches from the controlling terminal
  (``--new-session``, no ``TIOCSTI`` injection) and dies with its parent;
* runs under CPU, memory, file-size and core-dump limits, a wall-clock timeout
  (the whole process group is killed) and an output cap.

Anything that cannot meet these guarantees (no bubblewrap, user namespaces
disabled, a non-directory target, a foreign architecture) makes the sandbox
unavailable; callers then fall back to static analysis and say so.
"""

from __future__ import annotations

import contextlib
import os
import platform
import selectors
import shlex
import shutil
import signal
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass

from startup_sbom.log import ops

#: Identity inside the sandbox.
NOBODY = 65534
DEFAULT_TIMEOUT = 20.0
MAX_OUTPUT = 4 * 1024 * 1024
TMPFS_BYTES = 16 * 1024 * 1024
#: Resource limits applied to bwrap (and inherited by the sandboxed program).
LIMIT_CPU_SECONDS = 30
LIMIT_ADDRESS_SPACE = 2 * 1024 * 1024 * 1024
LIMIT_FILE_SIZE = 16 * 1024 * 1024
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#: Writable scratch space the target's tools may need.
SCRATCH_DIRS = ("tmp", "run")
#: Hidden behind empty tmpfs: user data and kernel state no probe needs.
HIDDEN_DIRS = ("home", "root", "mnt", "media", "sys")

#: ``platform.machine()`` spellings → the arch names :func:`machine_arch` produces.
_HOST_ARCH = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "armv7l": "arm",
    "armv6l": "arm",
    "i686": "x86",
    "i386": "x86",
    "ppc64le": "ppc64le",
    "s390x": "s390x",
    "riscv64": "riscv64",
}


class SandboxUnavailable(Exception):  # noqa: N818 - reads naturally at call sites
    """The sandbox cannot be used on this host for this target (reason in the message)."""


@dataclass(frozen=True, slots=True)
class RunResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def host_arch() -> str:
    machine = platform.machine().lower()
    return _HOST_ARCH.get(machine, machine)


class Sandbox:
    """A reusable sandbox over one target root directory."""

    def __init__(self, root: str, *, bwrap: str | None = None) -> None:
        if os.name != "posix" or platform.system() != "Linux":
            raise SandboxUnavailable("the chroot sandbox needs a Linux host")
        real = os.path.realpath(root)
        if not os.path.isdir(real):
            raise SandboxUnavailable(f"not a directory: {root}")
        exe = bwrap or shutil.which("bwrap")
        if exe is None:
            raise SandboxUnavailable(
                "bubblewrap (bwrap) is not installed; install it to use --mode chroot"
            )
        self.root = real
        self.bwrap = exe
        self.runs = 0
        self._has_proc = _real_dir(real, "proc")
        self._has_dev = _real_dir(real, "dev")
        self._tmp = [d for d in SCRATCH_DIRS if _real_dir(real, d)]
        self._hidden = [d for d in HIDDEN_DIRS if _real_dir(real, d)]

    # ------------------------------------------------------------------ argv
    def argv(self, command: Sequence[str]) -> list[str]:
        """The full bwrap command line for ``command`` (exposed for tests and the journal)."""
        args = [
            self.bwrap,
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--uid",
            str(NOBODY),
            "--gid",
            str(NOBODY),
            "--ro-bind",
            self.root,
            "/",
        ]
        if self._has_proc:
            args += ["--proc", "/proc"]
        if self._has_dev:
            args += ["--dev", "/dev"]
        for d in self._tmp:
            args += ["--size", str(TMPFS_BYTES), "--tmpfs", f"/{d}"]
        for d in self._hidden:
            args += ["--perms", "0555", "--size", "4096", "--tmpfs", f"/{d}"]
        args += [
            "--clearenv",
            "--setenv",
            "PATH",
            SAFE_PATH,
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "HOME",
            "/nonexistent",
            "--setenv",
            "SYSTEMD_PAGER",
            "",
            "--setenv",
            "SYSTEMD_COLORS",
            "0",
            "--chdir",
            "/",
            "--",
            *command,
        ]
        return args

    # ------------------------------------------------------------------ run
    def run(
        self,
        command: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_output: int = MAX_OUTPUT,
    ) -> RunResult:
        """Run ``command`` (paths are inside the target) and capture its output."""
        if not command or not command[0].startswith("/"):
            raise ValueError("sandboxed commands must name an absolute in-target executable")
        argv = self.argv(command)
        started = time.monotonic()
        self.runs += 1
        # As root, drop to host nobody *before* bwrap: inside the user namespace the
        # sandboxed uid maps to the caller's uid, which must never be host root.
        root = _is_root()
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell, sandboxed
            argv,
            user=NOBODY if root else None,
            group=NOBODY if root else None,
            extra_groups=[] if root else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
            env={"PATH": SAFE_PATH, "LC_ALL": "C"},
            preexec_fn=_limits,  # noqa: PLW1509 - only setrlimit, async-signal-safe enough
        )
        out, err, timed_out, truncated = _collect(proc, started + timeout, max_output)
        seconds = time.monotonic() - started
        result = RunResult(
            tuple(command),
            proc.returncode if not timed_out else -1,
            out[:max_output].decode("utf-8", "replace"),
            err[:65_536].decode("utf-8", "replace"),
            seconds,
            timed_out,
            truncated,
        )
        ops.info(
            "sandbox: %s → %s (%.0f ms, %s)",
            shlex.join(command)[:160],
            "timeout" if timed_out else f"exit {result.returncode}",
            seconds * 1000,
            f"{len(out):,} bytes{' truncated' if truncated else ''}",
        )
        return result

    def self_test(self) -> None:
        """Prove the sandbox works for this root before trusting any probe."""
        shell = next((p for p in ("/bin/sh", "/usr/bin/sh") if os.path.exists(self.root + p)), None)
        if shell is None:
            raise SandboxUnavailable("the target has no /bin/sh to verify the sandbox with")
        try:
            res = self.run([shell, "-c", "id -u 2>/dev/null || echo 65534"], timeout=10.0)
        except OSError as exc:
            raise SandboxUnavailable(f"bubblewrap failed to start: {exc}") from exc
        if not res.ok:
            reason = res.stderr.strip().splitlines()[-1:] or ["unknown error"]
            raise SandboxUnavailable(
                f"bubblewrap could not create the sandbox ({reason[0][:200]}); "
                "unprivileged user namespaces may be disabled on this host"
            )
        if res.stdout.strip() != str(NOBODY):
            raise SandboxUnavailable(
                f"sandbox self-test reported uid {res.stdout.strip()[:20]!r}, not {NOBODY}"
            )


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _real_dir(root: str, name: str) -> bool:
    """A real directory (not a symlink, which bwrap would follow) directly under ``root``."""
    path = os.path.join(root, name)
    return os.path.isdir(path) and not os.path.islink(path)


def _limits() -> None:  # pragma: no cover - runs in the child between fork and exec
    import resource

    for which, value in (
        (resource.RLIMIT_CPU, LIMIT_CPU_SECONDS),
        (resource.RLIMIT_AS, LIMIT_ADDRESS_SPACE),
        (resource.RLIMIT_FSIZE, LIMIT_FILE_SIZE),
        (resource.RLIMIT_CORE, 0),
    ):
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(which, (value, value))


def _collect(
    proc: subprocess.Popen[bytes], deadline: float, max_output: int
) -> tuple[bytes, bytes, bool, bool]:
    """Read stdout/stderr with hard caps; kill the sandbox on timeout or flood.

    ``communicate()`` would buffer whatever the target prints; a hostile program
    could exhaust memory.  Here each stream is capped and the whole process
    group is killed as soon as a cap or the deadline is hit.
    """
    if proc.stdout is None or proc.stderr is None:  # pragma: no cover - PIPE always set
        raise RuntimeError("sandbox pipes missing")
    out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
    caps = {out_fd: max_output, err_fd: 65_536}
    bufs: dict[int, bytearray] = {fd: bytearray() for fd in caps}
    timed_out = truncated = False
    with selectors.DefaultSelector() as sel:
        for stream in (proc.stdout, proc.stderr):
            sel.register(stream, selectors.EVENT_READ)
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in sel.select(timeout=min(remaining, 0.5)):
                fd = key.fd
                chunk = os.read(fd, 65_536)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                room = caps[fd] - len(bufs[fd])
                bufs[fd] += chunk[: max(room, 0)]
                if len(chunk) > room:
                    truncated = truncated or fd == out_fd
                    sel.unregister(key.fileobj)
            if truncated:
                break
    if timed_out or truncated:
        _kill_group(proc)
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        proc.wait()
    proc.stdout.close()
    proc.stderr.close()
    return bytes(bufs[out_fd]), bytes(bufs[err_fd]), timed_out, truncated


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()
