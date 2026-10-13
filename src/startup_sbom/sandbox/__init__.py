"""Chroot mode: confirm static findings with the target's own tools, safely sandboxed.

``--mode static`` (the default) never executes anything from the target.
``--mode chroot`` additionally runs a few read-only probes (the dynamic loader,
``systemctl --root``, the package manager) inside the unprivileged bubblewrap
sandbox described in :mod:`startup_sbom.sandbox.runner`; ``--mode auto`` does so
only when every precondition holds and otherwise stays static.  See
:func:`open_sandbox` for those preconditions.
"""

from __future__ import annotations

from startup_sbom.binaries.elf import read_elf
from startup_sbom.context import ScanContext
from startup_sbom.rootfs import DirectoryRootFS, RootFS
from startup_sbom.sandbox.probes import ProbeOutcome, run_all
from startup_sbom.sandbox.runner import Sandbox, SandboxUnavailable, host_arch

__all__ = ["ProbeOutcome", "Sandbox", "SandboxUnavailable", "open_sandbox", "run_all"]

MODES = ("static", "chroot", "auto")


def open_sandbox(ctx: ScanContext, fs: RootFS) -> Sandbox:
    """A verified sandbox over ``fs``, or :class:`SandboxUnavailable` saying why not.

    Preconditions: a directory target (``dir:`` / ``host:``; archives and images
    are read without ever being extracted, so there is nothing to sandbox), a
    target whose executables match the host CPU architecture, a working
    ``bwrap`` with unprivileged user namespaces, and a passing self-test that
    proves the program inside really runs as ``nobody``.
    """
    if ctx.container is not None and not isinstance(fs, DirectoryRootFS):
        raise SandboxUnavailable("container images and archives are analysed statically only")
    if not isinstance(fs, DirectoryRootFS):
        raise SandboxUnavailable(
            f"chroot mode needs a directory target (dir:PATH or host:), not {fs.name}"
        )
    arch = _target_arch(fs)
    if arch is not None and arch != host_arch():
        raise SandboxUnavailable(
            f"target executables are {arch} but this host is {host_arch()}; "
            "running them would need emulation"
        )
    sandbox = Sandbox(fs.root)
    sandbox.self_test()
    return sandbox


def _target_arch(fs: RootFS) -> str | None:
    for path in ("/bin/sh", "/usr/bin/sh", "/bin/busybox", "/usr/bin/env"):
        cpath = fs.try_resolve(path)
        if cpath is None:
            continue
        info = read_elf(fs, cpath)
        if info is not None:
            return info.arch
    return None
