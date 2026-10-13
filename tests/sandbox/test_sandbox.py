"""Chroot mode: the bubblewrap sandbox, its probes and the pipeline stage."""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

import pytest

from startup_sbom.context import ScanContext, ScanOptions
from startup_sbom.models import (
    Activation,
    Binary,
    InitSystem,
    LibraryLink,
    Package,
    PackageType,
    Service,
)
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.rootfs import DirectoryRootFS
from startup_sbom.sandbox import SandboxUnavailable, open_sandbox
from startup_sbom.sandbox.probes import (
    loader_probe,
    packages_probe,
    parse_loader_list,
    parse_unit_files,
    systemd_probe,
)
from startup_sbom.sandbox.runner import NOBODY, RunResult, Sandbox

#: The sandbox itself is Linux-only; parsers and probes are tested everywhere.
linux_only = pytest.mark.skipif(sys.platform != "linux", reason="bubblewrap sandbox is Linux-only")

LDD = """\
\tlinux-vdso.so.1 (0x00007ffd5d9f2000)
\tlibaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007f85e1fcc000)
\tlibmissing.so.3 => not found
\t/lib64/ld-linux-x86-64.so.2 (0x00007f85e2052000)
garbage line that is not ldd output
"""


# --------------------------------------------------------------------------- argv
@linux_only
def test_argv_enforces_isolation(tmp_path: Path) -> None:
    (tmp_path / "proc").mkdir()
    (tmp_path / "tmp").mkdir()
    (tmp_path / "home").mkdir()
    (tmp_path / "root").symlink_to("home")  # a symlink is never mounted over
    box = Sandbox(str(tmp_path), bwrap="/usr/bin/bwrap")
    argv = box.argv(["/bin/true"])
    joined = " ".join(argv)
    for flag in (
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ):
        assert flag in argv
    assert "--cap-drop ALL" in joined
    assert f"--uid {NOBODY} --gid {NOBODY}" in joined
    assert f"--ro-bind {os.path.realpath(tmp_path)} /" in joined
    assert "--share-net" not in argv
    assert "--bind" not in argv  # nothing writable from the host
    assert "--proc /proc" in joined
    assert "--dev" not in argv  # the root has no /dev directory
    assert argv[-2:] == ["--", "/bin/true"]
    assert "--tmpfs /home" in joined  # user data hidden
    assert "--tmpfs /root" not in joined


@linux_only
def test_relative_commands_are_refused(tmp_path: Path) -> None:
    box = Sandbox(str(tmp_path), bwrap="/usr/bin/bwrap")
    with pytest.raises(ValueError, match="absolute"):
        box.run(["sh", "-c", "true"])


@linux_only
def test_missing_bwrap_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(SandboxUnavailable, match="bubblewrap"):
        Sandbox(str(tmp_path))


# --------------------------------------------------------------------------- parsers
def test_parse_loader_list() -> None:
    found, missing = parse_loader_list(LDD)
    assert ("libaudit.so.1", "/lib/x86_64-linux-gnu/libaudit.so.1") in found
    assert ("ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2") in found
    assert missing == ["libmissing.so.3"]
    assert all("vdso" not in name for name, _ in found)


def test_parse_unit_files() -> None:
    text = "ssh.service  enabled  enabled\nfoo.service masked -\nbad line\nx.timer static -\n"
    assert parse_unit_files(text) == {
        "ssh.service": "enabled",
        "foo.service": "masked",
        "x.timer": "static",
    }


# --------------------------------------------------------------------------- probes
class FakeSandbox:
    """Answers sandboxed commands from a table instead of running anything."""

    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.calls: list[list[str]] = []
        self.runs = 0

    def run(self, command: list[str], **_kw: object) -> RunResult:
        self.calls.append(list(command))
        self.runs += 1
        key = next((k for k in self.answers if k in " ".join(command)), None)
        out = self.answers.get(key, "") if key else ""
        return RunResult(tuple(command), 0 if key else 1, out, "", 0.01)


def _ctx(root: Path) -> ScanContext:
    return ScanContext(fs=DirectoryRootFS(root), options=ScanOptions(offline=True))


def _mkfile(root: Path, path: str) -> None:
    p = root / path.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\x7fELF")


def test_loader_probe_adds_and_confirms_links(tmp_path: Path) -> None:
    for f in (
        "/usr/sbin/sshd",
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/libaudit.so.1",
        "/lib/x86_64-linux-gnu/libc.so.6",
    ):
        _mkfile(tmp_path, f)
    ctx = _ctx(tmp_path)
    b = Binary(
        path="/usr/sbin/sshd",
        kind="elf",
        interpreter="/lib64/ld-linux-x86-64.so.2",
        needed=["libaudit.so.1", "libc.so.6"],
        libraries=[LibraryLink(soname="libc.so.6", path="/lib/x86_64-linux-gnu/libc.so.6")],
        used_by=["systemd:ssh.service"],
    )
    ldd = LDD + "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1)\n"
    box = FakeSandbox({"--list /usr/sbin/sshd": ldd})
    out = loader_probe(ctx, box, [b], FileOwnerIndex(ctx.fs))  # type: ignore[arg-type]
    assert out.ran
    added = [li for li in b.libraries if li.via == "loader"]
    assert [li.path for li in added] == ["/lib/x86_64-linux-gnu/libaudit.so.1"]
    assert added[0].depth == 1  # in DT_NEEDED
    assert "libmissing.so.3" in b.unresolved
    assert "confirmed 1" in out.summary
    assert box.calls == [["/lib64/ld-linux-x86-64.so.2", "--list", "/usr/sbin/sshd"]]


def _svc(name: str, *, enabled: bool = True) -> Service:
    return Service(
        id=f"systemd:{name}",
        name=name,
        init_system=InitSystem.SYSTEMD,
        enabled=enabled,
        activation=[Activation.BOOT],
    )


def test_systemd_probe_records_but_never_suppresses(tmp_path: Path) -> None:
    _mkfile(tmp_path, "/usr/bin/systemctl")
    ctx = _ctx(tmp_path)
    masked, disabled, ok = _svc("a.service"), _svc("b.service"), _svc("c.service")
    box = FakeSandbox(
        {"list-unit-files": "a.service masked -\nb.service disabled -\nc.service enabled -\n"}
    )
    out = systemd_probe(ctx, box, [masked, disabled, ok])  # type: ignore[arg-type]
    assert out.ran
    assert not masked.masked  # the target's own tool never hides a service
    assert masked.starts_automatically
    assert any("never suppresses" in e for e in masked.evidence)
    assert any("reports disabled" in e for e in disabled.evidence)
    assert disabled.starts_automatically  # disagreement is evidence, not a verdict
    assert ok.evidence == []


def test_packages_probe_compares_inventories(tmp_path: Path) -> None:
    _mkfile(tmp_path, "/usr/bin/dpkg-query")
    ctx = _ctx(tmp_path)
    recs = [
        PackageRecord(
            package=Package(id=f"pkg:deb/debian/{n}@{v}", type=PackageType.DEB, name=n, version=v)
        )
        for n, v in (("bash", "5.2-1"), ("coreutils", "9.4-3"))
    ]
    box = FakeSandbox(
        {"dpkg-query": "bash\t5.2-1\tii \ncoreutils:amd64\t9.4-3\tii \nzsh\t5.9-6\tii \n"}
    )
    out = packages_probe(ctx, box, recs, ["dpkg"])  # type: ignore[arg-type]
    assert out.ran
    assert "2 agree" in out.summary
    assert "1 only reported by the package manager" in out.summary
    assert any("zsh 5.9-6" in w for w in ctx.warnings)


# --------------------------------------------------------------------------- preconditions
def test_open_sandbox_refuses_non_directory_targets(tmp_path: Path) -> None:
    from startup_sbom.rootfs.tar import LayeredTarRootFS

    fs = LayeredTarRootFS.__new__(LayeredTarRootFS)
    fs.name = "tar:x"
    ctx = ScanContext(fs=fs, options=ScanOptions(offline=True, mode="chroot"))
    with pytest.raises(SandboxUnavailable, match="directory target"):
        open_sandbox(ctx, fs)


def test_open_sandbox_refuses_foreign_architecture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import startup_sbom.sandbox as sb

    monkeypatch.setattr(sb, "_target_arch", lambda _fs: "s390x")
    monkeypatch.setattr(sb, "host_arch", lambda: "x86_64")
    ctx = _ctx(tmp_path)
    with pytest.raises(SandboxUnavailable, match="emulation"):
        open_sandbox(ctx, ctx.fs)


# --------------------------------------------------------------------------- real bwrap
def _real_sandbox() -> Sandbox:
    if shutil.which("bwrap") is None:
        pytest.skip("bubblewrap not installed")
    box = Sandbox("/")
    try:
        box.self_test()
    except SandboxUnavailable as exc:
        pytest.skip(f"sandbox unavailable here: {exc}")
    return box


@linux_only
def test_real_sandbox_identity_and_isolation() -> None:
    box = _real_sandbox()
    res = box.run(
        [
            "/bin/sh",
            "-c",
            "id -u; grep -E '^(CapEff|NoNewPrivs)' /proc/self/status; "
            "touch /etc/startup-sbom-probe 2>/dev/null && echo WROTE || echo RO; "
            "cat /sys/class/net/*/address 2>/dev/null | wc -l; echo ENV=$HOME",
        ]
    )
    assert res.ok, res.stderr
    lines = res.stdout.split()
    assert lines[0] == str(NOBODY)
    assert "0000000000000000" in res.stdout  # no effective capabilities
    assert "NoNewPrivs:\t1" in res.stdout or "NoNewPrivs: 1" in res.stdout.replace("\t", " ")
    assert "RO" in lines
    assert "WROTE" not in lines
    assert "ENV=/nonexistent" in res.stdout


@linux_only
def test_real_sandbox_hides_user_data() -> None:
    box = _real_sandbox()
    res = box.run(["/bin/sh", "-c", "find /home /root -mindepth 1 2>/dev/null | wc -l"])
    assert res.ok, res.stderr
    assert res.stdout.strip() == "0"


@linux_only
def test_real_sandbox_timeout_kills_the_process_group() -> None:
    box = _real_sandbox()
    started = time.monotonic()
    res = box.run(["/bin/sh", "-c", "sleep 30 & sleep 30"], timeout=1.0)
    assert res.timed_out
    assert not res.ok
    assert time.monotonic() - started < 10


@linux_only
def test_real_sandbox_caps_output_floods() -> None:
    box = _real_sandbox()
    res = box.run(["/bin/sh", "-c", "yes AAAAAAAAAAAAAAAA"], timeout=20.0, max_output=100_000)
    assert res.truncated
    assert len(res.stdout) <= 100_000


@linux_only
def test_root_callers_drop_to_nobody_before_bwrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    from startup_sbom.sandbox import runner

    captured: dict[str, object] = {}

    class FakePopen:
        def __init__(self, argv: list[str], **kw: object) -> None:
            captured.update(kw)
            raise OSError("not really started")

    monkeypatch.setattr(runner, "_is_root", lambda: True)
    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    box = Sandbox(str(tmp_path), bwrap="/usr/bin/bwrap")
    with pytest.raises(OSError, match="not really"):
        box.run(["/bin/true"])
    assert captured["user"] == NOBODY
    assert captured["group"] == NOBODY
    assert captured["extra_groups"] == []
