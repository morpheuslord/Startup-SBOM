"""Security and semantics tests for the root-confined filesystem."""

from __future__ import annotations

import os
import sys

import pytest

from fsbuilder import Dir, File, Symlink, Whiteout
from startup_sbom.errors import PathNotFoundError, RootFSError, SymlinkLoopError
from startup_sbom.pkgdb.ownership import FileOwnerIndex

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@needs_symlinks
def test_absolute_symlink_is_rerooted(make_fs):
    fs = make_fs(
        {
            "/etc/passwd": "image-passwd\n",
            "/etc/systemd/system/evil.service": Symlink("/etc/passwd"),
        }
    )
    assert fs.read_text("/etc/systemd/system/evil.service") == "image-passwd\n"


@needs_symlinks
def test_dotdot_cannot_escape_root(make_fs):
    fs = make_fs({"/a/link": Symlink("../../../../../../etc/hostname"), "/etc/hostname": "img"})
    assert fs.resolve("/a/link") == "/etc/hostname"
    assert fs.read_text("/a/link") == "img"
    assert fs.resolve("/../../etc/hostname") == "/etc/hostname"


@needs_symlinks
def test_host_files_never_reachable(make_dir_fs):
    host_file = "/etc/hostname"
    fs = make_dir_fs({"/x": Symlink(host_file), "/y": Symlink("/" + "../" * 20 + "etc")})
    with pytest.raises(PathNotFoundError):
        fs.read_text("/x")
    assert not fs.exists("/y/hostname")


@needs_symlinks
def test_symlink_loop_bounded(make_fs):
    fs = make_fs({"/a": Symlink("b"), "/b": Symlink("a")})
    with pytest.raises(SymlinkLoopError):
        fs.resolve("/a")
    assert not fs.exists("/a")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_fifo_is_refused_without_blocking(make_dir_fs):
    fs = make_dir_fs({"/etc": Dir()})
    os.mkfifo(os.path.join(fs.root, "etc", "fifo.service"))
    with pytest.raises(RootFSError):
        fs.read_text("/etc/fifo.service")


def test_read_limit(make_fs):
    fs = make_fs({"/big": "x" * 2048})
    with pytest.raises(RootFSError):
        fs.read_bytes("/big", limit=1024)


@needs_symlinks
def test_usrmerge_ownership(make_fs):
    fs = make_fs(
        {
            "/bin": Symlink("usr/bin"),
            "/usr/bin/ip": File(b"elf", mode=0o755),
            "/usr/bin/ss": File(b"elf", mode=0o755),
        }
    )
    idx = FileOwnerIndex(fs)
    idx.add("pkg:deb/debian/iproute2", ["/bin/ip"])
    idx.add("pkg:deb/debian/other", ["/usr/bin/ipx"])
    assert idx.owners("/usr/bin/ip") == ["pkg:deb/debian/iproute2"]
    assert idx.owners("/bin/ip") == ["pkg:deb/debian/iproute2"]
    assert idx.owners("/usr/bin/ss") == []  # exact match only, no substrings


def test_whiteouts_and_opaque(make_tar_fs):
    fs = make_tar_fs(
        {"/etc/a": "1", "/etc/b": "2", "/opt/x/keep": "k"},
        {"/etc/a": Whiteout(), "/etc/c": "3"},
    )
    assert fs.listdir("/etc") == ["b", "c"]
    assert fs.read_text("/opt/x/keep") == "k"


def test_setuid_and_caps_preserved_in_tar(make_tar_fs):
    caps = bytes.fromhex("0000000200200000000000000000000000000000")
    fs = make_tar_fs(
        {
            "/usr/bin/passwd": File(b"", mode=0o4755),
            "/usr/bin/ping": File(b"", mode=0o755, xattrs={"security.capability": caps}),
        }
    )
    assert fs.stat("/usr/bin/passwd").is_setuid
    cap = fs.stat("/usr/bin/ping").capabilities
    assert cap is not None
    assert "net_raw" in cap.permitted
