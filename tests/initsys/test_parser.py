"""systemd unit syntax, Exec lines, names, specifiers and socket listen grammar."""

from __future__ import annotations

import pytest

from startup_sbom.initsys.systemd.parser import (
    SpecifierContext,
    expand_specifiers,
    parse_exec,
    parse_unit_name,
    parse_unit_text,
    split_words,
)
from startup_sbom.initsys.systemd.sockets import loopback_restricted, parse_listen


def test_lines_comments_continuation_bom() -> None:
    text = (
        "﻿[Unit]\nDescription=x\n; comment\n[Service]\n"
        "ExecStart=/bin/a \\\n# dropped\n  b\nX-Ignored=1\nEnvironment=A=1 # not a comment\n"
        "[X-Vendor]\nFoo=bar\nnoequals\n=novalue\n"
    )
    assert parse_unit_text(text) == [
        ("Unit", "Description", "x"),
        ("Service", "ExecStart", "/bin/a    b"),
        ("Service", "Environment", "A=1 # not a comment"),
    ]


def test_escaped_backslash_does_not_continue() -> None:
    assert parse_unit_text("[S]\nA=x\\\\\nB=y\n") == [("S", "A", "x\\\\"), ("S", "B", "y")]


def test_split_words_quoting_and_escapes() -> None:
    assert split_words(r"""a "b c" 'd e' f\sg \x41 "\"q\"" """) == [
        "a", "b c", "d e", "f g", "A", '"q"',
    ]  # fmt: skip


def test_exec_prefixes_and_separators() -> None:
    specs = parse_exec("-+/bin/a x ; @/bin/b fake y ; !!/bin/c")
    assert [(s.path, s.argv) for s in specs] == [
        ("/bin/a", ["/bin/a", "x"]),
        ("/bin/b", ["fake", "y"]),
        ("/bin/c", ["/bin/c"]),
    ]
    assert specs[0].ignore_failure
    assert specs[0].full_privileges
    assert specs[1].argv0_override
    assert specs[2].no_setuid
    shell = parse_exec("|echo $HOME && true")[0]
    assert shell.via_shell
    assert shell.argv == ["sh", "-c", "echo $HOME && true"]
    assert parse_exec("relative/path x")[0].errors


@pytest.mark.parametrize(
    ("name", "parts"),
    [
        ("getty@tty1.service", ("getty", "tty1", "service")),
        ("getty@.service", ("getty", "", "service")),
        ("a-b.socket", ("a-b", None, "socket")),
        (
            "systemd-fsck@dev-disk-by\\x2duuid-1.service",
            ("systemd-fsck", "dev-disk-by\\x2duuid-1", "service"),
        ),
    ],
)
def test_unit_names(name: str, parts: tuple[str, str | None, str]) -> None:
    un = parse_unit_name(name)
    assert un is not None
    assert (un.prefix, un.instance, un.type) == parts


@pytest.mark.parametrize(
    "bad", ["foo", "foo.wants", "a/b.service", "x" * 300 + ".service", ".service"]
)
def test_invalid_unit_names(bad: str) -> None:
    assert parse_unit_name(bad) is None


def test_specifiers() -> None:
    table = SpecifierContext(
        name="systemd-fsck@dev-disk-by\\x2duuid-1.service",
        fragment="/usr/lib/systemd/system/systemd-fsck@.service",
        hostname="box",
    ).table()
    assert expand_specifiers("%i|%I|%p|%N|%f|%H|%t|%%|%Z", table) == (
        "dev-disk-by\\x2duuid-1|dev/disk/by-uuid/1|systemd-fsck|"
        "systemd-fsck@dev-disk-by\\x2duuid-1|/dev/disk/by-uuid/1|box|/run|%|%Z"
    )
    assert SpecifierContext(name="getty@.service").table()["i"] == "<instance>"


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("ListenStream", "22", ("tcp", None, 22, None, "network")),
        ("ListenStream", "0.0.0.0:80", ("tcp", "0.0.0.0", 80, None, "network")),  # noqa: S104
        ("ListenStream", "[::]:443", ("tcp", "::", 443, None, "network")),
        ("ListenStream", "127.0.0.1:631", ("tcp", "127.0.0.1", 631, None, "loopback")),
        ("ListenStream", "[::1]:631", ("tcp", "::1", 631, None, "loopback")),
        ("ListenStream", "192.168.1.5:8080", ("tcp", "192.168.1.5", 8080, None, "network")),
        ("ListenStream", "[fe80::1]:22%eth0", ("tcp", "fe80::1", 22, None, "network")),
        ("ListenDatagram", "53", ("udp", None, 53, None, "network")),
        ("ListenStream", "/run/x.sock", ("unix", None, None, "/run/x.sock", "local")),
        ("ListenStream", "@abstract", ("unix", None, None, "@abstract", "local")),
        ("ListenSequentialPacket", "/run/seq", ("unix", None, None, "/run/seq", "local")),
        ("ListenNetlink", "kobject-uevent 1", ("netlink", "kobject-uevent 1", None, None, "local")),
        ("ListenFIFO", "/run/initctl", ("fifo", None, None, "/run/initctl", "local")),
        ("ListenStream", "vsock::22", ("vsock", "vsock:any", 22, None, "local")),
    ],
)
def test_listen_grammar(key: str, value: str, expected: tuple[object, ...]) -> None:
    la = parse_listen(key, value, source="x.socket")
    assert la is not None
    assert (la.protocol, la.address, la.port, la.path, la.scope) == expected


def test_listen_loopback_restriction() -> None:
    assert loopback_restricted(["any"], ["localhost"], None)
    assert loopback_restricted([], [], "lo")
    assert not loopback_restricted(["any"], ["10.0.0.0/8"], None)
    la = parse_listen("ListenStream", "8080", source="s", loopback_only=True)
    assert la is not None
    assert la.scope == "loopback"
    assert parse_listen("ListenStream", "  ", source="s") is None
