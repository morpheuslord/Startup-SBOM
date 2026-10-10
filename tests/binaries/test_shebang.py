"""Kernel-compatible ``#!`` parsing and ``env`` resolution."""

from __future__ import annotations

import pytest
from elfbuilder import exe

from fsbuilder import File
from startup_sbom.binaries.shebang import interpreter_chain, parse_shebang, read_shebang


@pytest.mark.parametrize(
    ("head", "argv"),
    [
        (b"#!/bin/sh\necho", ["/bin/sh"]),
        (b"#! /bin/bash -e -u\n", ["/bin/bash", "-e -u"]),
        (b"#!\t/usr/bin/perl\t-w \r\n", ["/usr/bin/perl", "-w"]),
        (b"#!/usr/bin/env python3", ["/usr/bin/env", "python3"]),
        (b"#!\n", None),
        (b"#!   \n", None),
        (b"echo hi\n", None),
        (b"", None),
        (b"#!/bin/s\x00h\n", ["/bin/s"]),
    ],
)
def test_parse_shebang(head: bytes, argv: list[str] | None) -> None:
    assert parse_shebang(head) == argv


def test_only_first_256_bytes(make_fs) -> None:
    long = "#!/" + "a" * 300 + "\n"
    fs = make_fs({"/s": File(long, 0o755)})
    argv = read_shebang(fs, "/s")
    assert argv is not None
    assert len(argv[0]) == 254


def test_env_resolution(make_fs) -> None:
    fs = make_fs(
        {
            "/usr/bin/env": File(exe(), 0o755),
            "/usr/bin/python3": File(exe(), 0o755),
            "/usr/local/bin/node": File(exe(), 0o755),
            "/usr/sbin/notexec": File(exe(), 0o644),
            "/a": File("#!/usr/bin/env python3\n", 0o755),
            "/b": File("#!/usr/bin/env -S python3 -u -X dev\n", 0o755),
            "/c": File("#!/usr/bin/env -i FOO=bar -u BAZ node app.js\n", 0o755),
            "/d": File("#!/usr/bin/env missing\n", 0o755),
            "/e": File("#!/usr/bin/env\n", 0o755),
            "/f": File("#!/usr/bin/env notexec\n", 0o755),
            "/g": File("#!/usr/bin/env -- /usr/bin/python3\n", 0o755),
            "/h": "plain text",
        }
    )
    assert read_shebang(fs, "/a") == ["/usr/bin/env", "/usr/bin/python3"]
    assert read_shebang(fs, "/b") == ["/usr/bin/env", "/usr/bin/python3", "-u", "-X", "dev"]
    assert read_shebang(fs, "/c") == ["/usr/bin/env", "/usr/local/bin/node", "app.js"]
    assert read_shebang(fs, "/d") == ["/usr/bin/env", "missing"]
    assert read_shebang(fs, "/e") == ["/usr/bin/env"]
    assert read_shebang(fs, "/f") == ["/usr/bin/env", "notexec"]
    assert read_shebang(fs, "/g") == ["/usr/bin/env", "/usr/bin/python3"]
    assert read_shebang(fs, "/h") is None
    assert read_shebang(fs, "/missing") is None
    assert read_shebang(fs, "/usr/bin") is None
    assert read_shebang(fs, "/a", path_dirs=["/nowhere"]) == ["/usr/bin/env", "python3"]


def test_interpreter_chain() -> None:
    assert interpreter_chain(["/usr/bin/env", "/usr/bin/python3", "-u"]) == [
        "/usr/bin/env",
        "/usr/bin/python3",
    ]
    assert interpreter_chain(["/usr/bin/env", "python3"]) == ["/usr/bin/env"]
    assert interpreter_chain(["/bin/sh", "-e"]) == ["/bin/sh"]
    assert interpreter_chain(["sh"]) == []
    assert interpreter_chain([]) == []
