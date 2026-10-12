"""Command resolution, wrapper unwrapping and the shell-lite lexer."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from images import ELF, USRMERGE

from fsbuilder import File, Spec, Symlink
from startup_sbom.initsys.cmdline import (
    ShellEnv,
    execline_split,
    fs_glob,
    main_command,
    parse_shell,
    resolve_command,
    shell_function_body,
    strip_functions,
    unwrap_command,
)
from startup_sbom.rootfs import RootFS

MakeFS = Callable[[Spec], RootFS]

BIN: Spec = {
    **USRMERGE,
    "/usr/sbin/tini": ELF,  # invoked as /sbin/tini through the /sbin symlink
    "/usr/sbin/nginx": ELF,
    "/usr/sbin/gosu": ELF,
    "/usr/sbin/su-exec": ELF,
    "/usr/bin/env": ELF,
    "/usr/bin/nice": ELF,
    "/usr/bin/ionice": ELF,
    "/usr/bin/chpst": ELF,
    "/usr/bin/setpriv": ELF,
    "/usr/sbin/runuser": ELF,
    "/usr/bin/dumb-init": ELF,
    "/usr/bin/busybox": ELF,
    "/usr/bin/s6-setuidgid": ELF,
    "/opt/app/bin/server": ELF,
    "/usr/local/bin/docker-entrypoint.sh": File(
        '#!/bin/sh\nset -e\nif [ "$1" = "postgres" ]; then\n  chown x /data\n'
        '  exec gosu postgres "$@"\nfi\nexec "$@"\n',
        mode=0o755,
    ),
    "/usr/bin/escape": Symlink("/../../../../usr/sbin/nginx"),
}


@pytest.fixture
def fs(make_fs: MakeFS) -> RootFS:
    return make_fs(BIN)


def test_tini_sh_c_exec_nginx(fs: RootFS) -> None:
    exe, wrappers = resolve_command(
        fs, ["/sbin/tini", "--", "/bin/sh", "-c", "exec nginx -g 'daemon off;'"]
    )
    assert exe == "/usr/sbin/nginx"
    assert wrappers == ["/usr/sbin/tini", "/usr/bin/dash"]
    res = unwrap_command(fs, ["tini", "-s", "-g", "--", "sh", "-c", "exec nginx -g 'daemon off;'"])
    assert res.argv == ["nginx", "-g", "daemon off;"]


def test_sh_c_sequence_records_side_commands(fs: RootFS) -> None:
    res = unwrap_command(fs, ["sh", "-ec", "mkdir -p /run/x && FOO=1 exec /opt/app/bin/server --x"])
    assert res.executable == "/opt/app/bin/server"
    assert res.argv == ["/opt/app/bin/server", "--x"]
    assert res.side_executables == ["/usr/bin/mkdir"]


@pytest.mark.parametrize(
    ("argv", "exe", "user"),
    [
        (["gosu", "redis", "nginx"], "/usr/sbin/nginx", "redis"),
        (["su-exec", "app:app", "/opt/app/bin/server"], "/opt/app/bin/server", "app"),
        (["chpst", "-u", "www:www", "-e", "/etc/env", "nginx"], "/usr/sbin/nginx", "www"),
        (
            ["setpriv", "--reuid=1000", "--regid", "1000", "--no-new-privs", "--", "nginx"],
            "/usr/sbin/nginx",
            "1000",
        ),
        (["runuser", "-u", "svc", "--", "nginx", "-t"], "/usr/sbin/nginx", "svc"),
        (["runuser", "-l", "svc", "-c", "exec nginx"], "/usr/sbin/nginx", "svc"),
        (["s6-setuidgid", "abc", "nginx"], "/usr/sbin/nginx", "abc"),
        (["env", "-i", "PATH=/opt/app/bin", "server"], "/opt/app/bin/server", None),
        (["nice", "-n", "10", "ionice", "-c3", "nginx"], "/usr/sbin/nginx", None),
        (["dumb-init", "--single-child", "--", "nginx"], "/usr/sbin/nginx", None),
        (["exec", "-a", "fake", "nginx"], "/usr/sbin/nginx", None),
        (["busybox", "sh", "-c", "exec nginx"], "/usr/sbin/nginx", None),
    ],
)
def test_wrappers(fs: RootFS, argv: list[str], exe: str, user: str | None) -> None:
    res = unwrap_command(fs, argv)
    assert res.executable == exe
    assert res.user == user
    assert all(w.startswith("/") for w in res.wrappers)


def test_setpriv_no_new_privs(fs: RootFS) -> None:
    assert unwrap_command(fs, ["setpriv", "--no-new-privs", "nginx"]).no_new_privs


def test_entrypoint_script_exec_args_idiom(fs: RootFS) -> None:
    res = unwrap_command(fs, ["docker-entrypoint.sh", "nginx", "-g", "daemon off;"])
    assert res.executable == "/usr/sbin/nginx"
    assert res.wrappers == ["/usr/local/bin/docker-entrypoint.sh"]
    assert res.notes


def test_unresolvable_and_hostile(fs: RootFS) -> None:
    assert resolve_command(fs, ["/does/not/exist"]) == (None, [])
    assert resolve_command(fs, []) == (None, [])
    assert resolve_command(fs, ["$DAEMON", "x"]) == (None, [])
    # absolute symlink climbing out of the root stays inside it
    assert resolve_command(fs, ["/usr/bin/escape"])[0] == "/usr/sbin/nginx"
    res = unwrap_command(fs, [*(["nice"] * 40), "nginx"])  # wrapper chain beyond the budget
    assert res.executable is None
    assert res.notes


def test_bare_name_path_search(fs: RootFS) -> None:
    assert resolve_command(fs, ["nginx"])[0] == "/usr/sbin/nginx"
    assert resolve_command(fs, ["server"], path_env=["/opt/app/bin"])[0] == "/opt/app/bin/server"
    assert resolve_command(fs, ["server"])[0] is None


def test_parse_shell_assignments_and_expansion() -> None:
    env = ShellEnv()
    cmds = parse_shell(
        'NAME=nginx\nDAEMON=/usr/sbin/$NAME\n: ${OPTS:="-c /etc/x.conf"}\n'
        "export PIDFILE=/run/${NAME}.pid\nX=${MISSING:-dflt}\n"
        '$DAEMON $OPTS --pid "$PIDFILE" # comment\n',
        env,
    )
    assert env.vars["DAEMON"] == "/usr/sbin/nginx"
    assert env.vars["PIDFILE"] == "/run/nginx.pid"
    assert env.vars["X"] == "dflt"
    assert cmds[-1] == ["/usr/sbin/nginx", "-c", "/etc/x.conf", "--pid", "/run/nginx.pid"]


def test_parse_shell_structure() -> None:
    text = (
        'case "$1" in\n  start)\n    start-stop-daemon --start --exec /x 2>/dev/null\n    ;;\n'
        "esac\nif [ -x /y ]; then exec /y; fi\ncat <<EOF\nnot a command\nEOF\nlast\n"
        "f() {\n  inner\n}\n"
    )
    cmds = parse_shell(text)
    assert ["start-stop-daemon", "--start", "--exec", "/x"] in cmds
    assert ["exec", "/y"] in cmds
    assert ["not", "a", "command"] not in cmds
    assert ["last"] in cmds
    main, _ = main_command(cmds)
    assert main == ["exec", "/y"]
    assert parse_shell("a 'unterminated") == [["a", "unterminated"]]
    assert parse_shell('"$@"', ShellEnv(positional=["sh", "x", "y z"])) == [["x", "y z"]]


def test_shell_functions() -> None:
    text = "depend() {\n need net\n}\nstart() {\n if x; then { y; }; fi\n}\ncommand=/bin/z\n"
    assert shell_function_body(text, "depend") is not None
    assert "need net" in (shell_function_body(text, "depend") or "")
    assert "y;" in (shell_function_body(text, "start") or "")
    assert shell_function_body(text, "stop") is None
    assert strip_functions(text).strip() == "command=/bin/z"


def test_execline_split() -> None:
    assert execline_split('#!/command/execlineb -P\n# c\nwith-contenv\nfoo "a b" { x }\n') == [
        "with-contenv", "foo", "a b", "{", "x", "}",
    ]  # fmt: skip


def test_fs_glob(fs: RootFS) -> None:
    assert fs_glob(fs, "/usr/sbin/n*") == ["/usr/sbin/nginx"]
    assert fs_glob(fs, "bin/ng*", cwd="/usr/sbin/..") == []
    assert fs_glob(fs, "/nonexistent/*") == []
