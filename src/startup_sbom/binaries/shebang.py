"""``#!`` interpreter lines, parsed the way the Linux kernel does (``binfmt_script``).

Only the first 256 bytes (``BINPRM_BUF_SIZE``) are read.  After ``#!`` and
optional blanks comes the interpreter path, then at most one argument: the
rest of the line, passed as a single word.  ``/usr/bin/env`` indirection is
followed by resolving the program name through a ``PATH`` inside the root.
"""

from __future__ import annotations

import posixpath
from collections.abc import Sequence

from startup_sbom.errors import RootFSError
from startup_sbom.rootfs import RootFS, normalize

SHEBANG_READ = 256

#: systemd's default ``PATH`` plus the classic ``/sbin:/bin`` (SysV/OpenRC).
DEFAULT_PATH: tuple[str, ...] = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)


def parse_shebang(head: bytes) -> list[str] | None:
    """Split a ``#!`` line into ``[interpreter]`` or ``[interpreter, arg]``."""
    if not head.startswith(b"#!"):
        return None
    line = head[2:].split(b"\n", 1)[0].split(b"\x00", 1)[0].replace(b"\r", b"")
    text = line.decode("utf-8", "replace").strip(" \t")
    if not text:
        return None
    for i, ch in enumerate(text):
        if ch in " \t":
            interp, arg = text[:i], text[i:].strip(" \t")
            return [interp, arg] if arg else [interp]
    return [text]


def find_in_path(fs: RootFS, program: str, path_dirs: Sequence[str] = DEFAULT_PATH) -> str | None:
    """First executable regular file named ``program`` in ``path_dirs`` (lookup spelling)."""
    if not program or "\x00" in program:
        return None
    if "/" in program:
        cand = normalize(program if program.startswith("/") else "/" + program)
        st = fs.try_stat(cand)
        return cand if st is not None and st.is_file else None
    for d in path_dirs:
        if not d.startswith("/"):
            continue
        cand = posixpath.join(normalize(d), program)
        st = fs.try_stat(cand)
        if st is not None and st.is_file and st.mode & 0o111:
            return cand
    return None


def _env_program(words: list[str]) -> tuple[str | None, list[str]]:
    """Return ``(program, remaining args)`` from the argument words of ``env``."""
    i = 0
    while i < len(words):
        w = words[i]
        if w == "--":
            i += 1
            break
        if w in ("-u", "--unset", "-C", "--chdir"):
            i += 2
            continue
        if w.startswith("-") or ("=" in w and not w.startswith("/")):
            i += 1
            continue
        break
    if i >= len(words):
        return None, []
    return words[i], words[i + 1 :]


def is_env(interpreter: str) -> bool:
    """``True`` if ``interpreter`` is an ``env`` indirection."""
    return posixpath.basename(interpreter) == "env"


def read_shebang(
    fs: RootFS, path: str, *, path_dirs: Sequence[str] = DEFAULT_PATH
) -> list[str] | None:
    """Interpreter argv of the script at in-image ``path``, or ``None`` if not a script.

    Returns ``[interpreter]`` or ``[interpreter, arg]`` as the kernel would build
    it.  For ``env`` indirection (``#!/usr/bin/env [-S] python3 -u``) the result is
    ``[env, program, *args]`` with ``program`` replaced by its in-image path found
    through ``path_dirs`` when resolvable (left bare otherwise).
    """
    try:
        head = fs.read_head(path, SHEBANG_READ)
    except (RootFSError, OSError):
        return None
    argv = parse_shebang(head)
    if argv is None or not is_env(argv[0]) or len(argv) < 2:
        return argv
    program, rest = _env_program(argv[1].split())
    if program is None:
        return argv
    found = find_in_path(fs, program, path_dirs)
    return [argv[0], found or program, *rest]


def interpreter_chain(argv: Sequence[str]) -> list[str]:
    """Absolute executable paths an interpreter argv runs (``env`` adds its program)."""
    if not argv:
        return []
    out = [argv[0]] if argv[0].startswith("/") else []
    if is_env(argv[0]) and len(argv) > 1 and argv[1].startswith("/"):
        out.append(argv[1])
    return out
