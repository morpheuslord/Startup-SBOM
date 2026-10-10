"""Command-line resolution shared by every init-system analyzer.

Turns a configured argv into the program that actually runs: ``argv[0]`` is
resolved to a canonical in-image path (absolute paths through
:meth:`RootFS.resolve`, bare names through a PATH search *inside* the root) and
well-known wrappers (tini, dumb-init, gosu, su-exec, s6-setuidgid, chpst,
setpriv, runuser, env, nice, ``sh -c "..."``, execline chain-loaders, ...) are
peeled off until the real target is reached.

Also provides a small, non-executing POSIX shell lexer used to read init
scripts, run scripts and ``sh -c`` strings.  Nothing is ever executed; all
reads are bounded and every path is an in-image POSIX path.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass, field

from startup_sbom.errors import RootFSError
from startup_sbom.rootfs import RootFS

#: Docker/runc default PATH and a safe superset of systemd's built-in search path.
DEFAULT_PATH: tuple[str, ...] = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)
MAX_UNWRAP = 24
SCRIPT_LIMIT = 512 * 1024
MAX_COMMANDS = 20_000

SHELLS = frozenset({"sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "posh", "yash", "lksh"})
SHELL_BUILTINS = frozenset(
    {
        ":", ".", "[", "[[", "alias", "break", "case", "cd", "command", "continue",
        "declare", "echo", "elif", "else", "esac", "eval", "exit", "export", "false",
        "fi", "for", "getopts", "hash", "local", "printf", "read", "readonly",
        "return", "set", "shift", "source", "test", "then", "trap", "true", "type",
        "typeset", "ulimit", "umask", "unset", "wait", "let", "done", "do", "in",
        "while", "until", "function", "select", "shopt",
    }
)  # fmt: skip
_RESERVED_LEADERS = frozenset(
    {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "time"}
)
_RESERVED_ALONE = frozenset({"fi", "done", "esac", "}", "then", "else", "do", "{"})
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")
_EXEC_ARGS_RE = re.compile(
    r"""^\s*exec\s+(?:(?P<w>gosu|su-exec|s6-setuidgid|chpst\s+-u)\s+(?P<u>\S+)\s+)?"?\$(?:@|\{@\})"?\s*$""",
    re.MULTILINE,
)

# Launcher kinds (a program that starts a service manager).
SYSTEMD = "systemd"
SYSVINIT = "sysvinit"
BUSYBOX = "busybox"
OPENRC = "openrc"
RUNIT = "runit"
S6 = "s6"
SUPERVISORD = "supervisord"
SYSV_RC = "sysv-rc"

_RC_SCRIPTS = frozenset(
    {
        "/etc/init.d/rc", "/etc/init.d/rcS", "/etc/rc.d/rc", "/etc/rc.d/rcS",
        "/etc/rc.d/rc.sysinit", "/etc/rc", "/etc/rcS", "/etc/rc.d/init.d/rc",
    }
)  # fmt: skip


# --------------------------------------------------------------------------- PATH
def split_path_env(value: str) -> list[str]:
    """Split a ``PATH`` value, keeping only absolute entries (relative ones are ignored)."""
    out: list[str] = []
    for part in value.split(":"):
        if part.startswith("/") and part not in out:
            out.append(posixpath.normpath(part))
    return out


def which(fs: RootFS, name: str, path_env: list[str] | tuple[str, ...] | None = None) -> str | None:
    """Search ``name`` in in-image PATH directories; return the canonical path of the first hit."""
    if not name or "/" in name or name in (".", "..") or "\x00" in name:
        return None
    for d in path_env if path_env is not None else DEFAULT_PATH:
        if not d.startswith("/"):
            continue
        cand = posixpath.join(d, name)
        st = fs.try_stat(cand)
        if st is not None and st.is_file:
            return fs.try_resolve(cand)
    return None


def resolve_executable(
    fs: RootFS,
    word: str,
    path_env: list[str] | tuple[str, ...] | None = None,
    *,
    cwd: str = "/",
    root: str = "/",
) -> str | None:
    """Resolve one command word to a canonical in-image regular file (``None`` if absent)."""
    if not word or "\x00" in word or "$" in word or "`" in word:
        return None
    if word.startswith("/"):
        cand = word
    elif "/" in word:
        cand = posixpath.join(cwd if cwd.startswith("/") else "/", word)
    else:
        dirs = path_env if path_env is not None else DEFAULT_PATH
        if root != "/":
            dirs = [posixpath.join(root, d.lstrip("/")) for d in dirs]
        return which(fs, word, dirs)
    if root != "/":
        cand = posixpath.join(root, cand.lstrip("/"))
    st = fs.try_stat(cand)
    if st is not None and st.is_file:
        return fs.try_resolve(cand)
    return None


def read_script(fs: RootFS, path: str, limit: int = SCRIPT_LIMIT) -> str | None:
    """Return the text of a small file (``None`` if missing, special, or larger than ``limit``)."""
    return fs.try_read_text(path, limit)


def shebang(fs: RootFS, path: str) -> list[str] | None:
    """Return the shebang words of a script (``["/bin/sh", "-e"]``) or ``None``."""
    try:
        head = fs.read_head(path, 256)
    except (RootFSError, OSError):
        return None
    if not head.startswith(b"#!"):
        return None
    line = head[2:].split(b"\n", 1)[0].decode("utf-8", "replace").strip()
    return line.split() or None


# --------------------------------------------------------------------------- shell lexer
_Part = tuple[str, int]  # (text, mode) mode: 0 unquoted, 1 literal, 2 double-quoted


class _Lexer:
    """Tokenizes POSIX shell text into simple commands (words as quote-annotated parts)."""

    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0
        self.n = len(text)

    def _balanced(self, start: int, open_c: str, close_c: str) -> int:
        depth = 0
        j = start
        while j < self.n:
            c = self.s[j]
            if c == "\\":
                j += 2
                continue
            if c == open_c:
                depth += 1
            elif c == close_c:
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return self.n

    def _read_word(self) -> list[_Part]:
        """Read one word starting at a non-blank character (no operators)."""
        parts: list[_Part] = []
        buf: list[str] = []

        def flush(mode: int) -> None:
            if buf:
                parts.append(("".join(buf), mode))
                buf.clear()

        s = self.s
        while self.i < self.n:
            c = s[self.i]
            if c in " \t\r\n;&|()<>":
                break
            if c == "\\":
                if self.i + 1 < self.n and s[self.i + 1] == "\n":
                    self.i += 2
                    continue
                flush(0)
                if self.i + 1 < self.n:
                    parts.append((s[self.i + 1], 1))
                self.i += 2
                continue
            if c == "'":
                flush(0)
                end = s.find("'", self.i + 1)
                end = self.n if end < 0 else end
                parts.append((s[self.i + 1 : end], 1))
                self.i = end + 1
                continue
            if c == '"':
                flush(0)
                self.i += 1
                dq: list[str] = []
                while self.i < self.n and s[self.i] != '"':
                    ch = s[self.i]
                    if ch == "\\" and self.i + 1 < self.n:
                        nxt = s[self.i + 1]
                        if nxt in '$`"\\':
                            if dq:
                                parts.append(("".join(dq), 2))
                                dq.clear()
                            parts.append((nxt, 1))
                            self.i += 2
                            continue
                        if nxt == "\n":
                            self.i += 2
                            continue
                    if ch == "$" and self.i + 1 < self.n and s[self.i + 1] in "({":
                        end = self._balanced(
                            self.i + 1, s[self.i + 1], ")" if s[self.i + 1] == "(" else "}"
                        )
                        dq.append(s[self.i : end])
                        self.i = end
                        continue
                    dq.append(ch)
                    self.i += 1
                parts.append(("".join(dq), 2))
                self.i += 1
                continue
            if c == "$" and self.i + 1 < self.n and s[self.i + 1] in "({":
                end = self._balanced(
                    self.i + 1, s[self.i + 1], ")" if s[self.i + 1] == "(" else "}"
                )
                buf.append(s[self.i : end])
                self.i = end
                continue
            if c == "`":
                end = s.find("`", self.i + 1)
                end = self.n if end < 0 else end + 1
                buf.append(s[self.i : end])
                self.i = end
                continue
            buf.append(c)
            self.i += 1
        flush(0)
        return parts

    def commands(self) -> list[list[list[_Part]]]:
        """Return simple commands; each is a list of words, each word a list of parts."""
        out: list[list[list[_Part]]] = []
        cur: list[list[_Part]] = []
        heredocs: list[tuple[str, bool]] = []
        depth = 0
        s = self.s
        while self.i < self.n and len(out) < MAX_COMMANDS:
            c = s[self.i]
            if c in " \t\r":
                self.i += 1
                continue
            if c == "\\" and self.i + 1 < self.n and s[self.i + 1] == "\n":
                self.i += 2
                continue
            if c == "#":
                nl = s.find("\n", self.i)
                self.i = self.n if nl < 0 else nl
                continue
            if c == "\n":
                if cur:
                    out.append(cur)
                    cur = []
                pos = self.i + 1
                for delim, strip in heredocs:
                    pos = self._skip_heredoc(pos, delim, strip)
                heredocs.clear()
                self.i = pos
                continue
            if c in "<>" or (c == "&" and s[self.i + 1 : self.i + 2] == ">"):
                if cur and len(cur[-1]) == 1 and cur[-1][0][1] == 0 and cur[-1][0][0].isdigit():
                    cur.pop()  # fd number of the redirection
                op_m = re.match(r"&>>|&>|<<-|<<|>>|>&|<&|>\||<>|>|<", s[self.i :])
                op = op_m.group(0) if op_m else c
                self.i += len(op)
                while self.i < self.n and s[self.i] in " \t":
                    self.i += 1
                target = self._read_word() if self.i < self.n and s[self.i] not in "\n;&|()" else []
                if op in ("<<", "<<-"):
                    heredocs.append(("".join(t for t, _ in target), op == "<<-"))
                continue
            if c in ";&|()":
                two = s[self.i : self.i + 2]
                op = two if two in (";;", "&&", "||", ";&") else c
                self.i += len(op)
                if op == "(":
                    rest = s[self.i :].lstrip(" \t")
                    if cur and rest.startswith(")"):  # function definition: name ()
                        cur = []
                        self.i = self.n - len(rest) + 1
                        continue
                    depth += 1
                elif op == ")":
                    if depth == 0:  # case pattern
                        cur = []
                        continue
                    depth -= 1
                if cur:
                    out.append(cur)
                    cur = []
                continue
            word = self._read_word()
            if word:
                cur.append(word)
            elif self.i < self.n and self.s[self.i] not in " \t\r\n;&|()<>":
                self.i += 1  # safety: never stall
        if cur:
            out.append(cur)
        return out

    def _skip_heredoc(self, pos: int, delim: str, strip_tabs: bool) -> int:
        """Skip a here-document body starting at ``pos``; return the position after it."""
        while pos < self.n:
            end = self.s.find("\n", pos)
            end = self.n if end < 0 else end
            line = self.s[pos:end]
            if (line.lstrip("\t") if strip_tabs else line) == delim:
                return end + 1
            pos = end + 1
        return self.n


_VAR_RE = re.compile(
    r"\$(?:\{(?P<brace>[^}]*)\}|(?P<name>[A-Za-z_][A-Za-z0-9_]*)|(?P<special>[@*#?$!0-9-]))"
)


def _strip_pattern(value: str, op: str, pattern: str) -> str:
    if op in ("#", "##"):
        rng = range(len(value) + 1) if op == "#" else range(len(value), -1, -1)
        for k in rng:
            if fnmatch.fnmatchcase(value[:k], pattern):
                return value[k:]
        return value
    rng = range(len(value), -1, -1) if op == "%" else range(len(value) + 1)
    for k in rng:
        if fnmatch.fnmatchcase(value[k:], pattern):
            return value[:k]
    return value


class ShellEnv:
    """Variables and positional parameters used for best-effort parameter expansion."""

    def __init__(
        self,
        variables: MutableMapping[str, str] | None = None,
        positional: list[str] | None = None,
    ) -> None:
        self.vars: MutableMapping[str, str] = variables if variables is not None else {}
        self.positional = positional

    def lookup(self, name: str) -> str | None:
        if name.isdigit():
            if self.positional is None:
                return None
            idx = int(name)
            return self.positional[idx] if idx < len(self.positional) else ""
        return self.vars.get(name)

    def expand_text(self, text: str) -> tuple[list[str], bool]:
        """Expand ``$VAR`` forms in ``text``; returns pieces and whether ``$@`` was spliced."""
        out: list[str] = []
        pos = 0
        spliced = False
        while True:
            dollar = text.find("$", pos)
            if dollar < 0:
                out.append(text[pos:])
                break
            if text.startswith("$(", dollar):
                depth = 0
                j = dollar + 1
                while j < len(text):
                    if text[j] == "(":
                        depth += 1
                    elif text[j] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                out.append(text[pos : j + 1])
                pos = j + 1
                continue
            m = _VAR_RE.match(text, dollar)
            if not m:
                out.append(text[pos : dollar + 1])
                pos = dollar + 1
                continue
            out.append(text[pos:dollar])
            pos = m.end()
            if m.group("special") in ("@", "*") or m.group("brace") in ("@", "*"):
                if self.positional is None:
                    out.append(m.group(0))
                else:
                    out.append("\x00@")
                    spliced = True
                continue
            if m.group("special") is not None:
                val = self.lookup(m.group("special")) if m.group("special").isdigit() else None
                out.append(val if val is not None else m.group(0))
                continue
            if m.group("name") is not None:
                val = self.lookup(m.group("name"))
                out.append(val if val is not None else m.group(0))
                continue
            out.append(self._brace(m.group("brace") or "", m.group(0)))
        return out, spliced

    def _brace(self, body: str, literal: str) -> str:
        m = re.match(r"^(#?)([A-Za-z_][A-Za-z0-9_]*|\d+)(.*)$", body, re.DOTALL)
        if not m:
            return literal
        length, name, rest = m.groups()
        val = self.lookup(name)
        if length:
            return str(len(val)) if val is not None else literal
        if not rest:
            return val if val is not None else literal
        op_m = re.match(r"^(:?[-=+?]|##|#|%%|%)(.*)$", rest, re.DOTALL)
        if not op_m:
            return val if val is not None else literal
        op, word = op_m.groups()
        if len(word) >= 2 and word[0] == word[-1] and word[0] in "'\"":
            word = word[1:-1]
        word = "".join(self.expand_text(word)[0]).replace("\x00@", "")
        unset_or_empty = val is None or (op.startswith(":") and val == "")
        if op in (":-", "-"):
            return word if unset_or_empty else (val or "")
        if op in (":=", "="):
            if unset_or_empty:
                self.vars[name] = word
                return word
            return val or ""
        if op in (":+", "+"):
            return "" if unset_or_empty else word
        if op in (":?", "?"):
            return val if val is not None else literal
        if val is None:
            return literal
        return _strip_pattern(val, op, word)

    def expand_word(self, parts: list[_Part], *, split: bool = True) -> list[str]:
        """Expand one lexed word into zero or more fields."""
        fields: list[str] = [""]
        quoted = False
        for text, mode in parts:
            if mode == 1:
                fields[-1] += text
                quoted = True
                continue
            if mode == 2:
                quoted = True
            pieces, spliced = self.expand_text(text)
            for piece in pieces:
                if piece == "\x00@" and spliced and self.positional is not None:
                    args = self.positional[1:]
                    if mode == 2:
                        if args:
                            fields[-1] += args[0]
                            fields.extend(args[1:])
                    else:
                        for a in args:
                            fields.extend(a.split())
                    continue
                if mode == 0 and split and piece and any(ch.isspace() for ch in piece):
                    words = piece.split()
                    if words:
                        if piece[0].isspace() and fields[-1]:
                            fields.append("")
                        fields[-1] += words[0]
                        fields.extend(words[1:])
                        if piece[-1].isspace():
                            fields.append("")
                    continue
                fields[-1] += piece
        if not quoted:
            fields = [f for f in fields if f != ""]
        elif fields and fields[-1] == "" and len(fields) > 1:
            fields.pop()
        return fields


def parse_shell(
    text: str,
    env: ShellEnv | None = None,
    *,
    on_assign: Callable[[str, str], None] | None = None,
) -> list[list[str]]:
    """Lex and expand shell ``text`` into simple commands (argv lists).

    Assignment-only commands (``A=b``, ``export A=b``, ``local A=b``) update
    ``env`` in order and are not returned; prefix assignments (``A=b cmd``) are
    stripped.  Reserved words, case patterns and function headers are dropped.
    Unknown variables are kept literally so callers can see them.
    """
    env = env if env is not None else ShellEnv()
    result: list[list[str]] = []
    for words in _Lexer(text).commands():
        # strip leading reserved words
        while (
            words
            and len(words[0]) == 1
            and words[0][0][1] == 0
            and words[0][0][0] in _RESERVED_LEADERS
        ):
            words = words[1:]  # noqa: PLW2901 - strip reserved leaders
        if not words:
            continue
        first_raw = words[0][0][0] if words[0] else ""
        if len(words) == 1 and words[0][0][1] == 0 and first_raw in _RESERVED_ALONE:
            continue
        if first_raw == "case" and words[0][0][1] == 0:
            continue
        lead = first_raw if words[0][0][1] == 0 else ""
        assign_only = True
        argv: list[str] = []
        idx = 0
        if lead in ("export", "local", "readonly", "declare", "typeset") and len(words[0]) == 1:
            idx = 1
            for w in words[1:]:
                head = w[0][0] if w[0][1] == 0 else ""
                m = _ASSIGN_RE.match(head)
                if m:
                    value = "".join(env.expand_word([(head[m.end() :], 0), *w[1:]], split=False))
                    env.vars[m.group(1)] = value
                    if on_assign:
                        on_assign(m.group(1), value)
            continue
        for w in words[idx:]:
            head = w[0][0] if w[0][1] == 0 else ""
            m = _ASSIGN_RE.match(head) if not argv else None
            if m:
                value = "".join(env.expand_word([(head[m.end() :], 0), *w[1:]], split=False))
                if assign_only:
                    env.vars[m.group(1)] = value
                    if on_assign:
                        on_assign(m.group(1), value)
                continue
            assign_only = False
            argv.extend(env.expand_word(w))
        if argv:
            result.append(argv)
    return result


def shell_function_body(text: str, name: str) -> str | None:
    """Return the body of shell function ``name`` (``name() { ... }``) or ``None``."""
    m = re.search(
        rf"^[ \t]*(?:function[ \t]+)?{re.escape(name)}[ \t]*\([ \t]*\)[ \t]*\{{",
        text,
        re.MULTILINE,
    )
    if not m:
        m = re.search(rf"^[ \t]*function[ \t]+{re.escape(name)}[ \t]*\{{", text, re.MULTILINE)
        if not m:
            return None
    depth = 1
    j = m.end()
    quote = ""
    while j < len(text):
        c = text[j]
        if quote:
            if c == quote:
                quote = ""
            elif c == "\\" and quote == '"':
                j += 1
        elif c in "'\"":
            quote = c
        elif c == "\\":
            j += 1
        elif c == "#" and (j == 0 or text[j - 1] in " \t\n"):
            nl = text.find("\n", j)
            j = len(text) if nl < 0 else nl
            continue
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[m.end() : j]
        j += 1
    return text[m.end() :]


def strip_functions(text: str) -> str:
    """Remove shell function definitions, leaving only top-level statements."""
    out: list[str] = []
    pos = 0
    pattern = re.compile(
        r"^[ \t]*(?:function[ \t]+)?([A-Za-z_][A-Za-z0-9_.:-]*)[ \t]*(?:\([ \t]*\))[ \t]*\{",
        re.MULTILINE,
    )
    while True:
        m = pattern.search(text, pos)
        if not m:
            out.append(text[pos:])
            break
        out.append(text[pos : m.start()])
        body = shell_function_body(text[m.start() :], m.group(1))
        if body is None:
            pos = m.end()
            continue
        pos = m.end() + len(body) + 1
    return "".join(out)


def main_command(commands: list[list[str]]) -> tuple[list[str] | None, list[list[str]]]:
    """Pick the main process of a command sequence: the last ``exec CMD``, else the last command.

    Returns ``(main, others)``; ``others`` excludes shell builtins.
    """
    main_idx: int | None = None
    for i, cmd in enumerate(commands):
        if cmd[0] == "exec" and _exec_has_command(cmd):
            main_idx = i
    if main_idx is None:
        for i in range(len(commands) - 1, -1, -1):
            if commands[i][0] not in SHELL_BUILTINS:
                main_idx = i
                break
    others = [c for i, c in enumerate(commands) if i != main_idx and c[0] not in SHELL_BUILTINS]
    return (commands[main_idx] if main_idx is not None else None), others


def _exec_has_command(cmd: list[str]) -> bool:
    i = 1
    while i < len(cmd) and cmd[i].startswith("-"):
        i += 2 if cmd[i] == "-a" else 1
    return i < len(cmd)


# --------------------------------------------------------------------------- execline
def execline_split(text: str) -> list[str]:
    """Tokenize an execline script (``#!/command/execlineb -P``) into words; braces kept."""
    words: list[str] = []
    i = 0
    n = len(text)
    if text.startswith("#!"):
        nl = text.find("\n")
        i = n if nl < 0 else nl + 1
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c == "#":
            nl = text.find("\n", i)
            i = n if nl < 0 else nl + 1
            continue
        buf: list[str] = []
        while i < n and not text[i].isspace():
            ch = text[i]
            if ch == '"':
                i += 1
                while i < n and text[i] != '"':
                    if text[i] == "\\" and i + 1 < n:
                        esc = text[i + 1]
                        buf.append({"n": "\n", "t": "\t"}.get(esc, esc))
                        i += 2
                        continue
                    buf.append(text[i])
                    i += 1
                i += 1
                continue
            buf.append(ch)
            i += 1
        words.append("".join(buf))
    return words


# --------------------------------------------------------------------------- wrappers
@dataclass(frozen=True, slots=True)
class _Spec:
    with_arg: frozenset[str] = frozenset()
    positional: int = 0  # positional words consumed before the child
    user_pos: bool = False  # first positional is USER[:GROUP]
    block: bool = False  # takes one { ... } block before the child (execline)
    child: bool = True  # False: wrapper never has a child command


def _spec(*args: str, **kw: object) -> _Spec:
    return _Spec(with_arg=frozenset(args), **kw)  # type: ignore[arg-type]


_WRAPPERS: dict[str, _Spec] = {
    "tini": _spec("-p", "-e"),
    "docker-init": _spec("-p", "-e"),
    "dumb-init": _spec("-r", "--rewrite"),
    "catatonit": _spec(),
    "gosu": _spec(user_pos=True, positional=1),
    "su-exec": _spec(user_pos=True, positional=1),
    "s6-setuidgid": _spec(user_pos=True, positional=1),
    "s6-envuidgid": _spec("-D", user_pos=True, positional=1),
    "setuidgid": _spec(user_pos=True, positional=1),
    "envuidgid": _spec(user_pos=True, positional=1),
    "s6-applyuidgid": _spec("-u", "-g", "-G"),
    "chpst": _spec("-u", "-U", "-b", "-e", "-/", "-C", "-n", "-l", "-L", "-m", "-d", "-o",
                   "-p", "-f", "-c"),
    "setpriv": _spec(
        "--reuid", "--regid", "--groups", "--inh-caps", "--ambient-caps", "--bounding-set",
        "--securebits", "--pdeathsig", "--selinux-label", "--apparmor-profile",
        "--landlock-access", "--landlock-rule", "--ptracer", "--seccomp-filter",
    ),
    "runuser": _spec("-u", "--user", "-g", "--group", "-G", "--supp-group", "-c", "--command",
                     "-s", "--shell", "-w", "--whitelist-environment"),
    "su": _spec("-c", "--command", "-s", "--shell", "-g", "--group", "-G", "--supp-group",
                "-w", "--whitelist-environment"),
    "sudo": _spec("-u", "--user", "-g", "--group", "-C", "--close-from", "-D", "--chdir",
                  "-h", "--host", "-p", "--prompt", "-r", "--role", "-t", "--type", "-U",
                  "--other-user", "-T", "--command-timeout"),
    "env": _spec("-u", "--unset", "-C", "--chdir", "-S", "--split-string", "-P"),
    "nice": _spec("-n", "--adjustment"),
    "ionice": _spec("-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid",
                    "-u", "--uid"),
    "taskset": _spec(positional=1),
    "chrt": _spec(positional=1),
    "stdbuf": _spec("-i", "-o", "-e", "--input", "--output", "--error"),
    "nohup": _spec(),
    "setsid": _spec(),
    "timeout": _spec("-s", "--signal", "-k", "--kill-after", positional=1),
    "exec": _spec("-a"),
    "chroot": _spec("--userspec", "--groups", positional=1),
    "numactl": _spec("-i", "--interleave", "-N", "--cpunodebind", "-m", "--membind",
                     "-C", "--physcpubind", "-p", "--preferred"),
    "unshare": _spec("--propagation", "--setgroups", "--map-user", "--map-group", "-S",
                     "--setuid", "-G", "--setgid", "--root", "-R", "--wd", "-w"),
    "with-contenv": _spec(),
    "s6-envdir": _spec("-c"),
    "s6-notifyoncheck": _spec("-3", "-s", "-T", "-t", "-w", "-n", "-c"),
    "s6-setsid": _spec(),
    "fdmove": _spec(positional=2),
    "s6-fdmove": _spec(positional=2),
    "envdir": _spec(positional=1),
    "softlimit": _spec("-m", "-d", "-o", "-p", "-f", "-c", "-r", "-t", "-l", "-a", "-s"),
    "pgrphack": _spec(),
    "xvfb-run": _spec("-n", "--server-num", "-e", "--error-file", "-f", "--auth-file",
                      "-p", "--xauth-protocol", "-s", "--server-args"),
}  # fmt: skip
_WRAPPERS["s6-envdir"] = _Spec(with_arg=frozenset({"-c"}), positional=1)
_EXECLINE: dict[str, _Spec] = {
    "redirfd": _spec(positional=2),
    "cd": _spec(positional=1),
    "export": _spec(positional=2),
    "unexport": _spec(positional=1),
    "importas": _spec("-D", "-d", positional=2),
    "define": _spec("-d", positional=2),
    "umask": _spec(positional=1),
    "emptyenv": _spec(),
    "fdclose": _spec(positional=1),
    "fdswap": _spec(positional=2),
    "fdreserve": _spec(positional=1),
    "foreground": _spec(block=True),
    "background": _spec(block=True),
    "if": _spec(block=True),
    "backtick": _spec("-D", positional=1, block=True),
    "multisubstitute": _spec(block=True),
    "trap": _spec(block=True),
    "piperw": _spec(positional=2),
    "withstdinas": _spec("-D", positional=1),
    "elgetpositionals": _spec(),
    "elglob": _spec(positional=2),
    "s6-envuidgid": _spec("-D", user_pos=True, positional=1),
    "execline-cd": _spec(positional=1),
    "execline-umask": _spec(positional=1),
    "getpid": _spec(positional=1),
    "heredoc": _spec(positional=2),
}


def _wrapper_key(name: str) -> str | None:
    if name in _WRAPPERS:
        return name
    if name.startswith("tini"):
        return "tini"
    return None


def _parse_opts(args: list[str], with_arg: frozenset[str]) -> tuple[list[tuple[str, str]], int]:
    """Generic getopt-ish scan; returns (options, index of first non-option)."""
    opts: list[tuple[str, str]] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return opts, i + 1
        if not a.startswith("-") or a == "-":
            break
        if a.startswith("--"):
            key, eq, val = a.partition("=")
            if not eq and key in with_arg:
                val = args[i + 1] if i + 1 < len(args) else ""
                i += 2
            else:
                i += 1
            opts.append((key, val))
            continue
        if re.fullmatch(r"-\d+", a):  # nice -10
            opts.append((a, ""))
            i += 1
            continue
        consumed = 1
        for j in range(1, len(a)):
            o = "-" + a[j]
            if o in with_arg:
                if a[j + 1 :]:
                    opts.append((o, a[j + 1 :]))
                else:
                    opts.append((o, args[i + 1] if i + 1 < len(args) else ""))
                    consumed = 2
                break
            opts.append((o, ""))
        i += consumed
    return opts, i


def _split_user(spec: str) -> tuple[str, str | None]:
    user, _, group = spec.partition(":")
    return user, (group or None)


@dataclass(slots=True)
class Resolution:
    """Result of resolving and unwrapping one command line."""

    executable: str | None
    argv: list[str]
    wrappers: list[str] = field(default_factory=list)
    user: str | None = None
    group: str | None = None
    no_new_privs: bool = False
    chroot: str | None = None
    side_commands: list[list[str]] = field(default_factory=list)
    side_executables: list[str] = field(default_factory=list)
    launcher: str | None = None
    notes: list[str] = field(default_factory=list)


def _is_s6_overlay(fs: RootFS) -> bool:
    return (
        fs.is_dir("/etc/s6-overlay")
        or fs.is_dir("/package/admin/s6-overlay")
        or fs.lexists("/command/s6-svscan")
    )


def detect_launcher(fs: RootFS, executable: str | None, invoked: str | None = None) -> str | None:
    """Classify a resolved executable as a service-manager launcher (``None`` if it is not one)."""
    if executable is None:
        return None
    base = posixpath.basename(executable)
    inv = posixpath.basename(invoked or "")
    if executable in _RC_SCRIPTS or (invoked or "") in _RC_SCRIPTS:
        return SYSV_RC
    if base == "systemd" or executable.endswith("/systemd/systemd"):
        return SYSTEMD
    if base == "supervisord":
        return SUPERVISORD
    if base in ("runsvdir", "runsvdir-start", "my_init", "runit", "runit-init"):
        return RUNIT
    if base in ("s6-svscan", "s6-linux-init", "s6-overlay-suexec") or (
        executable == "/init" and _is_s6_overlay(fs)
    ):
        return S6
    if base in ("openrc-init", "openrc"):
        return OPENRC
    if base == "busybox" and inv in ("init", "linuxrc"):
        return BUSYBOX
    sysv_names = ("init", "sysvinit", "upstart")
    if base in sysv_names and inv in (*sysv_names, "") and fs.is_file("/etc/inittab"):
        return SYSVINIT
    return None


def unwrap_command(
    fs: RootFS,
    argv: list[str],
    *,
    path_env: list[str] | tuple[str, ...] | None = None,
    cwd: str = "/",
    follow_scripts: bool = True,
    execline: bool = False,
) -> Resolution:
    """Resolve ``argv`` to the real program, peeling wrappers; see module docstring."""
    path = list(path_env) if path_env is not None else list(DEFAULT_PATH)
    res = Resolution(executable=None, argv=list(argv))
    args = list(argv)
    root = "/"
    prev_busybox: str | None = None
    for _ in range(MAX_UNWRAP):
        while args and args[0] == "":
            args = args[1:]
        if not args:
            res.executable = None
            res.argv = []
            return res
        word = args[0]
        exe = resolve_executable(fs, word, path, cwd=cwd, root=root)
        inv = posixpath.basename(word)
        rbase = posixpath.basename(exe) if exe else ""
        if exe is None and prev_busybox is not None and "/" not in word:
            # busybox applet without its own symlink: busybox itself runs
            res.executable = prev_busybox
            res.wrappers.pop()
            res.argv = args
            return res
        prev_busybox = None
        key = None
        for nm in (inv, rbase):
            key = _wrapper_key(nm) or (nm if execline and nm in _EXECLINE else None)
            if key:
                break
        if key is None and (inv in SHELLS or (rbase in SHELLS and inv not in ("busybox",))):
            nxt = _unwrap_shell(fs, args, res, path)
            if nxt is None:
                res.executable, res.argv = exe, args
                break
            if exe:
                res.wrappers.append(exe)
            args = nxt
            continue
        if (key is None and inv == "busybox") or (
            key is None and rbase == "busybox" and inv == "busybox"
        ):
            if len(args) > 1 and not args[1].startswith("-"):
                if exe:
                    res.wrappers.append(exe)
                    prev_busybox = exe
                args = args[1:]
                continue
            res.executable, res.argv = exe, args
            break
        if key is None:
            if exe == "/init" and len(args) > 1 and _is_s6_overlay(fs):
                res.wrappers.append(exe)
                res.launcher = S6
                args = args[1:]
                continue
            if follow_scripts and exe and len(args) > 1:
                nxt = _unwrap_entry_script(fs, exe, args, res)
                if nxt is not None:
                    res.wrappers.append(exe)
                    args = nxt
                    continue
            res.executable, res.argv = exe, args
            break
        spec = _WRAPPERS.get(key) or _EXECLINE[key]
        child = _unwrap_wrapper(key, spec, args[1:], res, path)
        if child is None:
            res.executable, res.argv = exe, args
            break
        if exe:
            res.wrappers.append(exe)
        if key == "chroot" and res.chroot:
            root = res.chroot
        if key == "env":
            for a in args[1:]:
                m = re.match(r"^PATH=(.*)$", a)
                if m:
                    path = split_path_env(m.group(1)) or path
        args = child
    else:
        res.notes.append("wrapper unwrapping depth limit reached")
        res.executable = None
        res.argv = args
    for side in res.side_commands:
        side_exe = resolve_executable(fs, side[0], path, cwd=cwd) if side else None
        if side_exe and side_exe not in res.side_executables:
            res.side_executables.append(side_exe)
    if res.launcher is None:
        res.launcher = detect_launcher(fs, res.executable, res.argv[0] if res.argv else None)
    return res


def _unwrap_wrapper(
    key: str, spec: _Spec, rest: list[str], res: Resolution, path: list[str]
) -> list[str] | None:
    opts, i = _parse_opts(rest, spec.with_arg)
    if key in ("ionice",) and any(
        o in ("-p", "--pid", "-P", "--pgid", "-u", "--uid") for o, _ in opts
    ):
        return None
    for o, v in opts:
        if key in ("chpst",) and o in ("-u", "-U") and o == "-u":
            res.user, res.group = _split_user(v)
        elif key == "chpst" and o == "-/":
            res.chroot = v or None
        elif key == "setpriv":
            if o == "--reuid":
                res.user = v
            elif o == "--regid":
                res.group = v
            elif o == "--no-new-privs":
                res.no_new_privs = True
        elif key in ("runuser", "su") and o in ("-u", "--user"):
            res.user = v
        elif key in ("runuser", "su", "sudo") and o in ("-g", "--group"):
            res.group = v
        elif (key == "sudo" and o in ("-u", "--user")) or (key == "s6-applyuidgid" and o == "-u"):
            res.user = v
        elif key == "s6-applyuidgid" and o == "-g":
            res.group = v
        elif key == "chroot" and o == "--userspec":
            res.user, res.group = _split_user(v)
    rest = rest[i:]
    if key == "env":
        split = [v for o, v in opts if o in ("-S", "--split-string")]
        while rest and _ASSIGN_RE.match(rest[0]):
            rest = rest[1:]
        if split:
            rest = split[0].split() + rest
    if key in ("su", "runuser") and not any(o in ("-u", "--user") for o, _ in opts):
        if rest and not rest[0].startswith("-"):
            res.user = rest[0]
            more, j = _parse_opts(rest[1:], spec.with_arg)  # options may follow the user
            opts = [*opts, *more]
            rest = rest[1 + j :]
        elif key == "su":
            res.user = res.user or "root"
        command = next((v for o, v in opts if o in ("-c", "--command")), None)
        if command is not None:
            shell = next((v for o, v in opts if o in ("-s", "--shell")), None) or "/bin/sh"
            return [shell, "-c", command]
        return (
            [next((v for o, v in opts if o in ("-s", "--shell")), "/bin/sh")]
            if key == "su"
            else None
        )
    if key in ("runuser",) and any(o in ("-c", "--command") for o, _ in opts):
        command = next(v for o, v in opts if o in ("-c", "--command"))
        return ["/bin/sh", "-c", command]
    if key == "sudo" and not rest:
        return None
    if spec.user_pos:
        if not rest:
            return None
        res.user, res.group = _split_user(rest[0])
        rest = rest[1:]
    elif spec.positional:
        if len(rest) < spec.positional:
            return None
        if key == "chroot":
            res.chroot = posixpath.normpath(rest[0]) if rest[0].startswith("/") else None
            rest = rest[1:]
            return rest or ["/bin/sh"]
        rest = rest[spec.positional :]
    if spec.block:
        rest = _consume_block(rest, res)
    if not rest:
        return None
    return rest


def _consume_block(rest: list[str], res: Resolution) -> list[str]:
    """Strip one execline ``{ ... }`` block, recording its command as a side command."""
    if not rest or rest[0] != "{":
        return rest
    depth = 0
    for j, w in enumerate(rest):
        if w == "{":
            depth += 1
        elif w == "}":
            depth -= 1
            if depth == 0:
                inner = rest[1:j]
                if inner and inner[0] not in ("{", "}"):
                    res.side_commands.append([w for w in inner if w not in ("{", "}")])
                return rest[j + 1 :]
    return []


def _unwrap_shell(
    fs: RootFS, args: list[str], res: Resolution, path: list[str]
) -> list[str] | None:
    """Handle ``sh [opts] -c STRING [arg0 args...]`` and ``sh script args``."""
    i = 1
    has_c = False
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a in ("-o", "+o", "-O", "+O"):
            i += 2
            continue
        if a.startswith(("-", "+")) and len(a) > 1:
            if a.startswith("--"):  # bash long options (--login, --norc, ...)
                if a in ("--rcfile", "--init-file"):
                    i += 1
                i += 1
                continue
            if "c" in a[1:]:
                has_c = True
            i += 1
            continue
        break
    if has_c:
        if i >= len(args):
            return None
        string = args[i]
        positional = args[i + 1 :] or ["sh"]
        env = ShellEnv(positional=positional)
        commands = parse_shell(string, env)
        if not commands:
            return None
        main, others = main_command(commands)
        res.side_commands.extend(others)
        return main
    if i < len(args):
        script = args[i]
        if "/" in script or fs.exists(posixpath.join("/", script)):
            return args[i:]
    return None


def _unwrap_entry_script(
    fs: RootFS, exe: str, args: list[str], res: Resolution
) -> list[str] | None:
    """Heuristic: an entrypoint shell script that ends in ``exec "$@"`` runs its arguments."""
    sb = shebang(fs, exe)
    if not sb or posixpath.basename(sb[0]) not in SHELLS | {"env"}:
        return None
    if posixpath.basename(sb[0]) == "env" and (len(sb) < 2 or sb[1] not in SHELLS):
        return None
    if args[1].startswith("-"):
        return None
    text = read_script(fs, exe)
    if text is None:
        return None
    matches = list(_EXEC_ARGS_RE.finditer(text))
    if not matches:
        return None
    m = matches[-1]
    res.notes.append(f"{exe}: 'exec \"$@\"' idiom; arguments assumed to be the main program")
    if m.group("w"):
        user = m.group("u")
        if not user.startswith("$"):
            res.user, res.group = _split_user(user)
    return args[1:]


def resolve_command(
    fs: RootFS, argv: list[str], *, path_env: list[str] | None = None
) -> tuple[str | None, list[str]]:
    """Resolve ``argv`` to ``(canonical executable, [wrapper executables, outermost first])``."""
    res = unwrap_command(fs, argv, path_env=path_env)
    return res.executable, res.wrappers


def is_name(value: str) -> bool:
    """True if ``value`` is a valid shell variable name."""
    return bool(_NAME_RE.match(value))


_GLOB_CHARS = frozenset("*?[")


def fs_glob(fs: RootFS, pattern: str, *, cwd: str = "/", limit: int = 512) -> list[str]:
    """Expand a glob pattern inside the image root (sorted, bounded, no host access)."""
    if not pattern:
        return []
    if not pattern.startswith("/"):
        pattern = posixpath.join(cwd if cwd.startswith("/") else "/", pattern)
    comps = [c for c in pattern.split("/") if c not in ("", ".")]
    current = ["/"]
    for idx, comp in enumerate(comps):
        last = idx == len(comps) - 1
        nxt: list[str] = []
        for base in current:
            if _GLOB_CHARS & set(comp):
                for name in fs.safe_listdir(base):
                    if name.startswith(".") and not comp.startswith("."):
                        continue
                    if fnmatch.fnmatchcase(name, comp):
                        nxt.append(posixpath.join(base, name))
            elif comp == "..":
                nxt.append(posixpath.dirname(base) or "/")
            else:
                nxt.append(posixpath.join(base, comp))
            if len(nxt) > limit:
                break
        current = nxt[:limit] if last else [p for p in nxt[:limit] if fs.is_dir(p)]
        if not current:
            return []
    return sorted(p for p in current if fs.lexists(p))
