"""systemd unit-file syntax: lines, sections, value tokenizer, Exec lines, names, specifiers.

Implements systemd.syntax(7) / ``conf-parser.c`` (comments, continuation lines,
BOM), ``extract_first_word(EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE)`` for list values,
``config_parse_exec()`` prefixes and ``;`` separators, unit-name grammar and the
offline-resolvable subset of specifiers.  Pure functions over strings.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

MAX_LINE = 1024 * 1024
UNIT_TYPES = (
    "service", "socket", "device", "mount", "automount", "swap",
    "target", "path", "timer", "slice", "scope",
)  # fmt: skip
UNIT_RE = re.compile(
    r"^(?P<prefix>[A-Za-z0-9:_.\\-]+?)(?:@(?P<instance>[A-Za-z0-9:_.\\@-]*))?"
    r"\.(?P<type>" + "|".join(UNIT_TYPES) + r")$"
)
BOOL_TRUE = frozenset({"1", "yes", "y", "true", "t", "on"})
BOOL_FALSE = frozenset({"0", "no", "n", "false", "f", "off"})
EXEC_PREFIX = frozenset("-@:|+!")

Entry = tuple[str, str, str]  # (section, key, value)


# --------------------------------------------------------------------------- lines
def parse_unit_text(text: str) -> list[Entry]:
    """Parse unit-file text into ordered ``(section, key, value)`` assignments."""
    if text.startswith("\ufeff"):
        text = text[1:]
    entries: list[Entry] = []
    section: str | None = None
    lines = text.split("\n")
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        i += 1
        if raw.lstrip()[:1] in ("#", ";"):
            continue
        logical = raw
        while _continues(logical) and len(logical) < MAX_LINE:
            logical = logical[:-1] + " "
            while i < n and lines[i].lstrip()[:1] in ("#", ";"):
                i += 1
            if i >= n:
                break
            logical += lines[i]
            i += 1
        line = logical.strip()
        if not line:
            continue
        if line.startswith("["):
            section = line[1:-1] if line.endswith("]") and len(line) > 2 else None
            continue
        if section is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or key.startswith("X-") or section.startswith("X-"):
            continue
        entries.append((section, key, value.strip()))
    return entries


def _continues(line: str) -> bool:
    escaped = False
    for ch in line:
        escaped = (not escaped) if ch == "\\" else False
    return escaped


# --------------------------------------------------------------------------- values
_ESCAPES = {
    "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
    "\\": "\\", '"': '"', "'": "'", "s": " ",
}  # fmt: skip


def _cunescape_one(s: str, i: int) -> tuple[str, int]:
    """Decode the escape starting after the backslash at ``s[i]``; return (text, next index)."""
    if i >= len(s):
        return "\\", i
    c = s[i]
    if c in _ESCAPES:
        return _ESCAPES[c], i + 1
    if c == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", s[i + 1 : i + 3]):
        return chr(int(s[i + 1 : i + 3], 16)), i + 3
    if c == "u" and re.fullmatch(r"[0-9A-Fa-f]{4}", s[i + 1 : i + 5]):
        return chr(int(s[i + 1 : i + 5], 16)), i + 5
    if c == "U" and re.fullmatch(r"[0-9A-Fa-f]{8}", s[i + 1 : i + 9]):
        cp = int(s[i + 1 : i + 9], 16)
        return (chr(cp) if cp <= 0x10FFFF else "\ufffd"), i + 9
    if re.fullmatch(r"[0-7]{3}", s[i : i + 3]):
        return chr(int(s[i : i + 3], 8)), i + 3
    return c, i + 1  # unknown escape: systemd rejects; keep the character


def next_word(s: str, i: int = 0) -> tuple[str | None, int, bool]:
    """Extract one word from ``s`` at ``i``: returns (word, next index, was_quoted)."""
    n = len(s)
    while i < n and s[i] in " \t\n\r":
        i += 1
    if i >= n:
        return None, n, False
    buf: list[str] = []
    quoted = False
    quote = ""
    while i < n:
        c = s[i]
        if quote:
            if c == "\\":
                text, i = _cunescape_one(s, i + 1)
                buf.append(text)
                continue
            if c == quote:
                quote = ""
                i += 1
                continue
            buf.append(c)
            i += 1
            continue
        if c in " \t\n\r":
            break
        if c in "\"'" and (not buf or quoted):
            quote = c
            quoted = True
            i += 1
            continue
        if c == "\\":
            text, i = _cunescape_one(s, i + 1)
            buf.append(text)
            continue
        buf.append(c)
        i += 1
    return "".join(buf), i, quoted


def split_words(value: str) -> list[str]:
    """Split a list value per systemd quoting rules (``EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE``)."""
    out: list[str] = []
    i = 0
    while True:
        word, i, _ = next_word(value, i)
        if word is None:
            return out
        out.append(word)


def parse_bool(value: str | None) -> bool | None:
    """systemd ``parse_boolean``; ``None`` if unset or invalid."""
    if value is None:
        return None
    v = value.strip().lower()
    if v in BOOL_TRUE:
        return True
    if v in BOOL_FALSE:
        return False
    return None


# --------------------------------------------------------------------------- Exec lines
@dataclass(slots=True)
class ExecSpec:
    """One parsed command of an ``Exec*=`` value."""

    path: str
    argv: list[str]
    raw: str
    ignore_failure: bool = False
    argv0_override: bool = False
    no_env_expand: bool = False
    via_shell: bool = False
    full_privileges: bool = False
    no_setuid: bool = False
    errors: list[str] = field(default_factory=list)


def parse_exec(value: str) -> list[ExecSpec]:
    """Parse one ``Exec*=`` value into commands (``;``-separated, prefixes decoded)."""
    out: list[ExecSpec] = []
    i = 0
    n = len(value)
    while i < n:
        start = i
        word, i, _ = next_word(value, i)
        if word is None:
            break
        if word == ";":
            continue
        spec = ExecSpec(path="", argv=[], raw="")
        seen: set[str] = set()
        while word and word[0] in EXEC_PREFIX:
            c = word[0]
            if c == "!" and "!" in seen:
                c = "!!"
            seen.add(c)
            if c == "-":
                spec.ignore_failure = True
            elif c == "@":
                spec.argv0_override = True
            elif c == ":":
                spec.no_env_expand = True
            elif c == "|":
                spec.via_shell = True
            elif c == "+":
                spec.full_privileges = True
            elif c == "!":
                spec.no_setuid = True
            word = word[1:]
        if spec.via_shell:
            rest_start = i
            # the rest of the line up to an unquoted ' ; ' is the shell command
            words, i = _rest_until_separator(value, i)
            line = " ".join([word, *words]).strip() if word else " ".join(words).strip()
            spec.path = "/bin/sh"
            spec.argv = ["sh", "-c", line] if line else ["sh"]
            spec.raw = value[start:i].strip() or value[rest_start:i].strip()
            out.append(spec)
            continue
        spec.path = word
        words, i = _rest_until_separator(value, i)
        if spec.argv0_override:
            spec.argv = words if words else [word]
        else:
            spec.argv = [word, *words]
        spec.raw = value[start:i].strip()
        if not word:
            spec.errors.append("empty executable")
        elif not word.startswith("/") and "/" in word:
            spec.errors.append(f"executable path must be absolute or a bare name: {word!r}")
        out.append(spec)
    return out


def _rest_until_separator(value: str, i: int) -> tuple[list[str], int]:
    words: list[str] = []
    n = len(value)
    while i < n:
        j = i
        while j < n and value[j] in " \t":
            j += 1
        if value.startswith(";", j) and (j + 1 >= n or value[j + 1] in " \t"):
            return words, j + 1
        word, nxt, quoted = next_word(value, i)
        if word is None:
            return words, n
        if word == "\\;" or (word == ";" and quoted):
            word = ";"
        words.append(word)
        i = nxt
    return words, n


# --------------------------------------------------------------------------- names
@dataclass(frozen=True, slots=True)
class UnitName:
    """A parsed unit name: ``prefix[@instance].type``."""

    prefix: str
    instance: str | None
    type: str

    @property
    def is_template(self) -> bool:
        return self.instance == ""

    @property
    def is_instance(self) -> bool:
        return bool(self.instance)

    @property
    def template(self) -> str:
        return f"{self.prefix}@.{self.type}"

    def with_instance(self, instance: str) -> str:
        return f"{self.prefix}@{instance}.{self.type}"

    def __str__(self) -> str:
        if self.instance is None:
            return f"{self.prefix}.{self.type}"
        return f"{self.prefix}@{self.instance}.{self.type}"


def parse_unit_name(name: str) -> UnitName | None:
    """Parse a unit name; ``None`` if it is not a valid name."""
    if not name or len(name) > 255:
        return None
    m = UNIT_RE.match(name)
    if not m:
        return None
    return UnitName(m.group("prefix"), m.group("instance"), m.group("type"))


def unit_unescape(s: str, *, path: bool = False) -> str:
    """Undo systemd-escape: ``\\xNN`` → byte, ``-`` → ``/`` for path semantics."""
    if path:
        s = s.replace("-", "/")
    return re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)


# --------------------------------------------------------------------------- specifiers
@dataclass(slots=True)
class SpecifierContext:
    """Values for specifier expansion of one unit (system manager, offline)."""

    name: str
    fragment: str | None = None
    hostname: str | None = None
    machine_id: str | None = None
    os_release: Mapping[str, str] = field(default_factory=dict)
    instance_placeholder: str = "<instance>"

    def table(self) -> dict[str, str]:
        un = parse_unit_name(self.name)
        prefix = un.prefix if un else self.name.rsplit(".", 1)[0]
        inst = un.instance if un and un.instance is not None else ""
        if un and un.is_template:
            inst = self.instance_placeholder
        frag_dir = self.fragment.rsplit("/", 1)[0] or "/" if self.fragment else ""
        j = prefix.rsplit("-", 1)[-1]
        uprefix = unit_unescape(prefix, path=True)
        uinst = unit_unescape(inst, path=True) if inst else ""
        f = "/" + (uinst if inst else uprefix).lstrip("/")
        osr = self.os_release
        return {
            "%": "%",
            "n": self.name,
            "N": self.name.rsplit(".", 1)[0],
            "p": prefix,
            "P": uprefix,
            "i": inst,
            "I": uinst,
            "j": j,
            "J": unit_unescape(j, path=True),
            "f": f,
            "y": self.fragment or "",
            "Y": frag_dir,
            "u": "root",
            "U": "0",
            "g": "root",
            "G": "0",
            "h": "/root",
            "s": "/bin/sh",
            "t": "/run",
            "S": "/var/lib",
            "C": "/var/cache",
            "L": "/var/log",
            "E": "/etc",
            "T": "/tmp",  # noqa: S108 - specifier value, not a temp file
            "V": "/var/tmp",  # noqa: S108
            "d": "<credentials-directory>",
            "H": self.hostname or "<hostname>",
            "l": (self.hostname or "<hostname>").split(".", 1)[0],
            "q": self.hostname or "<hostname>",
            "m": self.machine_id or "<machine-id>",
            "b": "<boot-id>",
            "o": osr.get("ID", ""),
            "w": osr.get("VERSION_ID", ""),
            "W": osr.get("VARIANT_ID", ""),
            "B": osr.get("BUILD_ID", ""),
            "M": osr.get("IMAGE_ID", ""),
            "A": osr.get("IMAGE_VERSION", ""),
            "a": "<architecture>",
            "v": "<kernel-release>",
        }


def expand_specifiers(value: str, table: Mapping[str, str]) -> str:
    """Replace ``%x`` specifiers; unknown specifiers are left as-is."""
    if "%" not in value:
        return value
    out: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        c = value[i]
        if c == "%" and i + 1 < n:
            rep = table.get(value[i + 1])
            if rep is not None:
                out.append(rep)
                i += 2
                continue
        out.append(c)
        i += 1
    return "".join(out)
