"""systemd unit loading, root-confined: search path, name map, drop-ins, enablement dirs.

Mirrors ``path-lookup.c`` (search path incl. split-usr ``/lib`` before
``/usr/lib``), ``unit-file.c`` (name map: aliases vs linked units, masks,
template fallback) and ``dropin.c`` (candidate names, directory order,
first-basename-wins, lexicographic application, ``/dev/null`` masking).
Symlinks are only ever interpreted as in-image paths.
"""

from __future__ import annotations

import posixpath
from collections.abc import Iterable
from dataclasses import dataclass, field

from startup_sbom.errors import RootFSError
from startup_sbom.initsys.systemd.hardening import SettingsView
from startup_sbom.initsys.systemd.parser import (
    Entry,
    UnitName,
    parse_unit_name,
    parse_unit_text,
    split_words,
)
from startup_sbom.rootfs import RootFS, normalize

UNIT_READ_LIMIT = 4 * 1024 * 1024
MAX_ALIAS_HOPS = 16
MAX_DROPINS = 512
GENERATOR_DIRS = (
    "/etc/systemd/system-generators",
    "/usr/local/lib/systemd/system-generators",
    "/usr/lib/systemd/system-generators",
    "/lib/systemd/system-generators",
)
DEP_KEYS = frozenset(
    {
        "Wants", "Requires", "Requisite", "BindsTo", "PartOf", "Upholds", "Conflicts",
        "Before", "After", "OnFailure", "OnSuccess", "PropagatesReloadTo",
        "ReloadPropagatedFrom", "JoinsNamespaceOf", "WantedBy", "RequiredBy", "UpheldBy",
        "Also", "Alias",
    }
)  # fmt: skip
ENABLE_SUFFIXES = ((".wants", "Wants"), (".requires", "Requires"), (".upholds", "Upholds"))


def search_path(fs: RootFS) -> list[str]:
    """System-manager unit search path present in an offline image (highest precedence first)."""
    lib = fs.try_resolve("/lib")
    usr_lib = fs.try_resolve("/usr/lib")
    merged = lib is None or lib == usr_lib
    dirs = [
        "/etc/systemd/system.control",
        "/etc/systemd/system",
        "/etc/systemd/system.attached",
        "/usr/local/lib/systemd/system",
    ]
    dirs += (
        ["/usr/lib/systemd/system"]
        if merged
        else ["/lib/systemd/system", "/usr/lib/systemd/system"]
    )
    out: list[str] = []
    seen: set[str] = set()
    for d in dirs:
        key = fs.try_resolve(d) or d
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


class Settings:
    """Ordered unit assignments (fragment + drop-ins) with systemd reset semantics."""

    def __init__(self, entries: Iterable[Entry] = ()) -> None:
        self.ordered: list[Entry] = []
        self._raw: dict[tuple[str, str], list[str]] = {}
        self.extend(entries)

    def extend(self, entries: Iterable[Entry]) -> None:
        for section, key, value in entries:
            self.ordered.append((section, key, value))
            self._raw.setdefault((section, key), []).append(value)

    def raw(self, section: str, key: str) -> list[str]:
        """Every assignment in order, including empty (reset) ones."""
        return list(self._raw.get((section, key), []))

    def values(self, section: str, key: str) -> list[str]:
        """Effective list: assignments after the last empty one (dependencies never reset)."""
        vals = self._raw.get((section, key), [])
        if key in DEP_KEYS:
            return [v for v in vals if v]
        out: list[str] = []
        for v in vals:
            if v == "":
                out = []
            else:
                out.append(v)
        return out

    def get(self, section: str, key: str) -> str | None:
        """Scalar value: the last assignment (an empty assignment resets to the default)."""
        vals = self._raw.get((section, key))
        if not vals or vals[-1] == "":
            return None
        return vals[-1]

    def words(self, section: str, key: str) -> list[str]:
        out: list[str] = []
        for v in self.values(section, key):
            out.extend(split_words(v))
        return out

    def section(self, section: str) -> SectionView:
        return SectionView(self, section)


class SectionView(SettingsView):
    """:class:`SettingsView` over one section (``values`` returns raw assignments)."""

    def __init__(self, settings: Settings, section: str) -> None:
        self._s = settings
        self._section = section

    def get(self, key: str) -> str | None:
        return self._s.get(self._section, key)

    def values(self, key: str) -> list[str]:
        return self._s.raw(self._section, key)


@dataclass(frozen=True, slots=True)
class MapEntry:
    """Highest-precedence entry for a unit name in the search path."""

    name: str
    path: str  # the entry inside a search directory
    kind: str  # file | alias | linked | masked
    target: str | None = None  # alias: unit name; linked: in-image path of the real file


@dataclass(slots=True)
class GeneratedUnit:
    """Emulated generator output (lowest precedence, like ``generator.late``)."""

    name: str
    source: str  # in-image file the generator derived the unit from
    entries: list[Entry]
    generator: str


@dataclass(slots=True)
class Unit:
    """A loaded unit after alias resolution, template fallback and drop-in merging."""

    name: str
    requested: str
    parsed: UnitName | None
    found: bool = False
    masked: bool = False
    generated: str | None = None
    fragment: str | None = None
    content_path: str | None = None
    dropins: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)
    notes: list[str] = field(default_factory=list)

    @property
    def type(self) -> str:
        return self.parsed.type if self.parsed else ""

    @property
    def instance(self) -> str | None:
        return self.parsed.instance if self.parsed else None

    @property
    def names(self) -> list[str]:
        out = [self.name]
        for a in [self.requested, *self.aliases]:
            if a not in out:
                out.append(a)
        return out


class UnitLoader:
    """Loads units from an image root exactly as PID 1 would, without executing anything."""

    def __init__(self, fs: RootFS) -> None:
        self.fs = fs
        self.dirs = search_path(fs)
        self._dir_keys = self._dir_key_set()
        self.map: dict[str, MapEntry] = {}
        self.generated: dict[str, GeneratedUnit] = {}
        self.generated_wants: dict[str, list[tuple[str, str]]] = {}
        self._cache: dict[str, Unit] = {}
        self._reverse: dict[str, set[str]] = {}
        self._build_map()

    # -- name map -------------------------------------------------------------
    def _dir_key_set(self) -> set[str]:
        keys: set[str] = set()
        for d in [*self.dirs, "/lib/systemd/system", "/usr/lib/systemd/system"]:
            keys.add(d)
            r = self.fs.try_resolve(d)
            if r:
                keys.add(r)
        return keys

    def _build_map(self) -> None:
        for d in self.dirs:
            for name in self.fs.safe_listdir(d):
                if name in self.map or name.startswith(".") or name.endswith(".ignore"):
                    continue
                if parse_unit_name(name) is None:
                    continue
                path = posixpath.join(d, name)
                st = self.fs.try_lstat(path)
                if st is None or st.is_dir:
                    continue
                if st.is_symlink:
                    raw = st.linkname or ""
                    target = normalize(raw if raw.startswith("/") else posixpath.join(d, raw))
                    if target == "/dev/null":
                        self.map[name] = MapEntry(name, path, "masked", target)
                        continue
                    parent = posixpath.dirname(target)
                    tname = posixpath.basename(target)
                    in_search = parent in self._dir_keys or (
                        self.fs.try_resolve(parent) in self._dir_keys
                    )
                    if in_search and parse_unit_name(tname) is not None and tname != name:
                        self.map[name] = MapEntry(name, path, "alias", tname)
                    else:
                        self.map[name] = MapEntry(name, path, "linked", target)
                elif st.is_file:
                    self.map[name] = MapEntry(name, path, "masked" if st.size == 0 else "file")
        for name, entry in self.map.items():
            if entry.kind == "alias":
                final, _, _ = self._lookup(name)
                self._reverse.setdefault(final, set()).add(name)

    def _lookup(self, name: str) -> tuple[str, MapEntry | None, list[str]]:
        """Follow aliases (and instance→template fallback); returns (final name, entry, chain)."""
        chain: list[str] = []
        cur = name
        for _ in range(MAX_ALIAS_HOPS):
            entry = self.map.get(cur)
            if entry is None:
                un = parse_unit_name(cur)
                if un is not None and un.is_instance:
                    tentry = self.map.get(un.template)
                    if tentry is not None and tentry.kind == "alias" and tentry.target:
                        tun = parse_unit_name(tentry.target)
                        if tun is not None and tun.is_template:
                            chain.append(cur)
                            cur = tun.with_instance(un.instance or "")
                            continue
                    if tentry is not None:
                        return cur, tentry, chain
                return cur, None, chain
            if entry.kind == "alias" and entry.target:
                chain.append(cur)
                cur = entry.target
                continue
            return cur, entry, chain
        return cur, None, chain

    def resolve_name(self, name: str) -> str:
        """Final unit name after alias resolution."""
        return self._lookup(name)[0]

    def known_names(self) -> list[str]:
        """Every unit name in the map plus generated ones (sorted)."""
        return sorted(set(self.map) | set(self.generated))

    def has_unit(self, name: str) -> bool:
        """True if a unit of this name exists in the (non-generated) search path."""
        return name in self.map

    # -- loading --------------------------------------------------------------
    def load(self, name: str) -> Unit:
        """Load ``name`` (cached).  Never raises on hostile content."""
        cached = self._cache.get(name)
        if cached is not None:
            return cached
        final, entry, chain = self._lookup(name)
        if final in self._cache and final != name:
            unit = self._cache[final]
            if name not in unit.aliases and name != unit.name:
                unit.aliases.append(name)
            self._cache[name] = unit
            return unit
        unit = Unit(name=final, requested=name, parsed=parse_unit_name(final))
        unit.aliases = [a for a in chain if a != final]
        for alias in sorted(self._reverse.get(final, set())):
            if alias not in unit.aliases:
                unit.aliases.append(alias)
        if unit.parsed is not None and unit.parsed.is_instance:
            for alias in sorted(self._reverse.get(unit.parsed.template, set())):
                aun = parse_unit_name(alias)
                if aun is not None and aun.is_template:
                    inst_alias = aun.with_instance(unit.parsed.instance or "")
                    if inst_alias not in unit.aliases and inst_alias != final:
                        unit.aliases.append(inst_alias)
        self._cache[name] = unit
        self._cache[final] = unit
        if entry is None:
            gen = self.generated.get(final)
            if gen is None:
                return unit
            unit.found = True
            unit.generated = gen.generator
            unit.fragment = gen.source
            unit.settings = Settings(gen.entries)
            self._apply_dropins(unit)
            return unit
        unit.found = True
        unit.fragment = entry.path
        if entry.kind == "masked":
            unit.masked = True
            return unit
        content = entry.path if entry.kind == "file" else (entry.target or entry.path)
        if entry.kind == "linked":
            real = self._resolve_lenient(content)
            if real == "/dev/null":
                unit.masked = True
                return unit
            st = self.fs.try_stat(content)
            if st is not None and st.is_file and st.size == 0:
                unit.masked = True
                return unit
        unit.content_path = content
        text = self.fs.try_read_text(content, UNIT_READ_LIMIT)
        if text is None:
            unit.notes.append(f"unit file unreadable: {content}")
            unit.found = False
            return unit
        try:
            unit.settings = Settings(parse_unit_text(text))
        except (ValueError, RecursionError) as exc:  # pragma: no cover - defensive
            unit.notes.append(f"unit file unparsable: {content}: {exc}")
        self._apply_dropins(unit)
        return unit

    def _resolve_lenient(self, path: str) -> str | None:
        try:
            return self.fs.resolve(path, strict=False)
        except (RootFSError, OSError):
            return None

    # -- drop-ins ---------------------------------------------------------------
    @staticmethod
    def dropin_candidates(name: str) -> list[str]:
        """Candidate drop-in base names for ``name`` (exact, template, dash prefixes)."""
        un = parse_unit_name(name)
        out = [name]
        if un is None:
            return out
        if un.is_instance:
            out.append(un.template)
        for base in list(out):
            bun = parse_unit_name(base)
            if bun is None:
                continue
            prefix = bun.prefix
            for i in range(len(prefix) - 1, 0, -1):
                if prefix[i] != "-":
                    continue
                cand_prefix = prefix[: i + 1]
                if cand_prefix == prefix:
                    continue
                if bun.instance is None:
                    cand = f"{cand_prefix}.{bun.type}"
                else:
                    cand = f"{cand_prefix}@{bun.instance}.{bun.type}"
                if cand not in out:
                    out.append(cand)
        return out

    def _apply_dropins(self, unit: Unit) -> None:
        dirs: list[str] = []
        for n in unit.names:
            for d in self.dirs:
                for cand in self.dropin_candidates(n):
                    p = posixpath.join(d, cand + ".d")
                    if p not in dirs:
                        dirs.append(p)
        if unit.type:
            dirs += [posixpath.join(d, unit.type + ".d") for d in self.dirs]
        chosen: dict[str, str | None] = {}
        for d in dirs:
            for fname in self.fs.safe_listdir(d):
                if not fname.endswith(".conf") or fname.startswith(".") or fname in chosen:
                    continue
                path = posixpath.join(d, fname)
                st = self.fs.try_lstat(path)
                if st is None:
                    continue
                masked = False
                if st.is_symlink:
                    raw = st.linkname or ""
                    tgt = normalize(raw if raw.startswith("/") else posixpath.join(d, raw))
                    masked = tgt == "/dev/null" or self._resolve_lenient(path) == "/dev/null"
                if not masked:
                    fst = self.fs.try_stat(path)
                    masked = fst is None or not fst.is_file or fst.size == 0
                chosen[fname] = None if masked else path
                if len(chosen) >= MAX_DROPINS:
                    unit.notes.append("drop-in limit reached")
                    break
        for fname in sorted(chosen):
            dpath = chosen[fname]
            if dpath is None:
                continue
            text = self.fs.try_read_text(dpath, UNIT_READ_LIMIT)
            if text is None:
                continue
            unit.dropins.append(dpath)
            unit.settings.extend(parse_unit_text(text))

    # -- enablement directories ----------------------------------------------------
    def enablement(self, unit: Unit) -> list[tuple[str, str, str]]:
        """``(kind, dependency, label)`` from ``.wants/.requires/.upholds`` dirs of ``unit``."""
        names = list(unit.names)
        un = unit.parsed
        if un is not None and un.is_instance and un.template not in names:
            names.append(un.template)
        out: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        for d in self.dirs:
            for n in names:
                nun = parse_unit_name(n)
                for suffix, kind in ENABLE_SUFFIXES:
                    dirp = posixpath.join(d, n + suffix)
                    for entry in self.fs.safe_listdir(dirp):
                        if entry.startswith(".") or entry.endswith(".ignore"):
                            continue
                        eun = parse_unit_name(entry)
                        if eun is None:
                            continue
                        dep = entry
                        if (
                            nun is not None
                            and nun.is_template
                            and eun.is_template
                            and un is not None
                            and un.is_instance
                        ):
                            dep = eun.with_instance(un.instance or "")
                        if dep in seen:
                            continue
                        seen.add(dep)
                        out.append((kind, dep, f"{n}{suffix}/{entry}"))
        for n in names:
            for dep, label in self.generated_wants.get(n, []):
                if dep not in seen:
                    seen.add(dep)
                    out.append(("Wants", dep, label))
        return out

    def enablement_refs(self) -> dict[str, str]:
        """Every unit named by any enablement directory → first label (installed state)."""
        refs: dict[str, str] = {}
        for d in self.dirs:
            for entry in self.fs.safe_listdir(d):
                if not entry.endswith((".wants", ".requires", ".upholds")):
                    continue
                for dep in self.fs.safe_listdir(posixpath.join(d, entry)):
                    if parse_unit_name(dep) is not None:
                        refs.setdefault(dep, f"{entry}/{dep}")
        for deps in self.generated_wants.values():
            for dep, label in deps:
                refs.setdefault(dep, label)
        return refs

    def generator_present(self, name: str) -> bool:
        """True if generator binary ``name`` exists in one of the image's generator dirs."""
        return any(self.fs.lexists(posixpath.join(d, name)) for d in GENERATOR_DIRS)

    def add_generated(self, unit: GeneratedUnit, wanted_by: Iterable[tuple[str, str]] = ()) -> None:
        """Register emulated generator output; ``wanted_by`` is ``(target, label)`` pairs."""
        if unit.name not in self.map and unit.name not in self.generated:
            self.generated[unit.name] = unit
        for target, label in wanted_by:
            self.add_generated_want(target, unit.name, label)

    def add_generated_want(self, target: str, dep: str, label: str) -> None:
        lst = self.generated_wants.setdefault(target, [])
        if all(d != dep for d, _ in lst):
            lst.append((dep, label))
