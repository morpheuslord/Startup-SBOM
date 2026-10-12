"""What code a boot-time executable actually loads.

For every executable the transitive set of loaded objects is computed with the
root-confined loader emulation of :mod:`startup_sbom.binaries.linker`:

* ``PT_INTERP`` loader (``via="interpreter"``),
* ``/etc/ld.so.preload`` entries for glibc dynamic executables (``via="preload"``),
* ``DT_NEEDED`` closure (``via="needed"``, high confidence),
* FDO ``.note.dlopen`` entries of every loaded object (``via="dlopen"``; medium
  confidence for required/recommended, low for suggested),
* script interpreters from ``#!`` lines, which are analysed in turn and whose
  closure is merged into the script's.

Objects inherit the weakest confidence and the ``via`` of the edge that first
pulled their branch in; when an object is reachable several ways the strongest
(then shallowest) path wins.  All work is bounded (depth, objects per binary,
script nesting) and parsed ELF headers / resolutions are memoised across
executables.
"""

from __future__ import annotations

import heapq
import posixpath
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from packageurl import PackageURL

from startup_sbom.binaries.elf import ELF_MAGIC, ElfInfo
from startup_sbom.binaries.linker import ChainLink, LibraryResolver, Resolution
from startup_sbom.binaries.shebang import interpreter_chain, is_env, read_shebang
from startup_sbom.context import ScanContext
from startup_sbom.errors import RootFSError
from startup_sbom.models import Binary, Confidence, LibraryLink
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.rootfs import FileStat, RootFS, normalize

MAX_LIBS_PER_BINARY = 512
MAX_SCRIPT_NESTING = 4  # Linux binfmt_script recursion limit

_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}


def _weaker(a: Confidence, b: Confidence) -> Confidence:
    return a if _RANK[a] <= _RANK[b] else b


def capability_names(st: FileStat) -> list[str]:
    """File capabilities of ``st`` as sorted ``CAP_*`` names (empty if none)."""
    caps = st.capabilities
    if caps is None:
        return []
    return sorted("CAP_" + c.upper() for c in caps.all)


def is_privileged(st: FileStat) -> bool:
    """Regular file that is setuid, setgid or carries file capabilities."""
    return st.is_file and (st.is_setuid or st.is_setgid or bool(capability_names(st)))


def package_note_purl(note: Mapping[str, str] | None) -> str | None:
    """Render an ELF ``.note.package`` as a purl (or ``name@version`` if untyped)."""
    if not note:
        return None
    name = note.get("name")
    if not name:
        return None
    version = note.get("version") or None
    ptype = (note.get("type") or "").lower()
    if ptype and ptype.isalnum():
        qualifiers: dict[str, str] = {}
        if note.get("architecture"):
            qualifiers["arch"] = note["architecture"]
        os_id = (note.get("os") or "").lower() or None
        if os_id and note.get("osVersion"):
            qualifiers["distro"] = f"{os_id}-{note['osVersion']}"
        try:
            return PackageURL(
                type=ptype,
                namespace=os_id or None,
                name=name,
                version=version,
                qualifiers=qualifiers or None,
            ).to_string()
        except ValueError:
            pass
    return f"{name}@{version}" if version else name


def file_kind(fs: RootFS, path: str) -> str:
    """``elf``, ``script`` or ``unknown`` from the first bytes of ``path``."""
    try:
        head = fs.read_head(path, 4)
    except (RootFSError, OSError):
        return "unknown"
    if head == ELF_MAGIC:
        return "elf"
    if head.startswith(b"#!"):
        return "script"
    return "unknown"


@dataclass(slots=True)
class _Closure:
    links: dict[str, LibraryLink] = field(default_factory=dict)
    best: dict[str, tuple[int, int]] = field(default_factory=dict)
    unresolved: set[str] = field(default_factory=set)
    truncated: bool = False

    def offer(self, link: LibraryLink) -> bool:
        """Keep ``link`` if it beats what is known for its path; return ``True`` if kept."""
        if link.path is None:
            return False
        cand = (-_RANK[link.confidence], link.depth)
        old = self.best.get(link.path)
        if old is not None and old <= cand:
            return False
        if old is None and len(self.links) >= MAX_LIBS_PER_BINARY:
            self.truncated = True
            return False
        self.best[link.path] = cand
        self.links[link.path] = link
        return True


class BinaryAnalyzer:
    """Stateful analyser sharing ELF/resolution memo across many executables."""

    def __init__(
        self,
        ctx: ScanContext,
        owners: FileOwnerIndex,
        *,
        max_depth: int = 8,
        resolver: LibraryResolver | None = None,
    ) -> None:
        self.ctx = ctx
        self.fs = ctx.fs
        self.owners = owners
        self.max_depth = max(1, max_depth)
        self.resolver = resolver or LibraryResolver(ctx.fs)
        self.results: dict[str, Binary] = {}
        self.interp_edges: dict[str, list[str]] = {}
        self.truncated: list[str] = []
        self._owner_memo: dict[str, str | None] = {}
        self._active: set[str] = set()

    # -- helpers ---------------------------------------------------------------
    def owner(self, path: str) -> str | None:
        if path not in self._owner_memo:
            try:
                self._owner_memo[path] = self.owners.owner(path)
            except (RootFSError, OSError):
                self._owner_memo[path] = None
        return self._owner_memo[path]

    def base_binary(self, cpath: str) -> Binary:
        """Stat/ownership/kind facts of ``cpath`` without link analysis."""
        b = Binary(path=cpath, package=self.owner(cpath), kind=file_kind(self.fs, cpath))
        st = self.fs.try_stat(cpath)
        if st is not None:
            b.setuid = st.is_setuid
            b.setgid = st.is_setgid
            b.owner_uid = st.uid
            b.capabilities = capability_names(st)
        return b

    # -- entry point -----------------------------------------------------------
    def analyse(self, path: str, *, link_analysis: bool = True, nesting: int = 0) -> Binary | None:
        """Analyse the executable at ``path`` (memoised by canonical path)."""
        cpath = self.resolver.canonical(path)
        if cpath is None:
            return None
        done = self.results.get(cpath)
        if done is not None or cpath in self._active:
            return done
        self._active.add(cpath)
        try:
            b = self.base_binary(cpath)
            if link_analysis:
                if b.kind == "elf":
                    self._analyse_elf(b)
                elif b.kind == "script":
                    self._analyse_script(b, nesting)
        finally:
            self._active.discard(cpath)
        self.results[cpath] = b
        return b

    # -- ELF -------------------------------------------------------------------
    def _analyse_elf(self, b: Binary) -> None:
        info = self.resolver.elf(b.path)
        if info is None:
            return
        b.arch = info.arch
        b.needed = list(info.needed)
        b.embedded_package = package_note_purl(info.package_note)
        if info.interpreter:
            b.interpreter = self.resolver.canonical(info.interpreter) or info.interpreter
        closure = self.closure(b.path, info)
        self._finish(b, closure)

    def closure(self, exe_path: str, exe: ElfInfo) -> _Closure:
        """Everything the loader maps for executable ``exe`` at canonical ``exe_path``."""
        r = self.resolver
        c = _Closure()
        musl = r.is_musl(exe)
        heap: list[tuple[int, int, int, str, str, tuple[ChainLink, ...], str, Confidence]] = []
        seq = 0
        loaded: dict[str, Resolution] = {}  # ld.so reuses objects already mapped by name

        def remember(name: str, res: Resolution) -> None:
            loaded.setdefault(name, res)
            linfo = r.elf(res.path)
            if linfo is not None and linfo.soname:
                loaded.setdefault(linfo.soname, res)

        def find(
            soname: str, info: ElfInfo, lookup: str, chain: tuple[ChainLink, ...]
        ) -> Resolution | None:
            hit = loaded.get(soname)
            if hit is not None:
                return hit
            res = r.resolve_full(soname, info, lookup, chain=chain, musl=musl)
            if res is not None:
                remember(soname, res)
            return res

        def push(
            soname: str,
            res: Resolution,
            via: str,
            *,
            conf: Confidence,
            depth: int,
            chain: tuple[ChainLink, ...],
            parent: str,
        ) -> None:
            nonlocal seq
            if depth > self.max_depth or res.path == exe_path:
                return
            link = LibraryLink(
                soname=soname,
                path=res.path,
                package=self.owner(res.path),
                via=via,
                confidence=conf,
                depth=depth,
                parent=parent,
            )
            if c.offer(link):
                seq += 1
                heapq.heappush(
                    heap, (-_RANK[conf], depth, seq, res.path, res.lookup, chain, via, conf)
                )

        def expand(
            path: str,
            lookup: str,
            info: ElfInfo,
            chain: tuple[ChainLink, ...],
            *,
            via: str,
            conf: Confidence,
            depth: int,
        ) -> None:
            child_chain = (*chain, (info, lookup))
            for soname in info.needed:
                res = find(soname, info, lookup, chain)
                if res is None:
                    c.unresolved.add(soname)
                else:
                    push(
                        soname,
                        res,
                        via,
                        conf=conf,
                        depth=depth + 1,
                        chain=child_chain,
                        parent=path,
                    )
            for entry in info.dlopen:
                dconf = Confidence.LOW if entry.priority == "suggested" else Confidence.MEDIUM
                for soname in entry.sonames:
                    res = find(soname, info, lookup, chain)
                    if res is not None:
                        weaker = _weaker(conf, dconf)
                        push(
                            soname,
                            res,
                            "dlopen",
                            conf=weaker,
                            depth=depth + 1,
                            chain=child_chain,
                            parent=path,
                        )
                        break
                else:
                    if entry.priority == "required":
                        c.unresolved.add(entry.sonames[0])

        if exe.interpreter:
            interp = r.canonical(exe.interpreter)
            if interp is None:
                c.unresolved.add(exe.interpreter)
            elif interp != exe_path:
                remember(posixpath.basename(exe.interpreter), Resolution(exe.interpreter, interp))
                c.offer(
                    LibraryLink(
                        soname=posixpath.basename(exe.interpreter),
                        path=interp,
                        package=self.owner(interp),
                        via="interpreter",
                        confidence=Confidence.HIGH,
                        depth=1,
                        parent=exe_path,
                    )
                )
        root_chain: tuple[ChainLink, ...] = ((exe, exe_path),)
        if exe.is_dynamic and not musl:
            for entry in r.preload():
                res = find(entry, exe, exe_path, ())
                if res is None:
                    c.unresolved.add(entry)
                else:
                    name = posixpath.basename(entry)
                    push(
                        name,
                        res,
                        "preload",
                        conf=Confidence.HIGH,
                        depth=1,
                        chain=root_chain,
                        parent=exe_path,
                    )
        expand(exe_path, exe_path, exe, (), via="needed", conf=Confidence.HIGH, depth=0)
        while heap:
            negrank, depth, _seq, path, lookup, chain, via, conf = heapq.heappop(heap)
            if c.best.get(path) != (negrank, depth):
                continue  # superseded by a stronger/shallower path
            info = r.elf(path)
            if info is not None:
                expand(path, lookup, info, chain, via=via, conf=conf, depth=depth)
        c.unresolved -= loaded.keys()  # satisfied by an object another branch mapped
        return c

    # -- scripts ---------------------------------------------------------------
    def _analyse_script(self, b: Binary, nesting: int) -> None:
        argv = read_shebang(self.fs, b.path)
        if not argv:
            return
        c = _Closure()
        chain = interpreter_chain(argv)
        if not argv[0].startswith("/"):
            c.unresolved.add(argv[0])
        if is_env(argv[0]) and len(argv) > 1 and not argv[1].startswith("/"):
            c.unresolved.add(argv[1])
        for interp in chain:
            cinterp = self.resolver.canonical(interp)
            if cinterp is None:
                c.unresolved.add(interp)
                continue
            b.interpreter = cinterp
            c.offer(
                LibraryLink(
                    soname=posixpath.basename(interp),
                    path=cinterp,
                    package=self.owner(cinterp),
                    via="interpreter",
                    confidence=Confidence.HIGH,
                    depth=1,
                    parent=b.path,
                )
            )
            self.interp_edges.setdefault(b.path, []).append(cinterp)
            if nesting >= MAX_SCRIPT_NESTING:
                continue
            sub = self.analyse(cinterp, nesting=nesting + 1)
            if sub is None:
                continue
            for link in sub.libraries:
                if link.depth + 1 <= self.max_depth:
                    c.offer(link.model_copy(update={"depth": link.depth + 1}))
            c.unresolved.update(sub.unresolved)
        self._finish(b, c)

    def _finish(self, b: Binary, c: _Closure) -> None:
        b.libraries = sorted(c.links.values(), key=lambda lk: (lk.depth, lk.soname, lk.path or ""))
        b.unresolved = sorted(c.unresolved)
        if c.truncated:
            self.truncated.append(b.path)

    # -- used_by ---------------------------------------------------------------
    def apply_used_by(self, used_by: Mapping[str, Sequence[str]]) -> None:
        """Attach service ids to binaries and propagate them to script interpreters."""
        for raw, services in used_by.items():
            cpath = self.resolver.canonical(raw) or normalize(raw)
            stack = [cpath]
            seen: set[str] = set()
            while stack:
                p = stack.pop()
                if p in seen:
                    continue
                seen.add(p)
                b = self.results.get(p)
                if b is not None:
                    b.used_by = sorted({*b.used_by, *services})
                stack.extend(self.interp_edges.get(p, ()))


def analyze_executables(
    ctx: ScanContext,
    paths: Iterable[str],
    owners: FileOwnerIndex,
    *,
    max_depth: int | None = None,
    used_by: Mapping[str, list[str]] | None = None,
) -> dict[str, Binary]:
    """Analyse executables; return ``{canonical path: Binary}`` sorted by path.

    Script interpreters are analysed too and appear in the result.  Paths that
    do not exist in the root are skipped (counted in one warning).  With
    ``ctx.options.link_analysis`` disabled only stat/ownership/kind are filled.
    ``max_depth`` defaults to ``ctx.options.max_link_depth``.
    """
    depth = ctx.options.max_link_depth if max_depth is None else max_depth
    analyzer = BinaryAnalyzer(ctx, owners, max_depth=depth)
    link = ctx.options.link_analysis
    missing = 0
    for p in sorted(set(paths)):
        if not isinstance(p, str) or not p.startswith("/"):
            missing += 1
            continue
        try:
            if analyzer.analyse(p, link_analysis=link) is None:
                missing += 1
        except (RootFSError, OSError, ValueError) as exc:
            missing += 1
            ctx.fs.warnings.append(f"binary analysis failed for {p}: {exc}")
    if used_by:
        analyzer.apply_used_by(used_by)
    if missing:
        ctx.warn(f"{missing} executable path(s) could not be analysed (missing or unreadable)")
    if analyzer.truncated:
        ctx.limit(
            f"library closure truncated at {MAX_LIBS_PER_BINARY} objects for "
            f"{len(analyzer.truncated)} binary(ies)"
        )
    return {k: analyzer.results[k] for k in sorted(analyzer.results)}
