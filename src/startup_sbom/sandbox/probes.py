"""Chroot-mode probes: ask the target's *own* tools, in the sandbox, to confirm the scan.

Static analysis infers what the system would do; these probes let the target's
loader, service manager and package manager answer for themselves:

``loader``
    ``<target ld.so> --list <binary>`` for every analysed ELF executable.  The
    loader's answer (its own ``ld.so.cache``, hwcaps subdirectories, ``$ORIGIN``
    and RPATH handling) confirms static link closures, adds libraries the static
    resolver missed (``via="loader"``) and records libraries the loader cannot
    find.  ``--list`` maps the objects without running any of their code.
``systemd``
    ``systemctl --root=/ list-unit-files``: the manager's own verdict on which
    units are enabled, static, masked or aliases.  Disagreements are recorded as
    evidence on the service; the probe never switches a service off, so a hostile
    target cannot hide one.
``packages``
    ``dpkg-query`` / ``rpm -qa`` / ``apk info`` / ``pacman -Q``: the package
    manager's inventory, compared with what the database parsers read.

Every probe is bounded (binary count, total time) and a failing probe is a
coverage note, never a scan failure.  All output is untrusted text from the
target and is parsed defensively.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from startup_sbom.context import ScanContext
from startup_sbom.log import ops
from startup_sbom.models import Binary, Confidence, LibraryLink, Service
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.sandbox.runner import Sandbox

MAX_LOADER_BINARIES = 400
LOADER_BUDGET = 120.0
_LDD_LINE = re.compile(
    r"^\s*(?P<name>\S+)(?:\s+=>\s+(?P<path>not found|/\S*))?(?:\s+\(0x[0-9a-fA-F]+\))?\s*$"
)
_VDSO = re.compile(r"^linux-(?:vdso|gate)\.so")
_UNIT_LINE = re.compile(r"^(?P<unit>\S+\.(?:service|socket|timer|path))\s+(?P<state>[a-z-]+)")
_ENABLED_STATES = frozenset(
    {"enabled", "enabled-runtime", "linked", "linked-runtime", "indirect", "alias"}
)


@dataclass(slots=True)
class ProbeOutcome:
    """What one probe did (for coverage, digests and the journal)."""

    name: str
    ran: bool
    summary: str
    changes: int = 0
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- loader
def parse_loader_list(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """``ld.so --list`` output → ``([(soname, path)], [unresolved sonames])``."""
    found: list[tuple[str, str]] = []
    missing: list[str] = []
    for raw in text.splitlines()[:4096]:
        m = _LDD_LINE.match(raw)
        if m is None:
            continue
        name, path = m.group("name"), m.group("path")
        if _VDSO.match(name) or name.startswith("statically"):
            continue
        if path == "not found":
            missing.append(name)
        elif path:
            found.append((name, path))
        elif name.startswith("/"):
            found.append((name.rsplit("/", 1)[-1], name))  # the interpreter itself
    return found, missing


def loader_probe(
    ctx: ScanContext,
    sandbox: Sandbox,
    binaries: Iterable[Binary],
    owners: FileOwnerIndex,
) -> ProbeOutcome:
    elves = [b for b in binaries if b.kind == "elf" and b.interpreter]
    if not elves:
        return ProbeOutcome("loader", False, "no dynamically linked executables to confirm")
    started = time.monotonic()
    confirmed = added = unresolved = checked = 0
    skipped = 0
    for b in sorted(elves, key=lambda x: (not (x.used_by or x.setuid), x.path)):
        if checked >= MAX_LOADER_BINARIES or time.monotonic() - started > LOADER_BUDGET:
            skipped += 1
            continue
        interp = b.interpreter or ""
        if ctx.fs.try_resolve(interp) is None:
            continue
        res = sandbox.run([interp, "--list", b.path], timeout=10.0)
        checked += 1
        if not res.ok:
            continue
        pairs, missing = parse_loader_list(res.stdout)
        known = {li.path for li in b.libraries if li.path}
        direct = set(b.needed)
        for soname, path in pairs:
            canon = ctx.fs.try_resolve(path) or path
            if canon in (b.path, interp):
                continue
            if canon in known:
                confirmed += 1
                continue
            known.add(canon)
            added += 1
            b.libraries.append(
                LibraryLink(
                    soname=soname,
                    path=canon,
                    package=_owner(owners, canon),
                    via="loader",
                    confidence=Confidence.HIGH,
                    depth=1 if soname in direct else 2,
                )
            )
        for soname in missing:
            if soname not in b.unresolved:
                b.unresolved.append(soname)
                unresolved += 1
    summary = (
        f"target loader confirmed {confirmed:,} library link(s) across {checked:,} "
        f"executable(s), added {added:,} the static resolver missed"
    )
    if unresolved:
        summary += f", {unresolved:,} library(ies) the loader cannot find"
    outcome = ProbeOutcome("loader", True, summary, changes=added)
    if skipped:
        outcome.notes.append(f"loader probe skipped {skipped:,} executable(s) (count/time budget)")
    return outcome


def _owner(owners: FileOwnerIndex, path: str) -> str | None:
    try:
        return owners.owner(path)
    except Exception:  # noqa: BLE001 - ownership is best effort
        return None


# --------------------------------------------------------------------------- systemd
def parse_unit_files(text: str) -> dict[str, str]:
    """``systemctl list-unit-files --no-legend`` output → ``{unit: state}``."""
    out: dict[str, str] = {}
    for raw in text.splitlines()[:20_000]:
        m = _UNIT_LINE.match(raw.strip())
        if m is not None:
            out[m.group("unit")] = m.group("state")
    return out


def systemd_probe(ctx: ScanContext, sandbox: Sandbox, services: list[Service]) -> ProbeOutcome:
    systemctl = next(
        (p for p in ("/usr/bin/systemctl", "/bin/systemctl") if ctx.fs.try_resolve(p)), None
    )
    units = [s for s in services if s.init_system.value == "systemd"]
    if systemctl is None or not units:
        return ProbeOutcome("systemd", False, "no systemctl or no systemd units in the target")
    res = sandbox.run(
        [systemctl, "--root=/", "list-unit-files", "--no-legend", "--no-pager", "--full"],
        timeout=30.0,
    )
    states = parse_unit_files(res.stdout) if res.ok else {}
    if not states:
        return ProbeOutcome("systemd", False, "systemctl --root=/ list-unit-files gave no answer")
    masked = disagree = 0
    for svc in units:
        state = states.get(svc.name)
        if state is None:
            continue
        if state.startswith("masked") and not svc.masked:
            # Evidence only: a hostile target's systemctl must never be able to hide
            # a service from the report.  Static analysis owns the verdict.
            svc.evidence.append(
                f"systemctl (chroot probe) reports {state}, but no mask was found on disk; "
                "kept as started (the probe confirms, it never suppresses)"
            )
            masked += 1
            continue
        says_enabled = state in _ENABLED_STATES
        if says_enabled != svc.enabled and state not in ("static", "generated", "transient"):
            svc.evidence.append(
                f"systemctl (chroot probe) reports {state}; static analysis had "
                f"enabled={svc.enabled}"
            )
            disagree += 1
    summary = (
        f"systemctl agrees on {len(units) - masked - disagree:,} of {len(units):,} unit(s)"
        + (f"; {masked:,} unit(s) it calls masked kept (no mask on disk)" if masked else "")
        + (f"; {disagree:,} enablement disagreement(s) recorded" if disagree else "")
    )
    return ProbeOutcome("systemd", True, summary)


# --------------------------------------------------------------------------- packages
@dataclass(frozen=True, slots=True)
class _PkgQuery:
    db: str
    candidates: tuple[str, ...]
    args: tuple[str, ...]
    parse: Callable[[str], set[tuple[str, str]]]


def _tsv(text: str) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for line in text.splitlines()[:200_000]:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            if len(parts) >= 3 and not parts[2].startswith(("ii", "hi", "iU", "iF")):
                continue  # dpkg: not installed
            out.add((parts[0].split(":", 1)[0], parts[1]))
    return out


def _rpm(text: str) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for line in text.splitlines()[:200_000]:
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] and parts[0] != "gpg-pubkey":
            ver = parts[1].removeprefix("0:")
            out.add((parts[0], ver))
    return out


def _space(text: str) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for line in text.splitlines()[:200_000]:
        parts = line.split()
        if len(parts) == 2:
            out.add((parts[0], parts[1]))
    return out


_APK_RE = re.compile(r"^(?P<name>.+)-(?P<ver>\d[^-]*-r\d+)$")


def _apk(text: str) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for line in text.splitlines()[:200_000]:
        m = _APK_RE.match(line.strip())
        if m is not None:
            out.add((m.group("name"), m.group("ver")))
    return out


QUERIES: tuple[_PkgQuery, ...] = (
    _PkgQuery(
        "dpkg",
        ("/usr/bin/dpkg-query",),
        ("-W", "-f", "${binary:Package}\t${Version}\t${db:Status-Abbrev}\n"),
        _tsv,
    ),
    _PkgQuery(
        "rpm",
        ("/usr/bin/rpm", "/bin/rpm"),
        ("-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n"),
        _rpm,
    ),
    _PkgQuery("apk", ("/sbin/apk", "/usr/bin/apk"), ("info", "-v"), _apk),
    _PkgQuery("alpm", ("/usr/bin/pacman",), ("-Q",), _space),
)


_PTYPE = {"dpkg": "deb", "rpm": "rpm", "apk": "apk", "alpm": "alpm"}


def packages_probe(
    ctx: ScanContext, sandbox: Sandbox, records: list[PackageRecord], databases: list[str]
) -> ProbeOutcome:
    results: list[str] = []
    notes: list[str] = []
    ran = False
    for q in QUERIES:
        if q.db not in databases:
            continue
        exe = next((p for p in q.candidates if ctx.fs.try_resolve(p)), None)
        if exe is None:
            continue
        res = sandbox.run([exe, *q.args], timeout=60.0)
        theirs = q.parse(res.stdout) if res.ok else set()
        if not theirs:
            notes.append(f"{q.db}: {exe} gave no usable answer in the sandbox")
            continue
        ran = True
        ptype = _PTYPE[q.db]
        ours = {
            (r.package.name, _plain_version(r.package.version))
            for r in records
            if r.package.type.value == ptype
        }
        theirs = {(n, _plain_version(v)) for n, v in theirs}
        only_tool = theirs - ours
        only_parser = ours - theirs
        if not only_tool and not only_parser:
            results.append(f"{q.db}: package manager agrees on all {len(ours):,} package(s)")
            continue
        results.append(
            f"{q.db}: {len(theirs & ours):,} agree, {len(only_tool):,} only reported by the "
            f"package manager, {len(only_parser):,} only by the database parser"
        )
        sample = sorted(only_tool)[:5]
        if sample:
            ctx.warn(
                f"chroot probe: {q.db} reports {len(only_tool):,} package(s) the database "
                f"parser did not read (e.g. {', '.join(f'{n} {v}' for n, v in sample)})"
            )
    if not ran:
        return ProbeOutcome("packages", False, "no package manager answered", notes=notes)
    return ProbeOutcome("packages", True, "; ".join(results), notes=notes)


def _plain_version(version: str) -> str:
    return version.removeprefix("0:")


# --------------------------------------------------------------------------- entry
def run_all(
    ctx: ScanContext,
    sandbox: Sandbox,
    *,
    services: list[Service],
    binaries: Iterable[Binary],
    records: list[PackageRecord],
    databases: list[str],
    owners: FileOwnerIndex,
) -> list[ProbeOutcome]:
    """Run every probe, isolating failures."""
    out: list[ProbeOutcome] = []
    bins = list(binaries)
    probes: list[tuple[str, Callable[[], ProbeOutcome]]] = [
        ("systemd", lambda: systemd_probe(ctx, sandbox, services)),
        ("loader", lambda: loader_probe(ctx, sandbox, bins, owners)),
        ("packages", lambda: packages_probe(ctx, sandbox, records, databases)),
    ]
    for name, probe in probes:
        try:
            outcome = probe()
        except Exception as exc:  # noqa: BLE001 - a probe never aborts the scan
            outcome = ProbeOutcome(name, False, f"failed: {type(exc).__name__}: {exc}")
        ops.info("probe %s: %s", outcome.name, outcome.summary)
        for note in outcome.notes:
            ctx.limit(note)
        out.append(outcome)
    return out
