"""Boot transaction emulation: the pull-in closure of the default target.

Starting from ``default.target`` (``initrd.target`` for initrd images, the
compile-time fallback ``graphical.target`` when absent), follows ``Wants=``,
``Requires=``, ``BindsTo=``, ``Upholds=``, ``.wants/.requires/.upholds``
directories (all names, aliases and the template), ``Sockets=``,
``Type=dbus`` and default dependencies.  Masked units are recorded and not
traversed.  Each reached unit keeps the shortest human-readable chain.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from startup_sbom.initsys.systemd.loader import Unit, UnitLoader
from startup_sbom.initsys.systemd.parser import expand_specifiers, parse_bool, split_words

PULL_KEYS = ("Wants", "Requires", "BindsTo", "Upholds")
MAX_UNITS = 20_000
MAX_PATH = 6
#: Built-in skeleton (bootup(7)) used only for targets missing from the image.
SKELETON: dict[str, list[tuple[str, str]]] = {
    "graphical.target": [("Requires", "multi-user.target")],
    "multi-user.target": [("Requires", "basic.target")],
    "basic.target": [
        ("Requires", "sysinit.target"),
        ("Wants", "sockets.target"),
        ("Wants", "timers.target"),
        ("Wants", "paths.target"),
        ("Wants", "slices.target"),
    ],
    "sysinit.target": [("Wants", "local-fs.target"), ("Wants", "swap.target")],
    "rescue.target": [("Requires", "sysinit.target")],
    "initrd.target": [("Requires", "basic.target")],
    "sockets.target": [],
    "timers.target": [],
    "paths.target": [],
    "slices.target": [],
    "local-fs.target": [],
    "swap.target": [],
    "getty.target": [],
}
FALLBACK_TARGET = "graphical.target"


@dataclass(slots=True)
class BootGraph:
    """Result of the boot traversal."""

    goal: str
    paths: dict[str, list[str]] = field(default_factory=dict)
    masked: dict[str, list[str]] = field(default_factory=dict)
    not_found: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False


def shorten(steps: list[str]) -> list[str]:
    """Keep boot paths short: first step, an ellipsis, then the last four."""
    if len(steps) <= MAX_PATH:
        return list(steps)
    return [steps[0], "…", *steps[-4:]]


def unit_dependencies(
    loader: UnitLoader, unit: Unit, table: Mapping[str, str]
) -> list[tuple[str, str]]:
    """``(dependency, label)`` pull-ins of a loaded unit (directives, dirs, implicit)."""
    out: list[tuple[str, str]] = []
    s = unit.settings
    for key in PULL_KEYS:
        for value in s.values("Unit", key):
            for word in split_words(value):
                dep = expand_specifiers(word, table)
                out.append((dep, f"{unit.name} {key}={dep}"))
    out.extend((dep, label) for _kind, dep, label in loader.enablement(unit))
    if unit.type == "service":
        for value in s.values("Service", "Sockets"):
            for word in split_words(value):
                dep = expand_specifiers(word, table)
                out.append((dep, f"{unit.name} Sockets={dep}"))
        if (s.get("Service", "Type") or "").strip() == "dbus":
            out.append(("dbus.socket", f"{unit.name} Type=dbus"))
    if (
        unit.type in ("service", "socket", "timer", "path")
        and parse_bool(s.get("Unit", "DefaultDependencies")) is not False
    ):
        out.append(("sysinit.target", f"{unit.name} (default dependencies)"))
    return out


def traverse(
    loader: UnitLoader,
    *,
    goal: str = "default.target",
    tables: Callable[[Unit], Mapping[str, str]],
) -> BootGraph:
    """Compute the boot closure from ``goal``."""
    graph = BootGraph(goal=goal)
    queue: deque[tuple[str, list[str]]] = deque([(goal, [])])
    visited: set[str] = set()
    first = True
    while queue:
        name, steps = queue.popleft()
        if name in visited:
            continue
        visited.add(name)
        unit = loader.load(name)
        if first and not unit.found and name == "default.target":
            steps = [f"default.target missing → {FALLBACK_TARGET} (built-in fallback)"]
            name = FALLBACK_TARGET
            unit = loader.load(name)
        first = False
        if unit.found and unit.name != name:
            steps = [*steps, f"{name}→{unit.name}"]
        if unit.name in graph.paths or unit.name in graph.masked:
            continue
        if unit.masked:
            graph.masked[unit.name] = shorten(steps)
            continue
        if not unit.found:
            skeleton = SKELETON.get(unit.name)
            if skeleton is None:
                graph.not_found.setdefault(unit.name, shorten(steps))
                continue
            graph.paths[unit.name] = shorten(steps)
            for kind, dep in skeleton:
                queue.append((dep, [*steps, f"{unit.name} {kind}={dep} (built-in default)"]))
            for _kind, dep, label in loader.enablement(unit):  # .wants/ dirs still apply
                queue.append((dep, [*steps, label]))
            continue
        graph.paths[unit.name] = shorten(steps)
        visited.add(unit.name)
        if len(graph.paths) >= MAX_UNITS:
            graph.truncated = True
            break
        for dep, label in unit_dependencies(loader, unit, tables(unit)):
            if dep not in visited:
                queue.append((dep, [*steps, label]))
    return graph
