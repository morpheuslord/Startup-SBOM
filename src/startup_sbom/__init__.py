"""startup-sbom: what runs at boot, what it is made of, and how it can be attacked.

Library use::

    from startup_sbom import ScanOptions, scan

    report = scan("oci-dir:./image", ScanOptions(offline=True))
    for threat in report.threats:
        print(threat.ssvc.decision if threat.ssvc else "-", threat.title)
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING, Any

try:
    __version__ = version("startup-sbom")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0+unknown"

if TYPE_CHECKING:
    from startup_sbom.context import ScanOptions
    from startup_sbom.models import Report

__all__ = ["Report", "ScanOptions", "__version__", "scan"]


def scan(target: str, options: ScanOptions | None = None, **kwargs: Any) -> Report:
    """Analyse ``target`` (see :func:`startup_sbom.pipeline.scan`)."""
    from startup_sbom.pipeline import scan as _scan

    return _scan(target, options, **kwargs)


def __getattr__(name: str) -> Any:
    if name == "ScanOptions":
        from startup_sbom.context import ScanOptions

        return ScanOptions
    if name == "Report":
        from startup_sbom.models import Report

        return Report
    raise AttributeError(name)
