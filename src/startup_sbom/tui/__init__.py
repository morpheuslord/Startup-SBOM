"""Interactive terminal UI for startup-sbom (optional extra ``startup-sbom[tui]``).

This package imports Textual lazily so importing :mod:`startup_sbom` (or running
the CLI) never pays for it; :func:`run` raises a friendly error when the extra
is not installed.
"""

from __future__ import annotations

from pathlib import Path

from startup_sbom.errors import StartupSBOMError

__all__ = ["run"]


def run(report_path: Path | None = None, target: str | None = None) -> None:
    """Start the TUI, optionally opening ``report_path`` or prefilling ``target``.

    Raises :class:`~startup_sbom.errors.StartupSBOMError` when the optional
    ``tui`` extra (Textual) is missing.
    """
    try:
        import textual  # noqa: F401  (presence check only; imported lazily on purpose)
    except ModuleNotFoundError as exc:
        raise StartupSBOMError(
            "the interactive TUI needs the optional 'tui' extra: pip install 'startup-sbom[tui]'"
        ) from exc
    from startup_sbom.tui.app import StartupSbomApp

    StartupSbomApp(report_path=report_path, target=target).run()
