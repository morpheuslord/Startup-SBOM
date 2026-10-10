"""Exception hierarchy for startup-sbom."""

from __future__ import annotations


class StartupSBOMError(Exception):
    """Base class for all errors raised by startup-sbom."""


class TargetError(StartupSBOMError):
    """The scan target could not be opened, validated or acquired."""


class RootFSError(StartupSBOMError):
    """An operation on the analysed root filesystem failed or was refused."""


class PathNotFoundError(RootFSError, FileNotFoundError):
    """A path does not exist inside the analysed root filesystem."""


class SymlinkLoopError(RootFSError):
    """Symlink resolution exceeded the hop budget."""


class NotADirError(RootFSError, NotADirectoryError):
    """A path component that must be a directory is not one."""


class ReadLimitError(RootFSError):
    """A file exceeded the configured read limit."""


class ParseError(StartupSBOMError):
    """A package database or configuration file could not be parsed."""


class NetworkError(StartupSBOMError):
    """A remote data source could not be reached or returned bad data."""


class OutputError(StartupSBOMError):
    """A report could not be written."""


class ScanCancelledError(StartupSBOMError):
    """The scan was cancelled through its cancel event."""
