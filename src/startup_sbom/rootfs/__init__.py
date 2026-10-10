"""Read-only, root-confined access to the analysed filesystem."""

from startup_sbom.rootfs.base import (
    DEFAULT_READ_LIMIT,
    TEXT_READ_LIMIT,
    FileStat,
    RootFS,
    lexical_join,
    normalize,
    split_posix,
)
from startup_sbom.rootfs.caps import DANGEROUS_CAPS, FileCaps, decode_vfs_cap
from startup_sbom.rootfs.directory import DirectoryRootFS
from startup_sbom.rootfs.tar import LayerBlob, LayeredTarRootFS

__all__ = [
    "DANGEROUS_CAPS",
    "DEFAULT_READ_LIMIT",
    "TEXT_READ_LIMIT",
    "DirectoryRootFS",
    "FileCaps",
    "FileStat",
    "LayerBlob",
    "LayeredTarRootFS",
    "RootFS",
    "decode_vfs_cap",
    "lexical_join",
    "normalize",
    "split_posix",
]
