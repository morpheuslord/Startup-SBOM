"""Binary reachability: ELF metadata, loader emulation, shebangs, privileged files."""

from startup_sbom.binaries.analyze import BinaryAnalyzer, analyze_executables
from startup_sbom.binaries.elf import DlopenEntry, ElfInfo, parse_elf, read_elf
from startup_sbom.binaries.linker import LibraryResolver
from startup_sbom.binaries.privileged import find_privileged, find_unmanaged_executables
from startup_sbom.binaries.shebang import read_shebang

__all__ = [
    "BinaryAnalyzer",
    "DlopenEntry",
    "ElfInfo",
    "LibraryResolver",
    "analyze_executables",
    "find_privileged",
    "find_unmanaged_executables",
    "parse_elf",
    "read_elf",
    "read_shebang",
]
