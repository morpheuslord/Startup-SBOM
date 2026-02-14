from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class FileMetadata:
    path: str
    size: int = 0
    permissions: str = ""
    owner: str = ""
    group: str = ""
    checksum: str = ""
    file_type: str = "" # e.g., "file", "directory", "symlink"

@dataclass
class PackageMetadata:
    name: str
    version: str
    architecture: str = ""
    description: str = ""
    maintainer: str = ""
    homepage: str = ""
    license: str = ""
    source_package: str = ""
    installed_size: int = 0
    files: List[FileMetadata] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list) 

@dataclass
class ServiceMetadata:
    name: str
    status: str = "unknown" # active, enabled, disabled, etc.
    path: str = ""
    associated_package: Optional[str] = None
    version: str = "unknown"
    executables: List[str] = field(default_factory=list)
    executable_names: List[str] = field(default_factory=list)
    execution_time: str = ""
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class AnalysisResult:
    packages: List[PackageMetadata] = field(default_factory=list)
    services: List[ServiceMetadata] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
