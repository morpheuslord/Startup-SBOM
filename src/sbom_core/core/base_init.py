from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from ..models.package_info import ServiceMetadata

class BaseInitAnalyzer(ABC):
    """
    Abstract base class for Init System Analyzers (Systemd, SysV, OpenRC, etc.).
    Responsibility: Find *what* is running or configured to run.
    """

    @abstractmethod
    def detect(self, volume_path: str) -> bool:
        """
        Detects if this init system is present in the volume.
        """
        pass

    @abstractmethod
    def get_all_services(self, volume_path: str) -> List[ServiceMetadata]:
        """
        Returns a list of all services/units found in the system configuration.
        Should populate: name, path, status (if possible).
        """
        pass

    @abstractmethod
    def get_startup_services(self, volume_path: str) -> List[ServiceMetadata]:
        """
        Returns a list of services that are enabled to start at boot.
        """
        pass
        
    @abstractmethod
    def parse_service_executables(self, service_path: str) -> List[str]:
        """
        Extracts executable paths from a specific service definition file.
        """
        pass
