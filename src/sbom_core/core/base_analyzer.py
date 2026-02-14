from abc import ABC, abstractmethod
from typing import Optional
from .context import AnalysisContext
from ..models.package_info import AnalysisResult

class BaseAnalyzer(ABC):
    """Abstract base class for all package manager analyzers."""

    @abstractmethod
    def detect(self, volume_path: str) -> bool:
        """
        Determines if this analyzer can handle the given volume.
        
        Args:
            volume_path: Path to the root of the filesystem to analyze.
            
        Returns:
            True if this analyzer detects its package manager, False otherwise.
        """
        pass

    @abstractmethod
    def analyze_static(self, context: AnalysisContext) -> AnalysisResult:
        """
        Performs static analysis on the volume.
        
        Args:
            context: Analysis parameters.
            
        Returns:
            AnalysisResult containing discovered packages and metadata.
        """
        pass

    @abstractmethod
    def analyze_chroot(self, context: AnalysisContext) -> AnalysisResult:
        """
        Performs analysis within a chroot environment (or simulation of it).
        
        Args:
            context: Analysis parameters.
            
        Returns:
            AnalysisResult containing discovered packages and metadata.
        """
        pass
