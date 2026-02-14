"""
CVE Analyzer Module

Provides CVE vulnerability analysis for packages using the NIST NVD API.
Uses nvdlib to query the National Vulnerability Database.
"""

import os
import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

try:
    import nvdlib
    NVDLIB_AVAILABLE = True
except ImportError:
    NVDLIB_AVAILABLE = False


@dataclass
class CVEResult:
    """Model representing a CVE vulnerability."""
    cve_id: str
    severity: Optional[str] = None
    score: Optional[float] = None
    description: Optional[str] = None


class CVEAnalyzer:
    """
    Analyzes packages for known CVE vulnerabilities using the NVD API.
    
    Attributes:
        api_key: Optional NVD API key for faster rate limits
        delay: Delay between API requests (6s default, 0.6s with API key)
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the CVE analyzer.
        
        Args:
            api_key: NVD API key. If not provided, checks NVD_API_KEY env var.
        """
        if not NVDLIB_AVAILABLE:
            # We don't raise here to allow instantiation, but methods should check availability
            pass
        
        self.api_key = api_key or os.environ.get('NVD_API_KEY')
        # With API key: 0.6s delay, without: 6s delay (NVD recommendation)
        self.delay = 0.6 if self.api_key else 6
    
    def normalize_package_name(self, package_name: str) -> str:
        """
        Normalize package name for NVD search.
        
        Removes architecture suffixes and normalizes common patterns.
        """
        # Remove architecture suffixes like :amd64, :i386
        name = re.sub(r':[a-zA-Z0-9]+$', '', package_name)
        # Remove common prefixes/suffixes that won't help in search
        name = re.sub(r'^(lib|python3?-)|(-(dev|bin|common|doc|data))$', '', name)
        return name.lower().strip()
    
    def normalize_version(self, version: str) -> str:
        """
        Extract the core version number from distro-specific version strings.
        
        Examples:
            "1:8.2p1-4ubuntu0.13" -> "8.2"
            "2.0.9" -> "2.0.9"
            "245.4-4ubuntu3.21" -> "245.4"
        """
        if not version:
            return ""
        
        # Remove epoch (e.g., "1:" prefix)
        version = re.sub(r'^\d+:', '', version)
        
        # Extract version before distro-specific suffixes
        # Match patterns like: X.Y.Z, X.Y, or X.Yp1
        match = re.match(r'^(\d+(?:\.\d+)*(?:p\d+)?)', version)
        if match:
            return match.group(1)
        
        return version.split('-')[0] if '-' in version else version
    
    def lookup_cves(
        self, 
        package_name: str, 
        version: Optional[str] = None,
        max_results: int = 25
    ) -> List[CVEResult]:
        """
        Look up CVEs for a given package and optional version.
        
        Args:
            package_name: Name of the package to search for
            version: Optional version to filter results
            max_results: Maximum number of CVEs to return
            
        Returns:
            List of CVEResult objects representing found vulnerabilities
        """
        if not NVDLIB_AVAILABLE:
            return []
        
        normalized_name = self.normalize_package_name(package_name)
        normalized_version = self.normalize_version(version) if version else None
        
        # Build search keyword
        keyword = normalized_name
        if normalized_version:
            keyword = f"{normalized_name} {normalized_version}"
        
        try:
            # Search NVD with keyword
            search_params = {
                'keywordSearch': keyword,
                'keywordExactMatch': False,
                'delay': self.delay
            }
            
            if self.api_key:
                search_params['key'] = self.api_key
            
            results = nvdlib.searchCVE(**search_params)
            
            cve_list: List[CVEResult] = []
            for cve in results[:max_results]:
                # Extract severity and score (prefer CVSS v3.1)
                severity = None
                score = None
                
                if hasattr(cve, 'v31severity') and cve.v31severity:
                    severity = cve.v31severity
                    score = cve.v31score if hasattr(cve, 'v31score') else None
                elif hasattr(cve, 'v30severity') and cve.v30severity:
                    severity = cve.v30severity
                    score = cve.v30score if hasattr(cve, 'v30score') else None
                elif hasattr(cve, 'v2severity') and cve.v2severity:
                    severity = cve.v2severity
                    score = cve.v2score if hasattr(cve, 'v2score') else None
                
                # Extract description
                description = None
                if hasattr(cve, 'descriptions') and cve.descriptions:
                    for desc in cve.descriptions:
                        if hasattr(desc, 'lang') and desc.lang == 'en':
                            description = desc.value[:200] + "..." if len(desc.value) > 200 else desc.value
                            break
                
                cve_result = CVEResult(
                    cve_id=cve.id,
                    severity=severity,
                    score=score,
                    description=description
                )
                cve_list.append(cve_result)
            
            return cve_list
            
        except Exception as e:
            # Use standard print or logging here
            print(f"[CVE Analyzer] Error looking up CVEs for {package_name}: {e}")
            return []
    
    def analyze_packages(
        self, 
        packages: List[Dict[str, Any]],
        show_progress: bool = True
    ) -> Dict[str, List[CVEResult]]:
        """
        Analyze multiple packages for CVE vulnerabilities.
        
        Args:
            packages: List of dicts with 'Package' and 'Version' keys
            show_progress: Whether to print progress updates
            
        Returns:
            Dict mapping package names to lists of CVEResult objects
        """
        if not NVDLIB_AVAILABLE:
             print("[CVE Analysis] nvdlib not available. Install with: pip install nvdlib")
             return {}

        results: Dict[str, List[CVEResult]] = {}
        total = len(packages)
        
        for idx, pkg in enumerate(packages, 1):
            package_name = pkg.get('Package') or pkg.get('package')
            version = pkg.get('Version') or pkg.get('version')
            
            if not package_name:
                continue
            
            if show_progress:
                print(f"[CVE Analyzer] Scanning {idx}/{total}: {package_name} ({version or 'unknown version'})")
            
            cves = self.lookup_cves(package_name, version)
            results[package_name] = cves
            
            if show_progress and cves:
                critical_count = sum(1 for c in cves if c.severity == 'CRITICAL')
                high_count = sum(1 for c in cves if c.severity == 'HIGH')
                if critical_count or high_count:
                    print(f"  ⚠️  Found {len(cves)} CVEs ({critical_count} CRITICAL, {high_count} HIGH)")
        
        return results

    def get_vulnerability_summary(
        self, 
        cves: List[CVEResult]
    ) -> Dict[str, Any]:
        """
        Generate a summary of vulnerabilities.
        """
        summary = {
            'total': len(cves),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0,
            'risk_level': 'NONE'
        }
        
        for cve in cves:
            if cve.severity == 'CRITICAL':
                summary['critical'] += 1
            elif cve.severity == 'HIGH':
                summary['high'] += 1
            elif cve.severity == 'MEDIUM':
                summary['medium'] += 1
            elif cve.severity == 'LOW':
                summary['low'] += 1
            else:
                summary['unknown'] += 1
        
        # Determine overall risk level
        if summary['critical'] > 0:
            summary['risk_level'] = 'CRITICAL'
        elif summary['high'] > 0:
            summary['risk_level'] = 'HIGH'
        elif summary['medium'] > 0:
            summary['risk_level'] = 'MEDIUM'
        elif summary['low'] > 0:
            summary['risk_level'] = 'LOW'
        
        return summary

def check_nvdlib_available() -> bool:
    """Check if nvdlib is available for import."""
    return NVDLIB_AVAILABLE
