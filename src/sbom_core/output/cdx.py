import json
import os
from typing import List, Dict, Any
from ..models.package_info import AnalysisResult

def get_linux_distribution() -> str:
    """Detects Linux distribution for PURL generation."""
    if os.path.isfile("/etc/os-release"):
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("ID="):
                        dist_id = line.split("=")[1].strip().lower().replace('"', '')
                        if dist_id in ["ubuntu", "debian"]:
                            return "debian"
                        elif dist_id in ["centos", "rhel", "fedora"]:
                            return "rpm" # rpm is package type, redhat is namespace usually?
                            # Legacy code returned 'redhat' for centos/rhel
                        elif dist_id == "arch":
                             return "arch" # arch linux
                        else:
                             return "generic"
        except Exception:
            pass
            
    if os.path.isfile("/etc/debian_version"):
        return "debian"
    elif os.path.isfile("/etc/redhat-release"):
        return "redhat"
    elif os.path.isfile("/etc/arch-release"):
        return "arch"
    else:
        return "unknown"

def generate_cyclonedx(result: AnalysisResult) -> Dict[str, Any]:
    """Converts AnalysisResult to CycloneDX format."""
    components = []
    distro = get_linux_distribution()
    
    # Process Packages
    for pkg in result.packages:
        purl = f"pkg:{distro}/{pkg.name}@{pkg.version}"
        component = {
            "type": "application", # or library?
            "name": pkg.name,
            "version": pkg.version,
            "group": "Application", # Legacy default
            "purl": purl,
            "bom-ref": purl
        }
        
        # Add vulnerabilities if present
        if pkg.vulnerabilities:
            # CDX v1.4+ supports vulnerabilities in extra component or services?
            # Legacy code put them in custom output or just relied on custom fields?
            # Legacy cdx.py `CycloneDXComponent` class kept 'purl' etc.
            # But the actual JSON output structure in legacy seemed to just list components.
            # Convert_to_cdx... functions in legacy just returned a dict with "components": [...]
            # And specific fields.
            
            # Legacy custom_output: 
            # { "name": ..., "version": ..., "group": ..., "purl": ... }
            # It didn't seem to include vulnerabilities in the CDX component definition
            # But chroot/static service entries outputted by legacy had "Vulnerabilities" field.
            # Wait, `convert_to_cdx...` functions in legacy loop over entries and create `CycloneDXComponent`.
            # `CycloneDXComponent.custom_output()` returns name, version, group, purl.
            # It DOES NOT return vulnerabilities.
            # So legacy CDX export LOST the vulnerability data? 
            # Let's check `convert_to_cdx_apt_chroot`.
            # It creates CycloneDXComponent and appends .custom_output().
            # Yes, valid CDX output usually doesn't stick arbitrary fields in components list easily defined this way.
            pass
        
        components.append(component)
        
    # Process Services (if they are treated as components?)
    # Legacy rpm static service had logic to add services as components.
    # Apt static service did too.
    # "Package" and "Version" from service entry.
    
    # In our model, services are separate but linked to packages.
    # If we want to strictly follow legacy, we represent what was found.
    # But usually SBOMs list Packages. Services are effectively instances of packages running.
    # To avoid duplication, we might just list packages.
    # Legacy code seemed to map entries (which were services) to components.
    
    # Let's just output unique packages found, as that is a proper SBOM.
    # If a service has no associated package (unknown), we could list it?
    
    for svc in result.services:
        if svc.associated_package:
            # Already covered by package list?
            pass
        else:
             # Unknown package service
             purl = f"pkg:{distro}/{svc.name}@unknown"
             components.append({
                 "type": "application",
                 "name": svc.name,
                 "version": "unknown",
                 "purl": purl,
                 "bom-ref": purl
             })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": components
    }
    return bom
