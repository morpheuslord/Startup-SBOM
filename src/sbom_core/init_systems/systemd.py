import os
import re
from typing import List, Dict, Optional
from rich import print
from ..core.base_init import BaseInitAnalyzer
from ..models.package_info import ServiceMetadata

class SystemdAnalyzer(BaseInitAnalyzer):
    """
    Analyzer for Systemd Init System.
    Parses /usr/lib/systemd/system and /etc/systemd/system for unit files.
    """

    def detect(self, volume_path: str) -> bool:
        """
        Checks for systemd directories.
        """
        # Common locations
        paths = [
            "usr/lib/systemd/system",
            "lib/systemd/system",
            "etc/systemd/system"
        ]
        for p in paths:
            if os.path.isdir(os.path.join(volume_path, p)):
                return True
        return False

    def get_all_services(self, volume_path: str) -> List[ServiceMetadata]:
        """
        Lists all .service files found in standard systemd paths.
        """
        services = []
        seen = set()
        
        search_paths = [
            "etc/systemd/system",
            "usr/lib/systemd/system",
            "lib/systemd/system"
        ]
        
        for sp in search_paths:
            full_path = os.path.join(volume_path, sp)
            if not os.path.isdir(full_path):
                continue
                
            for f in os.listdir(full_path):
                if f.endswith(".service"):
                    if f in seen: continue
                    seen.add(f)
                    
                    service_path = os.path.join(full_path, f)
                    
                    # Basic status check (enabled?)
                    # To check if enabled, we look at symlinks in /etc/systemd/system/multi-user.target.wants/ etc.
                    status = self._check_status(volume_path, f)
                    
                    services.append(ServiceMetadata(
                        name=f,
                        path=service_path,
                        status=status,
                        executables=self.parse_service_executables(service_path),
                        # executable_names populated later? Or here?
                    ))
        
        # Populate executable names
        for s in services:
            s.executable_names = [os.path.basename(p) for p in s.executables]
            
        return services

    def get_startup_services(self, volume_path: str) -> List[ServiceMetadata]:
        """
        Returns enabled services.
        Heuristic: Check 'wants' directories in /etc/systemd/system.
        """
        startup_services = []
        wants_dirs = [
            "etc/systemd/system/multi-user.target.wants",
            "etc/systemd/system/graphical.target.wants",
            "etc/systemd/system/sysinit.target.wants"
        ]
        
        seen = set()
        
        for wd in wants_dirs:
            full_path = os.path.join(volume_path, wd)
            if not os.path.isdir(full_path):
                continue
                
            for link in os.listdir(full_path):
                # Typically symlinks to the actual service
                # We can trace it or just assume the name is correct if it ends in .service
                if link.endswith(".service"):
                    if link in seen: continue
                    seen.add(link)
                    
                    # Resolve real path to find the unit file
                    link_path = os.path.join(full_path, link)
                    real_path = link_path
                    if os.path.islink(link_path):
                         # relative link?
                         target = os.readlink(link_path)
                         # if absolute on target system (e.g. /lib/systemd/system/foo.service)
                         # we need to map to volume
                         if target.startswith("/"):
                             real_path = os.path.join(volume_path, target.lstrip("/"))
                         else:
                             # relative
                             real_path = os.path.normpath(os.path.join(full_path, target))
                    
                    # If real path doesn't exist, try finding it in standard search paths
                    if not os.path.exists(real_path):
                         # Fallback
                         found = False
                         for sp in ["etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"]:
                             candidate = os.path.join(volume_path, sp, link)
                             if os.path.exists(candidate):
                                 real_path = candidate
                                 found = True
                                 break
                    
                    if os.path.exists(real_path):
                         execs = self.parse_service_executables(real_path)
                         startup_services.append(ServiceMetadata(
                             name=link,
                             path=real_path,
                             status="enabled",
                             executables=execs,
                             executable_names=[os.path.basename(p) for p in execs]
                         ))

        return startup_services

    def parse_service_executables(self, service_path: str) -> List[str]:
        """
        Extracts ExecStart, ExecStop, ExecPre/Post.
        """
        paths = []
        try:
            with open(service_path, 'r', errors='ignore') as f:
                content = f.read()
                # Simple regex to catch Exec*=...
                # Multiline execs ending with \ are harder, this handles basic cases
                matches = re.findall(r'^(?:Exec(?:Start|Stop|Pre|Post|Reload))=(.+)$', content, re.MULTILINE)
                
                for cmd_line in matches:
                    # The command line might start with modifiers like - or @ or +
                    cmd = cmd_line.strip()
                    if not cmd: continue
                    
                    # Strip modifiers
                    while cmd and cmd[0] in ['-', '@', '+', '!', ':']:
                        cmd = cmd[1:]
                    
                    # Get first token
                    parts = cmd.split()
                    if parts:
                        exe = parts[0]
                        # Must be absolute path usually
                        if exe.startswith("/"):
                            paths.append(exe)
                            
        except Exception as e:
            print(f"Error parsing service {service_path}: {e}")
            
        return list(set(paths))
        
    def _check_status(self, volume_path: str, service_name: str) -> str:
        # Check if linked in wants dirs
        wants_dirs = [
            "etc/systemd/system/multi-user.target.wants",
            "etc/systemd/system/graphical.target.wants",
            "etc/systemd/system/sysinit.target.wants"
        ]
        for wd in wants_dirs:
            if os.path.exists(os.path.join(volume_path, wd, service_name)):
                return "enabled"
        return "disabled" # Default assumption if present but not linked
