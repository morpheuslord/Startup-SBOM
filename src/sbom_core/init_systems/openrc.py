import os
import re
from typing import List
from ..core.base_init import BaseInitAnalyzer
from ..models.package_info import ServiceMetadata

class OpenRCAnalyzer(BaseInitAnalyzer):
    """
    Analyzer for OpenRC Init System (common in Alpine, Gentoo).
    Parses /etc/init.d and /etc/runlevels.
    """

    def detect(self, volume_path: str) -> bool:
        return os.path.exists(os.path.join(volume_path, "etc/runlevels"))

    def get_all_services(self, volume_path: str) -> List[ServiceMetadata]:
        services = []
        init_d = os.path.join(volume_path, "etc/init.d")
        if not os.path.isdir(init_d):
            return []
            
        for f in os.listdir(init_d):
            full_path = os.path.join(init_d, f)
            if os.path.isfile(full_path) and not f.startswith('.'):
                 execs = self.parse_service_executables(full_path)
                 services.append(ServiceMetadata(
                     name=f,
                     path=full_path,
                     status="unknown",
                     executables=execs,
                     executable_names=[os.path.basename(p) for p in execs]
                 ))
        return services

    def get_startup_services(self, volume_path: str) -> List[ServiceMetadata]:
        # Check 'boot' and 'default' runlevels
        runlevels = ["boot", "default"]
        startup_services = []
        seen = set()
        
        for rl in runlevels:
            rl_dir = os.path.join(volume_path, f"etc/runlevels/{rl}")
            if not os.path.isdir(rl_dir):
                continue
                
            for link in os.listdir(rl_dir):
                # Symlinks to /etc/init.d/foo
                if link in seen: continue
                seen.add(link)
                
                # Check target
                link_path = os.path.join(rl_dir, link)
                real_path = ""
                
                # Resolve
                if os.path.islink(link_path):
                     target = os.readlink(link_path)
                     if target.startswith("/"):
                         real_path = os.path.join(volume_path, target.lstrip("/"))
                     else:
                         real_path = os.path.normpath(os.path.join(rl_dir, target))
                else:
                    real_path = link_path # unlikely for openrc
                
                if not os.path.exists(real_path):
                     # Fallback
                     real_path = os.path.join(volume_path, "etc/init.d", link)
                
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
        # OpenRC variables often: command="/usr/bin/foo"
        execs = [service_path]
        try:
            with open(service_path, 'r', errors='ignore') as f:
                content = f.read()
                # Look for command=...
                # Handles command="/bin/foo" or command=/bin/foo
                matches = re.findall(r'^command=["\']?([^"\']+)["\']?', content, re.MULTILINE)
                for m in matches:
                    path = m.strip()
                    if path.startswith("/"):
                        execs.append(path)
                        
                # Also check for command_args if command is a supervisor?
                # Usually command is the main binary.
        except Exception:
            pass
        return list(set(execs))
