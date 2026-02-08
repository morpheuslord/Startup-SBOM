import os
import re
from typing import List
from ..core.base_init import BaseInitAnalyzer
from ..models.package_info import ServiceMetadata

class SysVInitAnalyzer(BaseInitAnalyzer):
    """
    Analyzer for SysV Init System.
    Parses /etc/init.d and /etc/rc*.d.
    """

    def detect(self, volume_path: str) -> bool:
        # Presence of /etc/init.d is a strong signal, but Systemd also has it for compatibility.
        # We might check for absence of systemd? 
        # Or just return True and let main.py decide priority (Systemd > SysV).
        return os.path.isdir(os.path.join(volume_path, "etc/init.d")) and \
               not os.path.exists(os.path.join(volume_path, "run/systemd/system")) # Runtime check? No, we are static.

    def get_all_services(self, volume_path: str) -> List[ServiceMetadata]:
        services = []
        init_d = os.path.join(volume_path, "etc/init.d")
        if not os.path.exists(init_d):
            return []
            
        for f in os.listdir(init_d):
            full_path = os.path.join(init_d, f)
            if os.path.isfile(full_path) and not f.startswith('.'):
                 # It's a service script
                 execs = self.parse_service_executables(full_path)
                 services.append(ServiceMetadata(
                     name=f,
                     path=full_path,
                     status="unknown", # hard to tell without checking rc.d links
                     executables=execs,
                     executable_names=[os.path.basename(p) for p in execs]
                 ))
        return services

    def get_startup_services(self, volume_path: str) -> List[ServiceMetadata]:
        # Check Default Runlevel? usually 3 or 5.
        # Let's check all runlevels or just 3/5.
        # /etc/inittab might define default.
        
        # Taking a broad approach: Check rc2.d, rc3.d, rc4.d, rc5.d
        target_runlevels = ["2", "3", "4", "5"]
        startup_services = []
        seen = set()
        
        for rl in target_runlevels:
            rc_dir = os.path.join(volume_path, f"etc/rc{rl}.d")
            if not os.path.exists(rc_dir):
                continue
                
            for link in os.listdir(rc_dir):
                if link.startswith("S"): # Start script
                    service_name = link[3:] # S01nginx -> nginx
                    if service_name in seen: continue
                    seen.add(service_name)
                    
                    # Resolve to init.d script
                    # Usually /etc/rc3.d/S01nginx -> ../init.d/nginx
                    link_path = os.path.join(rc_dir, link)
                    real_path = os.path.realpath(link_path)
                    
                    # Fix volume path references if realpath resolves to host /etc/init.d
                    # If we are analyzing a mounted volume, realpath might point to /mnt/etc/init.d which is good.
                    
                    # If verify it exists
                    if not os.path.exists(real_path):
                        # Construct from volume
                        real_path = os.path.join(volume_path, "etc/init.d", service_name)
                    
                    if os.path.exists(real_path):
                        execs = self.parse_service_executables(real_path)
                        startup_services.append(ServiceMetadata(
                            name=service_name,
                            path=real_path,
                            status="enabled",
                            executables=execs,
                            executable_names=[os.path.basename(p) for p in execs]
                        ))
        return startup_services

    def parse_service_executables(self, service_path: str) -> List[str]:
        # Implicitly, the script itself is an executable
        execs = [service_path]
        
        # Try to find DAEMON variable or simple calls
        try:
            with open(service_path, 'r', errors='ignore') as f:
                content = f.read()
                # Look for DAEMON=/usr/sbin/foo
                matches = re.findall(r'^(?:DAEMON|BINARY|COMMAND)=["\']?([^"\']+)["\']?', content, re.MULTILINE)
                for m in matches:
                    path = m.strip()
                    if path.startswith("/"):
                        execs.append(path)
        except Exception:
            pass
            
        return list(set(execs))
