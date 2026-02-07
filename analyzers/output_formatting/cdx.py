import json
import os
from pydantic import BaseModel, Field
from typing import List, Dict, Any


class CycloneDXComponent(BaseModel):
    name: str
    version: str
    group: str = "Application"
    purl: str = Field(..., alias="purl")

    class Config:
        allow_population_by_field_name = True

    def custom_output(self):
        return {
            "name": self.name,
            "version": self.version,
            "group": self.group,
            "purl": self.purl
        }


def get_linux_distribution():
    if os.path.isfile("/etc/os-release"):
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("ID="):
                    dist_id = line.split("=")[1].strip().lower()
                    if dist_id == "ubuntu" or dist_id == "debian":
                        return "debian"
                    elif dist_id == "centos" or dist_id == "rhel":
                        return "redhat"
    if os.path.isfile("/etc/debian_version"):
        return "debian"
    elif os.path.isfile("/etc/redhat-release"):
        return "redhat"
    else:
        return "unknown"


def convert_to_cdx_apt_static_service(
        json_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    components = []
    os = get_linux_distribution()
    for entry in json_data:
        name = entry["Package"]
        version = entry['ServiceInformation']['Version']
        component = CycloneDXComponent(
            name=name,
            version=version,
            purl=f"pkg:{os}/{name}@{version}"
        )
        components.append(component.custom_output())

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.3",
        "components": components
    }

    return bom


def convert_to_cdx_rpm_static_service(
        json_data: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    components = []
    os = get_linux_distribution()
    for package, package_data in json_data.items():
        name = package
        version = package_data["package_version"]
        component = {
            "name": name,
            "version": version,
            "purl": f"pkg:{os}/{name}@{version}"
        }
        components.append(component)

        if "service_names" in package_data:
            for service_name, service_info in package_data[
                    "service_names"].items():
                service_version = service_info.get("package_version", version)
                service_component = {
                    "name": service_name,
                    "version": service_version,
                    "purl": f"pkg:{os}/{name}@{service_version}"
                }
                components.append(service_component)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.3",
        "components": components
    }

    return bom


def convert_to_cdx_rpm_chroot(data):
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON data: {e}")
            return []

    components = []
    os = get_linux_distribution()
    for package_name, package_data in data.items():
        package_version = package_data['PackageVersion']

        for service_file in package_data['ServiceFiles']:
            component = {
                "name": package_name,
                "version": package_version,
                "purl": f"pkg:{os}/{package_name}@{package_version}"
            }
            components.append(component)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.3",
        "components": components
    }

    return bom


def convert_to_cdx_apt_static_info(json_data: str) -> Dict[str, Any]:
    components = []
    os = get_linux_distribution()
    for entry in json_data:
        name = entry["Package"]
        version = entry['ServiceInformation']['Version']
        component = CycloneDXComponent(
            name=name,
            version=version,
            purl=f"pkg:{os}/{name}@{version}"
        )
        components.append(component.custom_output())

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.3",
        "components": components
    }

    return bom


def convert_to_cdx_apt_chroot(json_data: str) -> Dict[str, Any]:
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Error decoding JSON data: {e}")

    components = []
    os = get_linux_distribution()
    for entry in data:
        name = entry["Package"]
        # Version is at top level in chroot_mode_entry_service.dict() output
        version = entry.get('Version', 'unknown')
        component = CycloneDXComponent(
            name=name,
            version=version,
            purl=f"pkg:{os}/{name}@{version}"
        )
        components.append(component.custom_output())

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.3",
        "components": components,
    }
    return bom
