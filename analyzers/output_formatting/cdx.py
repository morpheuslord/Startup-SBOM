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
        "components": components,
    }
    return bom
