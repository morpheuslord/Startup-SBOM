"""SPDX 2.3 JSON document (hand-written, validated against the official schema in tests).

SPDX is kept a pure inventory: the operating system (and container) plus every
package with purl/CPE external refs and ``CONTAINS`` / ``DEPENDS_ON`` relationships.
Services, threats and attack chains have no SPDX 2.3 equivalent.
"""

from __future__ import annotations

import json
import re
from typing import Any

from license_expression import get_spdx_licensing

from startup_sbom.models import Package, Report
from startup_sbom.report.cyclonedx import (
    DISTRO_SUPPLIERS,
    clean,
    dependency_index,
    package_instances,
    package_refs,
    resolve_depends,
)
from startup_sbom.report.native import (
    PROJECT_URL,
    RenderOptions,
    iso_z,
    scan_uuid,
    short_hash,
    timestamp,
)

_ID_CHARS = re.compile(r"[^A-Za-z0-9.-]+")
_SAFE_URL = re.compile(r"^https?://[^\s\"<>\\^`{|}]+$")
_OS_ID = "SPDXRef-OperatingSystem"
_CONTAINER_ID = "SPDXRef-Container"
_OS_TYPES = ("deb", "rpm", "apk", "alpm")


def spdx_id(kind: str, key: str) -> str:
    """``SPDXRef-<kind>-<hash>``: matches ``SPDXRef-[A-Za-z0-9.-]+``, stable and unique."""
    return f"SPDXRef-{_ID_CHARS.sub('-', kind)}-{short_hash(key)}"


def _one_line(text: str) -> str:
    return " ".join(clean(text).split())


class _Licenses:
    """Classify declared license strings into SPDX expressions or ``LicenseRef-``s."""

    def __init__(self) -> None:
        self._licensing = get_spdx_licensing()
        self.extracted: dict[str, dict[str, str]] = {}

    def declared(self, text: str | None) -> str:
        if not text or not text.strip():
            return "NOASSERTION"
        raw = _one_line(text)
        try:
            info = self._licensing.validate(raw)
        except Exception:  # noqa: BLE001 - the parser raises assorted errors on junk input
            info = None
        if info is not None and not info.errors and not info.invalid_symbols:
            normalized = info.normalized_expression or ""
            if normalized and "LicenseRef-" not in normalized:
                return str(normalized)
        stem = _ID_CHARS.sub("-", raw).strip("-")[:48] or "unknown"
        ref = f"LicenseRef-{stem}-{short_hash(raw, length=8)}"
        self.extracted[ref] = {
            "licenseId": ref,
            "name": raw[:256],
            "extractedText": f"Declared by package metadata as: {raw}",
        }
        return ref


def _supplier(report: Report, pkg: Package) -> str:
    name = pkg.vendor
    if not name and pkg.type.value in _OS_TYPES:
        name = DISTRO_SUPPLIERS.get(report.os.id)
    if not name and pkg.maintainer:
        name = pkg.maintainer
    return f"Organization: {_one_line(name)}" if name and _one_line(name) else "NOASSERTION"


def _package(report: Report, pkg: Package, sid: str, licenses: _Licenses) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "SPDXID": sid,
        "name": _one_line(pkg.name) or "unknown",
        "versionInfo": clean(pkg.version),
        "supplier": _supplier(report, pkg),
        "primaryPackagePurpose": "LIBRARY",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": licenses.declared(pkg.license),
        "copyrightText": "NOASSERTION",
    }
    refs = []
    purl = pkg.purl or (pkg.id if pkg.id.startswith("pkg:") else None)
    if purl:
        refs.append(
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        )
    refs.extend(
        {
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type" if cpe.startswith("cpe:2.3:") else "cpe22Type",
            "referenceLocator": clean(cpe),
        }
        for cpe in pkg.cpes
    )
    if refs:
        entry["externalRefs"] = refs
    if pkg.summary:
        entry["summary"] = clean(pkg.summary)
    if pkg.homepage and _SAFE_URL.match(pkg.homepage.strip()):
        entry["homepage"] = pkg.homepage.strip()
    if pkg.source_name:
        src = f"built from source package {pkg.source_name} {pkg.source_version or ''}"
        entry["sourceInfo"] = _one_line(src)
    if pkg.arch:
        entry["comment"] = _one_line(f"arch: {pkg.arch}")
    return entry


def build_spdx(report: Report, options: RenderOptions) -> dict[str, Any]:
    """Build the SPDX 2.3 document as a dict."""
    del options
    o = report.os
    os_name = _one_line(o.id) or "unknown"
    os_ver = _one_line(o.version_id or "")
    licenses = _Licenses()
    packages: list[dict[str, Any]] = []
    rels: list[dict[str, str]] = []

    os_pkg: dict[str, Any] = {
        "SPDXID": _OS_ID,
        "name": os_name,
        "versionInfo": os_ver or "NOASSERTION",
        "primaryPackagePurpose": "OPERATING-SYSTEM",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if o.pretty_name:
        os_pkg["description"] = clean(o.pretty_name)
    if o.id in DISTRO_SUPPLIERS:
        os_pkg["supplier"] = f"Organization: {DISTRO_SUPPLIERS[o.id]}"
    packages.append(os_pkg)

    root = _OS_ID
    c = report.container
    if c is not None:
        name = _one_line(c.image or c.name or report.metadata.target.reference) or "container"
        cont: dict[str, Any] = {
            "SPDXID": _CONTAINER_ID,
            "name": name,
            "versionInfo": clean(c.image_digest) if c.image_digest else "NOASSERTION",
            "primaryPackagePurpose": "CONTAINER",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        packages.append(cont)
        rels.append(
            {
                "spdxElementId": _CONTAINER_ID,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": _OS_ID,
            }
        )
        root = _CONTAINER_ID
    rels.append(
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root,
        }
    )

    refs = package_refs(report)
    ids: dict[str, str] = {}
    by_id: dict[str, Package] = {}
    for pkg, ref in package_instances(report):
        sid = spdx_id("Package", ref)
        ids.setdefault(pkg.id, sid)
        by_id.setdefault(pkg.id, pkg)
        packages.append(_package(report, pkg, sid, licenses))
        rels.append(
            {"spdxElementId": _OS_ID, "relationshipType": "CONTAINS", "relatedSpdxElement": sid}
        )

    index = dependency_index(report, refs)
    for pid, pkg in by_id.items():
        rels.extend(
            {
                "spdxElementId": ids[pid],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": ids[dep],
            }
            for dep in sorted(resolve_depends(pkg, index, by_id))
            if dep in ids
        )

    unique_rels = {
        (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"]): r for r in rels
    }
    label = f"{os_name}-{os_ver}" if os_ver else os_name
    doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"startup-sbom {label}",
        "documentNamespace": (
            f"{PROJECT_URL}/spdx/{_ID_CHARS.sub('-', label)}-{scan_uuid(report, 'spdx')}"
        ),
        "creationInfo": {
            "created": iso_z(timestamp(report)),
            "creators": [f"Tool: startup-sbom-{_one_line(report.metadata.tool_version)}"],
        },
        "packages": packages,
        "relationships": [unique_rels[k] for k in sorted(unique_rels)],
    }
    if licenses.extracted:
        doc["hasExtractedLicensingInfos"] = [
            licenses.extracted[k] for k in sorted(licenses.extracted)
        ]
    return doc


def render_spdx(report: Report, options: RenderOptions) -> str:
    """Render the SPDX 2.3 JSON document."""
    return json.dumps(build_spdx(report, options), indent=2, ensure_ascii=False) + "\n"
