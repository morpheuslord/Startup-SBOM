"""Standalone CycloneDX VEX referencing the SBOM through BOM-Links.

Trivy only accepts CycloneDX VEX as an independent document whose ``affects``
refs are BOM-Links (``urn:cdx:<serial>/<version>#<bom-ref>``); Dependency-Track
ingests the same document through ``PUT /api/v1/vex``.
"""

from __future__ import annotations

import uuid

from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.impact_analysis import (
    ImpactAnalysisJustification,
    ImpactAnalysisResponse,
    ImpactAnalysisState,
)
from cyclonedx.model.tool import ToolRepository
from cyclonedx.model.vulnerability import VulnerabilityAnalysis

from startup_sbom.models import Report, VulnStatus
from startup_sbom.report.cyclonedx import (
    clean,
    os_ref,
    package_refs,
    prop,
    sbom_serial,
    serialize,
    vulnerability_entry,
)
from startup_sbom.report.native import RenderOptions, threats_by_vuln, timestamp
from startup_sbom.report.openvex import VexStatus, VexVerdict, assessments

SBOM_VERSION = 1


def bom_link(serial: uuid.UUID, ref: str, version: int = SBOM_VERSION) -> str:
    """BOM-Link to element ``ref`` of the SBOM ``serial``/``version``."""
    return f"urn:cdx:{serial}/{version}#{ref}"


def analysis(verdict: VexVerdict, status: VulnStatus) -> VulnerabilityAnalysis:
    """CycloneDX analysis block for a VEX verdict."""
    detail = clean(verdict.note) if verdict.note else None
    if verdict.status is VexStatus.FIXED:
        return VulnerabilityAnalysis(state=ImpactAnalysisState.RESOLVED, detail=detail)
    if verdict.status is VexStatus.NOT_AFFECTED:
        just = (
            ImpactAnalysisJustification.CODE_NOT_REACHABLE
            if verdict.justification == "vulnerable_code_not_in_execute_path"
            else ImpactAnalysisJustification.CODE_NOT_PRESENT
        )
        return VulnerabilityAnalysis(
            state=ImpactAnalysisState.NOT_AFFECTED, justification=just, detail=detail
        )
    if verdict.status is VexStatus.AFFECTED:
        if status is VulnStatus.WILL_NOT_FIX:
            responses = [ImpactAnalysisResponse.WILL_NOT_FIX]
        elif status is VulnStatus.NO_FIX_AVAILABLE:
            responses = [ImpactAnalysisResponse.CAN_NOT_FIX]
        else:
            responses = [ImpactAnalysisResponse.UPDATE]
        text = " ".join(x for x in (verdict.note, verdict.action) if x)
        return VulnerabilityAnalysis(
            state=ImpactAnalysisState.EXPLOITABLE, responses=responses, detail=clean(text)
        )
    return VulnerabilityAnalysis(state=ImpactAnalysisState.IN_TRIAGE, detail=detail)


def build_vex_bom(report: Report, options: RenderOptions) -> Bom:
    """Build the standalone CycloneDX VEX document."""
    serial = sbom_serial(report)
    tool = Component(
        type=ComponentType.APPLICATION,
        name="startup-sbom",
        group="morpheuslord",
        version=report.metadata.tool_version,
        bom_ref="tool:startup-sbom",
    )
    vex = Bom(
        serial_number=uuid.uuid5(serial, "vex"),
        version=1,
        metadata=BomMetaData(
            timestamp=timestamp(report),
            tools=ToolRepository(components=[tool]),
            properties=[
                prop("scanId", report.metadata.scan_id),
                prop("sbomSerialNumber", serial.urn),
                prop(
                    "vex:notAffectedUnreachable",
                    str(options.vex_not_affected_unreachable).lower(),
                ),
            ],
        ),
    )
    refs = package_refs(report)
    threats = threats_by_vuln(report)
    for v, verdict in assessments(report, options):
        target = bom_link(serial, refs.get(v.package, os_ref(report)))
        vex.vulnerabilities.add(
            vulnerability_entry(
                v,
                target,
                reach=verdict.reachability,
                threats=threats.get((v.id, v.package), []),
                analysis=analysis(verdict, v.status),
            )
        )
    return vex


def render_cdx_vex(report: Report, options: RenderOptions) -> str:
    """Render the CycloneDX VEX document (spec ``options.cdx_spec``)."""
    return serialize(build_vex_bom(report, options), options.cdx_spec)
