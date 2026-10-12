"""OpenVEX 0.2.0 document and the reachability → VEX status semantics.

Conservative by design: "not observed on an execution path" is *not* proof of
"not affected" (cron, login shells, dlopen, files parsed by any process are not
fully visible to static analysis).  Installed-only vulnerabilities are therefore
``under_investigation`` unless the operator opts in to ``not_affected`` with
``vulnerable_code_not_in_execute_path``; KEV-listed ones never are.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum

from packageurl import PackageURL

from startup_sbom.models import Reachability, Report, Threat, Vulnerability, VulnStatus
from startup_sbom.report.native import (
    PROJECT_URL,
    REACHABLE,
    RenderOptions,
    iso_z,
    package_reachability,
    scan_uuid,
    threats_by_vuln,
    timestamp,
    vuln_reachability,
)

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


class VexStatus(StrEnum):
    """OpenVEX statuses (CycloneDX analysis states are mapped from these)."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


@dataclass(frozen=True, slots=True)
class VexVerdict:
    """The VEX assessment of one vulnerability x package match."""

    status: VexStatus
    reachability: Reachability
    justification: str | None = None  # OpenVEX justification label
    note: str | None = None  # status_notes / impact_statement / CDX detail
    action: str | None = None  # action_statement (affected)
    upstream: bool = False  # True when the status came from the distribution advisory


def assess(
    v: Vulnerability,
    reach: Reachability,
    threats: list[Threat],
    options: RenderOptions,
) -> VexVerdict:
    """Decide the VEX status of ``v`` given its reachability."""
    if v.status is VulnStatus.FIXED:
        return VexVerdict(
            VexStatus.FIXED,
            reach,
            note="The distribution advisory marks the installed version as fixed.",
            upstream=True,
        )
    if v.status is VulnStatus.NOT_AFFECTED:
        return VexVerdict(
            VexStatus.NOT_AFFECTED,
            reach,
            justification="vulnerable_code_not_present",
            note="The distribution advisory marks the installed version as not affected.",
            upstream=True,
        )
    if v.status is VulnStatus.UNDER_INVESTIGATION:
        return VexVerdict(
            VexStatus.UNDER_INVESTIGATION,
            reach,
            note="The distribution is still investigating this vulnerability.",
            upstream=True,
        )
    if reach in REACHABLE:
        services = sorted({s for t in threats for s in t.services})
        where = f" ({', '.join(services)})" if services else ""
        if v.fixed_versions:
            action = f"Upgrade {v.package_name} to {' or '.join(v.fixed_versions)} or later."
        elif v.status is VulnStatus.WILL_NOT_FIX:
            action = "The distribution will not fix this; remove the package or restrict exposure."
        else:
            action = "No fixed version is available; restrict exposure and monitor for a fix."
        return VexVerdict(
            VexStatus.AFFECTED,
            reach,
            note=f"Reachable on the analysed system: {reach.value.replace('_', ' ')}{where}.",
            action=action,
        )
    if options.vex_not_affected_unreachable and v.kev is None:
        return VexVerdict(
            VexStatus.NOT_AFFECTED,
            reach,
            justification="vulnerable_code_not_in_execute_path",
            note=(
                "No startup service, linked library, setuid binary or kernel path uses this "
                "package (static boot-path analysis; operator opted in to treat this as "
                "not affected)."
            ),
        )
    return VexVerdict(
        VexStatus.UNDER_INVESTIGATION,
        reach,
        note=(
            "Installed but not observed on any static execution path; reachability not "
            "proven (cron, login shells, on-demand use and dlopen are not fully modelled)."
        ),
    )


def assessments(report: Report, options: RenderOptions) -> list[tuple[Vulnerability, VexVerdict]]:
    """VEX verdicts for every vulnerability of ``report``, in canonical order."""
    threats = threats_by_vuln(report)
    pkg_reach = package_reachability(report)
    out = []
    for v in sorted(report.vulnerabilities, key=lambda x: (x.id, x.package)):
        reach = vuln_reachability(report, v, threats=threats, pkg_reach=pkg_reach)
        out.append((v, assess(v, reach, threats.get((v.id, v.package), []), options)))
    return out


def _product(report: Report, v: Vulnerability) -> dict[str, object]:
    pkg = report.package_by_id().get(v.package)
    raw = (pkg.purl if pkg else None) or v.package
    try:
        full = PackageURL.from_string(raw)
    except ValueError:
        return {"@id": raw}
    # @id without qualifiers: Trivy treats a qualifier-less purl as "any qualifiers",
    # so distro=debian-12 vs debian-12.5 differences cannot break matching.
    bare = full._replace(qualifiers={}, subpath=None).to_string()
    return {"@id": bare, "identifiers": {"purl": full.to_string()}}


def build_openvex(report: Report, options: RenderOptions) -> dict[str, object]:
    """Build the OpenVEX 0.2.0 document as a dict."""
    statements: list[dict[str, object]] = []
    for v, verdict in assessments(report, options):
        stmt: dict[str, object] = {
            "vulnerability": {"name": v.id},
            "products": [_product(report, v)],
            "status": verdict.status.value,
        }
        aliases = sorted({a for a in v.aliases if a and a != v.id})
        if aliases:
            stmt["vulnerability"] = {"name": v.id, "aliases": aliases}
        if verdict.status is VexStatus.NOT_AFFECTED:
            stmt["justification"] = verdict.justification
            stmt["impact_statement"] = verdict.note
        elif verdict.status is VexStatus.AFFECTED:
            stmt["action_statement"] = verdict.action
            stmt["status_notes"] = verdict.note
        elif verdict.note:
            stmt["status_notes"] = verdict.note
        statements.append(stmt)
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"{PROJECT_URL}/vex/{scan_uuid(report, 'openvex')}",
        "author": "startup-sbom",
        "role": "automated-tool",
        "timestamp": iso_z(timestamp(report)),
        "version": 1,
        "tooling": f"startup-sbom/{report.metadata.tool_version}",
        "statements": statements,
    }


def render_openvex(report: Report, options: RenderOptions) -> str:
    """Render the OpenVEX document."""
    return json.dumps(build_openvex(report, options), indent=2, ensure_ascii=False) + "\n"
