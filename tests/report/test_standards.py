"""CycloneDX, CycloneDX VEX, SPDX, SARIF and OpenVEX: schema validity and semantics."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from reportdata import LIBC32, LIBC64, LZMA, SSHD, build_report, validate_schema

from startup_sbom.errors import OutputError
from startup_sbom.models import Report, Severity
from startup_sbom.report import RenderOptions, render
from startup_sbom.report import sarif as sarif_mod

SPECS = {"1.5": SchemaVersion.V1_5, "1.6": SchemaVersion.V1_6, "1.7": SchemaVersion.V1_7}
VARIANTS = {
    "plain": {},
    "container": {"container": True},
    "hostile": {"hostile": True},
}


def _cdx_valid(text: str, spec: str) -> None:
    errors = JsonStrictValidator(SPECS[spec]).validate_str(text, all_errors=True)
    assert errors is None, [repr(e)[:400] for e in errors]


def _props(obj: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in obj.get("properties", []):
        out.setdefault(p["name"], []).append(p["value"])
    return out


# --------------------------------------------------------------------------- CycloneDX
@pytest.mark.parametrize("spec", sorted(SPECS))
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_cyclonedx_validates(spec: str, variant: str) -> None:
    report = build_report(**VARIANTS[variant])
    _cdx_valid(render(report, "cyclonedx", RenderOptions(cdx_spec=spec)), spec)


@pytest.mark.parametrize("spec", sorted(SPECS))
@pytest.mark.parametrize("flag", [False, True])
def test_cdx_vex_validates(spec: str, flag: bool) -> None:
    opts = RenderOptions(cdx_spec=spec, vex_not_affected_unreachable=flag)
    _cdx_valid(render(build_report(hostile=True), "cdx-vex", opts), spec)


def test_cyclonedx_structure(report: Report) -> None:
    bom = json.loads(render(report, "cyclonedx"))
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"] == f"urn:uuid:{uuid.UUID(bom['serialNumber'][9:])}"
    root = bom["metadata"]["component"]
    assert root["type"] == "operating-system"
    assert (root["name"], root["version"]) == ("debian", "12")
    assert bom["metadata"]["tools"]["components"][0]["name"] == "startup-sbom"
    oses = [c for c in bom["components"] if c["type"] == "operating-system"]
    assert oses == []  # rootfs mode: the OS is the metadata component only

    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs)) == len(report.packages)
    assert LIBC64 in refs  # multi-arch twins stay distinct
    assert LIBC32 in refs

    deps = {d["ref"]: set(d.get("dependsOn", [])) for d in bom["dependencies"]}
    assert deps[root["bom-ref"]] == {p.id for p in report.packages}
    assert LIBC64 in deps[SSHD]  # same-arch resolution
    assert LIBC32 not in deps[SSHD]
    assert deps["svc:systemd:ssh.service"] >= {SSHD, LZMA}  # executable + linked libraries

    sshd = next(c for c in bom["components"] if c["bom-ref"] == SSHD)
    props = _props(sshd)
    assert props["aquasecurity:trivy:SrcName"] == ["openssh"]
    assert props["aquasecurity:trivy:SrcVersion"] == ["9.2p1-2+deb12u3"]
    assert props["aquasecurity:trivy:SrcEpoch"] == ["1"]
    assert props["startup-sbom:reachability"] == ["network_service"]
    assert sshd["licenses"] == [
        {"expression": "BSD-2-Clause AND ISC", "acknowledgement": "declared"}
    ]
    assert sshd["purl"] == SSHD

    ssh = next(s for s in bom["services"] if s["name"] == "ssh.service")
    assert ssh["endpoints"] == ["tcp://0.0.0.0:22"]
    assert ssh["x-trust-boundary"] is True

    v = next(x for x in bom["vulnerabilities"] if x["id"] == "CVE-2024-6387")
    assert {r["method"] for r in v["ratings"]} == {"CVSSv31", "CVSSv4"}
    assert v["cwes"] == [364]
    assert v["affects"][0]["ref"] == SSHD
    vprops = _props(v)
    assert vprops["startup-sbom:epss:score"] == ["0.43000"]
    assert vprops["startup-sbom:kev:listed"] == ["true"]
    assert "analysis" not in v  # affected upstream: the SBOM is a plain VDR
    na = next(x for x in bom["vulnerabilities"] if x["id"] == "CVE-2022-9999")
    assert na["analysis"]["state"] == "not_affected"

    ext = {e["type"]: e["url"] for e in bom["externalReferences"]}
    assert ext["threat-model"] == "report.json"
    assert ext["exploitability-statement"] == "vex.cdx.json"


def test_cyclonedx_trivy_compat_off(report: Report) -> None:
    text = render(report, "cyclonedx", RenderOptions(trivy_compat=False))
    assert "aquasecurity:trivy" not in text


def test_cyclonedx_container_root(container_report: Report) -> None:
    bom = json.loads(render(container_report, "cyclonedx"))
    root = bom["metadata"]["component"]
    assert root["type"] == "container"
    assert root["purl"].startswith("pkg:oci/nginx@sha256:")
    oses = [c for c in bom["components"] if c["type"] == "operating-system"]
    assert len(oses) == 1
    deps = {d["ref"]: set(d.get("dependsOn", [])) for d in bom["dependencies"]}
    assert deps[root["bom-ref"]] == {oses[0]["bom-ref"]}
    assert "API_TOKEN" in json.dumps(root)  # key name only, flagged as redacted


def test_cyclonedx_duplicate_ids_stay_valid(report: Report) -> None:
    dup = report.model_copy(deep=True)
    twin = dup.packages[0].model_copy(update={"summary": "a second record with the same id"})
    dup.packages.append(twin)
    text = render(dup, "cyclonedx")
    _cdx_valid(text, "1.6")
    refs = [c["bom-ref"] for c in json.loads(text)["components"]]
    assert len(refs) == len(set(refs)) == len(dup.packages)
    validate_schema(json.loads(render(dup, "spdx")), "spdx-2.3.schema.json")


def test_cdx_spec_option_validated() -> None:
    with pytest.raises(OutputError):
        RenderOptions(cdx_spec="1.4")


def test_cdx_serial_is_deterministic(report: Report) -> None:
    a = json.loads(render(report, "cyclonedx"))["serialNumber"]
    other = report.model_copy(
        update={"metadata": report.metadata.model_copy(update={"scan_id": "x"})}
    )
    b = json.loads(render(other, "cyclonedx"))["serialNumber"]
    assert a == json.loads(render(report, "cyclonedx"))["serialNumber"]
    assert a != b


# --------------------------------------------------------------------------- VEX semantics
def _cdx_vex(report: Report, **kw: Any) -> dict[str, dict[str, Any]]:
    doc = json.loads(render(report, "cdx-vex", RenderOptions(**kw)))
    return {v["id"]: v for v in doc["vulnerabilities"]}


def test_cdx_vex_bom_links(report: Report) -> None:
    serial = json.loads(render(report, "cyclonedx"))["serialNumber"][len("urn:uuid:") :]
    vex = json.loads(render(report, "cdx-vex"))
    assert vex["serialNumber"] != f"urn:uuid:{serial}"
    for v in vex["vulnerabilities"]:
        assert v["affects"][0]["ref"].startswith(f"urn:cdx:{serial}/1#pkg:")
    assert "components" not in vex


def test_cdx_vex_semantics_default(report: Report) -> None:
    v = _cdx_vex(report)
    assert v["CVE-2024-6387"]["analysis"]["state"] == "exploitable"
    assert v["CVE-2024-6387"]["analysis"]["response"] == ["update"]
    assert v["CVE-2024-3094"]["analysis"]["state"] == "exploitable"
    assert v["CVE-2023-7777"]["analysis"]["state"] == "exploitable"  # setuid
    assert v["CVE-2023-0001"]["analysis"]["state"] == "in_triage"  # installed only
    assert v["CVE-2023-0002"]["analysis"]["state"] == "in_triage"
    assert v["CVE-2022-9999"]["analysis"]["state"] == "not_affected"  # upstream


def test_cdx_vex_semantics_opt_in(report: Report) -> None:
    v = _cdx_vex(report, vex_not_affected_unreachable=True)
    assert v["CVE-2023-0001"]["analysis"]["state"] == "not_affected"
    assert v["CVE-2023-0001"]["analysis"]["justification"] == "code_not_reachable"
    assert v["CVE-2023-0002"]["analysis"]["state"] == "in_triage"  # KEV never auto-cleared
    assert v["CVE-2024-6387"]["analysis"]["state"] == "exploitable"


@pytest.mark.parametrize("flag", [False, True])
def test_openvex_validates(flag: bool) -> None:
    doc = json.loads(
        render(
            build_report(hostile=True), "openvex", RenderOptions(vex_not_affected_unreachable=flag)
        )
    )
    validate_schema(doc, "openvex-0.2.0.schema.json")


def test_openvex_semantics(report: Report) -> None:
    def statuses(flag: bool) -> dict[str, dict[str, Any]]:
        doc = json.loads(
            render(report, "openvex", RenderOptions(vex_not_affected_unreachable=flag))
        )
        return {s["vulnerability"]["name"]: s for s in doc["statements"]}

    default = statuses(False)
    assert default["CVE-2024-6387"]["status"] == "affected"
    assert default["CVE-2024-6387"]["action_statement"].startswith("Upgrade openssh-server")
    assert default["CVE-2023-0001"]["status"] == "under_investigation"
    assert "justification" not in default["CVE-2023-0001"]
    assert default["CVE-2022-9999"]["status"] == "not_affected"
    assert default["CVE-2022-9999"]["justification"] == "vulnerable_code_not_present"
    assert not any(
        s.get("justification") == "vulnerable_code_not_in_execute_path" for s in default.values()
    )
    opt = statuses(True)
    assert opt["CVE-2023-0001"]["status"] == "not_affected"
    assert opt["CVE-2023-0001"]["justification"] == "vulnerable_code_not_in_execute_path"
    assert opt["CVE-2023-0002"]["status"] == "under_investigation"  # KEV
    product = default["CVE-2024-6387"]["products"][0]
    assert product["@id"] == "pkg:deb/debian/openssh-server@1:9.2p1-2%2Bdeb12u3"
    assert product["identifiers"]["purl"] == SSHD


# --------------------------------------------------------------------------- SPDX
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_spdx_validates(variant: str) -> None:
    doc = json.loads(render(build_report(**VARIANTS[variant]), "spdx"))
    validate_schema(doc, "spdx-2.3.schema.json")


def test_spdx_structure(report: Report) -> None:
    doc = json.loads(render(report, "spdx"))
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(ids) == len(set(ids)) == len(report.packages) + 1
    kinds = {r["relationshipType"] for r in doc["relationships"]}
    assert kinds == {"DESCRIBES", "CONTAINS", "DEPENDS_ON"}
    purls = {
        ref["referenceLocator"]
        for p in doc["packages"]
        for ref in p.get("externalRefs", [])
        if ref["referenceType"] == "purl"
    }
    assert {LIBC32, LIBC64, SSHD} <= purls
    cpes = [
        ref
        for p in doc["packages"]
        for ref in p.get("externalRefs", [])
        if ref["referenceCategory"] == "SECURITY"
    ]
    assert cpes[0]["referenceType"] == "cpe23Type"
    assert doc["documentNamespace"].startswith("https://github.com/morpheuslord/Startup-SBOM/spdx/")
    lzma = next(p for p in doc["packages"] if p["name"] == "liblzma5")
    assert lzma["licenseDeclared"].startswith("LicenseRef-")
    assert doc["hasExtractedLicensingInfos"][0]["licenseId"] == lzma["licenseDeclared"]


# --------------------------------------------------------------------------- SARIF
@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_sarif_validates(variant: str) -> None:
    doc = json.loads(render(build_report(**VARIANTS[variant]), "sarif"))
    validate_schema(doc, "sarif-2.1.0.schema.json")


def test_sarif_semantics(report: Report) -> None:
    run = json.loads(render(report, "sarif"))["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules["CVE-2024-6387"]["properties"]["security-severity"] == "9.2"
    assert "security" in rules["CVE-2024-6387"]["properties"]["tags"]
    assert "SSBOM-CHAIN" in rules
    assert any(k.startswith("SSBOM-SC-") for k in rules)
    assert "CVE-2022-9999" not in rules  # upstream not_affected is not an alert
    by_rule = {r["ruleId"]: r for r in run["results"]}
    sshd = by_rule["CVE-2024-6387"]
    assert sshd["level"] == "error"
    loc = sshd["locations"][0]["physicalLocation"]["artifactLocation"]
    assert loc == {"uri": "usr/sbin/sshd", "uriBaseId": "ROOTFS"}
    for res in run["results"]:
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/")
        assert res["partialFingerprints"]["primaryLocationLineHash"].endswith(":1")
    db = by_rule["CVE-2023-0001"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert db == "var/lib/dpkg/status"
    assert by_rule["SSBOM-CHAIN"]["codeFlows"][0]["threadFlows"][0]["locations"]
    again = json.loads(render(report, "sarif"))["runs"][0]
    assert [r["partialFingerprints"] for r in again["results"]] == [
        r["partialFingerprints"] for r in run["results"]
    ]


def test_sarif_min_severity(report: Report) -> None:
    run = json.loads(render(report, "sarif", RenderOptions(sarif_min_severity=Severity.HIGH)))
    sev = {r["ruleId"] for r in run["runs"][0]["results"]}
    assert "CVE-2023-0001" not in sev
    assert "CVE-2024-6387" in sev
    as_text = RenderOptions(sarif_min_severity="critical")  # type: ignore[arg-type]
    assert as_text.sarif_min_severity is Severity.CRITICAL


def test_sarif_truncation(report: Report, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sarif_mod, "MAX_RESULTS", 2)
    doc = json.loads(render(report, "sarif"))
    validate_schema(doc, "sarif-2.1.0.schema.json")
    run = doc["runs"][0]
    assert len(run["results"]) == 2
    assert run["properties"]["truncated"] is True
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert any("truncated" in n["message"]["text"] for n in notes)
    assert {r["level"] for r in run["results"]} == {"error"}  # most severe kept
    used = {r["ruleId"] for r in run["results"]}
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == used
