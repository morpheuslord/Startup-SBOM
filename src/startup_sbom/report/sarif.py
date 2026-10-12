"""SARIF 2.1.0 for GitHub code scanning (and any SARIF viewer).

One rule per vulnerability id plus one rule per attack-chain / supply-chain
finding kind.  Results point at in-image paths relative to ``ROOTFS`` (the service
executable when known, else the package database) and carry our own stable
``primaryLocationLineHash`` because the analysed root filesystem is not part of
the repository.  GitHub limits (25 000 results/rules per run, 20 tags per rule,
1 000 locations per result) are respected.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

from startup_sbom.models import (
    AttackChain,
    Package,
    Report,
    Severity,
    SSVCDecision,
    SupplyChainFinding,
    Threat,
    Vulnerability,
    VulnStatus,
)
from startup_sbom.report.markdown import md
from startup_sbom.report.native import (
    PROJECT_URL,
    RenderOptions,
    canonical,
    package_db_path,
    package_reachability,
    severity_score,
    short_hash,
    threats_by_vuln,
    vuln_reachability,
    vuln_score,
    vuln_severity,
)

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
MAX_RESULTS = 25_000
MAX_RULES = 25_000
MAX_TAGS = 20
MAX_THREAD_LOCATIONS = 1_000
_RULE_ID = re.compile(r"[^A-Za-z0-9._/-]+")
_LEVEL_RANK = {"none": 0, "note": 1, "warning": 2, "error": 3}


def _text(s: str, limit: int = 1024) -> str:
    s = s.strip() or "-"
    return s if len(s) <= limit else s[: limit - 1] + "…"


def level_for(sev: Severity, score: float | None, decision: SSVCDecision | None = None) -> str:
    """SARIF level: CVSS ≥ 7 error, ≥ 4 warning, else note; SSVC Act/Attend raise it."""
    value = severity_score(sev, score)
    level = "note"
    if value is not None:
        level = "error" if value >= 7.0 else "warning" if value >= 4.0 else "note"
    if decision is SSVCDecision.ACT:
        level = "error"
    elif decision is SSVCDecision.ATTEND and _LEVEL_RANK[level] < _LEVEL_RANK["warning"]:
        level = "warning"
    return level


def artifact_uri(path: str) -> str:
    """Relative, percent-encoded URI of an in-image path (no leading slash)."""
    rel = path.lstrip("/") or "."
    return quote(rel, safe="/-._~")


def _location(path: str, message: str | None = None) -> dict[str, Any]:
    loc: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": artifact_uri(path), "uriBaseId": "ROOTFS"},
            "region": {"startLine": 1},
        }
    }
    if message:
        loc["message"] = {"text": _text(message)}
    return loc


def _fingerprint(*parts: str) -> dict[str, str]:
    h = short_hash(*parts, length=64)
    return {"primaryLocationLineHash": f"{h[:32]}:1", "startupSbom/v1": h}


def _package_path(report: Report, pkg: Package | None, threat: Threat | None) -> str:
    if threat is not None and threat.binaries:
        return threat.binaries[0]
    if threat is not None and threat.services:
        svc = report.service_by_id().get(threat.services[0])
        if svc is not None and svc.executables:
            return svc.executables[0]
    if pkg is not None:
        for svc in report.services:
            if pkg.id in svc.packages and svc.executables:
                return svc.executables[0]
        return package_db_path(pkg)
    return "/"


def _vuln_rule(v: Vulnerability, score: float | None, sev: Severity) -> dict[str, Any]:
    tags = ["security", "vulnerability", sev.value]
    if v.kev is not None:
        tags.append("kev")
    tags += [f"external/cwe/{c.lower()}" for c in v.cwes if c.upper().startswith("CWE-")]
    url = f"https://osv.dev/vulnerability/{quote(v.id, safe='')}"
    summary = v.summary or v.id
    help_md = f"**{md(v.id)}**: {md(summary, 500)}\n\nSee [OSV]({url})."
    if v.fixed_versions:
        help_md += f"\n\nFixed in: {md(', '.join(v.fixed_versions))}."
    rule: dict[str, Any] = {
        "id": v.id,
        "name": "OsPackageVulnerability",
        "shortDescription": {"text": _text(f"{v.id}: {summary}")},
        "fullDescription": {"text": _text(summary, 4000)},
        "helpUri": url,
        "help": {
            "text": _text(
                f"Upgrade to {', '.join(v.fixed_versions)}" if v.fixed_versions else "No fix known"
            ),
            "markdown": help_md,
        },
        "defaultConfiguration": {"level": level_for(sev, score)},
        "properties": {"precision": "very-high", "tags": tags[:MAX_TAGS]},
    }
    sec = severity_score(sev, score)
    if sec is not None:
        rule["properties"]["security-severity"] = f"{sec:.1f}"
    return rule


def _kind_rule(rule_id: str, name: str, text: str, sev: Severity, tag: str) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": _text(text)},
        "helpUri": PROJECT_URL,
        "defaultConfiguration": {"level": level_for(sev, None)},
        "properties": {"precision": "medium", "tags": ["security", tag]},
    }
    sec = severity_score(sev)
    if sec is not None:
        rule["properties"]["security-severity"] = f"{sec:.1f}"
    return rule


def _chain_result(report: Report, chain: AttackChain) -> dict[str, Any]:
    threats = {t.id: t for t in report.threats}
    svcs = report.service_by_id()
    pkgs = report.package_by_id()
    flow_locations = []
    first_path: str | None = None
    for step in chain.steps[:MAX_THREAD_LOCATIONS]:
        path = None
        t = threats.get(step.threat or "")
        if t is not None:
            path = _package_path(report, pkgs.get(t.package), t)
        elif step.service and step.service in svcs and svcs[step.service].executables:
            path = svcs[step.service].executables[0]
        first_path = first_path or path
        tech = f" [{step.technique.id}]" if step.technique else ""
        msg = f"{step.from_state} -> {step.to_state}: {step.title}{tech}"
        loc = _location(path, msg) if path else {"message": {"text": _text(msg)}}
        flow_locations.append({"location": loc})
    sev = Severity.from_score(chain.score / 10.0)
    path = first_path or "/etc/os-release"
    return {
        "ruleId": "SSBOM-CHAIN",
        "level": level_for(sev, chain.score / 10.0, chain.ssvc_decision),
        "message": {
            "text": _text(
                f"Attack chain {chain.id}: {chain.entry} -> {chain.goal} "
                f"(score {chain.score:.1f}, SSVC {chain.ssvc_decision.value}). {chain.narrative}"
            )
        },
        "locations": [_location(path)],
        "codeFlows": [{"threadFlows": [{"locations": flow_locations}]}] if flow_locations else [],
        "partialFingerprints": _fingerprint(
            "SSBOM-CHAIN",
            chain.entry,
            chain.goal,
            *(f"{s.from_state}>{s.to_state}>{s.rule}" for s in chain.steps),
        ),
        "properties": {
            "chainId": chain.id,
            "score": chain.score,
            "likelihood": chain.likelihood,
            "impact": chain.impact,
            "ssvcDecision": chain.ssvc_decision.value,
            "mitigated": chain.mitigated,
            "security-severity": f"{max(0.1, min(chain.score / 10.0, 10.0)):.1f}",
        },
    }


def _finding_result(report: Report, f: SupplyChainFinding) -> dict[str, Any]:
    pkg = report.package_by_id().get(f.subject)
    path = f.subject if f.subject.startswith("/") else _package_path(report, pkg, None)
    text = f"{f.title}" + (f": {f.detail}" if f.detail else "")
    return {
        "ruleId": f"SSBOM-SC-{_RULE_ID.sub('-', f.kind) or 'finding'}",
        "level": level_for(f.severity, None),
        "message": {"text": _text(text)},
        "locations": [_location(path)],
        "partialFingerprints": _fingerprint("SC", f.kind, f.subject),
        "properties": {"findingId": f.id, "subject": f.subject, "evidence": f.evidence[:50]},
    }


def build_sarif(report: Report, options: RenderOptions) -> dict[str, Any]:
    """Build the SARIF 2.1.0 log as a dict."""
    r = canonical(report)
    pkgs = r.package_by_id()
    by_vuln = threats_by_vuln(r)
    pkg_reach = package_reachability(r)
    min_rank = options.sarif_min_severity.rank
    rules: dict[str, dict[str, Any]] = {}
    ranked: list[tuple[tuple[int, float, str], dict[str, Any]]] = []

    for v in r.vulnerabilities:
        score = vuln_score(v)
        sev = vuln_severity(v)
        if sev.rank < min_rank or v.status in (VulnStatus.FIXED, VulnStatus.NOT_AFFECTED):
            continue
        threats: list[Threat | None] = list(by_vuln.get((v.id, v.package), [])) or [None]
        if v.id not in rules:
            rules[v.id] = _vuln_rule(v, score, sev)
        else:  # keep the highest severity seen for a shared rule id
            prev = rules[v.id]["properties"].get("security-severity")
            cur = severity_score(sev, score)
            if cur is not None and (prev is None or cur > float(prev)):
                rules[v.id]["properties"]["security-severity"] = f"{cur:.1f}"
        pkg = pkgs.get(v.package)
        for t in threats:
            path = _package_path(r, pkg, t)
            reach = t.reachability if t else vuln_reachability(r, v, pkg_reach=pkg_reach)
            decision = t.ssvc.decision if t and t.ssvc else None
            level = level_for(sev, score, decision)
            name = pkg.name if pkg else v.package_name
            msg = f"{name} {v.installed_version} is affected by {v.id}"
            if t is not None:
                msg += f" ({t.reachability.value.replace('_', ' ')}; {t.precondition} -> "
                msg += f"{t.postcondition}): {t.title}"
            if v.fixed_versions:
                msg += f". Fixed in {', '.join(v.fixed_versions)}."
            ident = f"{pkg.type.value}/{name}/{pkg.arch or ''}" if pkg else v.package
            props: dict[str, Any] = {
                "purl": (pkg.purl if pkg else None) or v.package,
                "installedVersion": v.installed_version,
                "fixedVersions": v.fixed_versions,
                "status": v.status.value,
                "reachability": reach.value,
                "epss": v.epss,
                "epssPercentile": v.epss_percentile,
                "kev": v.kev is not None,
            }
            if t is not None:
                props |= {
                    "threatId": t.id,
                    "riskScore": t.risk_score,
                    "ssvcDecision": decision.value if decision else None,
                    "services": t.services,
                    "attackTechniques": [a.id for a in t.attack_techniques],
                }
            result = {
                "ruleId": v.id,
                "level": level,
                "message": {"text": _text(msg, 4000)},
                "locations": [_location(path)],
                "partialFingerprints": _fingerprint(v.id, ident, path),
                "properties": props,
            }
            rank_score = t.risk_score if t else (severity_score(sev, score) or 0.0) * 10
            ranked.append(((-_LEVEL_RANK[level], -rank_score, v.id + ident + path), result))

    if r.attack_chains:
        rules["SSBOM-CHAIN"] = _kind_rule(
            "SSBOM-CHAIN",
            "AttackChain",
            "Chained attack path from an entry state to a privileged goal",
            Severity.HIGH,
            "attack-chain",
        )
        for chain in r.attack_chains:
            sev = Severity.from_score(chain.score / 10.0)
            if sev.rank < min_rank:
                continue
            res = _chain_result(r, chain)
            ranked.append(((-_LEVEL_RANK[res["level"]], -chain.score, chain.id), res))
    for f in r.supply_chain.findings:
        if f.severity.rank < min_rank:
            continue
        res = _finding_result(r, f)
        rid = res["ruleId"]
        if rid not in rules:
            rules[rid] = _kind_rule(
                rid,
                "SupplyChainFinding",
                f"Supply-chain finding: {f.kind}",
                f.severity,
                "supply-chain",
            )
        ranked.append(((-_LEVEL_RANK[res["level"]], -float(f.severity.rank), f.id), res))

    ranked.sort(key=lambda x: x[0])
    notifications: list[dict[str, Any]] = [
        {"level": "note", "message": {"text": _text(f"Coverage limitation: {x}")}}
        for x in r.metadata.coverage.limitations
    ]
    if len(ranked) > MAX_RESULTS:
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": f"Results truncated to the {MAX_RESULTS} most severe of {len(ranked)} "
                    "(GitHub code-scanning limit); see report.json for all findings."
                },
            }
        )
    results = [res for _key, res in ranked[:MAX_RESULTS]]
    used_rules = {res["ruleId"] for res in results}
    rule_list = [rules[k] for k in sorted(rules) if k in used_rules][:MAX_RULES]
    os_label = re.sub(r"[^A-Za-z0-9._-]+", "-", f"{r.os.id}-{r.os.version_id or 'unknown'}")
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "startup-sbom",
                "semanticVersion": r.metadata.tool_version,
                "informationUri": PROJECT_URL,
                "rules": rule_list,
            }
        },
        "automationDetails": {"id": f"startup-sbom/{os_label}/"},
        "originalUriBaseIds": {
            "ROOTFS": {
                "uri": "file:///",
                "description": {"text": "Root of the analysed filesystem or image"},
            }
        },
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notifications}],
        "results": results,
        "properties": {
            "scanId": r.metadata.scan_id,
            "target": r.metadata.target.reference,
            "truncated": len(ranked) > MAX_RESULTS,
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def render_sarif(report: Report, options: RenderOptions) -> str:
    """Render the SARIF log."""
    return json.dumps(build_sarif(report, options), indent=2, ensure_ascii=False) + "\n"
