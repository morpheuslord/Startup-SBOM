"""Canned agent outputs (dict args for FunctionModel tool calls) against reportdata."""

from __future__ import annotations

from typing import Any

EVIDENCE = [
    {"ref": "TH-0001", "kind": "threat", "note": "network-exposed sshd running as root"},
    {"ref": "CVE-2024-6387", "kind": "vulnerability", "note": "the underlying CVE"},
]


def good_assessment() -> dict[str, Any]:
    """A FinalAssessment payload that is fully grounded in ``build_report()``."""
    return {
        "executive_summary": (
            "The most important risk is TH-0001: a pre-authentication compromise of the "
            "network-exposed ssh service through CVE-2024-6387. Upgrading openssh-server "
            "removes it."
        ),
        "findings": [
            {
                "threat_id": "TH-0001",
                "title": "Pre-auth compromise of network-exposed sshd",
                "priority": "P1",
                "agrees_with_scanner": True,
                "evidence": EVIDENCE,
                "rationale": "sshd listens on 0.0.0.0:22 and runs as root.",
                "confidence": 0.9,
                "counterfactuals": [
                    {
                        "condition": "sshd bound to 127.0.0.1 only",
                        "effect": "priority drops from P1 to P3",
                    }
                ],
                "numbers": [{"ref": "TH-0001", "field": "risk_score", "value": 92.5}],
            }
        ],
        "remediation_plan": [
            {
                "title": "Upgrade openssh-server",
                "commands": ["apt-get install --only-upgrade openssh-server"],
                "fixes": ["TH-0001"],
                "evidence": [EVIDENCE[0]],
                "rationale": "The packaged fix closes the vulnerability.",
                "confidence": 0.85,
                "counterfactuals": [],
                "numbers": [],
            }
        ],
        "claims": [
            {
                "text": "TH-0001 has risk score 92.5 and must be fixed first.",
                "cites": ["TH-0001"],
                "numbers": [{"ref": "TH-0001", "field": "risk_score", "value": 92.5}],
                "kind": "finding",
            }
        ],
        "caveats": [],
    }


def bad_assessment() -> dict[str, Any]:
    """Invented CVE + wrong number + unknown evidence id: must trip grounding."""
    return {
        "executive_summary": "The system is exposed through CVE-2099-0001 in the mail service.",
        "findings": [
            {
                "threat_id": "TH-0001",
                "title": "Invented finding",
                "priority": "P1",
                "agrees_with_scanner": True,
                "evidence": [{"ref": "TH-9999", "kind": "threat", "note": "does not exist"}],
                "rationale": "Made up.",
                "confidence": 0.9,
                "counterfactuals": [],
                "numbers": [{"ref": "TH-0001", "field": "risk_score", "value": 50.0}],
            }
        ],
        "remediation_plan": [],
        "claims": [],
        "caveats": [],
    }


def good_triage() -> dict[str, Any]:
    """A grounded TriageReport payload."""
    return {
        "findings": [
            {
                "threat_id": "TH-0001",
                "title": "Pre-auth compromise of network-exposed sshd",
                "priority": "P1",
                "agrees_with_scanner": True,
                "evidence": EVIDENCE,
                "rationale": "Network reachable, runs as root, KEV-listed.",
                "confidence": 0.9,
                "counterfactuals": [],
                "numbers": [],
            }
        ],
        "caveats": [],
    }


def bad_triage() -> dict[str, Any]:
    """A TriageReport citing a CVE that is not in the report."""
    out = good_triage()
    out["findings"][0]["rationale"] = "Exploited through CVE-2031-0001 in the wild."
    return out
