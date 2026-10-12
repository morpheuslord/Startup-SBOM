"""Explainable output models and the built-in specialist agents.

Every output item inherits :class:`Explained` (evidence ids, rationale, calibrated
confidence, counterfactuals, and the numbers it states with their source ids) so the
grounding validator can check it and a reader can audit it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from startup_sbom.ai import INSTALL_HINT, AIUnavailableError, prompts
from startup_sbom.ai.grounding import attach_grounding
from startup_sbom.ai.tools import AgentDeps

try:
    from pydantic_ai import Agent
    from pydantic_ai.models import Model
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise AIUnavailableError(f"the AI features need 'pydantic-ai': {INSTALL_HINT}") from exc

EvidenceKind = Literal[
    "threat",
    "vulnerability",
    "package",
    "service",
    "chain",
    "supply_chain_finding",
    "attack_step",
]
Priority = Literal["P1", "P2", "P3", "P4"]
Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


class Evidence(BaseModel):
    """A pointer into the scan report. ``ref`` MUST be an id returned by a tool."""

    ref: str = Field(
        description="Exact report id: threat id, CVE id, package id (purl), service id, "
        "chain id, supply-chain finding id or attack step id"
    )
    kind: EvidenceKind
    note: str | None = Field(None, description="What this evidence shows, one sentence")


class Counterfactual(BaseModel):
    """If ``condition`` held, the conclusion would change as ``effect`` says."""

    condition: str = Field(description="e.g. 'sshd bound to 127.0.0.1 only'")
    effect: str = Field(description="e.g. 'priority drops from P1 to P3'")


class NumberRef(BaseModel):
    """A number stated in the output and the report object it was copied from."""

    ref: str = Field(description="Report id the number belongs to")
    field: str = Field(
        description="risk_score | epss | epss_percentile | cvss | likelihood | score | "
        "impact | blast_score | exposure"
    )
    value: float


class Explained(BaseModel):
    """XAI contract shared by every output item."""

    evidence: list[Evidence] = Field(min_length=1, max_length=12)
    rationale: str = Field(description="Why, in 1-4 sentences, using only cited facts")
    confidence: Confidence
    counterfactuals: list[Counterfactual] = Field(default_factory=list, max_length=3)
    numbers: list[NumberRef] = Field(
        default_factory=list,
        max_length=8,
        description="Every number stated in this item, copied exactly from a tool result",
    )


class RankedThreat(Explained):
    threat_id: str
    title: str
    priority: Priority
    agrees_with_scanner: bool = Field(
        description="False if this priority contradicts the scanner's SSVC decision / risk"
    )


class TriageReport(BaseModel):
    findings: list[RankedThreat] = Field(max_length=25)
    caveats: list[str] = Field(default_factory=list)


class ExploitabilityAssessment(Explained):
    threat_id: str
    exploitability: Literal["active", "weaponized", "poc", "theoretical", "unlikely"]
    attacker_precondition: str = Field(description="State the attacker needs, e.g. 'remote'")
    blocking_mitigations: list[str] = Field(default_factory=list)


class ExploitabilityReport(BaseModel):
    assessments: list[ExploitabilityAssessment] = Field(max_length=20)
    caveats: list[str] = Field(default_factory=list)


class ChainReview(Explained):
    chain_id: str
    plausible: bool
    weakest_step: str | None = Field(None, description="Step id or rule of the weakest step")
    missing_preconditions: list[str] = Field(default_factory=list)
    break_with: str | None = Field(None, description="The single fix that breaks the chain")


class ChainReviewReport(BaseModel):
    reviews: list[ChainReview] = Field(max_length=15)
    caveats: list[str] = Field(default_factory=list)


class SupplyChainReview(Explained):
    subject: str = Field(description="Package id or supply-chain finding id")
    concern: str
    affected_services: list[str] = Field(default_factory=list)
    worst_path: list[str] = Field(default_factory=list)


class SupplyChainReport(BaseModel):
    reviews: list[SupplyChainReview] = Field(max_length=15)
    caveats: list[str] = Field(default_factory=list)


class RemediationStep(Explained):
    title: str
    commands: list[str] = Field(
        default_factory=list, description="Suggested commands for a human; never executed"
    )
    fixes: list[str] = Field(default_factory=list, description="Threat ids this step resolves")
    requires_restart: bool = False


class RemediationPlan(BaseModel):
    steps: list[RemediationStep] = Field(max_length=20)
    caveats: list[str] = Field(default_factory=list)


class KeyRisk(Explained):
    statement: str


class ExecutiveBrief(BaseModel):
    headline: str = Field(max_length=200)
    summary: str = Field(max_length=2500)
    key_risks: list[KeyRisk] = Field(max_length=8)
    posture: Literal["critical", "poor", "fair", "good"]
    caveats: list[str] = Field(default_factory=list)


class Finding(Explained):
    threat_id: str | None = Field(None, description="Threat id when the finding is a threat")
    title: str
    priority: Priority
    agrees_with_scanner: bool = True


class ClaimOut(BaseModel):
    """One atomic statement of the final assessment and the ids/numbers it relies on."""

    text: str
    cites: list[str] = Field(default_factory=list, description="Report ids supporting it")
    numbers: list[NumberRef] = Field(default_factory=list)
    kind: Literal["finding", "recommendation", "context"] = "finding"


class FinalAssessment(BaseModel):
    """The orchestrator's synthesis, converted into an ``AIAssessment``."""

    executive_summary: str = Field(max_length=4000)
    findings: list[Finding] = Field(max_length=30)
    remediation_plan: list[RemediationStep] = Field(max_length=20)
    claims: list[ClaimOut] = Field(default_factory=list, max_length=60)
    caveats: list[str] = Field(default_factory=list)


def make_agent(
    model: Model | str,
    *,
    name: str,
    output_type: type[BaseModel],
    instructions: str,
) -> Agent[AgentDeps, Any]:
    """A grounded, read-only specialist agent (report tools are injected per run)."""
    agent: Agent[AgentDeps, Any] = Agent(
        model,
        name=name,
        deps_type=AgentDeps,
        output_type=output_type,
        instructions=instructions,
        retries={"tools": 2, "output": 2},
        defer_model_check=True,
    )
    attach_grounding(agent)
    return agent


def _builder(
    name: str, output_type: type[BaseModel], instructions: str
) -> Callable[[Model | str], Agent[AgentDeps, Any]]:
    def build(model: Model | str) -> Agent[AgentDeps, Any]:
        return make_agent(model, name=name, output_type=output_type, instructions=instructions)

    build.__doc__ = f"Build the {name} specialist."
    return build


#: name -> (description, output type, builder)
BUILTINS: dict[str, tuple[str, type[BaseModel], Callable[[Model | str], Agent[AgentDeps, Any]]]] = {
    "triage": (
        "Triage/prioritiser: ranks threats P1-P4 with evidence and flags disagreement "
        "with the scanner",
        TriageReport,
        _builder("triage", TriageReport, prompts.TRIAGE),
    ),
    "exploitability": (
        "Exploitability analyst: judges real-world exploitability from reachability, "
        "hardening, SSVC, EPSS, KEV and intel",
        ExploitabilityReport,
        _builder("exploitability", ExploitabilityReport, prompts.EXPLOITABILITY),
    ),
    "attack_chains": (
        "Attack-chain reviewer: plausibility, weakest step, missing preconditions and "
        "the fix that breaks each chain",
        ChainReviewReport,
        _builder("attack_chains", ChainReviewReport, prompts.CHAINS),
    ),
    "supply_chain": (
        "Supply-chain analyst: provenance findings, vendor exposure and blast radius "
        "through load paths",
        SupplyChainReport,
        _builder("supply_chain", SupplyChainReport, prompts.SUPPLY_CHAIN),
    ),
    "remediation": (
        "Remediation planner: ordered, minimal fix plan with the threat ids each step resolves",
        RemediationPlan,
        _builder("remediation", RemediationPlan, prompts.REMEDIATION),
    ),
    "executive": (
        "Executive summariser: headline, plain-language summary, key risks and posture",
        ExecutiveBrief,
        _builder("executive", ExecutiveBrief, prompts.EXECUTIVE),
    ),
}
